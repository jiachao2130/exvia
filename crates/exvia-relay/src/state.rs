// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 中继状态：sqlite 持久化 + 在线注册表 + 待决会话表。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::RngCore;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, watch};

use exvia_proto::msgs::MachineInfo;

pub type SharedState = Arc<RelayState>;

/// 注册令牌列表行：(id, label, created_at, used_at)。
pub type TokenRow = (i64, Option<String>, i64, Option<i64>);
/// 审计行：(ts, username, machine_id, kind, bytes_up, bytes_down, duration_ms)。
pub type AuditRow = (i64, Option<String>, Option<String>, String, i64, i64, i64);
/// 待决会话表：sid → (建立结果应答通道, 所属机器)。
pub type PendingSessions = HashMap<u64, (oneshot::Sender<Result<(), String>>, String)>;

/// -R 反向转发的回程登记：sid → { 所属机器, 发起用户, CLI 复用句柄, 并发回程流数 }。
/// 控制流桥接建立时登记，桥接结束（任一端断开）即摘除。
pub struct ReverseEntry {
    pub machine_id: String,
    pub username: String,
    pub mux: crate::axum_ws::RelayMux,
    /// 在途回程流数（上限 REVERSE_STREAM_LIMIT）。
    pub active: usize,
}

/// 每 sid 并发回程流上限：超限的 ReverseOpen 直接忽略（agent 侧等待超时兜底关闭）。
pub const REVERSE_STREAM_LIMIT: usize = 64;

/// 控制面通道容量：JSON 消息都在百字节级，256 条给足余量。满时发送方 await 背压
/// 而非丢消息；配合认证窗口/空闲超时，恶意慢排水的连接会被关停而不是无限积压。
pub const CONTROL_QUEUE: usize = 256;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 登录失败滑窗清理：清掉 60s 窗外的时间戳与随之变空的桶。
fn prune_buckets(fails: &mut HashMap<String, Vec<std::time::Instant>>, now: std::time::Instant) {
    for bucket in fails.values_mut() {
        bucket.retain(|t| now.duration_since(*t) < std::time::Duration::from_secs(60));
    }
    fails.retain(|_, v| !v.is_empty());
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn rand_b64(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// 一条在线 agent 连接的全部句柄。
pub struct AgentConn {
    pub machine_id: String,
    pub hostname: String,
    pub x25519_pub: String,
    /// RelayToAgent JSON 出口。
    pub control_tx: mpsc::Sender<String>,
    /// 在该 agent 连接上打开新会话流。
    pub mux: crate::axum_ws::RelayMux,
    pub last_seen: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct CliConn {
    pub username: String,
    pub role: String,
    pub x25519_pub: String,
    /// CLI 的 ed25519 公钥（登录时上报；票据验签在 agent 侧，这里仅留痕/透传）。
    pub pubkey: String,
    /// 本连接登录所用的会话令牌（Logout 时精确吊销这一行；admin 令牌登录无会话行为 None）。
    pub session_token: Option<String>,
    /// 连接代号：连接断开时按它把名下会话组整批下线（`drop_connection_state`）。
    pub conn_id: u64,
    pub control_tx: mpsc::Sender<String>,
    pub mux: crate::axum_ws::RelayMux,
}

/// 已建立会话的登记组：一个 sid 一组（控制桥 + 该 sid 的全部回程桥）。
/// 归属校验用所有者，审计与列表用其余字段；`cancel` 向组内全部桥接广播关闭信号。
pub struct SessionEntry {
    pub owner: String,
    pub machine_id: String,
    pub kind: String,
    pub started_at: u64,
    /// 会话所属 CLI 连接（`drop_connection_state` 按它把连接名下的组整批下线）。
    pub conn_id: u64,
    /// 主动关闭时向组内全部桥接广播；sender 被 drop（控制桥自然结束摘组）
    /// 同样让挂靠桥感知退出。组内桥接各持一个 `Receiver` clone。
    cancel: watch::Sender<bool>,
}

/// 未认证连接的接入配额。agent/CLI 都要先经 TLS + WS 握手再认证，这一阶段
/// 是公网上唯一谁都能摸到的面：不限额的话，并发错误密码就是 argon2 放大
/// DoS（每次校验 ~100ms CPU + ~19MB 内存）。上限取"正常使用永远碰不到、
/// 放大攻击塞不满"之间：私有部署就几台机器，每 IP 16、全局 128 绰绰有余。
struct UnauthConns {
    total: AtomicU64,
    per_ip: Mutex<HashMap<std::net::IpAddr, u32>>,
}

impl Default for UnauthConns {
    fn default() -> Self {
        Self {
            total: AtomicU64::new(0),
            per_ip: Mutex::new(HashMap::new()),
        }
    }
}

/// 未认证连接配额占用的凭据：认证成功或连接断开时自动释放。
/// 漏释放会让计数只增不减、中继最终拒绝一切新连接，Drop 是唯一出口。
pub struct UnauthConnGuard {
    conns: Arc<UnauthConns>,
    ip: std::net::IpAddr,
}

impl Drop for UnauthConnGuard {
    fn drop(&mut self) {
        self.conns.total.fetch_sub(1, Ordering::AcqRel);
        let mut per_ip = self
            .conns
            .per_ip
            .lock()
            .unwrap_or_else(|_| RelayState::bail_poisoned());
        if let Some(n) = per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                per_ip.remove(&self.ip);
            }
        }
    }
}

pub struct RelayState {
    db: Mutex<Connection>,
    pub agents: Mutex<HashMap<String, Arc<AgentConn>>>,
    /// sid 随机化防伪造/枚举。
    pub pending: Mutex<PendingSessions>,
    /// -R 回程登记（见 ReverseEntry）。
    pub reverse: Mutex<HashMap<u64, ReverseEntry>>,
    /// 登录失败时间戳（60s 滑动窗，限速用），按尝试用户名分桶 + 全局桶。
    login_fails: Mutex<HashMap<String, Vec<std::time::Instant>>>,
    /// 未认证连接配额（见 UnauthConns）。
    unauth: Arc<UnauthConns>,
    /// 活跃会话组：sid → 登记项（所有者、机器、类型、起始时间、所属连接、取消广播）。
    session_closers: Mutex<HashMap<u64, SessionEntry>>,
    /// CLI 连接代号发号器（连接级清理的分组键）。
    next_conn_id: AtomicU64,
}

impl RelayState {
    pub fn open(db_path: &std::path::Path) -> rusqlite::Result<Self> {
        let db = Connection::open(db_path)?;
        db.execute_batch("PRAGMA journal_mode = WAL;")?;
        Self::init_schema(&db)?;
        db.execute_batch("PRAGMA busy_timeout = 5000;").ok();
        Ok(Self::from_conn(db))
    }

    /// 建表 + 旧库迁移（open 与内存库测试共用同一套 schema）。
    fn init_schema(db: &Connection) -> rusqlite::Result<()> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS machines (
                machine_id   TEXT PRIMARY KEY,
                pubkey       TEXT NOT NULL,
                x25519_pub   TEXT NOT NULL,
                hostname     TEXT NOT NULL,
                os           TEXT NOT NULL,
                arch         TEXT NOT NULL,
                version      TEXT NOT NULL,
                registered_at INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                tags         TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                label      TEXT,
                created_at INTEGER NOT NULL,
                used_at    INTEGER
             );
             CREATE TABLE IF NOT EXISTS admin (
                id         INTEGER PRIMARY KEY CHECK (id = 1),
                token_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT NOT NULL UNIQUE,
                pass_salt  TEXT NOT NULL,
                pass_hash  TEXT NOT NULL,
                role       TEXT NOT NULL DEFAULT 'user',
                created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS machine_auth (
                username   TEXT NOT NULL,
                machine_id TEXT NOT NULL,
                UNIQUE(username, machine_id)
             );
             CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                role       TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS audit (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          INTEGER NOT NULL,
                username    TEXT,
                machine_id  TEXT,
                kind        TEXT NOT NULL,
                bytes_up    INTEGER DEFAULT 0,
                bytes_down  INTEGER DEFAULT 0,
                duration_ms INTEGER DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
             );",
        )?;
        // 旧库迁移：machines.tags 列（仅忽略"列已存在"错误）
        if let Err(e) =
            db.execute_batch("ALTER TABLE machines ADD COLUMN tags TEXT NOT NULL DEFAULT '';")
        {
            if !e.to_string().contains("duplicate column") {
                return Err(e);
            }
        }
        // 旧库迁移：admin.created_at。0 表示"未知"，用于提示长期未轮换的管理员令牌。
        if let Err(e) =
            db.execute_batch("ALTER TABLE admin ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;")
        {
            if !e.to_string().contains("duplicate column") {
                return Err(e);
            }
        }
        Ok(())
    }

    fn from_conn(db: Connection) -> Self {
        Self {
            db: Mutex::new(db),
            agents: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            reverse: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()),
            unauth: Arc::new(UnauthConns::default()),
            session_closers: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(1),
        }
    }

    /// 测试构造器：内存库，与 open 走同一套建表逻辑。
    #[cfg(test)]
    pub(crate) fn in_memory() -> rusqlite::Result<Self> {
        let db = Connection::open_in_memory()?;
        Self::init_schema(&db)?;
        Ok(Self::from_conn(db))
    }

    // 锁毒化即状态可能不一致：不 into_inner() 带病恢复，退出（码 2）交给 systemd 拉起；
    // tokio 任务 panic 不退进程，否则会留下连锁失败的僵尸中继。锁访问一律走下面这些 helper。

    fn bail_poisoned() -> ! {
        eprintln!("state lock poisoned (panic while held), exiting for systemd to restart");
        std::process::exit(2);
    }

    pub fn lock_db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|_| Self::bail_poisoned())
    }

    pub fn lock_agents(&self) -> MutexGuard<'_, HashMap<String, Arc<AgentConn>>> {
        self.agents.lock().unwrap_or_else(|_| Self::bail_poisoned())
    }

    pub fn lock_pending(&self) -> MutexGuard<'_, PendingSessions> {
        self.pending
            .lock()
            .unwrap_or_else(|_| Self::bail_poisoned())
    }

    pub fn lock_reverse(&self) -> MutexGuard<'_, HashMap<u64, ReverseEntry>> {
        self.reverse
            .lock()
            .unwrap_or_else(|_| Self::bail_poisoned())
    }

    pub fn lock_login_fails(&self) -> MutexGuard<'_, HashMap<String, Vec<std::time::Instant>>> {
        self.login_fails
            .lock()
            .unwrap_or_else(|_| Self::bail_poisoned())
    }

    // ---- 未认证连接配额 ----

    /// 同一来源 IP 同时允许的在握未认证连接数。agent 常驻连接认证后即释放
    /// 配额，这里只约束"还没过认证"的瞬间，正常部署每 IP 个位数。
    pub const MAX_UNAUTH_PER_IP: u32 = 16;
    /// 全局未认证连接数上限。钉死放大系数：最坏情况并发 argon2 尝试被限制在
    /// 这个数量级，小规格中继烧不穿。
    pub const MAX_UNAUTH_TOTAL: u64 = 128;

    /// WS 升级前调用：配额内返回凭据（持有即占用，认证成功或断开时自动释放），
    /// 超额的返回 None，HTTP 层直接 429 不升级。
    pub fn acquire_unauth(&self, ip: std::net::IpAddr) -> Option<UnauthConnGuard> {
        let mut per_ip = self
            .unauth
            .per_ip
            .lock()
            .unwrap_or_else(|_| Self::bail_poisoned());
        if self.unauth.total.load(Ordering::Acquire) >= Self::MAX_UNAUTH_TOTAL {
            return None;
        }
        let slot = per_ip.entry(ip).or_insert(0);
        if *slot >= Self::MAX_UNAUTH_PER_IP {
            return None;
        }
        *slot += 1;
        self.unauth.total.fetch_add(1, Ordering::AcqRel);
        Some(UnauthConnGuard {
            conns: self.unauth.clone(),
            ip,
        })
    }

    #[cfg(test)]
    fn unauth_total(&self) -> u64 {
        self.unauth.total.load(Ordering::Acquire)
    }

    pub fn lock_session_closers(&self) -> MutexGuard<'_, HashMap<u64, SessionEntry>> {
        self.session_closers
            .lock()
            .unwrap_or_else(|_| Self::bail_poisoned())
    }

    /// CLI 连接代号：连接级清理的分组键，单调递增不复用。
    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// 控制桥登记：一个 sid 一组，同 sid 已有活跃会话时拒绝（fail-closed，
    /// 防止旧桥的取消通道被顶掉——CloseSession 因此能一次杀干净整组）。
    /// 成功返回该会话的取消接收端：控制桥 select 臂持有，回程桥经
    /// `attach_session_bridge` 另取一份。
    pub fn register_session(
        &self,
        sid: u64,
        owner: String,
        machine_id: String,
        kind: String,
        conn_id: u64,
    ) -> Option<watch::Receiver<bool>> {
        let mut map = self.lock_session_closers();
        if map.contains_key(&sid) {
            return None;
        }
        let (cancel, cancel_rx) = watch::channel(false);
        map.insert(
            sid,
            SessionEntry {
                owner,
                machine_id,
                kind,
                started_at: now_secs(),
                conn_id,
                cancel,
            },
        );
        Some(cancel_rx)
    }

    /// 回程桥挂靠既有会话组，返回该组的取消接收端；会话不存在（控制桥已结束）返回 None。
    pub fn attach_session_bridge(&self, sid: u64) -> Option<watch::Receiver<bool>> {
        Some(self.lock_session_closers().get(&sid)?.cancel.subscribe())
    }

    /// 控制桥结束：摘除整组，会话从活跃列表消失。
    pub fn unregister_session(&self, sid: u64) {
        self.lock_session_closers().remove(&sid);
    }

    /// sid 是否有活跃会话组（CreateSession 撞号检查用）。
    pub fn session_active(&self, sid: u64) -> bool {
        self.lock_session_closers().contains_key(&sid)
    }

    /// 活跃会话快照；`viewer` 为 None 表示不过滤（admin）。
    pub fn list_sessions(&self, viewer: Option<&str>) -> Vec<exvia_proto::msgs::SessionInfo> {
        let map = self.lock_session_closers();
        let now = now_secs();
        let mut out: Vec<_> = map
            .iter()
            .filter(|(_, e)| viewer.map(|v| e.owner == v).unwrap_or(true))
            .map(|(sid, e)| exvia_proto::msgs::SessionInfo {
                sid: *sid,
                machine_id: e.machine_id.clone(),
                user: e.owner.clone(),
                kind: e.kind.clone(),
                age_secs: now.saturating_sub(e.started_at),
            })
            .collect();
        out.sort_by_key(|s| s.sid);
        out
    }

    /// 带用户归属校验的关闭：一次取消该 sid 的全部桥接（控制桥 + 回程桥），
    /// 并摘除 -R 回程登记；未命中（已结束）返回 false。
    pub fn close_session_owned(&self, sid: u64, username: &str, is_admin: bool) -> bool {
        let mut map = self.lock_session_closers();
        match map.get(&sid) {
            Some(e) if is_admin || e.owner == username => {}
            _ => return false,
        }
        let entry = map.remove(&sid).expect("entry checked above");
        let _ = entry.cancel.send(true);
        // 回程登记立刻摘除（被取消的控制桥收尾时还会再摘一次，幂等）
        self.lock_reverse().remove(&sid);
        true
    }

    /// CLI 连接断开：把该连接名下的全部活跃会话组取消下线（组取消会经由控制桥
    /// 收尾连带摘除回程登记），其它连接的会话不受波及。
    pub fn drop_connection_state(&self, conn_id: u64) {
        let dead: Vec<u64> = self
            .lock_session_closers()
            .iter()
            .filter(|(_, e)| e.conn_id == conn_id)
            .map(|(sid, _)| *sid)
            .collect();
        for sid in dead {
            if let Some(entry) = self.lock_session_closers().remove(&sid) {
                let _ = entry.cancel.send(true);
            }
        }
    }

    // ---- 令牌 ----

    pub fn ensure_admin_token(&self) -> anyhow::Result<Option<String>> {
        let db = self.lock_db();
        let exists: bool = db
            .query_row("SELECT COUNT(*) FROM admin WHERE id = 1", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n > 0)?;
        if exists {
            return Ok(None);
        }
        let token = format!("exvia_adm_{}", rand_b64(24));
        db.execute(
            "INSERT INTO admin (id, token_hash, created_at) VALUES (1, ?1, ?2)",
            rusqlite::params![sha256_hex(token.as_bytes()), now_secs() as i64],
        )?;
        Ok(Some(token))
    }

    pub fn check_admin_token(&self, token: &str) -> bool {
        let db = self.lock_db();
        let hash = sha256_hex(token.as_bytes());
        db.query_row(
            "SELECT COUNT(*) FROM admin WHERE token_hash = ?1",
            [&hash],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false)
    }

    /// 写新哈希即作废旧令牌（rotate 隐含 revoke），返回新明文。
    pub fn rotate_admin_token(&self) -> anyhow::Result<String> {
        let token = format!("exvia_adm_{}", rand_b64(24));
        let db = self.lock_db();
        db.execute(
            "INSERT INTO admin (id, token_hash, created_at) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET token_hash = excluded.token_hash,
                                           created_at = excluded.created_at",
            rusqlite::params![sha256_hex(token.as_bytes()), now_secs() as i64],
        )?;
        Ok(token)
    }

    /// 管理员令牌已存在多少秒；`None` 表示没有令牌或老库未记录时间。
    ///
    /// 这是"提醒"而不是"强制过期"：中继是自托管单点，令牌半夜失效等于把人锁在门外，
    /// 交由运维在拿到提示后自行择时轮换。
    pub fn admin_token_age_secs(&self) -> Option<u64> {
        let db = self.lock_db();
        let created: i64 = db
            .query_row("SELECT created_at FROM admin WHERE id = 1", [], |r| {
                r.get(0)
            })
            .ok()?;
        if created <= 0 {
            return None;
        }
        Some(now_secs().saturating_sub(created as u64))
    }

    pub fn create_token(&self, label: Option<&str>) -> anyhow::Result<String> {
        let token = format!("exvia_reg_{}", rand_b64(24));
        let db = self.lock_db();
        db.execute(
            "INSERT INTO tokens (token_hash, label, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![sha256_hex(token.as_bytes()), label, now_secs() as i64],
        )?;
        Ok(token)
    }

    pub fn list_tokens(&self) -> anyhow::Result<Vec<TokenRow>> {
        let db = self.lock_db();
        let mut st = db.prepare("SELECT id, label, created_at, used_at FROM tokens ORDER BY id")?;
        let rows = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn revoke_token(&self, id: i64) -> anyhow::Result<bool> {
        let db = self.lock_db();
        let n = db.execute("DELETE FROM tokens WHERE id = ?1", [id])?;
        Ok(n > 0)
    }

    /// 校验并核销一次性注册令牌。
    pub fn use_register_token(&self, token: &str) -> anyhow::Result<bool> {
        let db = self.lock_db();
        let hash = sha256_hex(token.as_bytes());
        let n = db.execute(
            "UPDATE tokens SET used_at = ?2 WHERE token_hash = ?1 AND used_at IS NULL",
            rusqlite::params![hash, now_secs() as i64],
        )?;
        Ok(n > 0)
    }

    // ---- 机器 ----

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_machine(
        &self,
        machine_id: &str,
        pubkey: &str,
        x25519_pub: &str,
        hostname: &str,
        os: &str,
        arch: &str,
        version: &str,
    ) -> anyhow::Result<()> {
        let db = self.lock_db();
        db.execute(
            "INSERT INTO machines (machine_id, pubkey, x25519_pub, hostname, os, arch, version, registered_at, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
             ON CONFLICT(machine_id) DO UPDATE SET
                pubkey = ?2, x25519_pub = ?3, hostname = ?4, os = ?5, arch = ?6,
                version = ?7, last_seen = ?8",
            rusqlite::params![machine_id, pubkey, x25519_pub, hostname, os, arch, version, now_secs() as i64],
        )?;
        Ok(())
    }

    /// 挑战验签用的 ed25519 公钥。
    pub fn get_machine_pubkey(&self, machine_id: &str) -> anyhow::Result<Option<String>> {
        Ok(self.get_machine_full(machine_id)?.map(|m| m.pubkey))
    }

    /// 机器完整登记信息（重连认证后重建元数据用）。
    pub fn get_machine_full(&self, machine_id: &str) -> anyhow::Result<Option<MachineFull>> {
        let db = self.lock_db();
        let mut st = db.prepare(
            "SELECT pubkey, x25519_pub, hostname, version FROM machines WHERE machine_id = ?1",
        )?;
        let mut rows = st.query_map([machine_id], |r| {
            Ok(MachineFull {
                pubkey: r.get(0)?,
                x25519_pub: r.get(1)?,
                hostname: r.get(2)?,
                version: r.get(3)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn update_machine_version(&self, machine_id: &str, version: &str) {
        let _ = self.lock_db().execute(
            "UPDATE machines SET version = ?1 WHERE machine_id = ?2",
            [version, machine_id],
        );
    }

    pub fn touch_machine(&self, machine_id: &str) {
        let db = self.lock_db();
        let _ = db.execute(
            "UPDATE machines SET last_seen = ?1 WHERE machine_id = ?2",
            rusqlite::params![now_secs() as i64, machine_id],
        );
    }

    // ---- 用户 / 授权 / 审计 ----

    /// argon2id 哈希（随机盐，PHC 字符串）。user_add / passwd / 旧哈希升级共用。
    fn hash_password(password: &str) -> anyhow::Result<String> {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        use argon2::Argon2;
        let salt = SaltString::generate(&mut OsRng);
        Ok(Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?
            .to_string())
    }

    pub fn user_add(&self, username: &str, password: &str, role: &str) -> anyhow::Result<()> {
        let phc = Self::hash_password(password)?;
        let db = self.lock_db();
        db.execute(
            "INSERT INTO users (username, pass_salt, pass_hash, role, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![username, "", phc, role, now_secs() as i64],
        )?;
        Ok(())
    }

    /// 改密即吊销该用户全部会话（安全惯例），授权关系不动；用户不存在返回 false。
    pub fn user_set_password(&self, username: &str, password: &str) -> anyhow::Result<bool> {
        let phc = Self::hash_password(password)?;
        let db = self.lock_db();
        let n = db.execute(
            "UPDATE users SET pass_salt = '', pass_hash = ?1 WHERE username = ?2",
            rusqlite::params![phc, username],
        )?;
        if n > 0 {
            db.execute("DELETE FROM sessions WHERE username = ?1", [username])?;
        }
        Ok(n > 0)
    }

    pub fn user_del(&self, username: &str) -> anyhow::Result<bool> {
        let db = self.lock_db();
        let n = db.execute("DELETE FROM users WHERE username = ?1", [username])?;
        // 会话令牌同步失效（防被删用户凭已签发令牌继续登录）
        let _ = db.execute("DELETE FROM sessions WHERE username = ?1", [username]);
        let _ = db.execute("DELETE FROM machine_auth WHERE username = ?1", [username]);
        Ok(n > 0)
    }

    pub fn user_list(&self) -> anyhow::Result<Vec<(String, String)>> {
        let db = self.lock_db();
        let mut st = db.prepare("SELECT username, role FROM users ORDER BY id")?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// 校验用户名/密码，返回角色。argon2 PHC 为主，兼容早期 sha256+salt 记录。
    pub fn check_user(&self, username: &str, password: &str) -> Option<String> {
        use argon2::password_hash::PasswordVerifier;
        use argon2::Argon2;
        // argon2 校验耗时 ~100ms：锁内一次取齐角色与凭证行（role 为 NOT NULL，
        // 行存在则必可读），锁外验证，避免卡死整个控制面 DB
        let row = {
            let db = self.lock_db();
            db.query_row(
                "SELECT role, pass_hash, pass_salt FROM users WHERE username = ?1",
                [username],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .ok()
        };
        let (role, stored, salt) = match row {
            Some(r) => r,
            None => {
                // 查无此人也付一次完整的 argon2 校验价（参数与真实路径完全一致）：
                // 响应时间不再泄露用户名存在性，密码洪水也不会因为"查无此人"而变便宜。
                let parsed = argon2::PasswordHash::new(Self::dummy_hash()).ok()?;
                let _ = Argon2::default().verify_password(password.as_bytes(), &parsed);
                return None;
            }
        };
        if stored.starts_with("$argon2") {
            let parsed = argon2::PasswordHash::new(&stored).ok()?;
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .ok()
                .map(|_| role)
        } else {
            // 旧版 sha256+salt 兼容：通过后迁移到 argon2
            let got = sha256_hex(format!("{salt}{password}").as_bytes());
            if got == stored {
                let _ = self.user_add_rehash(username, password);
                Some(role)
            } else {
                None
            }
        }
    }

    /// 查无此人时用于等值校验的 dummy 哈希：Argon2::default 参数与真实路径
    /// 完全一致（~100ms CPU、~19MB 内存一次不少），口令随机生成只存内存——
    /// 攻击者不可能命中，形态上与真实 PHC 无差别。
    fn dummy_hash() -> &'static str {
        use argon2::Argon2;
        static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        DUMMY.get_or_init(|| {
            use argon2::password_hash::{PasswordHasher, SaltString};
            let salt = SaltString::generate(argon2::password_hash::rand_core::OsRng);
            let rand_pw = format!("exvia-dummy-{}", rand_b64(24));
            Argon2::default()
                .hash_password(rand_pw.as_bytes(), &salt)
                .map(|h| h.to_string())
                .unwrap_or_default()
        })
    }

    /// 旧哈希记录升级为 argon2（校验通过后自动迁移）。
    fn user_add_rehash(&self, username: &str, password: &str) -> anyhow::Result<()> {
        let phc = Self::hash_password(password)?;
        let db = self.lock_db();
        db.execute(
            "UPDATE users SET pass_salt = '', pass_hash = ?1 WHERE username = ?2",
            [phc.as_str(), username],
        )?;
        Ok(())
    }

    pub fn auth_grant(&self, username: &str, machine_id: &str) -> anyhow::Result<()> {
        let db = self.lock_db();
        db.execute(
            "INSERT OR IGNORE INTO machine_auth (username, machine_id) VALUES (?1, ?2)",
            [username, machine_id],
        )?;
        Ok(())
    }

    pub fn auth_revoke(&self, username: &str, machine_id: &str) -> anyhow::Result<bool> {
        let db = self.lock_db();
        let n = db.execute(
            "DELETE FROM machine_auth WHERE username = ?1 AND machine_id = ?2",
            [username, machine_id],
        )?;
        Ok(n > 0)
    }

    /// 用户被授权的机器列表。
    pub fn user_machines(&self, username: &str) -> anyhow::Result<Vec<String>> {
        let db = self.lock_db();
        let mut st = db.prepare("SELECT machine_id FROM machine_auth WHERE username = ?1")?;
        let rows = st
            .query_map([username], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn user_machines_all(&self) -> Vec<(String, String)> {
        let db = self.lock_db();
        let mut st =
            match db.prepare("SELECT username, machine_id FROM machine_auth ORDER BY username") {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            };
        st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    /// 日常维护：清过期审计/会话令牌 + WAL checkpoint（TRUNCATE 让 db 单文件自包含）。
    /// None = 不清理审计（--audit-retention-days 0 的语义），但会话令牌仍要清，防无限增长。
    pub fn maintenance(&self, audit_cutoff_ts: Option<i64>) -> anyhow::Result<()> {
        // 先做内存清扫，再碰 DB 锁，避免在持 DB 锁期间做无关工作
        self.prune_login_fails();
        let db = self.lock_db();
        if let Some(cutoff) = audit_cutoff_ts {
            let n = db.execute("DELETE FROM audit WHERE ts < ?1", [cutoff])?;
            if n > 0 {
                tracing::info!("audit cleanup: removed {n} expired rows");
            }
        }
        let s = db.execute(
            "DELETE FROM sessions WHERE expires_at < ?1",
            [now_secs() as i64],
        )?;
        if s > 0 {
            tracing::info!("session token cleanup: removed {s} expired rows");
        }
        let _ = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        Ok(())
    }

    /// 优雅关闭收尾用：WAL checkpoint（TRUNCATE），保证 db 单文件自包含再退进程。
    pub fn checkpoint(&self) {
        if let Err(e) = self
            .lock_db()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        {
            tracing::warn!("WAL checkpoint failed: {e}");
        }
    }

    /// 签发会话令牌（7 天有效）。CLI 只落盘令牌，不落盘明文密码。
    pub fn issue_session_token(&self, username: &str, role: &str) -> anyhow::Result<String> {
        let token = format!("exvia_sess_{}", rand_b64(24));
        let db = self.lock_db();
        db.execute(
            "INSERT INTO sessions (token_hash, username, role, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                sha256_hex(token.as_bytes()),
                username,
                role,
                now_secs() as i64,
                (now_secs() + 7 * 86400) as i64
            ],
        )?;
        Ok(token)
    }

    /// 校验会话令牌，返回 (username, role)；过期则顺手删除。
    pub fn check_session_token(&self, token: &str) -> Option<(String, String)> {
        let db = self.lock_db();
        let hash = sha256_hex(token.as_bytes());
        let row: Option<(String, String, i64)> = db
            .query_row(
                "SELECT username, role, expires_at FROM sessions WHERE token_hash = ?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok();
        let (username, role, expires_at) = row?;
        if (expires_at as u64) < now_secs() {
            let _ = db.execute("DELETE FROM sessions WHERE token_hash = ?1", [&hash]);
            return None;
        }
        Some((username, role))
    }

    /// 精确吊销单个会话令牌（CLI logout 用），存在返回 true。
    pub fn revoke_session(&self, token: &str) -> anyhow::Result<bool> {
        let db = self.lock_db();
        let n = db.execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            [sha256_hex(token.as_bytes())],
        )?;
        Ok(n > 0)
    }

    /// 吊销某用户的全部会话令牌（relay 端 user logout），返回吊销数量。
    pub fn revoke_user_sessions(&self, username: &str) -> anyhow::Result<usize> {
        let db = self.lock_db();
        Ok(db.execute("DELETE FROM sessions WHERE username = ?1", [username])?)
    }

    /// 登录失败计数（60s 滑动窗），返回 max(该 key 桶, 全局桶)：
    /// 全局桶让"换用户名就清零"的绕过失效；空桶清扫防未认证连接撑大内存。
    pub fn register_login_fail(&self, key: &str) -> usize {
        const GLOBAL: &str = "__global__";
        let mut fails = self.lock_login_fails();
        let now = std::time::Instant::now();
        prune_buckets(&mut fails, now);
        let per_key = {
            let b = fails.entry(key.to_string()).or_default();
            b.push(now);
            b.len()
        };
        let global = {
            let b = fails.entry(GLOBAL.to_string()).or_default();
            b.push(now);
            b.len()
        };
        per_key.max(global)
    }

    /// 清扫过期时间戳与空桶（登录成功 / 日常维护时调用）。
    pub fn prune_login_fails(&self) {
        let mut fails = self.lock_login_fails();
        prune_buckets(&mut fails, std::time::Instant::now());
    }

    pub fn audit_write(
        &self,
        username: Option<&str>,
        machine_id: Option<&str>,
        kind: &str,
        bytes_up: u64,
        bytes_down: u64,
        duration_ms: u64,
    ) {
        if let Err(e) = self.lock_db().execute(
            "INSERT INTO audit (ts, username, machine_id, kind, bytes_up, bytes_down, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                now_secs() as i64,
                username,
                machine_id,
                kind,
                bytes_up as i64,
                bytes_down as i64,
                duration_ms as i64
            ],
        ) {
            tracing::warn!("audit write failed: {e}");
        }
    }

    pub fn audit_list(&self, limit: i64) -> anyhow::Result<Vec<AuditRow>> {
        let db = self.lock_db();
        let mut st = db.prepare(
            "SELECT ts, username, machine_id, kind, bytes_up, bytes_down, duration_ms FROM audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = st
            .query_map([limit], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// 导出用查询：按时间窗与可选过滤条件升序返回，便于追加导出与去重。
    pub fn audit_query(
        &self,
        since: Option<i64>,
        until: Option<i64>,
        user: Option<&str>,
        machine: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<AuditRow>> {
        let mut sql = String::from(
            "SELECT ts, username, machine_id, kind, bytes_up, bytes_down, duration_ms
             FROM audit WHERE 1=1",
        );
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(t) = since {
            sql.push_str(" AND ts >= ?");
            args.push(Box::new(t));
        }
        if let Some(t) = until {
            sql.push_str(" AND ts <= ?");
            args.push(Box::new(t));
        }
        if let Some(u) = user {
            sql.push_str(" AND username = ?");
            args.push(Box::new(u.to_string()));
        }
        if let Some(m) = machine {
            sql.push_str(" AND machine_id = ?");
            args.push(Box::new(m.to_string()));
        }
        sql.push_str(" ORDER BY ts ASC, id ASC LIMIT ?");
        args.push(Box::new(limit));
        let db = self.lock_db();
        let mut st = db.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let rows = st
            .query_map(params.as_slice(), |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn machine_set_tags(&self, machine_id: &str, tags: &str) -> anyhow::Result<bool> {
        let db = self.lock_db();
        let n = db.execute(
            "UPDATE machines SET tags = ?1 WHERE machine_id = ?2",
            [tags, machine_id],
        )?;
        Ok(n > 0)
    }

    /// 删除机器及其授权关系（重装前的清理；审计历史保留）。
    pub fn machine_del(&self, machine_id: &str) -> anyhow::Result<bool> {
        let db = self.lock_db();
        let n = db.execute("DELETE FROM machines WHERE machine_id = ?1", [machine_id])?;
        db.execute(
            "DELETE FROM machine_auth WHERE machine_id = ?1",
            [machine_id],
        )?;
        Ok(n > 0)
    }

    /// 在线列表：DB 全量 + 注册表在线状态。
    pub fn machine_list(&self) -> anyhow::Result<Vec<MachineInfo>> {
        let rows = {
            let db = self.lock_db();
            let mut st = db.prepare(
                "SELECT machine_id, hostname, os, arch, version, last_seen, tags FROM machines ORDER BY registered_at",
            )?;
            // 中间绑定是必需的：块尾表达式里的临时借用会延寿到外层语句，越过 st/db 的块局部作用域。
            #[allow(clippy::let_and_return)]
            let out = st
                .query_map([], |r| {
                    Ok(MachineRow {
                        machine_id: r.get(0)?,
                        hostname: r.get(1)?,
                        os: r.get(2)?,
                        arch: r.get(3)?,
                        version: r.get(4)?,
                        last_seen: r.get::<_, i64>(5)? as u64,
                        tags: r.get(6)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            out
        };
        let now = now_secs();
        let agents = self.lock_agents();
        Ok(rows
            .into_iter()
            .map(|row| {
                let online = agents.contains_key(&row.machine_id);
                let last_seen_secs_ago = if online {
                    agents
                        .get(&row.machine_id)
                        .map(|a| now.saturating_sub(a.last_seen.load(Ordering::Relaxed)))
                } else {
                    Some(now.saturating_sub(row.last_seen))
                };
                MachineInfo {
                    machine_id: row.machine_id,
                    hostname: row.hostname,
                    os: row.os,
                    arch: row.arch,
                    version: row.version,
                    online,
                    last_seen_secs_ago,
                    tags: row.tags,
                }
            })
            .collect())
    }

    // ---- 会话 ----

    pub fn register_pending(
        &self,
        sid: u64,
        machine_id: &str,
        tx: oneshot::Sender<Result<(), String>>,
    ) {
        self.lock_pending()
            .insert(sid, (tx, machine_id.to_string()));
    }

    /// 仅当应答来自该 sid 所属的机器连接时才生效（防跨机器伪造 accept/reject）。
    pub fn resolve_pending(&self, sid: u64, machine_id: &str, result: Result<(), String>) -> bool {
        let mut pending = self.lock_pending();
        let authorized = matches!(pending.get(&sid), Some((_, owner)) if owner == machine_id);
        if authorized {
            if let Some((tx, _)) = pending.remove(&sid) {
                let _ = tx.send(result);
            }
        }
        authorized
    }

    pub fn drop_pending(&self, sid: u64) {
        self.lock_pending().remove(&sid);
    }

    pub fn pending_contains(&self, sid: u64) -> bool {
        self.lock_pending().contains_key(&sid)
    }

    // ---- -R 反向转发登记 ----

    /// 控制流桥接建立时登记（sid 生成时已排除撞号）。
    pub fn register_reverse(
        &self,
        sid: u64,
        machine_id: &str,
        username: &str,
        mux: crate::axum_ws::RelayMux,
    ) {
        self.lock_reverse().insert(
            sid,
            ReverseEntry {
                machine_id: machine_id.to_string(),
                username: username.to_string(),
                mux,
                active: 0,
            },
        );
    }

    /// 认领一次回程流名额：sid 登记在案、来自登记所属的机器、并发未超限，
    /// 三者齐备才占用并返回 (发起用户, CLI 复用句柄)；否则 None（调用方忽略）。
    pub fn claim_reverse(
        &self,
        sid: u64,
        machine_id: &str,
        limit: usize,
    ) -> Option<(String, crate::axum_ws::RelayMux)> {
        let mut reverse = self.lock_reverse();
        let e = reverse.get_mut(&sid)?;
        if e.machine_id != machine_id || e.active >= limit {
            return None;
        }
        e.active += 1;
        Some((e.username.clone(), e.mux.clone()))
    }

    /// 回程流桥接结束，归还名额（登记已摘除时静默）。
    pub fn release_reverse(&self, sid: u64) {
        if let Some(e) = self.lock_reverse().get_mut(&sid) {
            e.active = e.active.saturating_sub(1);
        }
    }

    /// 控制流桥接结束（任一端断开）即摘除；之后同 sid 的 ReverseOpen 一律忽略。
    pub fn remove_reverse(&self, sid: u64) {
        self.lock_reverse().remove(&sid);
    }

    pub fn reverse_contains(&self, sid: u64) -> bool {
        self.lock_reverse().contains_key(&sid)
    }

    // ---- 运行设置 / 状态快照 ----

    /// 写入一条运行设置（目前仅 serve 启动时记录审计保留天数，供 status 子命令读取）。
    pub fn set_meta(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.lock_db().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    /// 持久化视角的状态快照（status 子命令用；独立进程看不到内存注册表，无"在线"数）。
    pub fn stats(&self) -> anyhow::Result<RelayStats> {
        let db = self.lock_db();
        let now = now_secs() as i64;
        let day_start = now - now % 86400; // 今日按 UTC 零点切分（不引本地时区依赖）
        let count = |sql: &str| -> rusqlite::Result<i64> { db.query_row(sql, [], |r| r.get(0)) };
        let version_dist = {
            let mut st = db.prepare(
                "SELECT version, COUNT(*) AS n FROM machines GROUP BY version ORDER BY n DESC, version",
            )?;
            // 同上：中间绑定是临时借用的存活边界，不能改成块尾表达式。
            #[allow(clippy::let_and_return)]
            let out = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            out
        };
        Ok(RelayStats {
            machines_total: count("SELECT COUNT(*) FROM machines")?,
            machines_active: db.query_row(
                "SELECT COUNT(*) FROM machines WHERE last_seen >= ?1",
                [now - 300],
                |r| r.get(0),
            )?,
            version_dist,
            users: count("SELECT COUNT(*) FROM users")?,
            auth_pairs: count("SELECT COUNT(*) FROM machine_auth")?,
            tokens_unused: count("SELECT COUNT(*) FROM tokens WHERE used_at IS NULL")?,
            sessions_today: db.query_row(
                "SELECT COUNT(*) FROM audit WHERE ts >= ?1",
                [day_start],
                |r| r.get(0),
            )?,
            audit_total: count("SELECT COUNT(*) FROM audit")?,
            audit_retention_days: db
                .query_row(
                    "SELECT value FROM meta WHERE key = 'audit_retention_days'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .ok()
                .and_then(|v| v.parse().ok()),
        })
    }
}

struct MachineRow {
    machine_id: String,
    hostname: String,
    os: String,
    arch: String,
    version: String,
    last_seen: u64,
    tags: String,
}

pub struct MachineFull {
    pub pubkey: String,
    pub x25519_pub: String,
    pub hostname: String,
    pub version: String,
}

/// status 子命令的持久化状态快照。
pub struct RelayStats {
    pub machines_total: i64,
    /// last_seen 距今不超过 5 分钟的机器数。
    pub machines_active: i64,
    /// (version, 台数)，按台数降序。
    pub version_dist: Vec<(String, i64)>,
    pub users: i64,
    pub auth_pairs: i64,
    /// 未使用（used_at IS NULL）的一次性注册令牌数。
    pub tokens_unused: i64,
    /// 今日（UTC 零点起）审计行数。
    pub sessions_today: i64,
    pub audit_total: i64,
    /// serve 启动时写入 meta 的审计保留天数；老库没记录过为 None。
    pub audit_retention_days: Option<i64>,
}

/// 机器标识 = ed25519 公钥（b64）SHA-256 前 16 字节的 hex。
pub fn machine_id_from_pubkey(pubkey_b64: &str) -> anyhow::Result<String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD.decode(pubkey_b64)?;
    let hash = Sha256::digest(&raw);
    Ok(hex::encode(&hash[..16]))
}

/// 发送一条控制面 JSON（序列化失败只可能是编程错误，panic 即可暴露）。
/// 有界通道满时 await 背压（不丢消息）；接收端已关闭则静默丢弃。
pub async fn send_json<T: serde::Serialize>(tx: &mpsc::Sender<String>, msg: &T) {
    let json = serde_json::to_string(msg).expect("control message serialization failed");
    let _ = tx.send(json).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st() -> RelayState {
        RelayState::in_memory().unwrap()
    }

    /// 直插一行用户（绕开 argon2，本测试只关心非认证逻辑）。
    fn insert_user_raw(s: &RelayState, username: &str, hash: &str, salt: &str) {
        s.lock_db()
            .execute(
                "INSERT INTO users (username, pass_salt, pass_hash, role, created_at) VALUES (?1, ?2, ?3, 'user', ?4)",
                rusqlite::params![username, salt, hash, now_secs() as i64],
            )
            .unwrap();
    }

    fn count(s: &RelayState, sql: &str) -> i64 {
        s.lock_db().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn user_add_and_check_user_accepts_only_correct_password() {
        let s = st();
        s.user_add("alice", "pw-correct", "admin").unwrap();
        assert_eq!(s.check_user("alice", "pw-correct"), Some("admin".into()));
        assert_eq!(s.check_user("alice", "pw-wrong"), None);
        assert_eq!(s.check_user("ghost", "pw-correct"), None);
    }

    #[test]
    fn legacy_sha256_user_falls_back_then_rehashes_to_argon2() {
        let s = st();
        let (user, salt, pass) = ("bob", "legacy-salt", "old-pass");
        insert_user_raw(
            &s,
            user,
            &sha256_hex(format!("{salt}{pass}").as_bytes()),
            salt,
        );
        // 旧格式 fallback 校验通过，且触发自动重哈希
        assert_eq!(s.check_user(user, pass), Some("user".into()));
        {
            let db = s.lock_db();
            let (hash, salt_now): (String, String) = db
                .query_row(
                    "SELECT pass_hash, pass_salt FROM users WHERE username = ?1",
                    [user],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert!(hash.starts_with("$argon2"));
            assert_eq!(salt_now, "");
        }
        // 重哈希后 argon2 主路径直接成功，错误密码仍拒绝
        assert_eq!(s.check_user(user, pass), Some("user".into()));
        assert_eq!(s.check_user(user, "nope"), None);
    }

    #[test]
    fn session_token_issue_expire_and_garbage() {
        let s = st();
        let tok = s.issue_session_token("carol", "user").unwrap();
        assert_eq!(
            s.check_session_token(&tok),
            Some(("carol".into(), "user".into()))
        );
        // 过期：expires_at 改到过去 → 拒绝且行被删除
        s.lock_db()
            .execute("UPDATE sessions SET expires_at = 1", [])
            .unwrap();
        assert_eq!(s.check_session_token(&tok), None);
        assert_eq!(count(&s, "SELECT COUNT(*) FROM sessions"), 0);
        // 垃圾令牌
        assert_eq!(s.check_session_token("exvia_sess_garbage"), None);
        assert_eq!(s.check_session_token(""), None);
    }

    #[test]
    fn login_fail_buckets_count_per_key() {
        let s = st();
        assert_eq!(s.register_login_fail("u1"), 1);
        assert_eq!(s.register_login_fail("u1"), 2);
        assert_eq!(s.register_login_fail("u1"), 3);
        // 换 key 也不再从 1 开始：全局桶已累计 4 次
        assert_eq!(s.register_login_fail("u2"), 4);
        assert_eq!(s.register_login_fail("u3"), 5);
        assert_eq!(s.register_login_fail("u1"), 6);
        // 空桶清扫不会误删活跃桶
        s.prune_login_fails();
        assert_eq!(s.register_login_fail("u1"), 7);
    }

    // ---- 未认证连接配额 ----
    #[test]
    fn unauth_guard_caps_per_ip_and_releases_clean() {
        let s = st();
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let guards: Vec<_> = (0..RelayState::MAX_UNAUTH_PER_IP)
            .map(|_| s.acquire_unauth(ip).expect("within per-ip cap"))
            .collect();
        assert_eq!(s.unauth_total(), RelayState::MAX_UNAUTH_PER_IP as u64);
        // 每 IP 到顶后拒绝，哪怕全局还很空
        assert!(s.acquire_unauth(ip).is_none());
        drop(guards);
        // 全量释放后计数归零、槽位立即恢复——漏减会让计数只增不减
        assert_eq!(s.unauth_total(), 0);
        assert!(s.acquire_unauth(ip).is_some());
    }

    #[test]
    fn unauth_guard_caps_global_across_ips() {
        let s = st();
        let mut guards = Vec::new();
        for i in 0..RelayState::MAX_UNAUTH_TOTAL {
            let ip = format!("10.1.{}.{}", i / 256 + 1, i % 256).parse().unwrap();
            guards.push(s.acquire_unauth(ip).expect("within global cap"));
        }
        assert_eq!(s.unauth_total(), RelayState::MAX_UNAUTH_TOTAL);
        assert!(s.acquire_unauth("10.9.9.9".parse().unwrap()).is_none());
        drop(guards);
        assert_eq!(s.unauth_total(), 0);
    }

    #[test]
    fn check_user_unknown_goes_through_dummy_verify() {
        let s = st();
        // 查无此人：走 dummy argon2 校验后同样返回 None
        assert!(s.check_user("no-such-user", "whatever").is_none());
        // dummy 哈希是合法 PHC，与真实凭证形态无差别
        assert!(argon2::PasswordHash::new(RelayState::dummy_hash()).is_ok());
        // 已知用户校验行为不变
        s.user_add("alice", "pw-correct", "user").unwrap();
        assert_eq!(s.check_user("alice", "pw-correct").as_deref(), Some("user"));
        assert!(s.check_user("alice", "pw-wrong").is_none());
    }

    #[test]
    fn maintenance_none_never_purges_audit() {
        let s = st();
        let now = now_secs() as i64;
        {
            let db = s.lock_db();
            for ts in [now - 10 * 86400, now - 400 * 86400] {
                db.execute("INSERT INTO audit (ts, kind) VALUES (?1, 'shell')", [ts])
                    .unwrap();
            }
        }
        s.maintenance(None).unwrap();
        assert_eq!(count(&s, "SELECT COUNT(*) FROM audit"), 2);
        // 但过期会话令牌仍被清理
        let expired = s.issue_session_token("b", "user").unwrap();
        s.lock_db()
            .execute(
                "UPDATE sessions SET expires_at = 1 WHERE token_hash = ?1",
                [sha256_hex(expired.as_bytes())],
            )
            .unwrap();
        s.maintenance(None).unwrap();
        assert_eq!(s.check_session_token(&expired), None);
    }

    #[test]
    fn register_session_fail_closed_on_active_sid_and_close_cancels_all_bridges() {
        let s = st();
        // 控制桥登记成功，拿到取消接收端
        let mut ctl = s
            .register_session(7, "u".into(), "m1".into(), "TcpfwdReverse".into(), 1)
            .expect("first registration must succeed");
        // 回程桥挂靠：各拿独立接收端，绝不覆盖控制桥登记（-R 顶掉控制桥的旧病根）
        let mut rev1 = s.attach_session_bridge(7).expect("reverse attach");
        let mut rev2 = s.attach_session_bridge(7).expect("reverse attach 2");
        // 同 sid 二次控制桥登记被拒（fail-closed）
        assert!(s
            .register_session(7, "u".into(), "m1".into(), "Pty".into(), 2)
            .is_none());
        // 整组只算一个活跃会话
        assert_eq!(s.list_sessions(None).len(), 1);
        // CloseSession 一次取消全组：控制桥 + 全部回程桥
        assert!(s.close_session_owned(7, "u", false));
        assert!(*ctl.borrow_and_update(), "control bridge must see cancel");
        assert!(
            *rev1.borrow_and_update(),
            "reverse bridge 1 must see cancel"
        );
        assert!(
            *rev2.borrow_and_update(),
            "reverse bridge 2 must see cancel"
        );
        // 会话从活跃列表消失；重复关闭幂等返回 false
        assert!(s.list_sessions(None).is_empty());
        assert!(!s.close_session_owned(7, "u", false));
    }

    #[test]
    fn close_session_owned_checks_owner_and_admin_override() {
        let s = st();
        let _ctl = s
            .register_session(9, "alice".into(), "m1".into(), "Pty".into(), 1)
            .unwrap();
        assert!(!s.close_session_owned(9, "bob", false));
        assert!(s.session_active(9), "非本人且非 admin 不得关闭");
        assert!(s.close_session_owned(9, "bob", true));
        assert!(!s.session_active(9), "admin 关闭后应从活跃列表消失");
    }

    #[test]
    fn session_active_tracks_registered_sid() {
        let s = st();
        assert!(!s.session_active(5));
        let _ctl = s
            .register_session(5, "u".into(), "m1".into(), "Exec".into(), 3)
            .unwrap();
        assert!(s.session_active(5));
        // 控制桥自然结束：整组摘除，同 sid 可以再次登记
        s.unregister_session(5);
        assert!(!s.session_active(5));
        assert!(s
            .register_session(5, "u".into(), "m1".into(), "Exec".into(), 3)
            .is_some());
    }

    #[tokio::test]
    async fn attached_bridge_wakes_on_group_removal_without_explicit_cancel() {
        let s = st();
        let _ctl = s
            .register_session(5, "u".into(), "m1".into(), "Pty".into(), 3)
            .unwrap();
        let mut attached = s.attach_session_bridge(5).unwrap();
        assert!(!*attached.borrow_and_update(), "未关闭时不得误报取消");
        // 控制桥自然结束：unregister drop 掉取消 sender，挂靠桥也要能被唤醒退出
        s.unregister_session(5);
        assert!(attached.changed().await.is_err());
    }

    #[test]
    fn list_sessions_filters_by_viewer() {
        let s = st();
        let a = s
            .register_session(11, "alice".into(), "m1".into(), "Pty".into(), 1)
            .unwrap();
        let b = s
            .register_session(12, "bob".into(), "m2".into(), "Exec".into(), 2)
            .unwrap();
        drop((a, b));
        assert_eq!(s.list_sessions(Some("alice")).len(), 1);
        assert_eq!(s.list_sessions(Some("alice"))[0].sid, 11);
        assert_eq!(s.list_sessions(None).len(), 2);
    }

    #[test]
    fn drop_connection_state_cancels_only_that_connections_sessions() {
        let s = st();
        let mut mine = s
            .register_session(1, "u".into(), "m1".into(), "Pty".into(), 100)
            .unwrap();
        let mut other = s
            .register_session(2, "u".into(), "m1".into(), "Pty".into(), 200)
            .unwrap();
        s.drop_connection_state(100);
        assert!(*mine.borrow_and_update(), "本连接的会话组应被取消");
        assert!(!*other.borrow_and_update(), "其它连接的会话组不得被波及");
        assert_eq!(
            s.list_sessions(None)
                .iter()
                .map(|x| x.sid)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn rotate_admin_token_invalidates_old() {
        let s = st();
        let old = s
            .ensure_admin_token()
            .unwrap()
            .expect("first call should generate a token");
        assert!(s.check_admin_token(&old));
        assert_eq!(s.ensure_admin_token().unwrap(), None); // 已存在不再重复生成
        let new = s.rotate_admin_token().unwrap();
        assert!(s.check_admin_token(&new));
        assert!(!s.check_admin_token(&old));
        assert!(!s.check_admin_token("random"));
    }

    #[test]
    fn auth_grant_revoke_and_listing() {
        let s = st();
        s.auth_grant("alice", "m1").unwrap();
        s.auth_grant("alice", "m2").unwrap();
        s.auth_grant("bob", "m1").unwrap();
        s.auth_grant("alice", "m1").unwrap(); // 重复 grant 幂等
        let mut machines = s.user_machines("alice").unwrap();
        machines.sort();
        assert_eq!(machines, vec!["m1".to_string(), "m2".to_string()]);
        assert_eq!(s.user_machines("nobody").unwrap(), Vec::<String>::new());
        let mut all = s.user_machines_all();
        all.sort();
        assert_eq!(
            all,
            vec![
                ("alice".into(), "m1".into()),
                ("alice".into(), "m2".into()),
                ("bob".into(), "m1".into())
            ]
        );
        assert!(s.auth_revoke("alice", "m1").unwrap());
        assert!(!s.auth_revoke("alice", "m1").unwrap()); // 不存在的关系撤销失败
        assert_eq!(s.user_machines("alice").unwrap(), vec!["m2".to_string()]);
    }

    #[test]
    fn machine_upsert_tags_del_keeps_audit() {
        let s = st();
        s.upsert_machine("mid", "pk", "xpk", "host1", "linux", "arm64", "v0.2.0")
            .unwrap();
        s.audit_write(Some("alice"), Some("mid"), "shell", 1, 2, 3);
        assert!(s.machine_set_tags("mid", "lab,web").unwrap());
        assert!(!s.machine_set_tags("ghost-mid", "x").unwrap()); // 不存在的机器
        let tags: String = s
            .lock_db()
            .query_row(
                "SELECT tags FROM machines WHERE machine_id = 'mid'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tags, "lab,web");
        s.auth_grant("alice", "mid").unwrap();
        assert!(s.machine_del("mid").unwrap());
        assert!(!s.machine_del("mid").unwrap()); // 二次删除失败
        assert!(s.get_machine_full("mid").unwrap().is_none());
        assert!(s.user_machines("alice").unwrap().is_empty()); // 授权关系一并清空
        let audits = s.audit_list(10).unwrap();
        assert_eq!(audits.len(), 1); // 审计历史保留
        assert_eq!(audits[0].3, "shell");
    }

    #[test]
    fn user_del_cascades_auth_and_sessions() {
        let s = st();
        insert_user_raw(&s, "dave", "irrelevant-hash", "");
        s.auth_grant("dave", "m9").unwrap();
        let tok = s.issue_session_token("dave", "user").unwrap();
        assert!(s.check_session_token(&tok).is_some());
        assert!(s.user_del("dave").unwrap());
        assert!(!s.user_del("dave").unwrap()); // 再删失败
        let db = s.lock_db();
        let auth: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM machine_auth WHERE username = 'dave'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let sess: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE username = 'dave'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        drop(db);
        assert_eq!((auth, sess), (0, 0));
        assert_eq!(s.check_session_token(&tok), None);
    }

    #[test]
    fn user_set_password_rotates_hash_revokes_sessions_keeps_auth() {
        let s = st();
        s.user_add("carol", "old-pass", "user").unwrap();
        s.auth_grant("carol", "m1").unwrap();
        let tok = s.issue_session_token("carol", "user").unwrap();
        assert!(s.check_session_token(&tok).is_some());

        assert!(s.user_set_password("carol", "new-pass").unwrap());
        assert!(!s.user_set_password("ghost", "x").unwrap()); // 不存在的用户
        assert_eq!(s.check_user("carol", "new-pass"), Some("user".into()));
        assert_eq!(s.check_user("carol", "old-pass"), None);
        assert_eq!(s.check_session_token(&tok), None); // 旧会话已吊销
        assert_eq!(s.user_machines("carol").unwrap(), vec!["m1".to_string()]); // 授权保留
    }

    #[test]
    fn revoke_session_by_token_and_by_user() {
        let s = st();
        let t1 = s.issue_session_token("a", "user").unwrap();
        let t2 = s.issue_session_token("a", "user").unwrap();
        let t3 = s.issue_session_token("b", "user").unwrap();
        // 精确吊销单个令牌
        assert!(s.revoke_session(&t1).unwrap());
        assert!(!s.revoke_session(&t1).unwrap()); // 再删已不存在
        assert_eq!(
            s.check_session_token(&t2),
            Some(("a".into(), "user".into()))
        );
        // 按用户全量吊销：只动 a 的，b 的保留
        assert_eq!(s.revoke_user_sessions("a").unwrap(), 1);
        assert_eq!(s.revoke_user_sessions("a").unwrap(), 0);
        assert_eq!(s.check_session_token(&t2), None);
        assert_eq!(
            s.check_session_token(&t3),
            Some(("b".into(), "user".into()))
        );
        assert_eq!(s.revoke_user_sessions("ghost").unwrap(), 0);
    }

    #[test]
    fn audit_write_then_list_desc_with_fields() {
        let s = st();
        s.audit_write(Some("u1"), Some("m1"), "shell", 10, 20, 30);
        s.audit_write(None, None, "denied/login", 0, 0, 0);
        s.audit_write(Some("u2"), Some("m2"), "scp", 1, 2, 3);
        let limited = s.audit_list(2).unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].3, "scp"); // 最新在前
        assert_eq!(limited[1].3, "denied/login");
        let all = s.audit_list(10).unwrap();
        assert_eq!(all.len(), 3);
        let (ts, user, machine, kind, up, down, ms) = all[2].clone();
        assert!(ts > 0 && ts <= now_secs() as i64);
        assert_eq!(
            (
                user.as_deref(),
                machine.as_deref(),
                kind.as_str(),
                up,
                down,
                ms
            ),
            (Some("u1"), Some("m1"), "shell", 10, 20, 30)
        );
    }

    #[test]
    fn maintenance_purges_expired_audit_only() {
        let s = st();
        let now = now_secs() as i64;
        {
            let db = s.lock_db();
            for ts in [now - 10 * 86400, now - 91 * 86400, now - 400 * 86400] {
                db.execute("INSERT INTO audit (ts, kind) VALUES (?1, 'shell')", [ts])
                    .unwrap();
            }
        }
        s.audit_write(Some("u"), None, "shell", 0, 0, 0); // 新行（now 写入）
        s.maintenance(Some(now - 90 * 86400)).unwrap();
        // 91 天/400 天的行被清，10 天前的和刚刚的保留
        assert_eq!(count(&s, "SELECT COUNT(*) FROM audit"), 2);
    }

    #[test]
    fn maintenance_purges_expired_sessions_only() {
        let s = st();
        let alive = s.issue_session_token("a", "user").unwrap();
        let expired = s.issue_session_token("b", "user").unwrap();
        s.lock_db()
            .execute(
                "UPDATE sessions SET expires_at = 1 WHERE token_hash = ?1",
                [sha256_hex(expired.as_bytes())],
            )
            .unwrap();
        s.maintenance(Some(0)).unwrap();
        assert!(s.check_session_token(&alive).is_some());
        assert_eq!(s.check_session_token(&expired), None);
    }

    #[test]
    fn pending_pairing_resolves_only_for_owner() {
        let s = st();
        let (tx, mut rx) = oneshot::channel::<Result<(), String>>();
        s.register_pending(7, "m1", tx);
        assert!(s.pending_contains(7));
        // 跨机器伪造应答：不生效、仍 pending
        assert!(!s.resolve_pending(7, "m2", Ok(())));
        assert!(s.pending_contains(7));
        // 不存在的 sid
        assert!(!s.resolve_pending(99, "m1", Ok(())));
        // 本机应答生效并送达结果
        assert!(s.resolve_pending(7, "m1", Err("refused".into())));
        assert!(!s.pending_contains(7));
        assert_eq!(rx.try_recv().unwrap(), Err("refused".into()));
        // drop_pending 直接移除
        let (tx2, _rx2) = oneshot::channel::<Result<(), String>>();
        s.register_pending(8, "m1", tx2);
        s.drop_pending(8);
        assert!(!s.pending_contains(8));
    }

    #[test]
    fn update_machine_version_persists() {
        let s = st();
        s.upsert_machine("mv", "pk", "xpk", "h", "linux", "amd64", "v0.1.0")
            .unwrap();
        s.update_machine_version("mv", "v0.2.0");
        assert_eq!(s.get_machine_full("mv").unwrap().unwrap().version, "v0.2.0");
        s.update_machine_version("nope", "v9");
        assert!(s.get_machine_full("nope").unwrap().is_none());
    }

    #[test]
    fn machine_id_is_32_lowercase_hex_chars() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let pk = b64.encode([7u8; 32]);
        let id = machine_id_from_pubkey(&pk).unwrap();
        assert_eq!(id.len(), 32);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(machine_id_from_pubkey(&pk).unwrap(), id); // 确定性
        assert_ne!(machine_id_from_pubkey(&b64.encode([8u8; 32])).unwrap(), id); // 输入敏感
        assert!(machine_id_from_pubkey("not-base64!!").is_err());
    }

    #[test]
    fn reopening_db_with_tags_column_tolerated() {
        let dir =
            std::env::temp_dir().join(format!("exvia_relay_test_{}_tags", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay.db");
        {
            // 模拟"已升级过"的老库：machines 表自带 tags 列
            let db = Connection::open(&path).unwrap();
            db.execute_batch(
                "CREATE TABLE machines (
                    machine_id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, x25519_pub TEXT NOT NULL,
                    hostname TEXT NOT NULL, os TEXT NOT NULL, arch TEXT NOT NULL, version TEXT NOT NULL,
                    registered_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                    tags TEXT NOT NULL DEFAULT ''
                 );",
            )
            .unwrap();
        }
        {
            let s = RelayState::open(&path).unwrap();
            s.upsert_machine("m", "pk", "xpk", "h", "linux", "amd64", "v")
                .unwrap();
        }
        // 二次 open：ALTER TABLE 撞 duplicate column，应被容忍
        let s = RelayState::open(&path).unwrap();
        assert!(s.get_machine_full("m").unwrap().is_some());
        drop(s);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stats_counts_persisted_rows() {
        let s = st();
        let now = now_secs() as i64;
        let day_start = now - now % 86400;
        // 机器：2 台活跃、1 台 1 小时前
        s.upsert_machine("m1", "pk", "x", "h1", "linux", "arm64", "v0.2.0")
            .unwrap();
        s.upsert_machine("m2", "pk", "x", "h2", "linux", "amd64", "v0.2.0")
            .unwrap();
        s.upsert_machine("m3", "pk", "x", "h3", "linux", "arm64", "v0.1.9")
            .unwrap();
        s.lock_db()
            .execute(
                "UPDATE machines SET last_seen = ?1 WHERE machine_id = 'm3'",
                [now - 3600],
            )
            .unwrap();
        // 用户 / 授权 / 令牌
        insert_user_raw(&s, "u", "x", "");
        s.auth_grant("u", "m1").unwrap();
        s.auth_grant("u", "m2").unwrap();
        let used_tok = s.create_token(Some("used")).unwrap();
        s.create_token(Some("fresh")).unwrap();
        assert!(s.use_register_token(&used_tok).unwrap());
        // 审计：昨天 1 行、今天 2 行
        {
            let db = s.lock_db();
            db.execute(
                "INSERT INTO audit (ts, kind) VALUES (?1, 'shell')",
                [day_start - 3600],
            )
            .unwrap();
            db.execute(
                "INSERT INTO audit (ts, kind) VALUES (?1, 'shell')",
                [day_start + 1],
            )
            .unwrap();
        }
        s.audit_write(Some("u"), Some("m1"), "scp", 0, 0, 0);
        s.set_meta("audit_retention_days", "30").unwrap();

        let snap = s.stats().unwrap();
        assert_eq!(snap.machines_total, 3);
        assert_eq!(snap.machines_active, 2);
        assert_eq!(
            snap.version_dist,
            vec![("v0.2.0".into(), 2), ("v0.1.9".into(), 1)]
        );
        assert_eq!(snap.users, 1);
        assert_eq!(snap.auth_pairs, 2);
        assert_eq!(snap.tokens_unused, 1);
        assert_eq!(snap.sessions_today, 2);
        assert_eq!(snap.audit_total, 3);
        assert_eq!(snap.audit_retention_days, Some(30));
    }

    #[test]
    fn meta_retention_visible_via_stats() {
        let s = st();
        assert_eq!(s.stats().unwrap().audit_retention_days, None);
        s.set_meta("audit_retention_days", "90").unwrap();
        assert_eq!(s.stats().unwrap().audit_retention_days, Some(90));
        s.set_meta("audit_retention_days", "7").unwrap(); // 覆盖
        assert_eq!(s.stats().unwrap().audit_retention_days, Some(7));
    }

    #[test]
    fn admin_token_rotation_is_tracked_and_revocable() {
        let s = st();
        // 还没有令牌：年龄未知，不该当成"0 秒前创建"
        assert_eq!(s.admin_token_age_secs(), None);

        let t1 = s.ensure_admin_token().unwrap().unwrap();
        let age = s.admin_token_age_secs().expect("age must be recorded");
        assert!(
            age < 5,
            "freshly created token should be ~0s old, got {age}"
        );
        assert!(s.check_admin_token(&t1));

        // 轮换：新令牌生效、旧令牌立即失效、时间被刷新
        let t2 = s.rotate_admin_token().unwrap();
        assert_ne!(t1, t2);
        assert!(s.check_admin_token(&t2));
        assert!(!s.check_admin_token(&t1));
        assert!(s.admin_token_age_secs().unwrap() < 5);
        // 再次 ensure 不应覆盖已有令牌
        assert!(s.ensure_admin_token().unwrap().is_none());
    }

    #[test]
    fn old_db_gains_admin_created_at_column() {
        // 模拟旧库：admin 表没有 created_at
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE admin (id INTEGER PRIMARY KEY CHECK (id = 1), token_hash TEXT NOT NULL);",
        )
        .unwrap();
        RelayState::init_schema(&db).expect("migration must not fail on an old schema");

        let has_col = db
            .prepare("PRAGMA table_info(admin)")
            .and_then(|mut s| {
                s.query_map([], |r| r.get::<_, String>(1))
                    .map(|rows| rows.filter_map(|x| x.ok()).any(|c| c == "created_at"))
            })
            .unwrap();
        assert!(has_col, "created_at should be added to legacy admin table");
        // 迁移后仍能正常查年龄（老行 created_at=0 → None，而非 1970 年的巨大年龄）
        let s = RelayState::from_conn(db);
        s.lock_db()
            .execute("INSERT INTO admin (id, token_hash) VALUES (1, 'x')", [])
            .unwrap();
        assert_eq!(s.admin_token_age_secs(), None);
    }
}
