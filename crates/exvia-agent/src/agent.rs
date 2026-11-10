// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! agent 核心逻辑：enroll、常驻运行（重连/心跳/会话分发）。

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex, Notify};
use x25519_dalek::StaticSecret as XStaticSecret;

use exvia_proto::frame::{read_frame, write_frame, Frame, FrameKind};
use exvia_proto::io::TungWs;
use exvia_proto::msgs::{
    AgentToRelay, CloseInfo, CtrlMsg, KickCode, RelayToAgent, SessionKind, SessionParams,
    SessionTicket, SESSION_TICKET_TTL,
};
use exvia_proto::mux::{Mux, MuxStream, StreamQueue};
use exvia_proto::PROTOCOL_VERSION;

use crate::conn::{connect, Backoff};

const HEARTBEAT_INTERVAL: Duration = std::time::Duration::from_secs(30);
/// 流与邀请同序到达，正常毫秒级，10s 兜底。
const INVITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// -R 接入连接等待回程流配对的上限，超时关闭（中继名额/建流失败的兜底）。
#[cfg(not(test))]
const REVERSE_WAIT: Duration = std::time::Duration::from_secs(10);
/// 测试时限：清理行为与生产一致，只把 10s 换成测试可等的时长。
#[cfg(test)]
const REVERSE_WAIT: Duration = std::time::Duration::from_millis(500);
/// -R 每 sid 的 pending 上限，与中继回程流并发上限一致，防积压内存。
const REVERSE_PENDING_LIMIT: usize = 64;
/// 可信 CLI 白名单上限：正常部署个位数，超限基本是误用或滥用。
const MAX_TRUSTED_CLI: usize = 64;
/// 白名单文件，与身份文件同目录；独立成文件可避免运行期重写私钥。
const ALLOWLIST_FILE: &str = "trusted-cli.json";
/// 会话收尾排干残余输出的上界：防后台子进程拖着输出泵不退出（exec 与 pty 一致）。
const DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(2);

fn default_ws_prefix() -> String {
    "/_exvia".to_string()
}

/// 校验并规范化 CLI 公钥：只接受 32 字节 ed25519 公钥的 b64。
fn normalize_cli_key(key: &str) -> anyhow::Result<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(key.trim())
        .map_err(|_| anyhow::anyhow!("trusted key is not valid base64"))?;
    if raw.len() != 32 {
        anyhow::bail!("trusted key must be a 32-byte ed25519 public key");
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(raw))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// enroll 的 `--trusted-cli-key` 逐个规范化（同 trust 会话的 `trust_add` 规则）。
/// 格式非法立即报错：坏键不能原样写进身份文件，否则上线后所有会话都被 fail-closed 拒绝。
fn normalize_trusted_keys(keys: &[String]) -> anyhow::Result<Vec<String>> {
    keys.iter().map(|k| normalize_cli_key(k)).collect()
}

/// 本地身份文件（0600）。
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    machine_id: String,
    server: String,
    fingerprint: String,
    ed_seed_b64: String,
    x25519_b64: String,
    /// 可信 CLI 公钥白名单（b64）；为空拒绝所有会话（fail-closed）。
    #[serde(default)]
    trusted_cli_pubkeys: Vec<String>,
    #[serde(default = "default_ws_prefix")]
    ws_prefix: String,
}

/// 已验签的会话邀请（票据入队前已消费，不随邀请传递）。
#[derive(Clone)]
struct Invite {
    peer_pub: String,
    /// 票据里的已验签用户名，仅用于日志/审计。
    peer_name: String,
}

/// agent 运行期共享状态。
struct Core {
    identity: exvia_proto::Identity,
    machine_id: String,
    server: String,
    fingerprint: String,
    ws_prefix: String,
    /// 部署期固化的可信 CLI 公钥，中继碰不到。
    /// 可通过 trust 会话追加（须先由白名单内的 CLI 发起），故用 RwLock。
    trusted_cli: std::sync::RwLock<Vec<String>>,
    /// 白名单独立落盘，避免运行期重写含私钥的身份文件。
    allowlist_path: std::path::PathBuf,
    /// 已消费票据 nonce → 过期时间，防重放。
    seen_tickets: std::sync::Mutex<HashMap<String, u64>>,
    sessions: AtomicU32,
    /// 按 sid 索引；流前导带 sid，精确配对消除到达顺序竞态。
    invites: Mutex<HashMap<u64, Invite>>,
    invite_notify: Notify,
    /// -R 回程流投递表：sid → 队列（会话注册，入向驱动投递）。
    /// std Mutex：临界区极短，且要在 Drop 守卫里同步摘除。
    reverse_streams: std::sync::Mutex<HashMap<u64, Arc<StreamQueue>>>,
}

impl Core {
    fn x25519_static(&self) -> XStaticSecret {
        XStaticSecret::from(self.identity.x25519_private())
    }

    async fn push_invite(&self, sid: u64, inv: Invite) {
        self.invites.lock().await.insert(sid, inv);
        // notify_waiters：notify_one 的许可会被过期等待者消费，目标任务错过唤醒。
        // 过期者醒来查不到自己的 sid 会重新睡下，无副作用。
        self.invite_notify.notify_waiters();
    }

    async fn next_invite(&self, sid: u64) -> Invite {
        loop {
            let notified = self.invite_notify.notified();
            tokio::pin!(notified);
            // 先 enable 再查 map：notify_waiters 不存许可，插入与首次 poll 间的唤醒会丢
            notified.as_mut().enable();
            if let Some(inv) = self.invites.lock().await.remove(&sid) {
                return inv;
            }
            notified.await;
        }
    }

    fn verify_ticket(
        &self,
        sid: u64,
        peer_pub: &str,
        ticket: Option<&SessionTicket>,
    ) -> anyhow::Result<String> {
        let trusted = self.trusted_cli.read().unwrap().clone();
        let mut seen = self.seen_tickets.lock().unwrap();
        verify_session_ticket(
            &trusted,
            &self.machine_id,
            sid,
            peer_pub,
            ticket,
            now_secs(),
            &mut seen,
        )
    }

    // ---- 可信 CLI 白名单维护 ----

    fn trusted_snapshot(&self) -> Vec<String> {
        self.trusted_cli.read().unwrap().clone()
    }

    /// 追加一把 CLI 公钥：幂等、去重、有上限，落盘成功后才算生效。
    fn trust_add(&self, key: &str) -> anyhow::Result<Vec<String>> {
        let key = normalize_cli_key(key)?;
        let mut list = self.trusted_cli.write().unwrap();
        if list.iter().any(|k| k == &key) {
            return Ok(list.clone());
        }
        if list.len() >= MAX_TRUSTED_CLI {
            anyhow::bail!("allowlist is full ({MAX_TRUSTED_CLI} keys); remove one first");
        }
        let mut next = list.clone();
        next.push(key);
        self.persist_allowlist(&next)?;
        *list = next.clone();
        Ok(next)
    }

    /// 移除一把公钥：不允许移除最后一把（否则无人能再连，且只能回到被控机手工改文件）。
    fn trust_remove(&self, key: &str) -> anyhow::Result<Vec<String>> {
        let key = normalize_cli_key(key)?;
        let mut list = self.trusted_cli.write().unwrap();
        if !list.iter().any(|k| k == &key) {
            anyhow::bail!("key is not in the allowlist");
        }
        if list.len() == 1 {
            anyhow::bail!(
                "refusing to remove the last trusted key: no one could log in afterwards"
            );
        }
        let next: Vec<String> = list.iter().filter(|k| *k != &key).cloned().collect();
        self.persist_allowlist(&next)?;
        *list = next.clone();
        Ok(next)
    }

    /// 原子落盘：临时文件 + fsync + rename，权限 0600。
    fn persist_allowlist(&self, keys: &[String]) -> anyhow::Result<()> {
        let dir = self
            .allowlist_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let tmp = dir.join(format!(".{}.tmp", ALLOWLIST_FILE));
        let body = serde_json::json!({ "trusted_cli_pubkeys": keys }).to_string();
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.allowlist_path)?;
        // 目录项也要落盘，否则崩溃后可能留下旧文件
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    // ---- -R 回程流投递 ----

    fn register_reverse(&self, sid: u64, q: Arc<StreamQueue>) {
        self.reverse_streams.lock().unwrap().insert(sid, q);
    }

    /// 入向驱动分流用：sid 在登记中 → 这是该 -R 会话的回程流。
    fn reverse_sink(&self, sid: u64) -> Option<Arc<StreamQueue>> {
        self.reverse_streams.lock().unwrap().get(&sid).cloned()
    }

    fn remove_reverse(&self, sid: u64) {
        self.reverse_streams.lock().unwrap().remove(&sid);
    }
}

/// 票据校验的纯逻辑（无 IO，便于穷尽单测）。
/// 中继只能透传票据，签名必须由部署期固化的白名单私钥产生；
/// sid / machine_id / x25519_pub 绑定到本次邀请，nonce + 短过期窗口防重放。
fn verify_session_ticket(
    trusted_cli: &[String],
    machine_id: &str,
    sid: u64,
    peer_pub: &str,
    ticket: Option<&SessionTicket>,
    now: u64,
    seen: &mut HashMap<String, u64>,
) -> anyhow::Result<String> {
    let t = ticket.ok_or_else(|| anyhow::anyhow!("missing session ticket"))?;
    if t.sid != sid {
        anyhow::bail!("ticket sid mismatch");
    }
    if t.machine_id != machine_id {
        anyhow::bail!("ticket machine_id mismatch");
    }
    if t.x25519_pub != peer_pub {
        anyhow::bail!("ticket x25519 pubkey mismatch");
    }
    if t.expires_at <= now {
        // NTP 自诊断：直接给出票据字段时间与本机时间，差值即时钟偏差
        anyhow::bail!(
            "ticket expired: expires_at={} agent_now={} (skew ≈ {}s)",
            t.expires_at,
            now,
            now as i64 - t.expires_at as i64
        );
    }
    if t.expires_at > now + SESSION_TICKET_TTL + 30 {
        // 本机时钟落后时偏差为负，同样给出两个时间便于诊断
        anyhow::bail!(
            "ticket expiry beyond allowed window: expires_at={} agent_now={} (skew ≈ {}s; agent clock may be behind)",
            t.expires_at,
            now,
            now as i64 - t.expires_at as i64
        );
    }
    if trusted_cli.is_empty() {
        anyhow::bail!(
            "no trusted cli pubkey configured (use --trusted-cli-key on enroll), rejecting session"
        );
    }
    let bytes = t.signing_bytes();
    let verified = trusted_cli
        .iter()
        .any(|k| exvia_proto::Identity::verify_b64(k, &bytes, &t.sig).is_ok());
    if !verified {
        anyhow::bail!("ticket signature invalid: signer not in trusted cli allowlist");
    }
    seen.retain(|_, exp| *exp > now);
    if seen.insert(t.nonce.clone(), t.expires_at).is_some() {
        // 窗口边界：nonce 去重表按记录的 expires_at 清扫，两个时间都给出
        anyhow::bail!(
            "ticket nonce replay: nonce_expires_at={} agent_now={} (replay detected inside the dedup window)",
            t.expires_at,
            now
        );
    }
    Ok(t.user.clone())
}

/// -R 登记守卫：任何退出路径（含 ? 早退）都摘除投递表。
struct ReverseReg(Arc<Core>, u64);

impl Drop for ReverseReg {
    fn drop(&mut self) {
        self.0.remove_reverse(self.1);
    }
}

pub async fn enroll(
    server: &str,
    token: &str,
    fingerprint: &str,
    path: &Path,
    trusted_cli: &[String],
    ws_prefix: &str,
) -> anyhow::Result<()> {
    if Path::new(path).exists() {
        anyhow::bail!(
            "identity already exists ({}); delete it to re-enroll",
            path.display()
        );
    }
    let fingerprint = exvia_proto::tls::normalize_fingerprint(fingerprint)?;
    let trusted_cli = &normalize_trusted_keys(trusted_cli)?;
    let identity = exvia_proto::Identity::generate();
    let hostname = hostname();
    let ws = connect(server, &fingerprint, ws_prefix).await?;
    let (incoming_tx, mut incoming_rx) = mpsc::unbounded_channel::<String>();
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel::<String>();
    let adapter = TungWs::new(ws, incoming_tx, outgoing_rx);
    let mux = Mux::new(adapter, yamux::Mode::Server);
    let _driver = exvia_proto::mux::spawn_inbound_driver(mux.clone(), |s: MuxStream| drop(s));

    send_json(
        &outgoing_tx,
        &AgentToRelay::Register {
            token: token.to_string(),
            pubkey: identity.ed25519_pub_b64(),
            x25519_pub: identity.x25519_pub_b64(),
            hostname: hostname.clone(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            version: PROTOCOL_VERSION.to_string(),
        },
    );

    let reply = wait_control(&mut incoming_rx).await?;
    match reply {
        RelayToAgent::RegisterOk { machine_id } => {
            let file = IdentityFile {
                machine_id: machine_id.clone(),
                server: server.to_string(),
                fingerprint,
                ed_seed_b64: identity.export_parts().0,
                x25519_b64: identity.export_parts().1,
                trusted_cli_pubkeys: trusted_cli.to_vec(),
                ws_prefix: ws_prefix.to_string(),
            };
            exvia_proto::keys::write_private(path, &serde_json::to_string_pretty(&file)?)?;
            println!("enrolled: machine_id = {machine_id}");
            if trusted_cli.is_empty() {
                eprintln!(
                    "warning: no --trusted-cli-key set, agent will reject all sessions (fail-closed)"
                );
                eprintln!(
                    "       get the cli pubkey with `exvia pubkey`, then re-enroll to set the allowlist"
                );
            } else {
                println!("trusted cli allowlist: {} keys", trusted_cli.len());
            }
            // 带外预置 CLI 侧信任锚：操作者在首连前执行下面这条命令，
            // 之后首连核对预置值，不再信任中继的介绍（TOFU 窗口被带外关闭）
            let x25519_pub = identity.x25519_pub_b64();
            println!("noise static pubkey (x25519 b64): {x25519_pub}");
            println!("anchor on the CLI side: exvia known add {machine_id} {x25519_pub}");
            println!(
                "identity saved to {}, run `exvia-agent run` to start",
                path.display()
            );
            Ok(())
        }
        RelayToAgent::RegisterErr { reason } => anyhow::bail!("enroll rejected: {reason}"),
        other => anyhow::bail!("unexpected message during enroll: {other:?}"),
    }
}

/// 单实例锁：对 identity 文件持有排他 flock（LOCK_EX | LOCK_NB）。
/// 同一身份跑两个实例会互踢重连，启动即拒绝。
struct InstanceGuard {
    file: std::fs::File,
}

impl InstanceGuard {
    /// LOCK_NB：已有实例在跑时立即失败，不排队等待。
    fn acquire(identity_path: &Path) -> anyhow::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(identity_path)
            .map_err(|e| {
                anyhow::anyhow!("open identity file failed {}: {e}", identity_path.display())
            })?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            anyhow::bail!(
                "another instance is running (identity file locked): {}",
                identity_path.display()
            );
        }
        Ok(Self { file })
    }
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // flock 随 fd 关闭由内核释放，这里显式解锁一次
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// 白名单文件（0600）；不存在或损坏时退回身份文件里的那份。
fn load_allowlist(path: &Path, fallback: &[String]) -> Vec<String> {
    #[derive(Deserialize)]
    struct AllowlistFile {
        #[serde(default)]
        trusted_cli_pubkeys: Vec<String>,
    }
    match std::fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<AllowlistFile>(&raw) {
            Ok(f) => f.trusted_cli_pubkeys,
            Err(e) => {
                tracing::warn!(
                    "allowlist file {} is unreadable ({e}), using identity copy",
                    path.display()
                );
                fallback.to_vec()
            }
        },
        Err(_) => fallback.to_vec(),
    }
}

pub async fn run(identity_path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(identity_path)?;
    let file: IdentityFile = serde_json::from_str(&raw)?;
    // 单实例锁：读到身份立即锁定，持有至进程退出
    let _instance = InstanceGuard::acquire(identity_path)?;
    let identity = exvia_proto::Identity::import_parts(&file.ed_seed_b64, &file.x25519_b64)?;
    // 白名单有独立文件后，身份文件里的那份仅作首次迁移来源。
    let allowlist_path = identity_path.with_file_name(ALLOWLIST_FILE);
    let trusted = load_allowlist(&allowlist_path, &file.trusted_cli_pubkeys);
    if trusted.is_empty() {
        tracing::warn!("no trusted cli pubkey allowlist: all sessions rejected (fail-closed)");
    } else {
        tracing::info!("trusted cli allowlist: {} keys", trusted.len());
    }
    let core = Arc::new(Core {
        identity,
        machine_id: file.machine_id,
        server: file.server,
        fingerprint: file.fingerprint,
        ws_prefix: file.ws_prefix,
        trusted_cli: std::sync::RwLock::new(trusted.clone()),
        allowlist_path: allowlist_path.clone(),
        seen_tickets: std::sync::Mutex::new(HashMap::new()),
        sessions: AtomicU32::new(0),
        invites: Mutex::new(HashMap::new()),
        invite_notify: Notify::new(),
        reverse_streams: std::sync::Mutex::new(HashMap::new()),
    });
    // 首次从身份文件迁移到独立白名单文件，之后运行期只读写后者。
    if !allowlist_path.exists() && !trusted.is_empty() {
        if let Err(e) = core.persist_allowlist(&trusted) {
            tracing::warn!(
                "cannot write allowlist file {}: {e}",
                allowlist_path.display()
            );
        }
    }
    tracing::info!(
        "starting: machine_id={} server={}",
        core.machine_id,
        core.server
    );

    let mut backoff = Backoff::new();
    loop {
        // 稳定在线超过 10s 才重置退避
        let connected_at = Instant::now();
        match run_once(&core).await {
            Ok(()) => {
                tracing::info!(
                    "connection ended after kick (version mismatch or takeover), exiting"
                );
                return Ok(());
            }
            Err(e) => {
                if connected_at.elapsed() > Duration::from_secs(10) {
                    tracing::info!("connection was stable, resetting backoff");
                    backoff.reset();
                }
                tracing::warn!(
                    "connection lost: {e}; reconnect in {:.1}s",
                    backoff.current()
                );
            }
        }
        backoff.wait().await;
    }
}

enum KickReaction {
    /// 身份被接管：重连会与接管者互踢，退出并告警。
    Takeover,
    /// 版本不兼容：重连无意义，退出等人工升级。
    Version,
    /// 维护踢：按断线处理，退避后自动重连。
    Reconnect,
}

/// 优先看 code；老中继不带 code 才回退到 reason 文案匹配。
fn kick_reaction(reason: &str, code: Option<KickCode>) -> KickReaction {
    match code {
        Some(KickCode::Takeover) => KickReaction::Takeover,
        Some(KickCode::Version) => KickReaction::Version,
        Some(KickCode::Reconnect) | Some(KickCode::Unknown) => KickReaction::Reconnect,
        // 兼容旧中继：老版不带 code，只发中文 reason；英文文案也一并兜底
        None if reason.contains("took over") || reason.contains("同机新连接") => {
            KickReaction::Takeover
        }
        None if reason.contains("protocol version mismatch")
            || reason.contains("协议版本不兼容") =>
        {
            KickReaction::Version
        }
        None => KickReaction::Reconnect,
    }
}

// 返回值区分被踢退出与异常重连。
async fn run_once(core: &Arc<Core>) -> anyhow::Result<()> {
    let ws = connect(&core.server, &core.fingerprint, &core.ws_prefix).await?;
    let (incoming_tx, mut incoming_rx) = mpsc::unbounded_channel::<String>();
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel::<String>();
    let adapter = TungWs::new(ws, incoming_tx, outgoing_rx);
    let mux = Mux::new(adapter, yamux::Mode::Server);
    let mux_ctrl = mux.clone();

    // 入向流先读 8B sid 前导：-R 回程流投给在册会话，其余走邀请配对
    let core2 = core.clone();
    let relay_tx2 = outgoing_tx.clone();
    let driver = exvia_proto::mux::spawn_inbound_driver(mux, move |mut stream: MuxStream| {
        let core = core2.clone();
        let relay_tx = relay_tx2.clone();
        core.sessions.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let sid = match read_sid_preamble(&mut stream).await {
                Some(s) => s,
                None => {
                    core.sessions.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            };
            if let Some(q) = core.reverse_sink(sid) {
                q.push(stream).await;
            } else {
                let _ = handle_session(&core, stream, sid, &relay_tx).await;
            }
            core.sessions.fetch_sub(1, Ordering::Relaxed);
        });
    });

    // 认证
    send_json(
        &outgoing_tx,
        &AgentToRelay::Hello {
            machine_id: core.machine_id.clone(),
            version: PROTOCOL_VERSION.to_string(),
        },
    );
    let reply = wait_control(&mut incoming_rx).await?;
    let RelayToAgent::Challenge { nonce } = reply else {
        anyhow::bail!("unexpected message during auth: {reply:?}");
    };
    let nonce_raw = base64::engine::general_purpose::STANDARD.decode(&nonce)?;
    send_json(
        &outgoing_tx,
        &AgentToRelay::ChallengeReply {
            sig: core.identity.sign_b64(&nonce_raw),
        },
    );

    // 心跳
    let hb_core = core.clone();
    let hb_tx = outgoing_tx.clone();
    let heartbeat = tokio::spawn(async move {
        let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            send_json(
                &hb_tx,
                &AgentToRelay::Heartbeat {
                    sessions: hb_core.sessions.load(Ordering::Relaxed),
                },
            );
        }
    });

    // 控制循环：SessionInvite 先回 Accept 再入队配对
    let disposition = loop {
        match incoming_rx.recv().await {
            None => break Err(anyhow::anyhow!("connection closed")),
            Some(text) => match serde_json::from_str::<RelayToAgent>(&text) {
                Ok(RelayToAgent::Kick { reason, code }) => match kick_reaction(&reason, code) {
                    KickReaction::Takeover => {
                        tracing::warn!(
                            "identity taken over by another instance, exiting to avoid mutual kicks; check the identity file if unexpected"
                        );
                        break Ok(reason);
                    }
                    KickReaction::Version => break Ok(reason),
                    KickReaction::Reconnect => {
                        break Err(anyhow::anyhow!("kicked by relay: {reason}"));
                    }
                },
                Ok(RelayToAgent::SessionInvite {
                    sid,
                    peer_pub,
                    peer_name: _,
                    ticket,
                }) => {
                    // 验签先于 Accept：中继说了不算，agent 独立判断。
                    match core.verify_ticket(sid, &peer_pub, ticket.as_ref()) {
                        Ok(verified_user) => {
                            tracing::info!("sid={sid} ticket verified user={verified_user}");
                            send_json(&outgoing_tx, &AgentToRelay::SessionAccept { sid });
                            core.push_invite(
                                sid,
                                Invite {
                                    peer_pub,
                                    peer_name: verified_user,
                                },
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!("sid={sid} session invite rejected: {e:#}");
                            send_json(
                                &outgoing_tx,
                                &AgentToRelay::SessionReject {
                                    sid,
                                    reason: format!("ticket verification failed: {e}"),
                                },
                            );
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::debug!("control message decode failed: {e}"),
            },
        }
    };

    heartbeat.abort();
    driver.abort();
    drop(mux_ctrl);
    // 退出/重连时清空邀请表：旧连接的邀请已不可兑现（流随连接作废），
    // 残留项还可能撞上新连接的 sid 造成错误配对
    core.invites.lock().await.clear();
    match disposition {
        Ok(reason) => {
            tracing::info!("received kick: {reason}");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// 单条会话流：等邀请 → Noise 响应端 → 按类型分发（sid 前导与 -R 分流已在驱动完成）。
async fn handle_session(
    core: &Arc<Core>,
    stream: MuxStream,
    sid: u64,
    relay_tx: &mpsc::UnboundedSender<String>,
) -> anyhow::Result<()> {
    let inv = tokio::time::timeout(INVITE_TIMEOUT, core.next_invite(sid)).await?;
    let (peer_pub, peer_name) = (inv.peer_pub, inv.peer_name);
    tracing::info!("sid={sid} claimed_user={peer_name} (self-asserted in the signed ticket)");
    // 握手必须有界：对端卡死不得挂住会话任务
    let handshake = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        exvia_proto::noise::handshake(
            stream,
            exvia_proto::noise::Role::Responder,
            &core.x25519_static(),
        ),
    )
    .await;
    let mut noise = match handshake {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::warn!("sid={sid} Noise handshake failed: {e}");
            return Err(e);
        }
        Err(_) => {
            tracing::warn!("sid={sid} Noise handshake timed out");
            anyhow::bail!("Noise handshake timed out");
        }
    };
    // TOFU：对端公钥须与邀请一致，不一致即中间人，立即断开。
    // fail-closed：拿不到对端静态公钥就断开，不能跳过校验。
    tofu_check(noise.remote_static(), &peer_pub).map_err(|e| anyhow::anyhow!("sid={sid} {e}"))?;
    let Some(first) = read_frame(&mut noise).await? else {
        anyhow::bail!("sid={sid} peer closed before Open");
    };
    let FrameKind::Ctrl = first.kind else {
        anyhow::bail!("sid={sid} first frame is not Open");
    };
    let CtrlMsg::Open { kind, params } = first.ctrl_msg()? else {
        anyhow::bail!("sid={sid} first frame is not Open");
    };
    tracing::debug!("sid={sid} session start kind={kind:?}");
    let result = match kind {
        SessionKind::Echo => echo_session(&mut noise, &params).await,
        SessionKind::Pty => pty_session(noise, &params).await,
        SessionKind::Exec => exec_session(&mut noise, &params).await,
        SessionKind::File => file_session(&mut noise, &params).await,
        SessionKind::Tcpfwd => tcpfwd_session(noise, &params).await,
        SessionKind::TcpfwdReverse => {
            tcpfwd_reverse_session(core, relay_tx, noise, sid, peer_pub).await
        }
        SessionKind::Trust => trust_session(core, &mut noise, &params, sid, &peer_name).await,
    };
    match &result {
        Ok(()) => tracing::debug!("sid={sid} session finished"),
        Err(e) => tracing::debug!("sid={sid} session error: {e}"),
    }
    result
}

/// 公钥的短标识，用于日志里区分"是哪把钥匙"。完整公钥有 44 字符，日志里太吵。
/// 显示用 hint：按字符取前 12 个（按字节切片会在多字节 UTF-8 中间 panic）。
fn key_hint(k: Option<&str>) -> String {
    match k {
        Some(s) => s.chars().take(12).collect(),
        None => "-".to_string(),
    }
}

/// 可信白名单维护：能进到这里说明票据已被白名单内的 CLI 签过名，
/// 也就是"已授权的操作者给自己再登记一把钥匙"。列表本身也回传给调用方，
/// 便于操作者确认改动结果而不必登录被控机。
async fn trust_session<S>(
    core: &Arc<Core>,
    io: &mut S,
    params: &SessionParams,
    sid: u64,
    peer_name: &str,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let action = params.trust_action.clone().unwrap_or_else(|| "list".into());
    let outcome: anyhow::Result<Vec<String>> = match action.as_str() {
        "list" => Ok(core.trusted_snapshot()),
        "add" => params
            .trust_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing trust_key"))
            .and_then(|k| core.trust_add(k)),
        "rm" => params
            .trust_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing trust_key"))
            .and_then(|k| core.trust_remove(k)),
        other => anyhow::bail!("unknown trust action: {other}"),
    };
    match outcome {
        Ok(keys) => {
            // `claimed_user` 用词刻意：名字是 CLI 在票据里自报的（签名覆盖该字段，
            // 中继改不了），但被控端只能证明"这把白名单钥匙报了这名"，不能证明
            // 名字对应哪个人。授权依据始终是签名，不是这个名字。
            tracing::info!(
                "sid={sid} allowlist action={action} claimed_user={peer_name} key={} -> {} keys now",
                key_hint(params.trust_key.as_deref()),
                keys.len()
            );
            write_frame(io, &Frame::ctrl(&CtrlMsg::TrustList { keys })?).await?;
            write_frame(io, &Frame::close(&CloseInfo::default())?).await?;
            Ok(())
        }
        Err(e) => {
            tracing::warn!(
                "sid={sid} allowlist action={action} key={} rejected: {e}",
                key_hint(params.trust_key.as_deref())
            );
            write_frame(
                io,
                &Frame::close(&CloseInfo {
                    code: Some(1),
                    reason: Some(e.to_string()),
                })?,
            )
            .await?;
            Ok(())
        }
    }
}

async fn echo_session<S>(io: &mut S, _params: &SessionParams) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(frame) = read_frame(io).await? {
        match frame.kind {
            FrameKind::Data => write_frame(io, &Frame::data(frame.payload)).await?,
            FrameKind::Ctrl => {}     // echo 不处理控制帧
            FrameKind::Shutdown => {} // echo 无下游写侧，半关闭无操作
            FrameKind::Close => return Ok(()),
        }
    }
    Ok(())
}

static ACTIVE_WRITES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
> = std::sync::OnceLock::new();

fn active_writes() -> &'static std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>> {
    ACTIVE_WRITES.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

/// 同一目标路径的进程内写锁。
///
/// 分片文件名只由目标路径（和内容哈希）决定，两个会话同时写同一个目标就会互相追加，
/// 最后双双哈希失败。这里直接拒绝第二个会话，比让 SHA-256 校验兜底更好解释。
/// 锁只在插入/删除时持有，不跨 await；中毒也不影响正确性（集合只增删）。
struct WriteClaim(std::path::PathBuf);

impl WriteClaim {
    fn acquire(path: &str) -> anyhow::Result<Self> {
        let key = std::path::PathBuf::from(path);
        let mut set = active_writes().lock().unwrap_or_else(|e| e.into_inner());
        if !set.insert(key.clone()) {
            anyhow::bail!("another transfer to {path} is already running on this machine");
        }
        Ok(Self(key))
    }
}

impl Drop for WriteClaim {
    fn drop(&mut self) {
        if let Ok(mut set) = active_writes().lock() {
            set.remove(&self.0);
        }
    }
}

/// 传输成功后清掉同一目标的陈旧分片（例如源文件改过内容留下的另一种哈希）。
fn prune_parts(dest: &std::path::Path, keep: &std::path::Path) {
    let dir = match dest.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p != keep && exvia_proto::resume::is_part_of(dest, &p) {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// agent 运行用户的家目录：优先 `$HOME`，缺失时回退 passwd 记录。
/// systemd 拉起的服务 `$HOME` 默认取自 User 的 passwd 项，两条路殊途同归。
#[cfg(unix)]
fn agent_home() -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return Some(std::path::PathBuf::from(home));
    }
    // SAFETY: getpwuid 返回进程静态存储，仅在本函数内读取，期间无其他 getpw* 调用。
    let pw = unsafe { libc::getpwuid(libc::getuid()) };
    if pw.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        dir.to_bytes(),
    )))
}

#[cfg(not(unix))]
fn agent_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

/// 机器侧路径展开：相对路径与 `~` 以 agent 运行用户的家目录为基准，与交互
/// shell 的 cwd 约定一致。file 会话没有 shell 替我们定 cwd，而 systemd 拉起时
/// 进程 cwd 未必是家目录——不展开的话，一个相对路径会落到取决于启动方式的
/// 莫名其妙的地方。拿不到家目录时原样返回，由打开文件时的报错兜底。
fn expand_machine_path(path: &str) -> String {
    expand_machine_path_with(path, agent_home().as_deref())
}

fn expand_machine_path_with(path: &str, home: Option<&std::path::Path>) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home {
            return home.join(rest).to_string_lossy().into_owned();
        }
        return path.to_string();
    }
    if path == "~" {
        if let Some(home) = home {
            return home.to_string_lossy().into_owned();
        }
        return path.to_string();
    }
    if std::path::Path::new(path).is_absolute() {
        return path.to_string();
    }
    match home {
        Some(home) => home.join(path).to_string_lossy().into_owned(),
        None => path.to_string(),
    }
}

/// 文件 put/get 传输，SHA-256 校验，临时文件原子改名；`--resume` 时复用分片续传。
async fn file_session<S>(io: &mut S, params: &SessionParams) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use anyhow::Context as _;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let direction = params.direction.clone().unwrap_or_default();
    let path = params
        .path
        .clone()
        .ok_or_else(|| anyhow::anyhow!("missing target path"))?;
    let path = expand_machine_path(&path);

    // 目录树传输：一次会话走完整棵树，避免逐文件建立 Noise 握手。
    if params.recursive {
        return match direction.as_str() {
            "put" => {
                let _claim = WriteClaim::acquire(&path)?;
                put_tree(io, &path).await
            }
            "get" => get_tree(io, &path, params.pattern.as_deref()).await,
            other => anyhow::bail!("unknown transfer direction: {other}"),
        };
    }

    if direction == "put" {
        // 接收端：CLI → agent
        let expect_size = params.size.unwrap_or(0);
        let expect_sha = params.sha256.clone().unwrap_or_default();
        // 同一目标路径的并发写会共用同一个分片文件，宁可明确拒绝也不要互相踩踏。
        let _claim = WriteClaim::acquire(&path)?;
        // 分片按内容哈希命名：换了内容就不会复用上一次的半截文件。
        let temp = exvia_proto::resume::part_path(std::path::Path::new(&path), Some(&expect_sha));

        let mut hasher = Sha256::new();
        let mut start = 0u64;
        if params.resume {
            let existing = tokio::fs::metadata(&temp).await.ok().map(|m| m.len());
            start = exvia_proto::resume::resume_from(existing, expect_size);
            if start > 0 {
                // 续算整文件哈希必须把已有前缀读一遍；读不动就丢掉重来。
                match exvia_proto::resume::hash_prefix(&temp, start).await {
                    Ok((n, h)) if n == start => hasher = h,
                    _ => {
                        let _ = tokio::fs::remove_file(&temp).await;
                        start = 0;
                        hasher = Sha256::new();
                    }
                }
            }
            write_frame(
                io,
                &Frame::ctrl(&CtrlMsg::ResumeFrom {
                    offset: start,
                    prefix_sha256: None, // 分片名带内容哈希，接收端无需再比对前缀
                })?,
            )
            .await?;
        }

        let mut file = if start > 0 {
            let f = tokio::fs::OpenOptions::new()
                .append(true)
                .open(&temp)
                .await
                .with_context(|| format!("open partial file failed: {}", temp.display()))?;
            f.set_len(start).await?;
            f
        } else {
            tokio::fs::File::create(&temp)
                .await
                .with_context(|| format!("create temp file failed: {}", temp.display()))?
        };
        let mut received: u64 = start;
        let mut chunk_index: u64 = 0;
        let result: anyhow::Result<()> = loop {
            let Some(frame) = read_frame(io).await? else {
                break Err(anyhow::anyhow!("peer closed during transfer"));
            };
            match frame.kind {
                FrameKind::Data => {
                    file.write_all(&frame.payload).await?;
                    hasher.update(&frame.payload);
                    received += frame.payload.len() as u64;
                    chunk_index += 1;
                    if chunk_index % 16 == 0 {
                        write_frame(io, &Frame::ctrl(&CtrlMsg::Ack { chunk_index })?).await?;
                    }
                }
                FrameKind::Ctrl => {
                    if matches!(frame.ctrl_msg()?, CtrlMsg::Eof { .. }) {
                        break Ok(());
                    }
                }
                FrameKind::Shutdown => {} // 文件会话以 Eof/Close 划界，半关闭无操作
                FrameKind::Close => break Err(anyhow::anyhow!("peer aborted transfer")),
            }
        };
        let outcome = match result {
            Err(e) => {
                // 保留分片给 --resume：截到最后一个完整块，避免半帧混进续传起点。
                // 一个字节都没收到就没什么可续的，别留空文件。
                let _ = file.set_len(received).await;
                let _ = file.flush().await;
                drop(file);
                if received == 0 {
                    let _ = std::fs::remove_file(&temp);
                    Err(e)
                } else {
                    Err(anyhow::anyhow!(
                        "{e}; partial kept at {} ({received} bytes)",
                        temp.display()
                    ))
                }
            }
            Ok(()) => {
                let mut verify: anyhow::Result<()> = Ok(());
                if let Err(e) = file.sync_all().await {
                    verify = Err(e.into());
                }
                drop(file);
                if verify.is_ok() && expect_size > 0 && received != expect_size {
                    verify = Err(anyhow::anyhow!(
                        "size mismatch: expected {expect_size}, got {received}"
                    ));
                }
                if verify.is_ok() && !expect_sha.is_empty() {
                    let got = hex::encode(hasher.finalize());
                    if got != expect_sha {
                        verify = Err(anyhow::anyhow!(
                            "SHA-256 mismatch: expected {expect_sha}, got {got}"
                        ));
                    }
                }
                if verify.is_ok() {
                    if let Err(e) = std::fs::rename(&temp, &path) {
                        verify = Err(anyhow::anyhow!("write file failed: {path}: {e}"));
                    }
                }
                if verify.is_ok() {
                    if let Some(mode) = params.mode {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
                    }
                    prune_parts(std::path::Path::new(&path), &temp);
                } else {
                    // 内容已经不可信，别留给下一次 --resume 复用。
                    let _ = std::fs::remove_file(&temp);
                }
                verify
            }
        };
        if let Err(e) = &outcome {
            write_frame(
                io,
                &Frame::close(&CloseInfo {
                    code: Some(1),
                    reason: Some(e.to_string()),
                })?,
            )
            .await?;
        } else {
            tracing::info!("file received: {path} ({received}B)");
            write_frame(
                io,
                &Frame::close(&CloseInfo {
                    code: Some(0),
                    reason: None,
                })?,
            )
            .await?;
        }
        return Ok(());
    }

    if direction == "get" {
        // 发送端：agent → CLI。路径不存在/不可读要给确切原因：直接断开的话，
        // CLI 只能报一句 "agent closed during transfer"，用户无从知道是哪头的谁错了。
        let meta = match tokio::fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) => {
                write_frame(
                    io,
                    &Frame::close(&CloseInfo {
                        code: Some(1),
                        reason: Some(format!("cannot read file: {path}: {e}")),
                    })?,
                )
                .await?;
                return Ok(());
            }
        };
        if meta.is_dir() {
            write_frame(
                io,
                &Frame::close(&CloseInfo {
                    code: Some(1),
                    reason: Some("target is a directory".into()),
                })?,
            )
            .await?;
            return Ok(());
        }
        let mut file = tokio::fs::File::open(&path)
            .await
            .with_context(|| format!("open file failed: {path}"))?;
        let mut hasher = Sha256::new();
        // 续传起点以 CLI 声明的本地进度为准；越界（远端文件变短）说明分片对不上，从头来。
        let mut start = if params.resume {
            exvia_proto::resume::resume_from(params.resume_offset, meta.len())
        } else {
            0
        };
        if start > 0 {
            match exvia_proto::resume::hash_prefix(std::path::Path::new(&path), start).await {
                Ok((n, h)) if n == start => hasher = h,
                _ => {
                    start = 0;
                    hasher = Sha256::new();
                }
            }
        }
        if params.resume {
            // 前缀哈希给接收端比对：进程被硬杀可能在分片尾部留下半帧，
            // 只有哈希对得上才说明两边的断点真是同一份内容。
            let prefix_sha256 = if start > 0 {
                Some(hex::encode(hasher.clone().finalize()))
            } else {
                None
            };
            write_frame(
                io,
                &Frame::ctrl(&CtrlMsg::ResumeFrom {
                    offset: start,
                    prefix_sha256,
                })?,
            )
            .await?;
        }
        if start > 0 {
            use tokio::io::AsyncSeekExt as _;
            file.seek(std::io::SeekFrom::Start(start)).await?;
        }
        let mut buf = vec![0u8; exvia_proto::FILE_CHUNK];
        let mut chunk_index: u64 = 0;
        write_frame(
            io,
            &Frame::ctrl(&CtrlMsg::FileMeta {
                size: meta.len(),
                sha256: String::new(), // sha 边发边算，Eof 携带结论由接收端比对
            })?,
        )
        .await?;
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            write_frame(io, &Frame::data(buf[..n].to_vec())).await?;
            chunk_index += 1;
            if chunk_index % 16 == 0 {
                // 等待对端 ACK，天然限速并给 CLI 进度
                let Some(frame) = read_frame(io).await? else {
                    break;
                };
                let _ = frame;
            }
        }
        let sha = hex::encode(hasher.finalize());
        write_frame(
            io,
            &Frame::ctrl(&CtrlMsg::Eof {
                sha256: Some(sha.clone()),
            })?,
        )
        .await?;
        // 等接收端校验结果
        if let Some(frame) = read_frame(io).await? {
            if frame.kind == FrameKind::Close {
                let info = frame.close_info()?;
                if info.code != Some(0) {
                    anyhow::bail!(
                        "receiver verification failed: {}",
                        info.reason.unwrap_or_default()
                    );
                }
            }
        }
        tracing::info!(
            "file sent: {path} ({}B, sha256={sha}, from={start})",
            meta.len()
        );
        return Ok(());
    }

    anyhow::bail!("unknown transfer direction: {direction}");
}

/// 接收整棵目录树（CLI → agent）。协议：`TreeEntryMeta` 划界，数据块跟随文件条目，`TreeDone` 收尾。
/// 帧循环与防逃逸/临时文件语义在 [`exvia_proto::tree::recv_tree_frames`]（CLI 下载同一份实现）；
/// 这里只保留根目录创建、Close 帧收发与目录属性还原。
async fn put_tree<S>(io: &mut S, root: &str) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let root_path = std::path::PathBuf::from(root);
    let outcome: anyhow::Result<(u64, u64)> = async {
        std::fs::create_dir_all(&root_path)
            .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", root_path.display()))?;
        let mut warn = |msg: &str| tracing::warn!("{}", msg);
        let (files, bytes, dirs) = exvia_proto::tree::recv_tree_frames(
            io,
            &root_path,
            "peer",
            "write",
            &mut warn,
            |_frame| anyhow::anyhow!("peer aborted transfer"),
        )
        .await?;

        // 目录元数据等全部写完再设（由深到浅）：子项写入会刷新父目录 mtime。
        for (p, mode, mtime) in dirs.into_iter().rev() {
            if let Err(e) = exvia_proto::tree::apply_mode(&p, mode) {
                tracing::warn!("chmod {} failed: {e}", p.display());
            }
            if let Err(e) = exvia_proto::tree::apply_mtime(&p, mtime) {
                tracing::warn!("utimes {} failed: {e}", p.display());
            }
        }
        Ok((files, bytes))
    }
    .await;

    match outcome {
        Ok((files, bytes)) => {
            tracing::info!("tree received: {root} ({files} files, {bytes}B)");
            write_frame(
                io,
                &Frame::close(&CloseInfo {
                    code: Some(0),
                    reason: Some(format!("received {files} files, {bytes}B")),
                })?,
            )
            .await?;
            Ok(())
        }
        Err(e) => {
            write_frame(
                io,
                &Frame::close(&CloseInfo {
                    code: Some(1),
                    reason: Some(e.to_string()),
                })?,
            )
            .await?;
            Err(e)
        }
    }
}

/// 发送整棵目录树（agent → CLI）。带 `pattern` 时为 `get` 的远端尾分量通配：
/// 在 root 的父目录内按尾分量匹配（与 put 侧 CLI 的展开同一套语义），匹配结果
/// 作为树清单回传。`root` 仍携带原始远端串：旧版 agent 忽略 pattern，会对原始串
/// 做目录扫描而报 "cannot read"——失败可见，不会静默整目录下载。
async fn get_tree<S>(io: &mut S, root: &str, pattern: Option<&str>) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (root_path, entries, stats) = match pattern {
        None => {
            let root_path = std::path::PathBuf::from(root);
            let meta = std::fs::symlink_metadata(&root_path)
                .map_err(|e| anyhow::anyhow!("cannot read {root}: {e}"))?;
            if !meta.is_dir() {
                write_frame(
                    io,
                    &Frame::close(&CloseInfo {
                        code: Some(1),
                        reason: Some(format!("not a directory: {root}")),
                    })?,
                )
                .await?;
                return Ok(());
            }
            let (entries, stats) = exvia_proto::tree::collect_tree(&root_path)?;
            (root_path, entries, stats)
        }
        Some(pat) => {
            // 尾分量模式：扫描根是原始串的父目录；无匹配明确报错，不静默空传
            let base = match root.rsplit_once('/') {
                Some((d, _)) if !d.is_empty() => std::path::PathBuf::from(d),
                _ => std::path::PathBuf::from("."),
            };
            let (entries, stats) = collect_glob_entries(&base, pat)?;
            if entries.is_empty() {
                write_frame(
                    io,
                    &Frame::close(&CloseInfo {
                        code: Some(1),
                        reason: Some(format!("no files match: {root}")),
                    })?,
                )
                .await?;
                return Ok(());
            }
            (base, entries, stats)
        }
    };

    let outcome: anyhow::Result<(u64, u64, usize)> = async {
        if stats.any() {
            // 符号链接不跟随、特殊文件不传：告诉操作者，别以为传全了。
            tracing::warn!("tree scan of {root}: {stats}");
        }
        let rooted: Vec<(exvia_proto::msgs::TreeEntry, std::path::PathBuf)> = entries
            .into_iter()
            .map(|e| (e, root_path.clone()))
            .collect();
        let (files, bytes) = exvia_proto::tree::send_tree_frames(io, &rooted, |_, _| {}).await?;
        Ok((
            files,
            bytes,
            stats.symlinks + stats.special + stats.unreadable,
        ))
    }
    .await;

    match outcome {
        Ok((files, bytes, skipped)) => {
            tracing::info!("tree sent: {root} ({files} files, {bytes}B, {skipped} skipped)");
            // 等接收端确认，失败要如实报给操作者
            if let Some(frame) = read_frame(io).await? {
                if frame.kind == FrameKind::Close {
                    let info = frame.close_info()?;
                    if info.code != Some(0) {
                        anyhow::bail!("receiver failed: {}", info.reason.unwrap_or_default());
                    }
                }
            }
            Ok(())
        }
        Err(e) => {
            write_frame(
                io,
                &Frame::close(&CloseInfo {
                    code: Some(1),
                    reason: Some(e.to_string()),
                })?,
            )
            .await?;
            Err(e)
        }
    }
}

// 尾分量通配与 CLI put 侧的展开共用 `exvia_proto::tree::glob_match` 这一份实现
// （`*`/`?`、不跨 `/`、仅尾分量的调用约定见该函数文档）。
/// `get` 远端尾分量通配的条目收集：在 base 内按文件名匹配。与 put 侧 CLI 的展开
/// 同一套语义：`*` 不匹配点开头的隐藏文件（pattern 以 `.` 开头时解除）、只支持
/// 尾分量；匹配到的文件为顶层条目（rel = 文件名，落到 CLI 的 localdir 下），
/// 匹配到的目录整棵递归（rel 以目录名为前缀）；符号链接不跟随、特殊文件跳过
/// （同 [`exvia_proto::tree::collect_tree`]）。不匹配任何条目时返回空清单，由
/// 调用方明确报错。
fn collect_glob_entries(
    base: &Path,
    pattern: &str,
) -> anyhow::Result<(
    Vec<exvia_proto::msgs::TreeEntry>,
    exvia_proto::tree::ScanStats,
)> {
    if pattern.contains('/') {
        anyhow::bail!("wildcards are only supported in the last path component: {pattern}");
    }
    let mut stats = exvia_proto::tree::ScanStats::default();
    let mut names: Vec<String> = std::fs::read_dir(base)
        .map_err(|e| anyhow::anyhow!("cannot scan {}: {e}", base.display()))?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        // 与 shell 一致：`*` 不匹配点开头的隐藏文件
        .filter(|n| !n.starts_with('.') || pattern.starts_with('.'))
        .filter(|n| exvia_proto::tree::glob_match(pattern, n))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let p = base.join(&name);
        let Ok(md) = std::fs::symlink_metadata(&p) else {
            stats.unreadable += 1;
            continue;
        };
        let ft = md.file_type();
        if ft.is_symlink() {
            stats.symlinks += 1;
            continue;
        }
        if ft.is_dir() {
            let (sub, sub_stats) = exvia_proto::tree::collect_tree(&p)?;
            stats.symlinks += sub_stats.symlinks;
            stats.special += sub_stats.special;
            stats.unreadable += sub_stats.unreadable;
            out.push(exvia_proto::msgs::TreeEntry {
                rel: name.clone(),
                dir: true,
                size: 0,
                mode: exvia_proto::tree::mode_of(&md),
                mtime: exvia_proto::tree::mtime_of(&md),
            });
            for mut e in sub {
                e.rel = format!("{name}/{}", e.rel);
                out.push(e);
            }
        } else if ft.is_file() {
            out.push(exvia_proto::msgs::TreeEntry {
                rel: name,
                dir: false,
                size: md.len(),
                mode: exvia_proto::tree::mode_of(&md),
                mtime: exvia_proto::tree::mtime_of(&md),
            });
        } else {
            stats.special += 1;
        }
    }
    Ok((out, stats))
}

/// TCP 端口转发（-L）：agent 侧连接目标，双向透传。
async fn tcpfwd_session<S>(io: S, params: &SessionParams) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = params
        .target_host
        .clone()
        .ok_or_else(|| anyhow::anyhow!("missing target address"))?;
    let port = params
        .target_port
        .ok_or_else(|| anyhow::anyhow!("missing target port"))?;
    let addr = format!("{host}:{port}");
    let target = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let mut io = io;
            let close = Frame::close(&CloseInfo {
                code: Some(1),
                reason: Some(format!("connection to {addr} failed: {e}")),
            })?;
            write_frame(&mut io, &close).await?;
            return Ok(());
        }
        Err(_) => {
            let mut io = io;
            let close = Frame::close(&CloseInfo {
                code: Some(1),
                reason: Some(format!("connection to {addr} timed out")),
            })?;
            write_frame(&mut io, &close).await?;
            return Ok(());
        }
    };
    bridge_noise_tcp(io, target, true).await
}

/// 会话帧流 ↔ TCP 双向透传，-L / -R 回程桥共用（语义同 ssh）。
/// Shutdown 帧半关闭向 TCP 传播 FIN；`tcp_eof_closes` 决定本端 TCP EOF 是否立即收尾
/// （-L 目标全关即结束；-R 接入方 `printf .. | nc` 早 FIN 是常态，须半关闭传播并排空回程）。
async fn bridge_noise_tcp<S, T>(io: S, target: T, tcp_eof_closes: bool) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut rh, mut wh) = tokio::io::split(target);
    // read_frame 放进独立任务：select 取消不丢已消费帧字节（cancel-safe 读泵）
    let (mut noise_r, mut noise_w) = tokio::io::split(io);
    let (frames_tx, mut frames_rx) = mpsc::channel::<Frame>(16);
    let read_pump = tokio::spawn(async move {
        while let Ok(Some(f)) = read_frame(&mut noise_r).await {
            if frames_tx.send(f).await.is_err() {
                break;
            }
        }
    });
    let mut buf_up = [0u8; exvia_proto::FILE_CHUNK];
    let mut tcp_eof = false; // 本端 TCP 读到 EOF（读臂随之停用，防 EOF 空转）
    let mut peer_eof = false; // 对端已传播写侧关闭（收到 Shutdown）
    let mut closed = false; // 收尾时是否发 Close（让对端立即结束，不必等流 EOF）
    loop {
        tokio::select! {
            // 会话流（L3 帧）→ 目标 TCP
            frame = frames_rx.recv() => match frame {
                None => break,
                Some(Frame { kind: FrameKind::Data, payload }) => {
                    if wh.write_all(&payload).await.is_err() { break; }
                }
                // 对端写侧关闭（半关闭）：向 TCP 传播 FIN，读侧继续回泵
                Some(Frame { kind: FrameKind::Shutdown, .. }) => {
                    peer_eof = true;
                    if wh.shutdown().await.is_err() { break; }
                    if tcp_eof && peer_eof {
                        closed = true;
                        break;
                    }
                }
                Some(Frame { kind: FrameKind::Close, .. }) => break,
                Some(Frame { kind: FrameKind::Ctrl, .. }) => {}
            },
            // 目标 TCP → 会话流
            n = rh.read(&mut buf_up), if !tcp_eof => match n {
                Ok(0) | Err(_) => {
                    tcp_eof = true;
                    if tcp_eof_closes {
                        // -L：目标主动全关即收尾
                        closed = true;
                        break;
                    }
                    // -R：接入方早 FIN 是常态，传播写侧关闭后继续排空回程
                    let _ = write_frame(&mut noise_w, &Frame::shutdown()).await;
                    if peer_eof {
                        closed = true;
                        break;
                    }
                }
                Ok(n) => {
                    if write_frame(&mut noise_w, &Frame::data(buf_up[..n].to_vec())).await.is_err() { break; }
                }
            },
        }
    }
    if closed {
        let _ = write_frame(
            &mut noise_w,
            &Frame::close(&CloseInfo {
                code: Some(0),
                reason: None,
            })?,
        )
        .await;
    }
    let _ = wh;
    // 终止读泵释放 noise_r，否则 yamux 流不 FIN，中继桥接任务悬挂
    read_pump.abort();
    Ok(())
}

/// 反向转发（-R，ssh -R 语义）：在 agent 侧监听 bind_addr:bind_port，
/// 每条接入连接对应一条独立回程流（新 yamux 流 + Noise responder）；
/// 目标端点由 CLI 决定，隧道不能当跳板扫 CLI 网络。
/// 会话流只用于控制帧，泛型化以便测试直连（Noise 握手由 handle_session 在外层完成）。
async fn tcpfwd_reverse_session<S>(
    core: &Arc<Core>,
    relay_tx: &mpsc::UnboundedSender<String>,
    mut io: S,
    sid: u64,
    peer_pub: String,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (bind_addr, bind_port) = loop {
        let Some(frame) = read_frame(&mut io).await? else {
            anyhow::bail!("peer closed before bind command");
        };
        match frame.kind {
            FrameKind::Ctrl => {
                if let CtrlMsg::TcpfwdReverse {
                    bind_addr,
                    bind_port,
                } = frame.ctrl_msg()?
                {
                    break (bind_addr, bind_port);
                }
            }
            FrameKind::Close => anyhow::bail!("peer cancelled reverse forward"),
            _ => {}
        }
    };
    let listener = match tokio::net::TcpListener::bind((bind_addr.as_str(), bind_port)).await {
        Ok(l) => l,
        Err(e) => {
            // 绑定失败经 Close.reason 浮出给操作者
            let close = Frame::close(&CloseInfo {
                code: Some(1),
                reason: Some(format!("bind {bind_addr}:{bind_port} failed: {e}")),
            })?;
            write_frame(&mut io, &close).await?;
            return Ok(());
        }
    };
    // 沿用 file 会话的 Ack（chunk_index=0 表示绑定成功）
    write_frame(&mut io, &Frame::ctrl(&CtrlMsg::Ack { chunk_index: 0 })?).await?;
    tracing::info!("sid={sid} reverse forward listening on {bind_addr}:{bind_port}");
    // 须在首个 ReverseOpen 前登记；守卫保证任何退出路径都摘除
    let returns = Arc::new(StreamQueue::new());
    core.register_reverse(sid, returns.clone());
    let _reg = ReverseReg(core.clone(), sid);

    let (mut io_r, _io_w) = tokio::io::split(io);
    let (frames_tx, mut frames_rx) = mpsc::channel::<Frame>(16);
    let read_pump = tokio::spawn(async move {
        while let Ok(Some(f)) = read_frame(&mut io_r).await {
            if frames_tx.send(f).await.is_err() {
                break;
            }
        }
    });

    // pending 接入排队等回程流配对，带时刻便于惰性清扫超时（用 tokio 时钟，与定时臂同源）
    let mut pending: std::collections::VecDeque<(
        tokio::net::TcpStream,
        std::net::SocketAddr,
        tokio::time::Instant,
    )> = std::collections::VecDeque::new();
    loop {
        // 超时未配对的接入直接关闭
        let now = tokio::time::Instant::now();
        pending.retain(|(_, peer, at)| {
            if now.duration_since(*at) > REVERSE_WAIT {
                tracing::debug!("sid={sid} {peer} timed out waiting for return stream, closing");
                false
            } else {
                true
            }
        });
        // 最早到期接入的 deadline（队首最早）：没有这个定时臂，最后一条接入
        // 会让循环停在 select 上，清扫只在其他事件唤醒时才跑，接入可永久挂起
        let wake = pending
            .front()
            .map(|(.., at)| *at + REVERSE_WAIT)
            .unwrap_or_else(|| tokio::time::Instant::now() + REVERSE_WAIT);
        tokio::select! {
            // 控制流：CLI 命令退出（Close/EOF）→ 解绑、清空 pending
            frame = frames_rx.recv() => match frame {
                // Shutdown 视同退出信号（CLI 写侧关闭意味着不再有绑定指令）
                None | Some(Frame { kind: FrameKind::Close, .. })
                    | Some(Frame { kind: FrameKind::Shutdown, .. }) => break,
                Some(_) => {}
            },
            // 被管机侧新接入
            accepted = listener.accept() => match accepted {
                Ok((tcp, peer)) => {
                    if pending.len() >= REVERSE_PENDING_LIMIT {
                        // 立即拒绝：回程流梗阻，不积压
                        tracing::warn!("sid={sid} reverse forward pending full ({REVERSE_PENDING_LIMIT}), rejecting {peer}");
                        drop(tcp);
                        continue;
                    }
                    pending.push_back((tcp, peer, tokio::time::Instant::now()));
                    send_json(relay_tx, &AgentToRelay::ReverseOpen { sid });
                }
                Err(e) => {
                    tracing::warn!("sid={sid} accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            // 回程流到达 → 与队首接入配对
            stream = returns.pop() => {
                match pending.pop_front() {
                    Some((tcp, peer, _)) => {
                        tokio::spawn(reverse_bridge(
                            core.clone(),
                            stream,
                            tcp,
                            peer,
                            peer_pub.clone(),
                            sid,
                        ));
                    }
                    None => {
                        // 迟到回程流直接丢弃，对端握手超时自然收尾
                        tracing::debug!("sid={sid} return stream has no pending accept, dropping");
                    }
                }
            }
            // 清扫定时器：无事件也要醒来执行 retain，接入超时才能兑现
            _ = tokio::time::sleep_until(wake) => {}
        }
    }
    tracing::info!(
        "sid={sid} reverse forward unbound {bind_addr}:{bind_port} ({} pending closed)",
        pending.len()
    );
    // 解绑：listener 随作用域关闭，pending 里的接入随 VecDeque 丢弃
    read_pump.abort();
    Ok(())
}

/// 单条 -R 回程桥：Noise responder 握手（TOFU 与邀请一致）→ 双向透传。
async fn reverse_bridge(
    core: Arc<Core>,
    stream: MuxStream,
    tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    peer_pub: String,
    sid: u64,
) {
    let handshake = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        exvia_proto::noise::handshake(
            stream,
            exvia_proto::noise::Role::Responder,
            &core.x25519_static(),
        ),
    )
    .await;
    let noise = match handshake {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::debug!("sid={sid} {peer} return bridge handshake failed: {e}");
            return;
        }
        Err(_) => {
            tracing::debug!("sid={sid} {peer} return bridge handshake timed out");
            return;
        }
    };
    // TOFU：回程流对端公钥须与邀请一致；拿不到公钥同样 fail-closed（与 handle_session 一致）
    if let Err(e) = tofu_check(noise.remote_static(), &peer_pub) {
        tracing::warn!("sid={sid} {peer} return stream rejected: {e}");
        return;
    }
    if let Err(e) = bridge_noise_tcp(noise, tcp, false).await {
        tracing::debug!("sid={sid} {peer} return bridge ended: {e}");
    }
}

/// 读流首 8B BE sid 前导（入向流分流的依据；超时/EOF 返回 None）。
async fn read_sid_preamble<S>(stream: &mut S) -> Option<u64>
where
    S: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut sid_buf = [0u8; 8];
    tokio::time::timeout(INVITE_TIMEOUT, stream.read_exact(&mut sid_buf))
        .await
        .ok()?
        .ok()?;
    Some(u64::from_be_bytes(sid_buf))
}

/// exec / exec -t 会话共用的 `--timeout` 构造：0 视为未配置（与 CLI 侧校验一致）。
/// 返回 (配置值, 到点 future)；未配置时 future 永不定完成，由 select 臂的
/// `if timeout.is_some()` 条件禁用。
fn command_timeout(
    secs: Option<u64>,
) -> (
    Option<std::time::Duration>,
    std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
) {
    let timeout = secs.filter(|t| *t > 0).map(std::time::Duration::from_secs);
    // `Option<Duration>` 是 Copy，`move` 捕获后外侧的 timeout 仍可用于 select 臂条件
    let fut = Box::pin(async move {
        match timeout {
            Some(t) => tokio::time::sleep(t).await,
            None => std::future::pending().await,
        }
    });
    (timeout, fut)
}

/// 交互式终端：在 PTY 里拉起用户 shell，双向透传。
async fn pty_session<S>(io: S, params: &SessionParams) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};

    let cols = params.cols.unwrap_or(80).max(2);
    let rows = params.rows.unwrap_or(24).max(2);
    let pty_system = native_pty_system();
    let pair = pty_system.openpty(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    // `exec -t`（ssh -t 语义）：pty_command 携带指定命令，在 PTY 里交给 sh -c 执行
    // （CLI 已按 shell 规则把 argv 拼回串）；None 维持现状拉起登录 shell。
    // 旧版 CLI 不带该字段，行为不变。
    let mut cmd = match params.pty_command.as_deref() {
        Some(c) if !c.is_empty() => {
            let mut b = CommandBuilder::new("sh");
            b.arg("-c");
            b.arg(c);
            b
        }
        _ => CommandBuilder::new(std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())),
    };
    cmd.env(
        "TERM",
        params
            .term
            .clone()
            .unwrap_or_else(|| "xterm-256color".into()),
    );
    if let Ok(home) = std::env::var("HOME") {
        cmd.cwd(home);
    }
    let mut child = pair.slave.spawn_command(cmd)?;
    drop(pair.slave); // 父端必须放掉 slave，否则读不到 EOF
                      // wait 阻塞，挪进 blocking 线程避免卡死 tokio worker；
                      // kill 用克隆的 killer（child 已 move 进 wait 线程，不能抢 &mut）
    let mut killer = child.clone_killer();
    let wait_task = tokio::task::spawn_blocking(move || child.wait());

    let mut reader = pair.master.try_clone_reader()?;
    let mut writer = pair.master.take_writer()?;

    // PTY 读写是阻塞 IO，用独立线程双泵。
    // 通道有界（64×8KB=512KB）：背压传导回 PTY，防内存膨胀。
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let read_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(64);
    // 不留 handle：write 线程随输入通道关闭自然退出。
    // 线程退出即 drop PTY writer，portable-pty 的 writer Drop 会向 master 写入
    // \n+VEOF，这正是把"输入半关闭"传播成 shell 读到 EOF 的机制。
    std::thread::spawn(move || {
        while let Some(chunk) = in_rx.blocking_recv() {
            if writer.write_all(&chunk).is_err() || writer.flush().is_err() {
                break;
            }
        }
    });

    let mut exit_code: Option<i32> = None;
    // 只有输出通道关闭才允许 join；其余路径 reader 可能仍阻塞在 master read
    // （slave fd 被孙进程持有），join 会永久挂起
    let mut reader_done = false;
    // 输入半关闭后置 None：关掉发送端，write 线程退出并 drop PTY writer（见上）
    let mut in_tx = Some(in_tx);
    let (mut noise_r, mut noise_w) = tokio::io::split(io);
    let (frames_tx, mut frames_rx) = mpsc::channel::<Frame>(16);
    tokio::spawn(async move {
        while let Ok(Some(f)) = read_frame(&mut noise_r).await {
            if frames_tx.send(f).await.is_err() {
                break;
            }
        }
    });
    // --timeout（exec -t）：到点杀掉 PTY 里的命令并回 124（与 exec 会话同语义）；
    // 交互 shell 不带 timeout_secs，此臂不启用，行为不变
    let (timeout, mut timeout_fut) = command_timeout(params.timeout_secs);
    loop {
        tokio::select! {
            // PTY 输出 → 远端
            chunk = out_rx.recv() => {
                match chunk {
                    // 写失败不能 `?` 早退，必须走统一收尾（kill + wait + join + Close），否则留孤儿 shell
                    Some(data) => {
                        if write_frame(&mut noise_w, &Frame::data(data)).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        reader_done = true; // PTY 关闭，reader 线程已收尾
                        break;
                    }
                }
            }
            // 远端输入 → PTY；窗口变更；关闭
            frame = frames_rx.recv() => {
                let Some(frame) = frame else { break }; // 对端关闭或流错误
                match frame {
                    Frame { kind: FrameKind::Data, payload } => {
                        // 输入已半关闭时迟到的数据无从投递，直接丢弃
                        if let Some(tx) = &in_tx {
                            if tx.send(payload).await.is_err() {
                                break;
                            }
                        }
                    }
                    Frame { kind: FrameKind::Ctrl, payload } => {
                        if let Ok(CtrlMsg::Resize { cols, rows }) = serde_json::from_slice::<CtrlMsg>(&payload) {
                            let _ = pair.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
                        }
                    }
                    Frame { kind: FrameKind::Close, payload } => {
                        let _ = killer.kill();
                        let info: CloseInfo = serde_json::from_slice(&payload).unwrap_or_default();
                        exit_code = info.code;
                        break;
                    }
                    // 对端输入 EOF（ssh 语义）：关掉输入半边。write 线程退出时 drop PTY
                    // writer，slave 读 stdin 得到 EOF，shell 如 bash 自行退出；输出泵与
                    // 退出码回传照常，会话等子进程自然结束
                    Frame { kind: FrameKind::Shutdown, .. } => in_tx = None,
                }
            }
            // --timeout 到点：杀命令、报文案、回 124（文案与 exec 会话一致）
            _ = &mut timeout_fut, if timeout.is_some() => {
                let _ = killer.kill();
                let _ = write_frame(
                    &mut noise_w,
                    &Frame::data(b"timed out, process killed\n".to_vec()),
                )
                .await;
                exit_code = Some(124);
                break;
            }
        }
    }
    let _ = killer.kill(); // 任何退出路径都不留孤儿 shell
                           // 排干 PTY 已缓冲的输出再收尾：超时/被 kill 的路径可能有残余；正常 EOF 路径
                           // 输出通道已关，立即返回。2s 上界与 exec 会话的排干一致，防后台子进程拖住。
    let drain_deadline = tokio::time::Instant::now() + DRAIN_LIMIT;
    while let Ok(Some(data)) = tokio::time::timeout_at(drain_deadline, out_rx.recv()).await {
        if write_frame(&mut noise_w, &Frame::data(data)).await.is_err() {
            break;
        }
    }
    // SIGKILL 后 wait 很快返回，此处 await 只等收尸
    let code = match exit_code {
        Some(c) => c,
        None => match wait_task.await {
            Ok(Ok(s)) => s.exit_code() as i32,
            _ => -1,
        },
    };
    if reader_done {
        let _ = read_thread.join(); // 线程已退出，join 只是收尸
    }
    drop(in_tx); // 关闭输入通道，write 线程自然退出
    write_frame(
        &mut noise_w,
        &Frame::close(&CloseInfo {
            code: Some(code),
            reason: None,
        })?,
    )
    .await?;
    Ok(())
}

/// 一次性命令执行：stdout/stderr 分通道回传，带回退出码。
async fn exec_session<S>(io: &mut S, params: &SessionParams) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let program = params.cmd.clone().unwrap_or_default();
    if program.is_empty() {
        write_frame(
            io,
            &Frame::close(&CloseInfo {
                code: Some(127),
                reason: Some("empty command".into()),
            })?,
        )
        .await?;
        return Ok(());
    }
    let mut command = tokio::process::Command::new(&program);
    command.args(&params.argv);
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    // 独立进程组：超时/收尾时整组 kill。`sh -c 'sleep 30'` 里只杀 shell 会留下
    // 孙进程持有 stdout/stderr 写端，输出泵永不 EOF、Close 帧发不出去。
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            // 进程正常输出的 stderr 以行为单位；这条合成报错也要带换行，
            // 否则终端提示符会贴在错误后面
            let reason = format!("cannot start {program}: {e}\n");
            let _ = write_frame(
                io,
                &Frame::data([1u8].into_iter().chain(reason.bytes()).collect::<Vec<u8>>()),
            )
            .await;
            write_frame(
                io,
                &Frame::close(&CloseInfo {
                    code: Some(127),
                    reason: None,
                })?,
            )
            .await?;
            return Ok(());
        }
    };
    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");

    // 输出通道有界（32×8KB=256KB）：管道填满→子进程写阻塞→天然背压
    let (tx, mut rx) = mpsc::channel::<(u8, Vec<u8>)>(32);
    fn pump<S>(mut stream: S, mark: u8, tx: mpsc::Sender<(u8, Vec<u8>)>)
    where
        S: AsyncRead + Unpin + Send + 'static,
    {
        use tokio::io::AsyncReadExt;
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send((mark, buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
    pump(stdout, 0, tx.clone());
    pump(stderr, 1, tx);

    let (timeout, mut timeout_fut) = command_timeout(params.timeout_secs);

    // 监督任务：等进程退出或外部 kill（kill 整个进程组）
    let pgid = child.id().unwrap_or(0);
    let (kill_tx, mut kill_rx) = mpsc::unbounded_channel::<()>();
    let _kill_guard = ExecKillGuard(kill_tx.clone());
    let mut sup: tokio::task::JoinHandle<anyhow::Result<i32>> = tokio::spawn(async move {
        tokio::select! {
            st = child.wait() => Ok(st.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)),
            _ = kill_rx.recv() => {
                #[cfg(unix)]
                kill_process_group(pgid);
                #[cfg(not(unix))]
                let _ = child.start_kill();
                let st = child.wait().await;
                Ok(st.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1))
            }
        }
    });

    let exit_code: i32;
    loop {
        tokio::select! {
            item = rx.recv() => match item {
                Some((mark, data)) => {
                    if write_frame(io, &Frame::data([mark].into_iter().chain(data).collect::<Vec<u8>>())).await.is_err() {
                        exit_code = -1;
                        break;
                    }
                }
                None => {
                    // 输出全部结束，取退出码
                    exit_code = sup.await.unwrap_or(Ok(-1)).unwrap_or(-1);
                    break;
                }
            },
            code = &mut sup => {
                exit_code = code.unwrap_or(Ok(-1)).unwrap_or(-1);
                break;
            }
            _ = &mut timeout_fut, if timeout.is_some() => {
                let _ = kill_tx.send(());
                let _ = write_frame(io, &Frame::data([1u8].into_iter().chain("timed out, process killed".as_bytes().to_vec()).collect::<Vec<u8>>())).await;
                exit_code = 124;
                break;
            }
        }
    }
    // 排干剩余输出：等泵自然结束（不用 rx.close()，在途尾块不会被丢）。
    // 2s 上界：后台子进程仍持写端时不让会话任务永久挂住。
    let drain_deadline = tokio::time::Instant::now() + DRAIN_LIMIT;
    while let Ok(Some((mark, data))) = tokio::time::timeout_at(drain_deadline, rx.recv()).await {
        if write_frame(
            io,
            &Frame::data([mark].into_iter().chain(data).collect::<Vec<u8>>()),
        )
        .await
        .is_err()
        {
            break;
        }
    }
    // _kill_guard 在任何退出路径 drop 时请求整组 kill（含 ? 早退）。
    write_frame(
        io,
        &Frame::close(&CloseInfo {
            code: Some(exit_code),
            reason: None,
        })?,
    )
    .await?;
    Ok(())
}

/// exec 进程组清理守卫：任何退出路径（含 `?` 早退）都请求整组 kill，同 ReverseReg。
struct ExecKillGuard(mpsc::UnboundedSender<()>);

impl Drop for ExecKillGuard {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

// ---- 工具 ----

fn send_json<T: Serialize>(tx: &mpsc::UnboundedSender<String>, msg: &T) {
    let _ = tx.send(serde_json::to_string(msg).expect("control message serialization failed"));
}

async fn wait_control(rx: &mut mpsc::UnboundedReceiver<String>) -> anyhow::Result<RelayToAgent> {
    let text = tokio::time::timeout(std::time::Duration::from_secs(15), rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for relay response"))?
        .ok_or_else(|| anyhow::anyhow!("relay closed the connection"))?;
    Ok(serde_json::from_str(&text)?)
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".into())
}

fn decode_b64_32(s: &str) -> anyhow::Result<[u8; 32]> {
    base64::engine::general_purpose::STANDARD
        .decode(s)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid pubkey length"))
}

/// TOFU 纯逻辑：对端静态公钥须与邀请一致。拿不到公钥同样拒绝（fail-closed），
/// 不能因为校验信息缺失就跳过。会话流与 -R 回程流共用这一规则。
fn tofu_check(remote_static: Option<&[u8; 32]>, invite_pub_b64: &str) -> anyhow::Result<()> {
    let rs = remote_static
        .ok_or_else(|| anyhow::anyhow!("Noise gave no remote static pubkey, disconnect"))?;
    let expect = decode_b64_32(invite_pub_b64)?;
    if rs.as_slice() != expect.as_slice() {
        anyhow::bail!("peer pubkey does not match invite, possible mitm, disconnect");
    }
    Ok(())
}

/// 对 exec 子进程所在进程组发 SIGKILL。`process_group(0)` 令 pid 即 pgid，负号按组发信号。
/// 仅在监督任务持有 child 时调用，避免子进程退出后 pgid 被复用误伤。
#[cfg(unix)]
fn kill_process_group(pgid: u32) {
    if pgid == 0 {
        return;
    }
    unsafe {
        libc::kill(-(pgid as i32), libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 机器侧路径展开：相对路径/~ 以 agent 用户家目录为基准 ----
    #[test]
    fn expand_machine_path_relative_and_tilde_go_home() {
        let home = std::path::Path::new("/home/chao");
        assert_eq!(
            expand_machine_path_with("Downloads/f.rpm", Some(home)),
            "/home/chao/Downloads/f.rpm"
        );
        assert_eq!(
            expand_machine_path_with("~/Downloads/f.rpm", Some(home)),
            "/home/chao/Downloads/f.rpm"
        );
        assert_eq!(expand_machine_path_with("~", Some(home)), "/home/chao");
        assert_eq!(
            expand_machine_path_with(".config/x", Some(home)),
            "/home/chao/.config/x"
        );
    }

    #[test]
    fn expand_machine_path_absolute_untouched() {
        let home = std::path::Path::new("/home/chao");
        assert_eq!(
            expand_machine_path_with("/var/log/messages", Some(home)),
            "/var/log/messages"
        );
        // 文件名里的 ~ 不是家目录语法，不能误展开
        assert_eq!(
            expand_machine_path_with("/tmp/~bak/x", Some(home)),
            "/tmp/~bak/x"
        );
    }

    #[test]
    fn expand_machine_path_without_home_keeps_input() {
        // 拿不到家目录时不瞎猜，原样返回，由打开文件时的报错兜底
        assert_eq!(expand_machine_path_with("relative/x", None), "relative/x");
        assert_eq!(expand_machine_path_with("~/x", None), "~/x");
        assert_eq!(expand_machine_path_with("/abs/x", None), "/abs/x");
    }

    // 未知 reason 归入重连，宁可多连一次不误退
    #[test]
    fn kick_reactions_split_by_code() {
        assert!(matches!(
            kick_reaction("anything", Some(KickCode::Takeover)),
            KickReaction::Takeover
        ));
        assert!(matches!(
            kick_reaction("anything", Some(KickCode::Version)),
            KickReaction::Version
        ));
        assert!(matches!(
            kick_reaction("anything", Some(KickCode::Reconnect)),
            KickReaction::Reconnect
        ));
        assert!(matches!(
            kick_reaction("anything", Some(KickCode::Unknown)),
            KickReaction::Reconnect
        ));
        // code 优先于 reason 文案
        assert!(matches!(
            kick_reaction("协议版本不兼容", Some(KickCode::Reconnect)),
            KickReaction::Reconnect
        ));
    }

    #[test]
    fn kick_reactions_legacy_relay_falls_back_to_reason() {
        assert!(matches!(
            kick_reaction("同机新连接接入", None),
            KickReaction::Takeover
        ));
        assert!(matches!(
            kick_reaction("协议版本不兼容: agent v0.3.0 / relay v0.2.0", None),
            KickReaction::Version
        ));
        assert!(matches!(
            kick_reaction("服务维护中，请稍后自动重连", None),
            KickReaction::Reconnect
        ));
        assert!(matches!(
            kick_reaction("some unknown reason", None),
            KickReaction::Reconnect
        ));
    }

    #[test]
    fn kick_reactions_match_english_reason() {
        assert!(matches!(
            kick_reaction("new connection from the same machine took over", None),
            KickReaction::Takeover
        ));
        assert!(matches!(
            kick_reaction(
                "protocol version mismatch: agent v0.5.0 / relay v0.4.0, upgrade the agent",
                None
            ),
            KickReaction::Version
        ));
        assert!(matches!(
            kick_reaction("service maintenance, reconnect shortly", None),
            KickReaction::Reconnect
        ));
    }

    // 票据验签是中继不可信模型下的唯一授权依据

    const MACHINE: &str = "machine-1";
    const NOW: u64 = 1_700_000_000;

    /// 用指定身份签一张合法票据；`edit` 可在签名前篡改任意字段。
    fn ticket(
        signer: &exvia_proto::Identity,
        edit: impl FnOnce(&mut SessionTicket),
    ) -> SessionTicket {
        let mut t = SessionTicket {
            machine_id: MACHINE.into(),
            sid: 42,
            x25519_pub: signer.x25519_pub_b64(),
            user: "alice".into(),
            expires_at: NOW + SESSION_TICKET_TTL / 2,
            nonce: "nonce-001".into(),
            sig: String::new(),
        };
        edit(&mut t);
        t.sig = signer.sign_b64(&t.signing_bytes());
        t
    }

    fn verify(
        trusted: &[String],
        t: Option<&SessionTicket>,
        sid: u64,
        peer_pub: &str,
        seen: &mut HashMap<String, u64>,
    ) -> anyhow::Result<String> {
        verify_session_ticket(trusted, MACHINE, sid, peer_pub, t, NOW, seen)
    }

    #[test]
    fn ticket_valid_passes_and_is_tamper_evident() {
        let cli = exvia_proto::Identity::generate();
        let trusted = vec![cli.ed25519_pub_b64()];
        let t = ticket(&cli, |_| {});
        let peer = t.x25519_pub.clone();
        let mut seen = HashMap::new();
        assert_eq!(
            verify(&trusted, Some(&t), 42, &peer, &mut seen).unwrap(),
            "alice"
        );
        assert_eq!(seen.get(&t.nonce), Some(&t.expires_at));

        // 改写 user 后验签失败（签名字节含 user）
        let mut forged = t.clone();
        forged.user = "root".into();
        assert!(verify(&trusted, Some(&forged), 42, &peer, &mut HashMap::new()).is_err());
        // 中继改写过期时间 → 同样失败
        let mut forged = t.clone();
        forged.expires_at += 1;
        assert!(verify(&trusted, Some(&forged), 42, &peer, &mut HashMap::new()).is_err());
    }

    #[test]
    fn ticket_missing_is_rejected() {
        let cli = exvia_proto::Identity::generate();
        let trusted = vec![cli.ed25519_pub_b64()];
        assert!(verify(&trusted, None, 42, "any", &mut HashMap::new()).is_err());
    }

    #[test]
    fn ticket_binds_sid_machine_and_peer_pub() {
        let cli = exvia_proto::Identity::generate();
        let trusted = vec![cli.ed25519_pub_b64()];

        // 每个用例重新签名，确保失败是绑定字段不一致而非签名失效
        let wrong_sid = ticket(&cli, |t| t.sid = 43);
        assert!(verify(
            &trusted,
            Some(&wrong_sid),
            42,
            &wrong_sid.x25519_pub,
            &mut HashMap::new()
        )
        .is_err());

        let wrong_machine = ticket(&cli, |t| t.machine_id = "machine-2".into());
        assert!(verify(
            &trusted,
            Some(&wrong_machine),
            42,
            &wrong_machine.x25519_pub,
            &mut HashMap::new()
        )
        .is_err());

        // 中继把邀请里的 peer_pub 换成自己的，即使票据本身合法也拒绝
        let good = ticket(&cli, |_| {});
        assert!(verify(
            &trusted,
            Some(&good),
            42,
            "relay-owned-x25519",
            &mut HashMap::new()
        )
        .is_err());
    }

    #[test]
    fn ticket_expiry_window_is_bounded() {
        let cli = exvia_proto::Identity::generate();
        let trusted = vec![cli.ed25519_pub_b64()];
        let expired = ticket(&cli, |t| t.expires_at = NOW - 1);
        let err = verify(
            &trusted,
            Some(&expired),
            42,
            &expired.x25519_pub,
            &mut HashMap::new(),
        )
        .unwrap_err()
        .to_string();
        // 过期报错直接给出票据字段时间与本机时间，运维一眼看出时钟偏差
        assert!(
            err.contains("expires_at=1699999999")
                && err.contains("agent_now=1700000000")
                && err.contains("skew ≈ 1s"),
            "{err}"
        );

        let at_now = ticket(&cli, |t| t.expires_at = NOW);
        assert!(verify(
            &trusted,
            Some(&at_now),
            42,
            &at_now.x25519_pub,
            &mut HashMap::new()
        )
        .is_err());

        // 超长有效期（中继/恶意 CLI 想让票据长期可用）也不接受
        let too_long = ticket(&cli, |t| t.expires_at = NOW + SESSION_TICKET_TTL + 31);
        let err = verify(
            &trusted,
            Some(&too_long),
            42,
            &too_long.x25519_pub,
            &mut HashMap::new(),
        )
        .unwrap_err()
        .to_string();
        // 本机时钟落后时的偏差是负的，同样要可读
        assert!(
            err.contains(&format!("expires_at={}", NOW + SESSION_TICKET_TTL + 31))
                && err.contains("agent_now=1700000000")
                && err.contains(&format!("skew ≈ -{}s", SESSION_TICKET_TTL + 31)),
            "{err}"
        );

        let at_boundary = ticket(&cli, |t| t.expires_at = NOW + SESSION_TICKET_TTL + 30);
        assert!(verify(
            &trusted,
            Some(&at_boundary),
            42,
            &at_boundary.x25519_pub,
            &mut HashMap::new()
        )
        .is_ok());
    }

    /// 时钟偏差自诊断：构造过期 120s 的票据，报错里的两个时间戳可被
    /// 运维直接作差（或脚本解析），得出 120s 的偏差结论。
    #[test]
    fn ticket_expired_error_reports_parseable_skew() {
        let cli = exvia_proto::Identity::generate();
        let trusted = vec![cli.ed25519_pub_b64()];
        let expired = ticket(&cli, |t| t.expires_at = NOW - 120);
        let err = verify(
            &trusted,
            Some(&expired),
            42,
            &expired.x25519_pub,
            &mut HashMap::new(),
        )
        .unwrap_err()
        .to_string();
        // 从报错里解析出两个时间戳（模拟运维或脚本作差）
        let num_after = |hay: &str, tag: &str| -> Option<u64> {
            let rest = hay.split_once(tag)?.1;
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            rest[..end].parse().ok()
        };
        let exp_at = num_after(&err, "expires_at=")
            .unwrap_or_else(|| panic!("error should carry a parseable expires_at=: {err}"));
        let agent_at = num_after(&err, "agent_now=")
            .unwrap_or_else(|| panic!("error should carry a parseable agent_now=: {err}"));
        // 时间差可解析且等于构造的 120s 偏差
        assert_eq!(agent_at - exp_at, 120, "{err}");
        assert!(err.contains("skew ≈ 120s"), "{err}");
    }

    #[test]
    fn ticket_fail_closed_and_untrusted_signer_rejected() {
        let cli = exvia_proto::Identity::generate();
        let attacker = exvia_proto::Identity::generate();
        let t = ticket(&cli, |_| {});
        let peer = t.x25519_pub.clone();

        // 没配白名单：一律拒绝（enroll 时未带 --trusted-cli-key）
        assert!(verify(&[], Some(&t), 42, &peer, &mut HashMap::new()).is_err());
        // 中继用自己的私钥伪造票据：不在白名单内
        let forged = ticket(&attacker, |mut_| mut_.nonce = "relay-forged".into());
        assert!(verify(
            &[cli.ed25519_pub_b64()],
            Some(&forged),
            42,
            &forged.x25519_pub,
            &mut HashMap::new()
        )
        .is_err());
        // 白名单里混了无关公钥也不能放行
        assert!(verify(
            &[attacker.ed25519_pub_b64()],
            Some(&t),
            42,
            &peer,
            &mut HashMap::new()
        )
        .is_err());
    }

    #[test]
    fn ticket_nonce_replay_blocked_but_pruned_after_expiry() {
        let cli = exvia_proto::Identity::generate();
        let trusted = vec![cli.ed25519_pub_b64()];
        let t = ticket(&cli, |_| {});
        let peer = t.x25519_pub.clone();
        let mut seen = HashMap::new();

        assert!(verify(&trusted, Some(&t), 42, &peer, &mut seen).is_ok());
        let replay = verify(&trusted, Some(&t), 42, &peer, &mut seen)
            .unwrap_err()
            .to_string();
        // 重放报错带去重窗口边界（nonce 记录的过期时间）与本机时间
        assert!(
            replay.contains(&format!("nonce_expires_at={}", t.expires_at))
                && replay.contains("agent_now=1700000000"),
            "{replay}"
        );

        // 过期 nonce 被清扫，不会让 seen 无限增长
        seen.insert("old-nonce".into(), NOW - 1);
        seen.insert("expired-exactly".into(), NOW);
        let t2 = ticket(&cli, |x| x.nonce = "nonce-002".into());
        assert!(verify(&trusted, Some(&t2), 42, &peer, &mut seen).is_ok());
        assert!(!seen.contains_key("old-nonce"));
        assert!(!seen.contains_key("expired-exactly"));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn trusted_key_must_be_a_32_byte_pubkey() {
        let good = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(normalize_cli_key(&good).unwrap(), good);
        assert_eq!(normalize_cli_key(&format!(" {good} ")).unwrap(), good);
        // 长度不对、非 base64、空串一律拒绝
        assert!(normalize_cli_key("short").is_err());
        assert!(normalize_cli_key("!!!not-base64!!!").is_err());
        assert!(normalize_cli_key("").is_err());
        let wrong_len = base64::engine::general_purpose::STANDARD.encode([7u8; 31]);
        assert!(normalize_cli_key(&wrong_len).is_err());
    }

    // TOFU 纯逻辑：对端静态公钥缺失（fail-closed）或与邀请不符都必须拒绝，
    // 会话流（handle_session）与 -R 回程流（reverse_bridge）共用这一规则
    #[test]
    fn tofu_check_is_fail_closed_and_binds_invite() {
        let a = exvia_proto::Identity::generate();
        let b = exvia_proto::Identity::generate();
        let pub_a = a.x25519_pub_b64();
        assert!(tofu_check(Some(&a.x25519_pub()), &pub_a).is_ok());
        // 拿不到对端静态公钥：拒绝，不能跳过校验
        assert!(tofu_check(None, &pub_a).is_err());
        // 公钥与邀请不符：疑似中间人
        assert!(tofu_check(Some(&b.x25519_pub()), &pub_a).is_err());
        // 邀请公钥本身损坏
        assert!(tofu_check(Some(&a.x25519_pub()), "not-b64!!").is_err());
    }

    // 日志里的 key 截断必须按字符：trust add 的 key 来自对端，多字节 UTF-8
    // 按字节切片会 panic（&s[..12] 落在字符中间）
    #[test]
    fn key_hint_is_utf8_safe_and_bounded() {
        // 44 字符的 b64 公钥只留前 12 个字符
        let key = "aA0+zZ9/=".repeat(5);
        assert_eq!(key_hint(Some(&key)), "aA0+zZ9/=aA0");
        // 多字节输入按字符截取，不得 panic，也不必恰好落在第 12 字节
        let multibyte = "密钥测试多字节输入超长会被截断哦";
        assert_eq!(key_hint(Some(multibyte)), "密钥测试多字节输入超长会");
        assert_eq!(key_hint(Some("短")), "短");
        assert_eq!(key_hint(None), "-");
    }

    // enroll 的 --trusted-cli-key 必须逐个规范化，格式非法在联网前就报错退出，
    // 不能把坏键原样写进身份文件
    #[test]
    fn enroll_trusted_keys_are_normalized_or_rejected() {
        let good = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let keys = vec![format!(" {good} "), good.clone()];
        let normalized = normalize_trusted_keys(&keys).unwrap();
        assert_eq!(normalized, vec![good.clone(), good.clone()]);
        // 任一键非法即整体报错
        let bad = vec![good, "not-a-key".into()];
        assert!(normalize_trusted_keys(&bad).is_err());
        assert!(normalize_trusted_keys(&[]).unwrap().is_empty());
    }

    fn test_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "exvia-agent-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // get 远端尾分量通配：与 put 侧 CLI 展开同一套语义（不匹配隐藏文件、只支持
    // 尾分量、`?` 单字符、目录整棵递归）；无匹配返回空清单，由调用方明确报错
    #[test]
    fn collect_glob_matches_tail_pattern_semantics() {
        let dir = test_dir("glob");
        std::fs::write(dir.join("a.log"), b"a").unwrap();
        std::fs::write(dir.join("b.log"), b"b").unwrap();
        std::fs::write(dir.join("c.txt"), b"c").unwrap();
        std::fs::write(dir.join(".hidden.log"), b"h").unwrap();
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::write(dir.join("data/x.bin"), b"x").unwrap();

        // 尾分量匹配：字典序、不混入隐藏文件与其它后缀
        let (entries, _) = collect_glob_entries(&dir, "*.log").unwrap();
        let rels: Vec<&str> = entries.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(rels, vec!["a.log", "b.log"]);

        // 匹配到目录：整棵递归，rel 以目录名为前缀
        let (entries, _) = collect_glob_entries(&dir, "data").unwrap();
        let rels: Vec<&str> = entries.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(rels, vec!["data", "data/x.bin"]);
        assert!(entries[0].dir);

        // `?` 匹配单个字符
        let (entries, _) = collect_glob_entries(&dir, "?.log").unwrap();
        assert_eq!(entries.len(), 2);

        // 无匹配：空清单（调用方据此报 no files match）
        let (entries, _) = collect_glob_entries(&dir, "*.zip").unwrap();
        assert!(entries.is_empty());

        // 中间分量通配在协议层同样拒绝（CLI 侧已拦，agent 侧兜底）
        let err = collect_glob_entries(&dir, "a*/x.log")
            .unwrap_err()
            .to_string();
        assert!(err.contains("last path component"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -R 接入在等待回程流配对：没有任何事件时也必须在 REVERSE_WAIT 后被关闭，
    // 不能因为循环停在 select 上（最后一条接入）而永久挂起
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reverse_pending_times_out_without_events() {
        use tokio::io::AsyncReadExt as _;

        // listener 在被测函数内部创建，端口 0 的真实值测试拿不到：先占一个空闲端口再释放
        let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let core = Arc::new(Core {
            identity: exvia_proto::Identity::generate(),
            machine_id: "machine-test".into(),
            server: String::new(),
            fingerprint: String::new(),
            ws_prefix: "/_exvia".into(),
            trusted_cli: std::sync::RwLock::new(Vec::new()),
            allowlist_path: std::path::PathBuf::from("/tmp/exvia-agent-test-unused"),
            seen_tickets: std::sync::Mutex::new(HashMap::new()),
            sessions: AtomicU32::new(0),
            invites: Mutex::new(HashMap::new()),
            invite_notify: Notify::new(),
            reverse_streams: std::sync::Mutex::new(HashMap::new()),
        });
        let (relay_tx, mut relay_rx) = mpsc::unbounded_channel::<String>();
        let (session_io, mut peer) = tokio::io::duplex(64 * 1024);
        let peer_pub = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let task = {
            let core = core.clone();
            tokio::spawn(async move {
                tcpfwd_reverse_session(&core, &relay_tx, session_io, 7, peer_pub).await
            })
        };

        // 发绑定命令并确认绑定成功（Ack{0}）
        write_frame(
            &mut peer,
            &Frame::ctrl(&CtrlMsg::TcpfwdReverse {
                bind_addr: "127.0.0.1".into(),
                bind_port: port,
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let ack = read_frame(&mut peer).await.unwrap().unwrap();
        assert!(
            matches!(ack.ctrl_msg().unwrap(), CtrlMsg::Ack { chunk_index: 0 }),
            "bind must succeed"
        );

        // 被管机侧一条接入：入 pending，并通知中继一次
        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let msg = relay_rx.recv().await.unwrap();
        assert!(msg.contains("reverse_open"), "{msg}");

        // 此后无任何事件：时限一到接入必须被关闭（读侧 EOF），而不是无限等待
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf))
            .await
            .expect("pending accept must be closed after REVERSE_WAIT without any event")
            .unwrap();
        assert_eq!(n, 0, "connection should be closed, not left open");
        // 清理不发第二条 ReverseOpen
        assert!(relay_rx.try_recv().is_err());

        // Close 收尾，会话正常退出
        write_frame(&mut peer, &Frame::close(&CloseInfo::default()).unwrap())
            .await
            .unwrap();
        task.await.unwrap().unwrap();
    }

    // stdin EOF 必须传播到 PTY 里的进程（ssh 语义）：对端发 Shutdown 后，agent 放下
    // PTY writer（portable-pty 随之向 master 写入换行 + VEOF），进程读到 EOF 自行
    // 退出，会话以 Close + 退出码收尾，且此前的输入与输出仍照常工作。
    // 是否响应 EOF 是进程自身的行为（登录 shell 可能因用户配置忽略单个 EOF，与
    // ssh 一致），exvia 的契约只是把 EOF 送到位——所以这里用 cat 这个对 EOF
    // 确定性退出的进程来钉链路，不依赖运行环境的登录 shell。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pty_input_shutdown_propagates_eof() {
        let (session_io, mut peer) = tokio::io::duplex(256 * 1024);
        let params = SessionParams {
            term: Some("dumb".into()),
            pty_command: Some("exec cat".into()),
            ..Default::default()
        };
        let task = tokio::spawn(async move { pty_session(session_io, &params).await });

        // 先送一条输入验证通路，随后 stdin EOF（Shutdown）
        write_frame(&mut peer, &Frame::data(b"__EXVIA_EOF__\n".to_vec()))
            .await
            .unwrap();
        write_frame(&mut peer, &Frame::shutdown()).await.unwrap();

        // 持续读输出直到 Close：EOF 没有传播到 PTY 的话这里会超时
        let mut output: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let close_code = loop {
            let frame = tokio::time::timeout_at(deadline, read_frame(&mut peer))
                .await
                .expect("pty session must end after stdin EOF (child never exited)")
                .unwrap()
                .expect("pty session stream ended without Close");
            match frame.kind {
                FrameKind::Data => output.extend(frame.payload),
                FrameKind::Close => break frame.close_info().unwrap().code,
                _ => {}
            }
        };
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains("__EXVIA_EOF__"),
            "child output missing marker: {output}"
        );
        assert_eq!(close_code, Some(0), "cat exits 0 on EOF");
        task.await.unwrap().unwrap();
    }

    // exec -t（ssh -t 语义）：pty_command 指定的命令在 PTY 里运行（而非登录 shell），
    // 命令的退出码随 Close 透传给 CLI
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pty_exec_command_runs_instead_of_shell() {
        let (session_io, mut peer) = tokio::io::duplex(256 * 1024);
        let params = SessionParams {
            term: Some("dumb".into()),
            pty_command: Some("echo __EXVIA_PTYCMD__; exit 5".into()),
            ..Default::default()
        };
        let task = tokio::spawn(async move { pty_session(session_io, &params).await });

        // 命令不读 stdin：立即 EOF（Shutdown），会话等命令自然结束
        write_frame(&mut peer, &Frame::shutdown()).await.unwrap();

        let mut output: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let close_code = loop {
            let frame = tokio::time::timeout_at(deadline, read_frame(&mut peer))
                .await
                .expect("pty exec session must end when the command exits")
                .unwrap()
                .expect("pty exec session stream ended without Close");
            match frame.kind {
                FrameKind::Data => output.extend(frame.payload),
                FrameKind::Close => break frame.close_info().unwrap().code,
                _ => {}
            }
        };
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains("__EXVIA_PTYCMD__"),
            "command output missing marker: {output}"
        );
        assert_eq!(close_code, Some(5), "command exit code must pass through");
        task.await.unwrap().unwrap();
    }

    // exec -t + --timeout：到点杀掉 PTY 里的命令，回 124 与提示文案（与 exec 会话同语义）
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pty_exec_command_times_out_with_124() {
        let (session_io, mut peer) = tokio::io::duplex(256 * 1024);
        let params = SessionParams {
            term: Some("dumb".into()),
            pty_command: Some("sleep 30".into()),
            timeout_secs: Some(1),
            ..Default::default()
        };
        let task = tokio::spawn(async move { pty_session(session_io, &params).await });
        write_frame(&mut peer, &Frame::shutdown()).await.unwrap();

        let mut output: Vec<u8> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let close_code = loop {
            let frame = tokio::time::timeout_at(deadline, read_frame(&mut peer))
                .await
                .expect("pty exec session must end after the timeout")
                .unwrap()
                .expect("pty exec session stream ended without Close");
            match frame.kind {
                FrameKind::Data => output.extend(frame.payload),
                FrameKind::Close => break frame.close_info().unwrap().code,
                _ => {}
            }
        };
        let output = String::from_utf8_lossy(&output);
        assert!(output.contains("timed out"), "missing notice: {output}");
        assert_eq!(close_code, Some(124), "timeout must report 124");
        task.await.unwrap().unwrap();
    }
}
