// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI 本地配置与已知主机指纹（0600）

use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use exvia_proto::keys::write_private;
use exvia_proto::Result;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientConfig {
    pub server: String,
    pub fingerprint: String,
    /// admin 令牌（管理员模式）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
    pub ed_seed_b64: String,
    pub x25519_b64: String,
    /// WS 路径前缀，部署可配（默认 /_exvia）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_prefix: Option<String>,
}

impl ClientConfig {
    pub fn ws_prefix(&self) -> String {
        let raw = self.ws_prefix.as_deref().unwrap_or("/_exvia").trim();
        let raw = raw.trim_end_matches('/');
        if raw.is_empty() {
            return "/_exvia".to_string();
        }
        if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("/{raw}")
        }
    }
}

pub fn config_dir() -> PathBuf {
    let base = dirs::config_dir().expect("cannot determine user config directory (is HOME set?)");
    let dir = base.join("exvia");
    migrate_legacy_dir(&base, &dir);
    dir
}

// 旧目录名留在这里是刻意的：改名后要把身份、别名和已知公钥整体搬过来，
// 否则 CLI 公钥变了会被 agent 白名单拒之门外。
fn migrate_legacy_dir(base: &Path, dir: &Path) {
    let legacy = base.join("rctl");
    if dir.exists() || !legacy.exists() {
        return;
    }
    match std::fs::rename(&legacy, dir) {
        // rename 保留 0600 与所有权，跨设备失败时不动旧目录，让用户自己搬
        Ok(()) => eprintln!("[exvia] migrated local config from {}", legacy.display()),
        Err(e) => eprintln!(
            "[exvia] cannot migrate {} to {}: {e}",
            legacy.display(),
            dir.display()
        ),
    }
}

pub fn config_path() -> PathBuf {
    config_dir().join("client.json")
}

pub fn known_agents_path() -> PathBuf {
    config_dir().join("known_agents.json")
}

// 敏感字段 default + skip，封进 sealed 后明文 JSON 不再出现
#[derive(Serialize, Deserialize)]
struct StoredConfig {
    server: String,
    fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pass: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ed_seed_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x25519_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ws_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<Sealed>,
}

// CLI 身份单独持久化，login 不换密钥，agent 白名单才稳定
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    ed_seed_b64: String,
    x25519_b64: String,
}

pub fn identity_path() -> PathBuf {
    config_dir().join("cli-identity.json")
}

// 身份文件缺失时迁移旧 client.json 里的身份，避免 pubkey 与签票据的私钥分叉、agent 白名单失效
fn identity_from_legacy_raw(raw: &str) -> Option<(String, String)> {
    let stored: StoredConfig = serde_json::from_str(raw).ok()?;
    if stored.sealed.is_some() {
        return None;
    }
    Some((stored.ed_seed_b64?, stored.x25519_b64?))
}

fn write_identity(ed: &str, x: &str) -> Result<()> {
    write_private(
        &identity_path(),
        &serde_json::to_string_pretty(&StoredIdentity {
            ed_seed_b64: ed.to_string(),
            x25519_b64: x.to_string(),
        })?,
    )
}

// CLI 身份以 cli-identity.json 为单一真相源：优先读它，其次迁移旧配置，最后新建
pub fn load_or_create_identity() -> Result<(String, String)> {
    let path = identity_path();
    if path.exists() {
        let stored: StoredIdentity = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        return Ok((stored.ed_seed_b64, stored.x25519_b64));
    }
    if let Ok(raw) = std::fs::read_to_string(config_path()) {
        if let Some((ed, x)) = identity_from_legacy_raw(&raw) {
            write_identity(&ed, &x)?;
            return Ok((ed, x));
        }
    }
    let parts = exvia_proto::Identity::generate().export_parts();
    write_identity(&parts.0, &parts.1)?;
    Ok(parts)
}

pub fn current_pubkey() -> Result<String> {
    let (ed, x) = load_or_create_identity()?;
    Ok(exvia_proto::Identity::import_parts(&ed, &x)?.ed25519_pub_b64())
}

#[derive(Serialize, Deserialize)]
struct SealedPlain {
    token: Option<String>,
    ed_seed_b64: String,
    x25519_b64: String,
}

// 口令加密块：argon2id 派生 32 字节密钥，AES-256-GCM
#[derive(Serialize, Deserialize)]
struct Sealed {
    salt_b64: String,
    nonce_b64: String,
    ct_b64: String,
    ver: u32,
}

// ---- 口令加密（--encrypt）；argon2 参数与 relay 侧一致 ----

const SEALED_VER: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("base64 decode failed: {e}"))
}

fn derive_key(pass: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    use argon2::Argon2;
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

fn seal(plain: &SealedPlain, pass: &str) -> Result<Sealed> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::Aead;
    use aes_gcm::KeyInit;
    use argon2::password_hash::rand_core::{OsRng, RngCore};

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(pass, &salt)?;
    let cipher = aes_gcm::Aes256Gcm::new(GenericArray::from_slice(&key));
    let ct = cipher
        .encrypt(
            GenericArray::from_slice(&nonce),
            serde_json::to_vec(plain)?.as_slice(),
        )
        .map_err(|_| anyhow::anyhow!("failed to encrypt config"))?;
    Ok(Sealed {
        salt_b64: b64(&salt),
        nonce_b64: b64(&nonce),
        ct_b64: b64(&ct),
        ver: SEALED_VER,
    })
}

fn unseal(sealed: &Sealed, pass: &str) -> Result<SealedPlain> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::Aead;
    use aes_gcm::KeyInit;

    let salt = unb64(&sealed.salt_b64)?;
    let nonce = unb64(&sealed.nonce_b64)?;
    let ct = unb64(&sealed.ct_b64)?;
    let key = derive_key(pass, &salt)?;
    let cipher = aes_gcm::Aes256Gcm::new(GenericArray::from_slice(&key));
    let plain = cipher
        .decrypt(GenericArray::from_slice(&nonce), ct.as_slice())
        .map_err(|_| {
            anyhow::anyhow!(
                "wrong passphrase or corrupted config; decryption failed (log in again to reset)"
            )
        })?;
    Ok(serde_json::from_slice(&plain)?)
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt)
        .map_err(|e| anyhow::anyhow!("failed to read passphrase: {e}"))
}

// 新口令读两遍确认；空口令等于没加密，都重来
fn prompt_new_passphrase() -> Result<String> {
    loop {
        let first = prompt_passphrase("set config passphrase: ")?;
        if first.is_empty() {
            println!("passphrase cannot be empty, try again");
            continue;
        }
        let second = prompt_passphrase("confirm passphrase: ")?;
        if first == second {
            return Ok(first);
        }
        println!("passphrases do not match, try again");
    }
}

impl ClientConfig {
    pub fn save(&self) -> Result<()> {
        write_private(&config_path(), &serde_json::to_string_pretty(self)?)
    }

    pub fn save_encrypted(&self) -> Result<()> {
        let pass = prompt_new_passphrase()?;
        write_private(&config_path(), &self.sealed_json(&pass)?)
    }

    // 敏感字段不出现在明文 JSON 里
    fn sealed_json(&self, pass: &str) -> Result<String> {
        let sealed = seal(
            &SealedPlain {
                token: self.token.clone(),
                ed_seed_b64: self.ed_seed_b64.clone(),
                x25519_b64: self.x25519_b64.clone(),
            },
            pass,
        )?;
        Ok(serde_json::to_string_pretty(&StoredConfig {
            server: self.server.clone(),
            fingerprint: self.fingerprint.clone(),
            token: None,
            user: self.user.clone(),
            pass: None,
            ed_seed_b64: None,
            x25519_b64: None,
            ws_prefix: self.ws_prefix.clone(),
            sealed: Some(sealed),
        })?)
    }

    // 统一用 cli-identity.json 的身份；两份私钥分叉会让 agent 白名单公钥对不上签票据的私钥
    fn adopt_canonical_identity(&mut self) -> Result<()> {
        let (ed, x) = load_or_create_identity()?;
        self.ed_seed_b64 = ed;
        self.x25519_b64 = x;
        Ok(())
    }

    // 读不到配置时给出可执行提示；裸 io 错误（os error 2）会让用户以为二进制坏了
    fn read_config_raw() -> Result<String> {
        Self::read_config_at(&config_path())
    }

    fn read_config_at(path: &std::path::Path) -> Result<String> {
        match std::fs::read_to_string(path) {
            Ok(raw) => Ok(raw),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
                "not logged in: no config at {}\n  run: exvia login --server <wss-url> --fingerprint <sha256> [--token <token>]",
                path.display()
            ),
            Err(e) => anyhow::bail!("cannot read {}: {e}", path.display()),
        }
    }

    pub fn load() -> Result<Self> {
        let raw = Self::read_config_raw()?;
        let mut cfg = Self::from_json(&raw, &|| prompt_passphrase("config passphrase: "))?;
        cfg.adopt_canonical_identity()?;
        Ok(cfg)
    }

    // 登出时把口令随配置带回（仅内存），按原落盘形态回写
    pub fn load_with_pass() -> Result<(Self, Option<String>)> {
        let raw = Self::read_config_raw()?;
        let probe: StoredConfig = serde_json::from_str(&raw)?;
        let (mut cfg, pass) = match probe.sealed {
            Some(_) => {
                let pass = prompt_passphrase("config passphrase: ")?;
                (Self::from_json(&raw, &|| Ok(pass.clone()))?, Some(pass))
            }
            None => (
                Self::from_json(&raw, &|| {
                    // 明文配置不该走到解密分支；真走到了就报错，别 panic
                    Err(anyhow::anyhow!(
                        "config is plaintext but a passphrase was requested"
                    ))
                })?,
                None,
            ),
        };
        cfg.adopt_canonical_identity()?;
        Ok((cfg, pass))
    }

    // 按读盘形态回写：明文仍明文，加密仍用原口令重封（身份密钥保留）
    pub fn save_after_logout(cfg: &ClientConfig, pass: Option<&str>) -> Result<()> {
        match pass {
            Some(pass) => write_private(&config_path(), &cfg.sealed_json(pass)?),
            None => write_private(&config_path(), &serde_json::to_string_pretty(cfg)?),
        }
    }

    // 带 sealed 就提示一次口令解密，错一次即退出不重试
    fn from_json(raw: &str, prompt: &dyn Fn() -> Result<String>) -> Result<Self> {
        let stored: StoredConfig = serde_json::from_str(raw)?;
        match stored.sealed {
            Some(sealed) => {
                let plain = unseal(&sealed, &prompt()?)?;
                Ok(Self {
                    server: stored.server,
                    fingerprint: stored.fingerprint,
                    token: plain.token,
                    user: stored.user,
                    pass: stored.pass,
                    ed_seed_b64: plain.ed_seed_b64,
                    x25519_b64: plain.x25519_b64,
                    ws_prefix: stored.ws_prefix,
                })
            }
            None => Ok(Self {
                server: stored.server,
                fingerprint: stored.fingerprint,
                token: stored.token,
                user: stored.user,
                pass: stored.pass,
                ed_seed_b64: stored
                    .ed_seed_b64
                    .ok_or_else(|| anyhow::anyhow!("config missing ed_seed_b64"))?,
                x25519_b64: stored
                    .x25519_b64
                    .ok_or_else(|| anyhow::anyhow!("config missing x25519_b64"))?,
                ws_prefix: stored.ws_prefix,
            }),
        }
    }
}

// known_hosts 式记录 agent 公钥（TOFU）：首次记录，之后不一致即拒绝（fail-closed）。
// 旧格式是「machine_id → 公钥 b64」的纯映射；新格式带首见时间，读取兼容两种，
// 写出统一新格式。0600 语义由 write_private 保持。

/// known_agents.json 里的一条记录。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KnownAgentEntry {
    pub pubkey_b64: String,
    /// 首次记录的 Unix 秒；旧格式条目没有
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<u64>,
}

// 兼容新旧两种落盘形态
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum KnownAgentRaw {
    Detailed(KnownAgentEntry),
    Legacy(String),
}

type KnownAgents = std::collections::BTreeMap<String, KnownAgentEntry>;

fn known_agents_at(path: &Path) -> Result<KnownAgents> {
    if !path.exists() {
        return Ok(Default::default());
    }
    let raw = std::fs::read_to_string(path)?;
    let parsed: std::collections::BTreeMap<String, KnownAgentRaw> = serde_json::from_str(&raw)
        .map_err(|e| {
            anyhow::anyhow!("failed to parse known agents file {}: {e}", path.display())
        })?;
    Ok(parsed
        .into_iter()
        .map(|(id, v)| {
            let entry = match v {
                KnownAgentRaw::Detailed(e) => e,
                KnownAgentRaw::Legacy(pubkey_b64) => KnownAgentEntry {
                    pubkey_b64,
                    first_seen: None,
                },
            };
            (id, entry)
        })
        .collect())
}

fn write_known_agents_at(path: &Path, map: &KnownAgents) -> Result<()> {
    write_private(path, &serde_json::to_string_pretty(map)?)
}

pub fn load_known_agents() -> Result<KnownAgents> {
    known_agents_at(&known_agents_path())
}

/// 删除一条已知 agent 记录；返回是否真的存在过（不存在由调用方报错）。
pub fn known_agent_remove(machine_id: &str) -> Result<bool> {
    known_agent_remove_at(&known_agents_path(), machine_id)
}

fn known_agent_remove_at(path: &Path, machine_id: &str) -> Result<bool> {
    let mut map = known_agents_at(path)?;
    if map.remove(machine_id).is_none() {
        return Ok(false);
    }
    write_known_agents_at(path, &map)?;
    Ok(true)
}

/// agent 公钥的短指纹：sha256(解码后的公钥) 前 16 个 hex 字符，供 `known list` 展示。
pub fn key_fingerprint(pubkey_b64: &str) -> String {
    use sha2::{Digest, Sha256};
    match base64::engine::general_purpose::STANDARD.decode(pubkey_b64) {
        Ok(raw) => format!("sha256:{:.16}", hex::encode(Sha256::digest(raw))),
        Err(_) => "(undecodable key)".to_string(),
    }
}

pub fn check_known_agent(machine_id: &str, peer_pub_b64: &str) -> Result<bool> {
    let path = known_agents_path();
    let mut map = known_agents_at(&path)?;
    match map.get(machine_id) {
        Some(entry) => Ok(entry.pubkey_b64 == peer_pub_b64),
        None => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            map.insert(
                machine_id.to_string(),
                KnownAgentEntry {
                    pubkey_b64: peer_pub_b64.to_string(),
                    first_seen: Some(now),
                },
            );
            write_known_agents_at(&path, &map)?;
            Ok(true)
        }
    }
}

// 预置信任锚（`exvia known add`）：TOFU 的首连窗口靠带外核对关闭——agent enroll
// 输出里给出 `exvia known add <machine_id> <x25519_pub>` 现成命令，操作者在首连前
// 执行它；之后首连核对的是预置值，中继的"介绍"不再被无条件信任。

/// 预置一条 agent 公钥记录。语义：
/// - 已有记录且钥匙相同 → 幂等，返回 Ok(false)（CLI 提示 already anchored）；
/// - 已有记录且钥匙不同 → 拒绝（提示先 `known rm`），不静默覆盖；
/// - 无记录 → 写入（first_seen = 预置时刻），返回 Ok(true)。
pub fn known_agent_anchor(machine_id: &str, pubkey_b64: &str) -> Result<bool> {
    known_agent_anchor_at(&known_agents_path(), machine_id, pubkey_b64)
}

fn known_agent_anchor_at(path: &Path, machine_id: &str, pubkey_b64: &str) -> Result<bool> {
    let mut map = known_agents_at(path)?;
    match map.get(machine_id) {
        Some(entry) if entry.pubkey_b64 == pubkey_b64 => Ok(false),
        Some(entry) => anyhow::bail!(
            "machine {machine_id} is already recorded with a different key ({}); \
             run `exvia known rm {machine_id}` first if the agent really re-keyed",
            key_fingerprint(&entry.pubkey_b64)
        ),
        None => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            map.insert(
                machine_id.to_string(),
                KnownAgentEntry {
                    pubkey_b64: pubkey_b64.to_string(),
                    first_seen: Some(now),
                },
            );
            write_known_agents_at(path, &map)?;
            Ok(true)
        }
    }
}

/// 预置公钥的输入校验：合法 base64 且解码后恰为 32 字节（x25519 静态公钥）。
pub fn normalize_agent_pubkey(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        anyhow::bail!("pubkey is empty");
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| anyhow::anyhow!("pubkey is not valid base64: {s}"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "pubkey must decode to 32 bytes (x25519 static key), got {}: {s}",
            bytes.len()
        );
    }
    Ok(s.to_string())
}

// ---- 机器别名：纯本地、离线可用 ----
// 别名映射只在本机维护（aliases.json, 0600）：中继可伪造 hostname 把别名指向攻击者 agent
// 票据按完整 machine_id 签发，agent 会校验，中继无法重定向

pub type AliasMap = std::collections::BTreeMap<String, String>;

pub fn aliases_path() -> PathBuf {
    config_dir().join("aliases.json")
}

pub fn load_aliases() -> Result<AliasMap> {
    let path = aliases_path();
    if !path.exists() {
        return Ok(AliasMap::new());
    }
    let raw = std::fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse alias file {}: {e}", path.display()))
}

fn save_aliases(map: &AliasMap) -> Result<()> {
    write_private(&aliases_path(), &serde_json::to_string_pretty(map)?)
}

// 别名字符集收紧，避免与命令参数、`host:path` 写法混淆
pub fn validate_alias_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 32 {
        anyhow::bail!("alias must be 1..32 chars: {name}");
    }
    if name.starts_with('-')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        anyhow::bail!(
            "alias may only contain letters, digits, ., _, - and must not start with -: {name}"
        );
    }
    Ok(())
}

pub fn alias_add(name: &str, machine_id: &str) -> Result<()> {
    validate_alias_name(name)?;
    let id = machine_id.trim();
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_whitespace) {
        anyhow::bail!("invalid machine_id: {machine_id}");
    }
    let mut map = load_aliases()?;
    map.insert(name.to_string(), id.to_string());
    save_aliases(&map)
}

pub fn alias_remove(name: &str) -> Result<bool> {
    let mut map = load_aliases()?;
    if map.remove(name).is_none() {
        return Ok(false);
    }
    save_aliases(&map)?;
    Ok(true)
}

// 测试与旧调用点的便捷入口：不查机器缓存
#[cfg(test)]
pub fn resolve_machine_local(input: &str, map: &AliasMap) -> Result<(String, Option<String>)> {
    resolve_machine_with_cache(input, map, &MachineCache::new())
}

/// 机器缓存：最近一次 `exvia ls` 的结果（id → hostname），只用于补全输入。
/// 缓存过期不影响正确性：解析出的完整 ID 仍需 agent 端票据验签。
pub type MachineCache = std::collections::BTreeMap<String, String>;

pub fn machine_cache_path() -> PathBuf {
    config_dir().join("machines.json")
}

pub fn load_machine_cache() -> MachineCache {
    std::fs::read_to_string(machine_cache_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn save_machine_cache(cache: &MachineCache) {
    // 纯本地便利数据，写失败不影响任何功能
    let _ = write_private(
        &machine_cache_path(),
        &serde_json::to_string_pretty(cache).unwrap_or_default(),
    );
}

/// 依次尝试：别名 → 完整 ID → 缓存里的 ID 前缀 → 缓存里的主机名 → 别名表里的 ID 前缀。
pub fn resolve_machine_with_cache(
    input: &str,
    map: &AliasMap,
    cache: &MachineCache,
) -> Result<(String, Option<String>)> {
    let s = input.trim();
    if s.is_empty() {
        anyhow::bail!("machine name is empty");
    }
    if let Some(id) = map.get(s) {
        return Ok((id.clone(), Some(format!("{s} -> {id}"))));
    }
    // machine_id 是 32 位小写 hex，完整 ID 原样直通，零配置可用
    if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok((s.to_ascii_lowercase(), None));
    }
    // 缓存命中：ID 前缀或主机名，唯一才接受
    if !cache.is_empty() {
        let by_prefix: std::collections::BTreeSet<&String> =
            cache.keys().filter(|id| id.starts_with(s)).collect();
        if by_prefix.len() == 1 {
            let id = (*by_prefix.iter().next().unwrap()).clone();
            return Ok((id.clone(), Some(format!("id prefix {s} -> {id}"))));
        }
        if by_prefix.len() > 1 {
            anyhow::bail!(
                "prefix {s:?} matches {} machines, use a longer prefix or a unique alias: {}",
                by_prefix.len(),
                by_prefix
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let by_host: Vec<&String> = cache
            .iter()
            .filter(|(_, h)| h.eq_ignore_ascii_case(s))
            .map(|(id, _)| id)
            .collect();
        if by_host.len() == 1 {
            let id = by_host[0].clone();
            return Ok((id.clone(), Some(format!("host {s} -> {id}"))));
        }
        if by_host.len() > 1 {
            anyhow::bail!(
                "hostname {s:?} matches {} machines, use the full id: {}",
                by_host.len(),
                by_host
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    let hits: Vec<String> = map
        .values()
        .filter(|id| id.starts_with(s))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    match hits.len() {
        1 => {
            let id = hits[0].clone();
            Ok((id.clone(), Some(format!("id prefix {s} -> {id}"))))
        }
        n if n > 1 => anyhow::bail!(
            "prefix {s:?} matches {n} machines, use a longer prefix or a unique alias: {}",
            hits.join(", ")
        ),
        _ => {
            let hint = if map.is_empty() {
                "no aliases configured".to_string()
            } else {
                format!(
                    "available aliases: {}",
                    map.keys().cloned().collect::<Vec<_>>().join(", ")
                )
            };
            let seen = if cache.is_empty() {
                String::new()
            } else {
                format!(
                    "; known machines: {}",
                    cache
                        .iter()
                        .map(|(id, h)| format!("{h}={id}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            anyhow::bail!(
                "unknown machine {s:?}: not a machine_id, configured alias, hostname, or unique id prefix; {hint}{seen}; \
                 use `exvia ls` to find machine ids, `exvia alias add <name> <machine_id>` to set an alias"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 32 字节 b64 占位即可，roundtrip 不解析密钥
    const FAKE_SEED: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const FAKE_X25519: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    const PASS: &str = "correct horse battery staple 123";

    fn sample() -> ClientConfig {
        ClientConfig {
            server: "wss://relay.example.com:8443".into(),
            fingerprint: "ab".repeat(32),
            token: Some("sess-tok-secret".into()),
            user: Some("bob".into()),
            pass: None,
            ed_seed_b64: FAKE_SEED.into(),
            x25519_b64: FAKE_X25519.into(),
            ws_prefix: None,
        }
    }

    fn fixed_prompt(pass: &str) -> impl Fn() -> Result<String> + '_ {
        move || Ok(pass.to_string())
    }

    #[test]
    fn ws_prefix_normalizes_and_defaults() {
        let mut c = sample();
        assert_eq!(c.ws_prefix(), "/_exvia");
        c.ws_prefix = Some("api/v2/".into());
        assert_eq!(c.ws_prefix(), "/api/v2");
        c.ws_prefix = Some("  /custom  ".into());
        assert_eq!(c.ws_prefix(), "/custom");
        c.ws_prefix = Some("".into());
        assert_eq!(c.ws_prefix(), "/_exvia");
    }

    #[test]
    fn sealed_roundtrip_and_no_plaintext() {
        let cfg = sample();
        let json = cfg.sealed_json(PASS).unwrap();
        assert!(!json.contains("sess-tok-secret"));
        assert!(!json.contains(FAKE_SEED));
        assert!(!json.contains(FAKE_X25519));
        assert!(json.contains("\"sealed\""));
        // server/fingerprint/user 保持明文便于诊断
        assert!(json.contains("wss://relay.example.com:8443"));
        let loaded = ClientConfig::from_json(&json, &fixed_prompt(PASS)).unwrap();
        assert_eq!(loaded.server, cfg.server);
        assert_eq!(loaded.fingerprint, cfg.fingerprint);
        assert_eq!(loaded.token, cfg.token);
        assert_eq!(loaded.user, cfg.user);
        assert_eq!(loaded.ed_seed_b64, FAKE_SEED);
        assert_eq!(loaded.x25519_b64, FAKE_X25519);
    }

    #[test]
    fn wrong_passphrase_fails_without_retry() {
        let json = sample().sealed_json(PASS).unwrap();
        let err = ClientConfig::from_json(&json, &fixed_prompt("wrong pass")).unwrap_err();
        assert!(err.to_string().contains("wrong passphrase"));
    }

    #[test]
    fn plain_legacy_json_loads() {
        let raw = format!(
            "{{\"server\": \"wss://old.example.com:8443\", \"fingerprint\": \"{}\", \
             \"token\": \"legacy-tok\", \"ed_seed_b64\": \"{}\", \"x25519_b64\": \"{}\"}}",
            "cd".repeat(32),
            FAKE_SEED,
            FAKE_X25519
        );
        let loaded = ClientConfig::from_json(&raw, &|| {
            panic!("plaintext config should not prompt for a passphrase")
        })
        .unwrap();
        assert_eq!(loaded.server, "wss://old.example.com:8443");
        assert_eq!(loaded.token.as_deref(), Some("legacy-tok"));
        assert_eq!(loaded.ed_seed_b64, FAKE_SEED);
        assert_eq!(loaded.x25519_b64, FAKE_X25519);
    }

    #[test]
    fn legacy_client_json_identity_is_migrated_not_replaced() {
        let raw = format!(
            "{{\"server\":\"wss://old:8443\",\"fingerprint\":\"{}\",\"token\":\"t\",\
             \"ed_seed_b64\":\"{}\",\"x25519_b64\":\"{}\"}}",
            "ab".repeat(32),
            FAKE_SEED,
            FAKE_X25519
        );
        let (ed, x) = identity_from_legacy_raw(&raw).unwrap();
        assert_eq!(ed, FAKE_SEED);
        assert_eq!(x, FAKE_X25519);
        // 加密配置无口令取不出身份，缺字段/坏 JSON 也不该 panic
        assert!(identity_from_legacy_raw(&sample().sealed_json(PASS).unwrap()).is_none());
        assert!(identity_from_legacy_raw("{\"server\":\"x\"}").is_none());
        assert!(identity_from_legacy_raw("not json").is_none());
    }

    #[test]
    fn sealed_file_roundtrip_keeps_0600() {
        let path = std::env::temp_dir().join(format!("exvia-cfg-test-{}.json", std::process::id()));
        write_private(&path, &sample().sealed_json(PASS).unwrap()).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(FAKE_SEED));
        let loaded = ClientConfig::from_json(&raw, &fixed_prompt(PASS)).unwrap();
        assert_eq!(loaded.ed_seed_b64, FAKE_SEED);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(&path).unwrap();
    }

    // ---- 机器别名解析（纯函数，不碰真实配置目录）----
    const ID_LAB: &str = "3b07c2d94e1a8f6b4c5d90e2f8a1b6c0";
    const ID_EDGE: &str = "aa11bb22cc33dd44ee55ff6677889900";

    fn alias_fixture() -> AliasMap {
        let mut m = AliasMap::new();
        m.insert("lab-1".into(), ID_LAB.into());
        m.insert("edge".into(), ID_EDGE.into());
        // 同一台机器允许多个别名，前缀去重后不应误判为歧义
        m.insert("lab-1-bak".into(), ID_LAB.into());
        m
    }

    #[test]
    fn alias_names_are_restricted() {
        assert!(validate_alias_name("lab-01").is_ok());
        assert!(validate_alias_name("db.prod").is_ok());
        assert!(validate_alias_name("-bad").is_err());
        assert!(validate_alias_name("has space").is_err());
        assert!(validate_alias_name("host:path").is_err());
        assert!(validate_alias_name("").is_err());
        assert!(validate_alias_name(&"x".repeat(33)).is_err());
    }

    #[test]
    fn resolve_prefers_exact_alias_then_full_id() {
        let m = alias_fixture();
        assert_eq!(resolve_machine_local("lab-1", &m).unwrap().0, ID_LAB);
        assert_eq!(resolve_machine_local("edge", &m).unwrap().0, ID_EDGE);
        assert_eq!(
            resolve_machine_local(ID_LAB, &AliasMap::new()).unwrap().0,
            ID_LAB
        );
        assert_eq!(
            resolve_machine_local(&ID_LAB.to_ascii_uppercase(), &m)
                .unwrap()
                .0,
            ID_LAB
        );
        assert!(resolve_machine_local(ID_LAB, &m).unwrap().1.is_none());
        // 别名与某 ID 前缀同名时，别名优先
        let mut clash = m.clone();
        clash.insert("aa".into(), "11111111111111111111111111111111".into());
        assert_eq!(
            resolve_machine_local("aa", &clash).unwrap().0,
            "11111111111111111111111111111111"
        );
    }

    #[test]
    fn resolve_unique_id_prefix_and_reject_ambiguity() {
        let m = alias_fixture();
        let (id, note) = resolve_machine_local("3b07", &m).unwrap();
        assert_eq!(id, ID_LAB);
        assert!(note.unwrap().contains("id prefix"));
        assert_eq!(resolve_machine_local("aa11", &m).unwrap().0, ID_EDGE);

        let mut amb = AliasMap::new();
        amb.insert("x".into(), "ab11111111111111111111111111111111".into());
        amb.insert("y".into(), "ab22222222222222222222222222222222".into());
        let err = resolve_machine_local("ab", &amb).unwrap_err().to_string();
        assert!(err.contains("matches 2 machines"), "{err}");
    }

    #[test]
    fn unknown_name_fails_closed_with_hints() {
        let err = resolve_machine_local("prod-db", &AliasMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unknown machine") && err.contains("no aliases configured"),
            "{err}"
        );
        let err = resolve_machine_local("nope", &alias_fixture())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("available aliases") && err.contains("lab-1"),
            "{err}"
        );
        assert!(resolve_machine_local("", &alias_fixture()).is_err());
    }

    #[test]
    fn machine_cache_resolves_prefix_and_hostname() {
        let mut cache = MachineCache::new();
        cache.insert(ID_LAB.into(), "db-01".into());
        cache.insert(ID_EDGE.into(), "edge-node".into());

        // 缓存里的 ID 前缀（不需要先建别名）
        let (id, note) = resolve_machine_with_cache("3b07", &AliasMap::new(), &cache).unwrap();
        assert_eq!(id, ID_LAB);
        assert!(note.unwrap().contains("id prefix"));

        // 主机名，大小写不敏感
        let (id, note) = resolve_machine_with_cache("edge-node", &AliasMap::new(), &cache).unwrap();
        assert_eq!(id, ID_EDGE);
        assert!(note.unwrap().contains("host"));

        // 别名优先于缓存
        let (id, _) = resolve_machine_with_cache("lab-1", &alias_fixture(), &cache).unwrap();
        assert_eq!(id, ID_LAB);

        // 主机名重复时必须报歧义，不能猜
        let mut dup = MachineCache::new();
        dup.insert("aaaa".into(), "same".into());
        dup.insert("bbbb".into(), "same".into());
        let err = resolve_machine_with_cache("same", &AliasMap::new(), &dup)
            .unwrap_err()
            .to_string();
        assert!(err.contains("matches 2 machines"), "{err}");

        // 未命中时把已知机器列出来，减少去翻 ls
        let err = resolve_machine_with_cache("nope", &AliasMap::new(), &cache)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("known machines") && err.contains("edge-node"),
            "{err}"
        );
    }

    #[test]
    fn missing_config_tells_the_user_to_log_in() {
        let p = std::env::temp_dir().join("exvia-definitely-missing-config.json");
        let _ = std::fs::remove_file(&p);
        let err = ClientConfig::read_config_at(&p).unwrap_err().to_string();
        // 不能把裸 io 错误抛给用户，必须给出下一步动作
        assert!(err.contains("not logged in"), "{err}");
        assert!(err.contains("exvia login"), "{err}");
        assert!(!err.contains("os error"), "{err}");
    }

    // ---- known_agents（TOFU 记录）----
    const FAKE_PUB: &str = "cHVibGljLWtleQ==";

    #[test]
    fn known_agents_roundtrip_and_legacy_entries() {
        let path = std::env::temp_dir().join(format!(
            "exvia-known-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        // 旧格式：纯「id → 公钥」映射，读出来首见时间为空
        std::fs::write(&path, format!("{{\"{ID_LAB}\": \"{FAKE_PUB}\"}}")).unwrap();
        let map = known_agents_at(&path).unwrap();
        assert_eq!(map[ID_LAB].pubkey_b64, FAKE_PUB);
        assert_eq!(map[ID_LAB].first_seen, None);

        // rm 删条目：第二次删必须报不存在
        assert!(known_agent_remove_at(&path, ID_LAB).unwrap());
        assert!(!known_agent_remove_at(&path, ID_LAB).unwrap());
        assert!(known_agents_at(&path).unwrap().is_empty());

        // 新格式（带首见时间）写出后 roundtrip，0600 语义保持
        let mut m = KnownAgents::new();
        m.insert(
            ID_LAB.to_string(),
            KnownAgentEntry {
                pubkey_b64: FAKE_PUB.into(),
                first_seen: Some(1700000000),
            },
        );
        write_known_agents_at(&path, &m).unwrap();
        let map = known_agents_at(&path).unwrap();
        assert_eq!(map[ID_LAB].pubkey_b64, FAKE_PUB);
        assert_eq!(map[ID_LAB].first_seen, Some(1700000000));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn known_agent_fingerprint_is_short_sha256() {
        let fp = key_fingerprint(FAKE_PUB);
        assert!(fp.starts_with("sha256:"), "{fp}");
        assert_eq!(fp.len(), "sha256:".len() + 16, "{fp}");
        // 解不开的公钥不能 panic，也不能给出假指纹
        assert_eq!(key_fingerprint("%%%"), "(undecodable key)");
        // 同一公钥指纹稳定，不同公钥不同
        assert_eq!(fp, key_fingerprint(FAKE_PUB));
        assert_ne!(fp, key_fingerprint("AAAA"));
    }

    // ---- known add：首连前预置信任锚（带外核对，关掉 TOFU 首连窗口）----

    #[test]
    fn known_agent_anchor_is_idempotent_and_never_overwrites() {
        let path = std::env::temp_dir().join(format!(
            "exvia-anchor-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let good = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let other = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);

        // 无记录 → 写入
        assert!(known_agent_anchor_at(&path, ID_LAB, &good).unwrap());
        assert_eq!(known_agents_at(&path).unwrap()[ID_LAB].pubkey_b64, good);

        // 同钥重复预置 → 幂等（CLI 提示 already anchored），记录保持不变
        assert!(!known_agent_anchor_at(&path, ID_LAB, &good).unwrap());
        assert_eq!(known_agents_at(&path).unwrap()[ID_LAB].pubkey_b64, good);

        // 不同钥 → 拒绝且不静默覆盖，提示先 known rm
        let err = known_agent_anchor_at(&path, ID_LAB, &other)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("different key") && err.contains("known rm"),
            "{err}"
        );
        assert_eq!(known_agents_at(&path).unwrap()[ID_LAB].pubkey_b64, good);

        // 旧格式台账（纯 id→公钥映射）读出后同样可幂等预置：
        // 预置值与既有 TOFU 记录相同 → 不改写
        std::fs::write(&path, format!("{{\"{ID_EDGE}\": \"{FAKE_PUB}\"}}")).unwrap();
        assert!(!known_agent_anchor_at(&path, ID_EDGE, FAKE_PUB).unwrap());
        assert_eq!(known_agents_at(&path).unwrap()[ID_EDGE].first_seen, None);

        // 写入路径保持 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn agent_pubkey_must_be_base64_of_32_bytes() {
        let good = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(normalize_agent_pubkey(&good).unwrap(), good);
        assert_eq!(normalize_agent_pubkey(&format!(" {good} ")).unwrap(), good);
        // 长度不对、非 base64、空串一律拒绝
        assert!(normalize_agent_pubkey("short").is_err());
        assert!(normalize_agent_pubkey("!!!not-base64!!!").is_err());
        assert!(normalize_agent_pubkey("").is_err());
        let wrong_len = base64::engine::general_purpose::STANDARD.encode([7u8; 31]);
        assert!(normalize_agent_pubkey(&wrong_len).is_err());
    }
}
