// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 控制面消息（JSON，走 WebSocket Text 帧，不进复用层）。

use serde::{Deserialize, Serialize};

/// 会话类型；`Echo` 为回环通道。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Echo,
    Pty,
    Exec,
    File,
    Tcpfwd,
    /// 反向端口转发（-R，ssh -R 语义）：被管机侧监听，流量经隧道回到操作者侧。
    TcpfwdReverse,
    /// 可信 CLI 白名单维护：只有已在白名单内的 CLI 能发起，被控端本地改配置。
    Trust,
}

/// 会话参数：四类会话共用一个创建入口，故字段放宽。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionParams {
    // exec
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// `exec -t`（ssh -t 语义）：命令在远端 PTY 里以 `sh -c <command>` 运行，
    /// 由 Pty 会话携带本字段。旧版 agent 忽略未知字段（无 `deny_unknown_fields`），
    /// 会退化成开一个登录 shell——升级 agent 后才有强制 PTY 语义。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pty_command: Option<String>,
    // pty
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    // file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>, // "put" | "get"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// 目录树传输（`put -r` / `get -r`）：流上按 `TreeEntryMeta` + 数据块 + `TreeDone` 组织。
    #[serde(default, skip_serializing_if = "is_false")]
    pub recursive: bool,
    /// `get` 的远端尾分量通配符（`dir/*.log`）：`path` 携带原始远端串，agent 在其
    /// 父目录内按本字段匹配后按树清单回传。旧版 agent 忽略本字段，会对原始串做
    /// 目录扫描并以"cannot read"失败——错误可见，不会静默整目录下载。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// 断点续传（`--resume`）：复用接收端上次留下的分片。
    ///
    /// 置位后发送端必须先发 `CtrlMsg::ResumeFrom` 告知实际起点，双方据此前滚哈希；
    /// 旧版本对端不理解该字段，会因为收不到 `ResumeFrom` 而超时报错（可退化为不带 `--resume`）。
    #[serde(default, skip_serializing_if = "is_false")]
    pub resume: bool,
    /// `get --resume`：CLI 本地分片已有字节数。agent 校验后以其实际文件长度为准。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_offset: Option<u64>,
    // tcpfwd
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    // trust
    /// `list` | `add` | `rm`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_action: Option<String>,
    /// 待增删的 CLI ed25519 公钥（b64）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_key: Option<String>,
}

/// 目录树传输中的一个条目。
///
/// `rel` 是相对于传输根的 POSIX 路径，安全约束见 `crate::tree::safe_rel_path`：
/// 不含前导 `/`、不含 `..` 分量、不含 NUL。接收端必须再校验一次，不能信任发送端。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    pub rel: String,
    /// true 表示目录（无数据块），false 表示普通文件。
    pub dir: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size: u64,
    /// 权限位（0o777 掩码）；None 表示沿用接收端默认。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// 修改时间，Unix 秒；None 表示不还原。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineInfo {
    pub machine_id: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub online: bool,
    #[serde(default)]
    pub tags: String,
    /// 距最后活跃的秒数；离线时为 None（离线信息以注册记录为准）。
    pub last_seen_secs_ago: Option<u64>,
}

/// 活跃会话摘要：中继视角，供 `exvia sessions` 展示与按 sid 终止。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub sid: u64,
    pub machine_id: String,
    /// 发起者用户名；只有本人（或 admin）能终止这条会话。
    pub user: String,
    /// 会话类型名（`Pty` / `Exec` / `File` / `Tcpfwd` / `TcpfwdReverse` / `Echo`）。
    pub kind: String,
    /// 建立至今的秒数。
    pub age_secs: u64,
}

/// 票据有效期（秒）。短窗口 + 一次性 nonce 共同防重放。
pub const SESSION_TICKET_TTL: u64 = 60;

/// CLI 签发的会话票据：ed25519 签名，中继只透传，agent 用可信公钥白名单独立验签，
/// 并把 `x25519_pub` 与 Noise `remote_static` 绑定；中继被攻陷也无法伪造。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTicket {
    pub machine_id: String,
    pub sid: u64,
    /// CLI 的 x25519 静态公钥（b64）。
    pub x25519_pub: String,
    pub user: String,
    /// 过期时间（Unix 秒，绝对时间）。
    pub expires_at: u64,
    /// 一次性随机数（b64），agent 侧去重防重放。
    pub nonce: String,
    /// ed25519 签名（b64），覆盖 [`SessionTicket::signing_bytes`]。
    pub sig: String,
}

impl SessionTicket {
    /// 规范化签名字节串：长度前缀消除字段边界歧义，字段顺序即协议语义。
    /// 签名**不含** sig 本身，也不含中继可改写的任何外围字段。
    pub fn signing_bytes(&self) -> Vec<u8> {
        fn push(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        let mut out = Vec::with_capacity(192);
        push(&mut out, "exvia-session-ticket-v1");
        push(&mut out, &self.machine_id);
        out.extend_from_slice(&self.sid.to_be_bytes());
        push(&mut out, &self.x25519_pub);
        push(&mut out, &self.user);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        push(&mut out, &self.nonce);
        out
    }
}

/// Agent → Relay（WSS Text 帧 JSON）。
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentToRelay {
    /// 日常重连的第一条消息：自报身份，等中继下发挑战。
    Hello {
        machine_id: String,
        /// 实时协议版本（升级后随重连上报，中继据此协商而非查 enroll 存档）。
        version: String,
    },
    Register {
        token: String,
        pubkey: String,
        /// x25519 静态公钥（Noise DH），中继登记后供 CLI 的 SessionReady 使用。
        x25519_pub: String,
        hostname: String,
        os: String,
        arch: String,
        version: String,
    },
    ChallengeReply {
        sig: String,
    },
    Heartbeat {
        sessions: u32,
    },
    SessionAccept {
        sid: u64,
    },
    SessionReject {
        sid: u64,
        reason: String,
    },
    /// -R 回程流请求：agent 的监听器 accept 到连接后，请中继开一对新流
    /// （agent 侧、CLI 侧各一条，各带 8B sid 前导）。
    ReverseOpen {
        sid: u64,
    },
}

/// 踢出连接的机器可读原因。`unknown` 兜住未来新增取值，避免旧 agent 反序列化失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KickCode {
    /// 同一身份被新连接顶掉：应退出，避免两个实例互踢。
    Takeover,
    /// 协议版本不兼容：应退出并由运维升级，重连无意义。
    Version,
    /// 服务维护等瞬时原因：稍后重连。
    Reconnect,
    /// 未归类原因（含未来新增）：按重连处理，宁可多连一次不误退。
    Unknown,
}

/// Relay → Agent。
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayToAgent {
    Challenge {
        nonce: String,
    },
    RegisterOk {
        machine_id: String,
    },
    RegisterErr {
        reason: String,
    },
    /// 通知 agent：有 CLI 要开一条会话流（流已由中继在复用层打开）。
    SessionInvite {
        sid: u64,
        /// 对端（CLI）x25519 公钥，Noise XX 握手时的"介绍人"信息。
        peer_pub: String,
        /// 对端用户名（中继断言，仅供留痕；身份以票据验签为准）。
        peer_name: String,
        /// CLI 签发的会话票据；中继只能透传，agent 独立验签。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ticket: Option<SessionTicket>,
    },
    Kick {
        /// 机器可读踢出原因；老版中继无此字段（`None`），agent 回退到 reason 字符串判定以兼容滚动升级。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<KickCode>,
        /// 人类可读的说明，仅用于日志展示。
        reason: String,
    },
}

/// Cli → Relay。
#[allow(clippy::large_enum_variant)] // wire 枚举按消息频次实例化，装箱大变体只会拖累 serde derive 的可读性
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CliToRelay {
    Login {
        /// 管理员令牌（admin）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pass: Option<String>,
        /// CLI 自己的 ed25519 公钥。
        pubkey: String,
        /// CLI 的 x25519 静态公钥（agent 侧 TOFU 指纹固定的对象）。
        x25519_pub: String,
        /// CLI 协议版本，供三端版本协商。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    ListMachines,
    CreateSession {
        machine_id: String,
        kind: SessionKind,
        #[serde(default)]
        params: SessionParams,
        /// CLI 生成的 sid（票据已绑定，中继无权改写）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sid: Option<u64>,
        /// CLI 签发的会话票据（中继原样透传给 agent）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ticket: Option<SessionTicket>,
    },
    CloseSession {
        sid: u64,
    },
    /// 列出已建立的活跃会话（用户只看自己的，admin 看全部）。
    ListSessions,
    /// 请求吊销本连接登录所用的会话令牌（无字段：中继按连接登录身份定位会话行）。
    Logout,
    /// CLI 空闲心跳（保活）：中继对任何入站帧都刷新空闲计时，本帧专为无业务
    /// 流量时续命，无字段、无应答。additive 兼容：旧版中继解析失败会回 Error
    /// 帧但不断连。
    CliHeartbeat,
}

/// Relay → Cli。
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayToCli {
    LoginOk {
        /// "admin" 或 "user"。
        role: String,
        /// 用户/密码登录时签发的会话令牌（CLI 只存它，不存明文密码）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
    },
    LoginErr {
        reason: String,
    },
    MachineList {
        machines: Vec<MachineInfo>,
    },
    SessionReady {
        sid: u64,
        /// 对端（agent）x25519 公钥。
        peer_pub: String,
    },
    SessionFailed {
        sid: u64,
        reason: String,
    },
    /// CloseSession 的应答：中继已撤销该 sid 的桥接任务。
    SessionClosed {
        sid: u64,
    },
    /// 活跃会话列表。
    SessionList {
        sessions: Vec<SessionInfo>,
    },
    /// 会话令牌已吊销（Logout 的应答）。
    LogoutOk,
    Error {
        reason: String,
    },
}

/// 会话内控制帧（L3 CTRL 帧的 payload，JSON）。
#[allow(clippy::large_enum_variant)] // 同 CliToRelay：wire 枚举不做装箱
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "ctrl", rename_all = "snake_case")]
pub enum CtrlMsg {
    /// 会话开场：声明类型与参数（relay 只桥接，参数在端到端之内传递）。
    Open {
        kind: SessionKind,
        #[serde(default)]
        params: SessionParams,
    },
    /// PTY 窗口尺寸变更。
    Resize { cols: u16, rows: u16 },
    /// 文件传输进度确认（每 N 块一次）。
    Ack { chunk_index: u64 },
    /// 文件数据发送完毕。get 方向 agent 携带整文件 SHA-256 供接收端比对。
    Eof {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
    },
    /// get 会话的元数据（agent 发出，CLI 据此校验与显示进度）。
    FileMeta { size: u64, sha256: String },
    /// 断点续传握手（`--resume`）：发送端从 `offset` 处继续，接收端据此对齐。
    ///
    /// `offset == 0` 表示没有可用分片（或对端判断分片不可信），从头传。
    /// `prefix_sha256` 是发送端已有前缀字节的哈希：接收端拿自己的前缀比对，
    /// 对不上就说明两边的"断点"不是同一份内容（进程被硬杀可能留下半帧尾巴）。
    ResumeFrom {
        offset: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix_sha256: Option<String>,
    },
    /// -R 绑定指令：目标端点由 CLI 侧拨号，不上报被管机，避免隧道被当跳板。
    TcpfwdReverse { bind_addr: String, bind_port: u16 },
    /// 被控端当前的可信 CLI 公钥白名单（trust 会话应答）。
    TrustList { keys: Vec<String> },
    /// 目录传输：一个条目的元数据。若 `entry.dir` 为 false，其后紧跟该文件的数据块，
    /// 到下一个 `TreeEntryMeta` 或 `TreeDone` 为止；目录条目没有数据块。
    TreeEntryMeta { entry: TreeEntry },
    /// 目录传输结束：所有条目已发送完毕。
    TreeDone,
}

/// L3 Close 帧的 payload（JSON）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloseInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msgs_roundtrip() {
        let m = CliToRelay::CreateSession {
            machine_id: "abc".into(),
            kind: SessionKind::Echo,
            params: SessionParams::default(),
            sid: None,
            ticket: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: CliToRelay = serde_json::from_str(&s).unwrap();
        assert!(matches!(
            back,
            CliToRelay::CreateSession {
                kind: SessionKind::Echo,
                ..
            }
        ));

        let a = RelayToAgent::SessionInvite {
            sid: 7,
            peer_pub: "xx".into(),
            peer_name: "bob".into(),
            ticket: None,
        };
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("\"session_invite\""));
        assert!(serde_json::from_str::<RelayToAgent>(&s).is_ok());

        // 登出消息与应答的 roundtrip（snake_case tag）
        let s = serde_json::to_string(&CliToRelay::Logout).unwrap();
        assert!(s.contains("\"logout\""));
        assert!(matches!(
            serde_json::from_str::<CliToRelay>(&s).unwrap(),
            CliToRelay::Logout
        ));
        let s = serde_json::to_string(&RelayToCli::LogoutOk).unwrap();
        assert!(s.contains("\"logout_ok\""));
        assert!(matches!(
            serde_json::from_str::<RelayToCli>(&s).unwrap(),
            RelayToCli::LogoutOk
        ));
    }

    #[test]
    fn session_ticket_signing_bytes_are_canonical_and_tamper_evident() {
        use crate::Identity;
        let id = Identity::generate();
        let t = SessionTicket {
            machine_id: "abc".into(),
            sid: 42,
            x25519_pub: "pub".into(),
            user: "admin".into(),
            expires_at: 1_700_000_000,
            nonce: "n1".into(),
            sig: String::new(),
        };
        let bytes = t.signing_bytes();
        assert_eq!(bytes, t.signing_bytes());
        let mut signed = t.clone();
        signed.sig = id.sign_b64(&bytes);
        Identity::verify_b64(&id.ed25519_pub_b64(), &signed.signing_bytes(), &signed.sig).unwrap();
        // 任一被签字段被改，验签必须失败
        let mut tampered = signed.clone();
        tampered.sid = 43;
        assert!(Identity::verify_b64(
            &id.ed25519_pub_b64(),
            &tampered.signing_bytes(),
            &tampered.sig
        )
        .is_err());
        let mut tampered = signed.clone();
        tampered.x25519_pub = "attacker".into();
        assert!(Identity::verify_b64(
            &id.ed25519_pub_b64(),
            &tampered.signing_bytes(),
            &tampered.sig
        )
        .is_err());
        let mut tampered = signed;
        tampered.machine_id.push('x');
        assert!(Identity::verify_b64(
            &id.ed25519_pub_b64(),
            &tampered.signing_bytes(),
            &tampered.sig
        )
        .is_err());
        // 字段边界不可混淆（"ab"+"c" != "a"+"bc"）
        let a = SessionTicket {
            machine_id: "ab".into(),
            user: "c".into(),
            ..t.clone()
        };
        let b = SessionTicket {
            machine_id: "a".into(),
            user: "bc".into(),
            ..t
        };
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn new_msg_fields_roundtrip() {
        let m = CliToRelay::CreateSession {
            machine_id: "m".into(),
            kind: SessionKind::Echo,
            params: SessionParams::default(),
            sid: Some(9),
            ticket: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"sid\":9"));
        assert!(matches!(
            serde_json::from_str::<CliToRelay>(&s).unwrap(),
            CliToRelay::CreateSession { sid: Some(9), .. }
        ));
        // 旧版消息（无 sid/ticket/version）仍可解析
        let old = r#"{"type":"create_session","machine_id":"m","kind":"echo","params":{}}"#;
        assert!(matches!(
            serde_json::from_str::<CliToRelay>(old).unwrap(),
            CliToRelay::CreateSession {
                sid: None,
                ticket: None,
                ..
            }
        ));
        let old_login = r#"{"type":"login","pubkey":"p","x25519_pub":"x"}"#;
        assert!(serde_json::from_str::<CliToRelay>(old_login).is_ok());
    }

    #[test]
    fn kick_code_roundtrip_and_legacy_default() {
        // 兼容旧中继：中文 reason 为遗留值，保留原样，由别的 crate 判定
        let m = RelayToAgent::Kick {
            code: Some(KickCode::Version),
            reason: "协议版本不兼容".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"code\":\"version\""));
        assert!(matches!(
            serde_json::from_str::<RelayToAgent>(&s).unwrap(),
            RelayToAgent::Kick {
                code: Some(KickCode::Version),
                ..
            }
        ));
        let old = r#"{"type":"kick","reason":"同机新连接接入"}"#;
        assert!(matches!(
            serde_json::from_str::<RelayToAgent>(old).unwrap(),
            RelayToAgent::Kick { code: None, .. }
        ));
    }

    // CLI 心跳（additive）：线格式稳定，老中继收到未知 tag 只回 Error 不断连
    #[test]
    fn cli_heartbeat_roundtrip() {
        let s = serde_json::to_string(&CliToRelay::CliHeartbeat).unwrap();
        assert!(s.contains("\"cli_heartbeat\""), "{s}");
        assert!(matches!(
            serde_json::from_str::<CliToRelay>(&s).unwrap(),
            CliToRelay::CliHeartbeat
        ));
    }

    // -R 变体：additive 兼容，不升协议版本
    #[test]
    fn msgs_reverse_roundtrip() {
        // AgentToRelay::ReverseOpen
        let s = serde_json::to_string(&AgentToRelay::ReverseOpen { sid: 42 }).unwrap();
        assert!(s.contains("\"reverse_open\""));
        match serde_json::from_str::<AgentToRelay>(&s).unwrap() {
            AgentToRelay::ReverseOpen { sid } => assert_eq!(sid, 42),
            other => panic!("unexpected variant: {other:?}"),
        }
        // CtrlMsg::TcpfwdReverse
        let c = CtrlMsg::TcpfwdReverse {
            bind_addr: "127.0.0.1".into(),
            bind_port: 9000,
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains("\"tcpfwd_reverse\""));
        match serde_json::from_str::<CtrlMsg>(&s).unwrap() {
            CtrlMsg::TcpfwdReverse {
                bind_addr,
                bind_port,
            } => {
                assert_eq!((bind_addr.as_str(), bind_port), ("127.0.0.1", 9000));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
        // SessionKind::TcpfwdReverse（CreateSession 携带）
        let m = CliToRelay::CreateSession {
            machine_id: "abc".into(),
            kind: SessionKind::TcpfwdReverse,
            params: SessionParams::default(),
            sid: None,
            ticket: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"tcpfwd_reverse\""));
        match serde_json::from_str::<CliToRelay>(&s).unwrap() {
            CliToRelay::CreateSession {
                kind: SessionKind::TcpfwdReverse,
                ..
            } => {}
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn trust_messages_roundtrip() {
        let m = CliToRelay::CreateSession {
            machine_id: "abc".into(),
            kind: SessionKind::Trust,
            params: SessionParams {
                trust_action: Some("add".into()),
                trust_key: Some("KEY".into()),
                ..Default::default()
            },
            sid: Some(1),
            ticket: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"trust\""));
        assert!(s.contains("\"trust_action\":\"add\""));
        match serde_json::from_str::<CliToRelay>(&s).unwrap() {
            CliToRelay::CreateSession { kind, params, .. } => {
                assert_eq!(kind, SessionKind::Trust);
                assert_eq!(params.trust_action.as_deref(), Some("add"));
                assert_eq!(params.trust_key.as_deref(), Some("KEY"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
        // 旧版参数（无 trust 字段）仍可解析，默认 None
        let old =
            r#"{"type":"create_session","machine_id":"m","kind":"exec","params":{"cmd":"ls"}}"#;
        match serde_json::from_str::<CliToRelay>(old).unwrap() {
            CliToRelay::CreateSession { params, .. } => {
                assert!(params.trust_action.is_none());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
        let c = CtrlMsg::TrustList {
            keys: vec!["a".into()],
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains("\"trust_list\""));
        let l = RelayToCli::SessionList { sessions: vec![] };
        assert!(serde_json::to_string(&l)
            .unwrap()
            .contains("\"session_list\""));
        assert!(serde_json::to_string(&CliToRelay::ListSessions)
            .unwrap()
            .contains("\"list_sessions\""));
    }

    #[test]
    fn tree_entries_roundtrip_and_defaults_are_compact() {
        let dir = TreeEntry {
            rel: "src".into(),
            dir: true,
            size: 0,
            mode: Some(0o755),
            mtime: Some(1_700_000_000),
        };
        let file = TreeEntry {
            rel: "src/main.rs".into(),
            dir: false,
            size: 1234,
            mode: Some(0o644),
            mtime: None,
        };
        let msg = CtrlMsg::TreeEntryMeta {
            entry: file.clone(),
        };
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains("\"tree_entry_meta\""));
        assert!(s.contains("\"src/main.rs\""));
        // 目录条目的 size=0 不该出现在线上（is_zero 跳过），省字节
        let d = serde_json::to_string(&CtrlMsg::TreeEntryMeta { entry: dir.clone() }).unwrap();
        assert!(!d.contains("\"size\""), "{d}");

        match serde_json::from_str::<CtrlMsg>(&s).unwrap() {
            CtrlMsg::TreeEntryMeta { entry } => {
                assert_eq!(entry.rel, "src/main.rs");
                assert!(!entry.dir);
                assert_eq!(entry.size, 1234);
                assert_eq!(entry.mode, Some(0o644));
                assert!(entry.mtime.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(serde_json::to_string(&CtrlMsg::TreeDone)
            .unwrap()
            .contains("\"tree_done\""));
    }

    #[test]
    fn recursive_flag_is_absent_from_old_params() {
        // 老版 CLI 发的 Open 里没有 recursive 字段，必须默认 false
        let old = r#"{"ctrl":"open","kind":"file","params":{"direction":"put","path":"a"}}"#;
        match serde_json::from_str::<CtrlMsg>(old).unwrap() {
            CtrlMsg::Open { params, .. } => assert!(!params.recursive),
            other => panic!("unexpected: {other:?}"),
        }
        // 新代码也不会把 false 写到线上，保持线格式紧凑
        let p = SessionParams::default();
        assert!(!serde_json::to_string(&p).unwrap().contains("recursive"));
    }

    // exec -t 的 pty_command 与 get 通配的 pattern 都是 additive 字段：
    // 老版对端（无 deny_unknown_fields）解析时忽略未知字段，不报错
    #[test]
    fn pty_command_and_pattern_fields_are_additive() {
        // 老版对端发来的 Open（无新字段）：解析成功、新字段为 None
        let old = r#"{"ctrl":"open","kind":"pty","params":{"cols":80,"rows":24}}"#;
        match serde_json::from_str::<CtrlMsg>(old).unwrap() {
            CtrlMsg::Open { params, .. } => {
                assert!(params.pty_command.is_none());
                assert!(params.pattern.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
        // 新版发出去：字段随线格式传输并 roundtrip
        let p = SessionParams {
            pty_command: Some("echo hi".into()),
            pattern: Some("*.log".into()),
            ..Default::default()
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("pty_command"), "{s}");
        assert!(s.contains("pattern"), "{s}");
        let back: SessionParams = serde_json::from_str(&s).unwrap();
        assert_eq!(back.pty_command.as_deref(), Some("echo hi"));
        assert_eq!(back.pattern.as_deref(), Some("*.log"));
    }
}
