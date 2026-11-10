// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! exvia 协议核心。
//!
//! 分层（自下而上）：
//! - [`io`]：把 WebSocket 消息流适配成 `AsyncRead + AsyncWrite` 字节流（Text 帧旁路到控制面）
//! - [`frame`]：会话内统一帧 `[1B kind][u16 BE len][payload]`
//! - [`noise`]：会话流上的 Noise XX 端到端加密（中继不可读）
//! - [`mux`]：yamux 封装（一条连接多条会话流）
//! - [`msgs`]：控制面 JSON 消息（注册/心跳/会话管理）
//! - [`keys`]：身份密钥（ed25519 签名 + x25519 DH），落盘 0600
//! - [`tls`]：中继自签证书 + 两端指纹固定（不依赖第三方 CA）
//! - [`tree`]：目录传输的路径安全规则（拒绝 `..`、绝对路径与盘符）
//! - [`resume`]：断点续传的分片命名与续传点规则

pub mod frame;
pub mod io;
pub mod keys;
pub mod msgs;
pub mod mux;
pub mod noise;
pub mod resume;
pub mod tls;
pub mod tree;

pub use frame::{Frame, FrameKind};
pub use keys::Identity;
pub use msgs::*;

pub type Result<T> = anyhow::Result<T>;

/// 单帧载荷上限：L3 长度域为 u16。
pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;
/// 文件传输分块：恰好装进一条 Noise 记录（60000+16 ≤ 65535）。
pub const FILE_CHUNK: usize = 60_000;

/// Noise 记录的明文分片上限（密文 = 明文 + 16B tag，u16 长度域）。
pub const NOISE_CHUNK: usize = 60_000;

pub const PROTOCOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 兼容窗口的下限 minor 版本。
///
/// 0.1 是首个对外发布，已含"CLI 签发一次性票据、被控端独立验签"；更早的内部
/// 构建没有这套机制，放回窗口等于让中继重新获得伪造会话的能力，永不回退。
pub const MIN_COMPAT_MINOR: u32 = 1;

fn major_minor(v: &str) -> Option<(u32, u32)> {
    // 只接受完整的 major.minor.patch（patch 允许 `-rc1`/`+build` 后缀），
    // 残缺版本（如 "0.2"）或垃圾串一律判不兼容，避免宽松解析误放行。
    let parts: Vec<&str> = v.trim().split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse::<u32>().ok()?;
    let minor = parts[1].parse::<u32>().ok()?;
    let patch: String = parts[2].chars().take_while(char::is_ascii_digit).collect();
    if patch.is_empty() {
        return None;
    }
    patch.parse::<u32>().ok()?;
    Some((major, minor))
}

/// 三端共用的版本兼容性判断。
///
/// 窗口规则：major 必须一致；minor 相差不超过 1，但不得低于
/// [`MIN_COMPAT_MINOR`]。这样滚动升级时新旧两端可以并存在线一个版本周期，
/// 而 patch 差异始终允许（同一 minor 内不改变协议语义）。
pub fn version_compatible(peer: &str, ours: &str) -> bool {
    match (major_minor(peer), major_minor(ours)) {
        (Some((pmaj, pmin)), Some((omaj, omin))) => {
            pmaj == omaj && pmin >= MIN_COMPAT_MINOR && pmin.abs_diff(omin) <= 1
        }
        _ => false,
    }
}

/// 版本被拒时的统一报错文案：`peer_label` 为 "agent" / "cli"。
pub fn version_mismatch_hint(peer_label: &str, peer_version: &str) -> String {
    format!(
        "protocol version mismatch: {peer_label} v{peer_version} / relay v{}",
        PROTOCOL_VERSION
    )
}

/// 版本窗口内但不同版本时给出提示，供三端日志说明"正在跑跨版本组合"。
pub fn version_window_note(peer: &str, ours: &str) -> Option<String> {
    if peer == ours {
        return None;
    }
    let (Some((pmaj, pmin)), Some((omaj, omin))) = (major_minor(peer), major_minor(ours)) else {
        return None;
    };
    if pmaj == omaj && pmin >= MIN_COMPAT_MINOR && pmin.abs_diff(omin) <= 1 {
        let dir = if pmin < omin { "older" } else { "newer" };
        return Some(format!(
            "peer runs {peer} ({dir} than local {ours}); rolling upgrade window is one minor version"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_compat_matrix() {
        // 同 minor、patch 不同：始终兼容
        assert!(version_compatible("0.1.0", "0.1.3"));
        assert!(version_compatible("0.1.7", "0.1.0"));
        // 兼容窗口：minor 相差 1，且不低于下限
        assert!(version_compatible("0.2.0", "0.1.0"));
        assert!(version_compatible("0.1.0", "0.2.0"));
        // 跨 major 或超过一个 minor：拒绝
        assert!(!version_compatible("0.3.0", "0.1.0"));
        assert!(!version_compatible("1.1.0", "0.1.0"));
        // 低于下限（0.1 之前的内部构建没有会话票据）：永不进窗口
        assert!(!version_compatible("0.0.9", "0.1.0"));
        assert!(!version_compatible("garbage", "0.1.0"));
        assert!(!version_compatible("0.1", "0.1.0"));
        assert!(!version_compatible("0.1.0", "0.1"));
        assert!(version_compatible("0.1.0-rc1", "0.1.3"));
        assert!(!version_compatible("", "0.1.0"));
    }

    #[test]
    fn version_mismatch_hint_format() {
        assert_eq!(
            version_mismatch_hint("cli", "0.1.0"),
            format!("protocol version mismatch: cli v0.1.0 / relay v{PROTOCOL_VERSION}")
        );
        assert_eq!(
            version_mismatch_hint("agent", "0.1.0"),
            format!("protocol version mismatch: agent v0.1.0 / relay v{PROTOCOL_VERSION}")
        );
    }

    #[test]
    fn version_window_note_only_for_mixed_versions() {
        assert!(version_window_note("0.1.0", "0.1.0").is_none());
        assert!(version_window_note("0.1.0", "0.1.1").is_some());
        assert!(version_window_note("0.2.0", "0.1.0")
            .unwrap()
            .contains("newer"));
        assert!(version_window_note("0.0.9", "0.1.0").is_none());
    }
}
