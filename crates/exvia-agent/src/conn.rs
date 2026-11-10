// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! WSS 出站连接（证书指纹固定）与服务器地址处理。

use std::sync::Arc;
use std::time::Duration;

use exvia_proto::tls;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// 规范化为 wss scheme + 前缀/agent 路径。
pub fn agent_url(server: &str, ws_prefix: &str) -> anyhow::Result<String> {
    let base = server
        .trim_end_matches('/')
        .trim_start_matches("wss://")
        .trim_start_matches("ws://");
    if server.starts_with("ws://") {
        anyhow::bail!("plaintext ws:// is not allowed, use wss://");
    }
    let prefix = ws_prefix.trim_end_matches('/');
    if prefix.is_empty() || !prefix.starts_with('/') || prefix.contains("..") {
        anyhow::bail!("invalid ws path prefix: {ws_prefix}");
    }
    Ok(format!("wss://{base}{prefix}/agent"))
}

pub async fn connect(
    server: &str,
    fingerprint: &str,
    ws_prefix: &str,
) -> anyhow::Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let url = agent_url(server, ws_prefix)?;
    let request = url
        .clone()
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("build request failed ({url}): {e}"))?;
    let cfg = tls::pinned_client_config(fingerprint)?;
    let (ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(Arc::new(
            (*cfg).clone(),
        ))),
    )
    .await
    .map_err(|e| anyhow::anyhow!("connection failed ({url}): {e}"))?;
    Ok(ws)
}

pub struct Backoff {
    secs: f64,
}

impl Backoff {
    pub fn new() -> Self {
        Self { secs: 1.0 }
    }

    pub async fn wait(&mut self) {
        let jitter = 0.8 + rand::Rng::gen_range(&mut rand::thread_rng(), 0.0..0.4);
        tokio::time::sleep(Duration::from_secs_f64(self.secs * jitter)).await;
        self.secs = (self.secs * 2.0).min(60.0);
    }

    pub fn current(&self) -> f64 {
        self.secs
    }

    /// 稳定连接后重置，避免长故障后每次断线都等满 60s。
    pub fn reset(&mut self) {
        self.secs = 1.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_url_respects_prefix() {
        assert_eq!(
            agent_url("wss://h:8443", "/_exvia").unwrap(),
            "wss://h:8443/_exvia/agent"
        );
        assert_eq!(
            agent_url("h:8443", "/api/v2/").unwrap(),
            "wss://h:8443/api/v2/agent"
        );
        assert!(agent_url("h:8443", "bad").is_err());
        assert!(agent_url("ws://h:8443", "/x").is_err());
    }

    #[test]
    fn backoff_reset_after_growth() {
        let mut b = Backoff::new();
        b.secs = 60.0;
        assert_eq!(b.current(), 60.0);
        b.reset();
        assert_eq!(b.current(), 1.0);
    }
}
