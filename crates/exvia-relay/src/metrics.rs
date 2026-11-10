// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 只读指标出口：独立监听，默认关闭。
//!
//! 与业务端口分开的理由：业务端口对外必须是"一个普通网页"，任何额外的公开路径
//! 都是可探测面。指标只给本机采集器看：只许绑回环，远程采集走 ssh 隧道；
//! `--metrics-token` 保留为回环之上的可选加固。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

use crate::state::{now_secs, SharedState};

#[derive(Clone)]
struct MetricsState {
    relay: SharedState,
    token: Option<Arc<String>>,
    started_at: u64,
    version: &'static str,
}

/// 指标监听地址判定：只允许回环。指标暴露机器 id 与会话数，历史上"配了令牌就放行"
/// 的口子收紧为启动即拒绝——运维应绑回环 + 走 ssh 隧道（与 operations.md 口径一致）。
fn loopback_only(addr: SocketAddr) -> anyhow::Result<()> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    anyhow::bail!(
        "--metrics-listen must bind a loopback address (got {addr}); \
         bind 127.0.0.1 and reach the endpoint over an SSH tunnel instead"
    )
}

/// 校验配置并绑定指标监听。配置非法（非回环）或端口被占都直接返回错误，
/// 由调用方在启动路径上传播——中继拒绝启动，不静默降级为无指标运行。
pub async fn bind(
    listen: String,
    token: Option<String>,
    started_at: u64,
    version: &'static str,
    relay: SharedState,
) -> anyhow::Result<(tokio::net::TcpListener, Router)> {
    let addr: SocketAddr = listen.parse()?;
    loopback_only(addr)?;
    let state = MetricsState {
        relay,
        token: token.map(Arc::new),
        started_at,
        version,
    };
    let app = Router::new()
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("metrics listening on {addr}");
    Ok((listener, app))
}

/// 已绑定监听器上的接受循环，运行期错误返回给调用方记录。
pub async fn serve(listener: tokio::net::TcpListener, app: Router) -> anyhow::Result<()> {
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics(State(st): State<MetricsState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(expected) = &st.token {
        let got = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();
        // 长度固定比较：避免按字节提前返回泄露令牌前缀
        if !ct_eq(got.as_bytes(), expected.as_bytes()) {
            return (StatusCode::UNAUTHORIZED, "unauthorized".to_string());
        }
    }
    let body = render(&st);
    (StatusCode::OK, body)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn render(st: &MetricsState) -> String {
    let online = st.relay.lock_agents().len();
    let pending = st.relay.lock_pending().len();
    let sessions = st.relay.lock_session_closers().len();
    let reverse_streams: usize = st.relay.lock_reverse().values().map(|e| e.active).sum();
    let uptime = now_secs().saturating_sub(st.started_at);

    let mut out = String::with_capacity(512);
    out.push_str("# HELP exvia_up relay is serving\n# TYPE exvia_up gauge\n");
    out.push_str("exvia_up 1\n");
    out.push_str("# HELP exvia_uptime_seconds seconds since the relay started\n# TYPE exvia_uptime_seconds counter\n");
    out.push_str(&format!("exvia_uptime_seconds {uptime}\n"));
    out.push_str("# HELP exvia_machines_online agents currently connected\n# TYPE exvia_machines_online gauge\n");
    out.push_str(&format!("exvia_machines_online {online}\n"));
    out.push_str(
        "# HELP exvia_sessions_active established sessions\n# TYPE exvia_sessions_active gauge\n",
    );
    out.push_str(&format!("exvia_sessions_active {sessions}\n"));
    out.push_str("# HELP exvia_sessions_pending session setup in flight\n# TYPE exvia_sessions_pending gauge\n");
    out.push_str(&format!("exvia_sessions_pending {pending}\n"));
    out.push_str("# HELP exvia_reverse_streams open reverse-forward streams\n# TYPE exvia_reverse_streams gauge\n");
    out.push_str(&format!("exvia_reverse_streams {reverse_streams}\n"));
    out.push_str("# HELP exvia_build_info relay build metadata\n# TYPE exvia_build_info gauge\n");
    out.push_str(&format!(
        "exvia_build_info{{version=\"{}\"}} 1\n",
        st.version
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn metrics_rejects_non_loopback_listen_even_with_token() {
        use std::net::SocketAddr;
        let parse = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(loopback_only(parse("127.0.0.1:9101")).is_ok());
        assert!(loopback_only(parse("[::1]:9101")).is_ok());
        // 非回环一律拒绝，配了令牌也不放行：报错要明确提示回环 + ssh 隧道（与 operations.md 口径一致）
        let err = loopback_only(parse("0.0.0.0:9101")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("loopback"), "{msg}");
        assert!(msg.to_lowercase().contains("ssh tunnel"), "{msg}");
        assert!(loopback_only(parse("192.168.1.10:9101")).is_err());
    }

    #[test]
    fn render_exposes_core_gauges() {
        let st = crate::state::SharedState::new(
            crate::state::RelayState::open(std::path::Path::new(":memory:")).unwrap(),
        );
        let m = MetricsState {
            relay: st,
            token: None,
            started_at: now_secs(),
            version: "0.1.0",
        };
        let body = render(&m);
        assert!(body.contains("exvia_machines_online 0"));
        assert!(body.contains("exvia_sessions_active 0"));
        assert!(body.contains("exvia_build_info{version=\"0.1.0\"} 1"));
    }
}
