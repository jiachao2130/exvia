// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! exvia 中继：TLS 入口、机器登记、心跳、会话配对与密文搬运。
//! 只登记、撮合、搬字节，不理解也不可读会话内容。

// 生产代码零 unwrap 是本项目的一贯纪律（与 agent/CLI 对齐）：锁 helper 用
// unwrap_or_else + 显式退出的模式不受影响；测试代码不受此限制。
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

mod agent_conn;
mod axum_ws;
mod cli_conn;
mod metrics;
mod state;

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{extract::ConnectInfo, extract::State, http::StatusCode, Router};
use clap::{Parser, Subcommand};
use time::{Date, Month};

use exvia_proto::msgs::RelayToAgent;

use state::{RelayState, SharedState};

/// 未认证连接必须在此窗口内完成握手（CLI 的 Login / agent 的 Hello 签名）。
///
/// 绝对期限而非空闲超时：连接一旦建立就开始计时，发多少垃圾帧都不续期，
/// 否则持续发数据的连接可以无限期占着名额。正常握手在 2s 内完成，15s 留足余量。
pub(crate) const AUTH_WINDOW: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Parser)]
#[command(name = "exvia-relay", about = "exvia relay server", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// start the relay
    Serve {
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
        /// days to keep audit rows; 0 = keep forever
        #[arg(long, default_value_t = 90)]
        audit_retention_days: i64,
        /// CN/SAN for the self-signed cert
        #[arg(long, default_value = "localhost")]
        cert_name: String,
        /// validity of a newly generated self-signed cert, in days; ignored for existing certs
        #[arg(long, default_value_t = 3650)]
        cert_validity_days: u32,
        /// WebSocket path prefix (must match on all three ends)
        #[arg(long, default_value = "/_exvia")]
        ws_prefix: String,
        /// Prometheus metrics listener, e.g. 127.0.0.1:9101; loopback only (use an SSH tunnel for remote scraping)
        #[arg(long)]
        metrics_listen: Option<String>,
        /// optional bearer token for the metrics endpoint (extra hardening on loopback)
        #[arg(long)]
        metrics_token: Option<String>,
    },
    /// manage enrollment tokens
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// manage users
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// manage machine authorizations
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },
    /// show audit log
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// export audit rows as csv or json lines
    Export {
        #[arg(long, default_value = "csv", value_parser = ["csv", "jsonl"])]
        format: String,
        /// start time: unix seconds or YYYY-MM-DD (UTC)
        #[arg(long)]
        since: Option<String>,
        /// end time: unix seconds or YYYY-MM-DD (UTC)
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        machine: Option<String>,
        #[arg(long, default_value_t = 100_000)]
        limit: i64,
        /// write to this file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// show persisted state snapshot
    Status {
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
        /// output structured JSON
        #[arg(long)]
        json: bool,
    },
    /// manage machines
    Machine {
        #[command(subcommand)]
        cmd: MachineCmd,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// add a user
    Add {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "user")]
        role: String,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// list users
    List {
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// delete a user
    Del {
        #[arg(long)]
        username: String,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// set a user password
    Passwd {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// revoke a user's sessions
    Logout {
        #[arg(long)]
        username: String,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuthCmd {
    /// grant access to a machine
    Grant {
        #[arg(long)]
        username: String,
        #[arg(long)]
        machine_id: String,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// revoke access to a machine
    Revoke {
        #[arg(long)]
        username: String,
        #[arg(long)]
        machine_id: String,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// list authorizations
    List {
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum MachineCmd {
    /// tag a machine
    Tag {
        machine_id: String,
        /// comma-separated tags, e.g. lab,web
        tags: String,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// delete a machine
    Del {
        machine_id: String,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// create a one-time enrollment token
    Create {
        #[arg(long)]
        label: Option<String>,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// list enrollment tokens
    List {
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// revoke an enrollment token by id
    Revoke {
        id: i64,
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// rotate the admin token
    RotateAdmin {
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
}

async fn decoy() -> impl IntoResponse {
    Html(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>It works</title></head>\
         <body><h1>Welcome</h1><p>This site is under construction.</p></body></html>",
    )
}

// 控制面全是小 JSON，最大的合法消息离 1MB 有两个数量级（审计导出走 relay
// 本地子命令，不经 WS）。单帧不设限等于把内存交给对端，必须钉死。
const MAX_WS_MESSAGE: usize = 1 << 20;

async fn agent_ws(
    State(st): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    upgrade: axum::extract::ws::WebSocketUpgrade,
) -> impl IntoResponse {
    let Some(guard) = st.acquire_unauth(addr.ip()) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    upgrade
        .max_message_size(MAX_WS_MESSAGE)
        .max_frame_size(MAX_WS_MESSAGE)
        .on_upgrade(move |ws| agent_conn::handle_agent(ws, st, guard))
}

async fn cli_ws(
    State(st): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    upgrade: axum::extract::ws::WebSocketUpgrade,
) -> impl IntoResponse {
    let Some(guard) = st.acquire_unauth(addr.ip()) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    upgrade
        .max_message_size(MAX_WS_MESSAGE)
        .max_frame_size(MAX_WS_MESSAGE)
        .on_upgrade(move |ws| cli_conn::handle_cli(ws, st, guard))
}

fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "exvia_relay=info,warn".into()),
        )
        .init();
}

fn open_state(data_dir: &Path) -> anyhow::Result<RelayState> {
    Ok(RelayState::open(&data_dir.join("relay.db"))?)
}

/// 审计保留期换算成清理截止时间；0（或负）= 永不清理（None）。
///
/// 保留期大于"当前时间到 epoch 的秒数"时饱和到 0：没有比 epoch 更早的行可清，
/// 不能让 `now - days*86400` 回绕成一个未来时间（或 debug 下 panic）。
fn audit_cutoff(now: u64, retention_days: i64) -> Option<i64> {
    if retention_days <= 0 {
        return None;
    }
    Some(now.saturating_sub((retention_days as u64).saturating_mul(86400)) as i64)
}

#[allow(clippy::too_many_arguments)] // serve 子命令的旗标直通，参数彼此并列，包一层结构体是仪式性封装
async fn serve(
    listen: String,
    data_dir: PathBuf,
    audit_retention_days: i64,
    cert_name: String,
    cert_validity_days: u32,
    ws_prefix: String,
    metrics_listen: Option<String>,
    metrics_token: Option<String>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&data_dir)?;
    let st = state::SharedState::new(open_state(&data_dir)?);
    let started_at = state::now_secs();

    let retention = audit_retention_days.clamp(0, 36500);
    // 记到 DB，status 子命令（独立进程）才读得到；失败不阻塞启动。
    let _ = st.set_meta("audit_retention_days", &retention.to_string());

    // 日常维护：清过期审计 + WAL checkpoint（保证 db 单文件随时可拷贝）。
    {
        let st = st.clone();
        tokio::spawn(async move {
            loop {
                // retention=0 = 永不清理审计（传 None），但过期会话令牌仍要清。
                let cutoff = audit_cutoff(state::now_secs(), retention);
                let _ = st.maintenance(cutoff);
                tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
            }
        });
    }

    // 每小时快照日志（含内存注册表）。
    {
        let st = st.clone();
        let start = std::time::Instant::now();
        tokio::spawn(async move {
            let mut hour = tokio::time::interval(std::time::Duration::from_secs(3600));
            hour.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                hour.tick().await;
                let online = st.lock_agents().len();
                let pending = st.lock_pending().len();
                let mins = start.elapsed().as_secs() / 60;
                let uptime = if mins >= 60 {
                    format!("{}h{}m", mins / 60, mins % 60)
                } else {
                    format!("{mins}m")
                };
                tracing::info!("snapshot: online={online} pending={pending} uptime={uptime}");
            }
        });
    }

    // 证书与指纹。
    let cert = exvia_proto::tls::load_or_create_cert(&data_dir, &cert_name, cert_validity_days)?;
    let fingerprint = cert.fingerprint.clone();
    println!("Certificate fingerprint (SHA-256): {fingerprint}");
    println!("pin it on enroll/login with --fingerprint {fingerprint}");
    if let Some(meta) = &cert.meta {
        tracing::info!(
            "relay cert subject={} validity={}d",
            meta.subject,
            (meta.not_after - meta.not_before) / 86_400
        );
        if let Some(warning) = meta.warning(state::now_secs() as i64) {
            tracing::warn!("{warning}");
        }
    }
    let (certs, key) = (cert.certs, cert.key);

    // 指标出口：与业务端口分开监听，不增加对外可探测路径。绑定在启动路径上完成，
    // 非回环或端口被占直接拒绝启动，不静默降级为无指标运行。
    if let Some(addr) = metrics_listen {
        let (metrics_listener, metrics_app) = metrics::bind(
            addr,
            metrics_token,
            started_at,
            exvia_proto::PROTOCOL_VERSION,
            st.clone(),
        )
        .await?;
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(metrics_listener, metrics_app).await {
                tracing::error!("metrics listener failed: {e:#}");
            }
        });
    }

    // 管理员令牌（首次生成，落盘 0600 供部署者取用）。
    if let Some(token) = st.ensure_admin_token()? {
        let token_path = data_dir.join("admin-token.txt");
        exvia_proto::keys::write_private(&token_path, &token)?;
        println!("admin token (saved to {}): {token}", token_path.display());
        println!(
            "CLI login: exvia login --server wss://<host>:<port> --fingerprint {fingerprint} --token {token}"
        );
    } else if let Some(age) = st.admin_token_age_secs() {
        // 提醒而非强制：长期不换的管理员令牌等于一把永不过期的钥匙
        if age > 365 * 86_400 {
            tracing::warn!(
                "admin token is {} days old; consider: exvia-relay token rotate-admin",
                age / 86_400
            );
        }
    }

    // 优雅关闭顺序：停接新连接 → 通知 agent 重连 → 等在途会话收尾（10s 上限）→ checkpoint。
    // SIGTERM（systemd stop/restart）与 Ctrl-C 都触发；超时强制退出，靠 systemd 拉起恢复。
    let handle = axum_server::Handle::new();
    {
        let st = st.clone();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            wait_stop_signal().await;
            tracing::info!("stop signal received, shutting down gracefully");
            let reason = "service maintenance, reconnect shortly".to_string();
            // 先取出出口句柄再发 Kick：send 是 await 背压的，不能拿着 agents 锁等它
            let kicks: Vec<tokio::sync::mpsc::Sender<String>> = st
                .lock_agents()
                .values()
                .map(|a| a.control_tx.clone())
                .collect();
            for tx in &kicks {
                state::send_json(
                    tx,
                    &RelayToAgent::Kick {
                        code: Some(exvia_proto::msgs::KickCode::Reconnect),
                        reason: reason.clone(),
                    },
                )
                .await;
            }
            // 等连接任务自行清理注册表（agent 收到 Kick 会重连）；超时强制退出。
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !st.lock_agents().is_empty() && std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            st.checkpoint();
            tracing::info!("graceful shutdown complete, exiting");
            // axum-server 0.7 优雅关闭入口：停止 accept，剩余连接 10s 后强制断开。
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
        });
    }

    // WS 前缀可配置，不把 "/_exvia/agent|cli" 写死。
    let prefix = ws_prefix.trim_end_matches('/');
    if prefix.is_empty() || !prefix.starts_with('/') || prefix.contains("..") {
        anyhow::bail!("--ws-prefix must be a valid path prefix starting with /");
    }
    let agent_path = format!("{prefix}/agent");
    let cli_path = format!("{prefix}/cli");
    let app = Router::new()
        .route(&agent_path, get(agent_ws))
        .route(&cli_path, get(cli_ws))
        .fallback(decoy)
        .with_state(st);
    if prefix == "/_exvia" {
        println!(
            "using default WS path prefix /_exvia; set --ws-prefix to a custom path in production (all three ends must match)"
        );
    }

    let tls = axum_server::tls_rustls::RustlsConfig::from_config(exvia_proto::tls::server_config(
        certs, key,
    )?);
    let addr: std::net::SocketAddr = listen.parse().context("invalid listen address")?;
    println!("Listening on {addr}");

    // ConnectInfo 让处理器拿到真实对端 IP（未认证连接配额按 IP 计数）。
    // 前提是中继直连公网；若将来套了反向代理，这里看到的全是代理 IP，
    // per-IP 配额会误伤——届时需改读受信任的 X-Forwarded-For。
    axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;
    Ok(())
}

/// SIGTERM（systemd stop）或 Ctrl-C，任一先到即返回。
async fn wait_stop_signal() {
    #[cfg(unix)]
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            #[cfg(unix)]
            if let Some(s) = sigterm.as_mut() {
                s.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
            #[cfg(not(unix))]
            std::future::pending::<()>().await;
        } => {}
    }
}

fn machine_cmd(cmd: MachineCmd) -> anyhow::Result<()> {
    match cmd {
        MachineCmd::Tag {
            machine_id,
            tags,
            data_dir,
        } => {
            let st = open_state(&data_dir)?;
            if st.machine_set_tags(&machine_id, &tags)? {
                println!("{machine_id} tags = {tags}");
            } else {
                println!("{machine_id} not found");
            }
            Ok(())
        }
        MachineCmd::Del {
            machine_id,
            data_dir,
        } => {
            let st = open_state(&data_dir)?;
            if st.machine_del(&machine_id)? {
                println!(
                    "{machine_id} deleted (authorizations removed); on the agent, delete the local identity and enroll again"
                );
            } else {
                println!("{machine_id} not found");
            }
            Ok(())
        }
    }
}

fn audit_cmd(limit: i64, data_dir: PathBuf) -> anyhow::Result<()> {
    let st = open_state(&data_dir)?;
    println!(
        "{:<12} {:<12} {:<34} {:<10} {:>10} {:>10} {:>8}",
        "TIME", "USER", "MACHINE", "KIND", "UP", "DOWN", "MS"
    );
    for (ts, user, machine, kind, up, down, ms) in st.audit_list(limit)? {
        println!(
            "{:<12} {:<12} {:<34} {:<10} {:>10} {:>10} {:>8}",
            ts,
            user.unwrap_or_else(|| "-".into()),
            machine.unwrap_or_else(|| "-".into()),
            kind,
            up,
            down,
            ms
        );
    }
    Ok(())
}

/// 子命令是独立进程，只有 DB 视角，看不到 serve 进程内的在线注册表。
fn status_cmd(data_dir: PathBuf, json: bool) -> anyhow::Result<()> {
    let st = open_state(&data_dir)?;
    let s = st.stats()?;
    if json {
        // 指标出口：供采集脚本解析。
        println!(
            "{}",
            serde_json::json!({
                "machines_total": s.machines_total,
                "machines_active": s.machines_active,
                // Vec<(String,i64)> 默认序列化成数组的数组，转成对象便于采集。
                "version_dist": s.version_dist.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
                "users": s.users,
                "auth_pairs": s.auth_pairs,
                "tokens_unused": s.tokens_unused,
                "sessions_today": s.sessions_today,
                "audit_total": s.audit_total,
                "audit_retention_days": s.audit_retention_days,
                "protocol_version": exvia_proto::PROTOCOL_VERSION,
            })
        );
        return Ok(());
    }
    println!("exvia-relay status snapshot (persisted view, no in-process registry)");
    let versions = if s.version_dist.is_empty() {
        "-".to_string()
    } else {
        s.version_dist
            .iter()
            .map(|(v, n)| format!("{v}×{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "machines: {} total, {} active in the last 5m",
        s.machines_total, s.machines_active
    );
    println!("version dist: {versions}");
    println!(
        "users: {}  authorizations: {}  unused enrollment tokens: {}",
        s.users, s.auth_pairs, s.tokens_unused
    );
    println!(
        "sessions today: {}  audit rows: {}  audit retention: {}",
        s.sessions_today,
        s.audit_total,
        s.audit_retention_days
            .map(|d| format!("{d} days"))
            .unwrap_or_else(|| "not set (serve defaults to 90 days)".into())
    );
    Ok(())
}

/// 审核导出：`--since/--until` 支持 unix 秒或 `YYYY-MM-DD`（UTC）。
fn parse_time(s: &str) -> anyhow::Result<i64> {
    if let Ok(v) = s.parse::<i64>() {
        return Ok(v);
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid time {s:?}: use unix seconds or YYYY-MM-DD");
    }
    let y: i64 = parts[0].parse().context("invalid year")?;
    let m: i64 = parts[1].parse().context("invalid month")?;
    let d: i64 = parts[2].parse().context("invalid day")?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        anyhow::bail!("invalid date {s:?}");
    }
    // 日历换算交给 time：先取该月 1 号，d 的合法性沿用旧的 1..=31 宽松口径，
    // 超出月长的天数自然顺延到后续日期（与原手写 days_from_civil 一致）。
    let day_one = Date::from_calendar_date(
        i32::try_from(y).map_err(|_| anyhow::anyhow!("invalid date {s:?}"))?,
        Month::try_from(m as u8).expect("month validated above"),
        1,
    )
    .map_err(|_| anyhow::anyhow!("invalid date {s:?}"))?;
    let days = i64::from(day_one.to_julian_day() - 2_440_588) + (d - 1);
    Ok(days * 86_400)
}

#[allow(clippy::too_many_arguments)] // export 子命令的旗标直通，理由同 serve
fn export_cmd(
    format: String,
    since: Option<String>,
    until: Option<String>,
    user: Option<String>,
    machine: Option<String>,
    limit: i64,
    out: Option<PathBuf>,
    data_dir: PathBuf,
) -> anyhow::Result<()> {
    let st = open_state(&data_dir)?;
    let since_ts = since.as_deref().map(parse_time).transpose()?;
    let until_ts = until.as_deref().map(parse_time).transpose()?;
    let rows = st.audit_query(
        since_ts,
        until_ts,
        user.as_deref(),
        machine.as_deref(),
        limit.clamp(1, 10_000_000),
    )?;
    let mut body = String::with_capacity(rows.len() * 96);
    if format == "csv" {
        body.push_str("ts,iso,user,machine,kind,bytes_up,bytes_down,duration_ms\n");
        for (ts, u, m, kind, up, down, ms) in &rows {
            body.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                ts,
                iso_utc(*ts),
                csv_field(u.as_deref().unwrap_or("")),
                csv_field(m.as_deref().unwrap_or("")),
                csv_field(kind),
                up,
                down,
                ms
            ));
        }
    } else {
        for (ts, u, m, kind, up, down, ms) in &rows {
            body.push_str(
                &serde_json::json!({
                    "ts": ts,
                    "iso": iso_utc(*ts),
                    "user": u,
                    "machine": m,
                    "kind": kind,
                    "bytes_up": up,
                    "bytes_down": down,
                    "duration_ms": ms,
                })
                .to_string(),
            );
            body.push('\n');
        }
    }
    match out {
        Some(p) => {
            std::fs::write(&p, body).with_context(|| format!("cannot write {}", p.display()))?;
            println!("exported {} rows to {}", rows.len(), p.display());
        }
        None => print!("{body}"),
    }
    Ok(())
}

/// RFC3339 UTC 时间戳；只用于导出可读列。
fn iso_utc(ts: i64) -> String {
    let secs = ts.rem_euclid(86_400);
    // 儒略日换算交给 time；审计 ts 由服务端生成、必然落在 time 的可表示范围
    // （Date::MIN..=Date::MAX，±32767 年），超界理论值夹到边界日期渲染，不 panic。
    let jd = (ts.div_euclid(86_400) + 2_440_588).clamp(
        i64::from(Date::MIN.to_julian_day()),
        i64::from(Date::MAX.to_julian_day()),
    ) as i32;
    let date = Date::from_julian_day(jd).expect("jd clamped into Date's representable range");
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date.year(),
        u8::from(date.month()),
        date.day(),
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// CSV 字段转义：含逗号/引号/换行时加引号，内部引号翻倍。
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn user_cmd(cmd: UserCmd) -> anyhow::Result<()> {
    match cmd {
        UserCmd::Add {
            username,
            password,
            role,
            data_dir,
        } => {
            let st = open_state(&data_dir)?;
            st.user_add(&username, &password, &role)?;
            println!("user {username} ({role}) created");
            Ok(())
        }
        UserCmd::List { data_dir } => {
            let st = open_state(&data_dir)?;
            for (u, r) in st.user_list()? {
                println!("{u}  ({r})");
            }
            Ok(())
        }
        UserCmd::Del { username, data_dir } => {
            let st = open_state(&data_dir)?;
            if st.user_del(&username)? {
                println!("user {username} deleted (with authorizations)");
            } else {
                println!("{username} not found");
            }
            Ok(())
        }
        UserCmd::Passwd {
            username,
            password,
            data_dir,
        } => {
            let st = open_state(&data_dir)?;
            if st.user_set_password(&username, &password)? {
                println!("password updated, all sessions for this user revoked");
            } else {
                println!("{username} not found");
            }
            Ok(())
        }
        UserCmd::Logout { username, data_dir } => {
            let st = open_state(&data_dir)?;
            let n = st.revoke_user_sessions(&username)?;
            println!("{username} logged out, {n} sessions revoked");
            Ok(())
        }
    }
}

fn auth_cmd(cmd: AuthCmd) -> anyhow::Result<()> {
    match cmd {
        AuthCmd::Grant {
            username,
            machine_id,
            data_dir,
        } => {
            let st = open_state(&data_dir)?;
            st.auth_grant(&username, &machine_id)?;
            println!("{username} → {machine_id} granted");
            Ok(())
        }
        AuthCmd::Revoke {
            username,
            machine_id,
            data_dir,
        } => {
            let st = open_state(&data_dir)?;
            if st.auth_revoke(&username, &machine_id)? {
                println!("{username} → {machine_id} revoked");
            } else {
                println!("authorization not found");
            }
            Ok(())
        }
        AuthCmd::List { data_dir } => {
            let st = open_state(&data_dir)?;
            let mut s2 = st.user_machines_all();
            s2.sort();
            for (u, m) in s2 {
                println!("{u} → {m}");
            }
            Ok(())
        }
    }
}

fn token_cmd(cmd: TokenCmd) -> anyhow::Result<()> {
    match cmd {
        TokenCmd::Create { label, data_dir } => {
            let st = open_state(&data_dir)?;
            let token = st.create_token(label.as_deref())?;
            println!("{token}");
            println!("(one-time token, used by the agent on enroll, then void)");
        }
        TokenCmd::List { data_dir } => {
            let st = open_state(&data_dir)?;
            for (id, label, created, used) in st.list_tokens()? {
                println!(
                    "#{id}  {}  created={} {}",
                    label.unwrap_or_else(|| "-".into()),
                    created,
                    used.map(|u| format!("used@{u}"))
                        .unwrap_or_else(|| "unused".into())
                );
            }
        }
        TokenCmd::Revoke { id, data_dir } => {
            let st = open_state(&data_dir)?;
            if st.revoke_token(id)? {
                println!("#{id} revoked");
            } else {
                println!("#{id} not found");
            }
        }
        TokenCmd::RotateAdmin { data_dir } => {
            let st = open_state(&data_dir)?;
            let token = st.rotate_admin_token()?;
            let token_path = data_dir.join("admin-token.txt");
            exvia_proto::keys::write_private(&token_path, &token)?;
            println!("{token}");
            println!(
                "(new admin token written to {}, old token void)",
                token_path.display()
            );
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    init();
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Serve {
            listen,
            data_dir,
            audit_retention_days,
            cert_name,
            cert_validity_days,
            ws_prefix,
            metrics_listen,
            metrics_token,
        } => {
            serve(
                listen,
                data_dir,
                audit_retention_days,
                cert_name,
                cert_validity_days,
                ws_prefix,
                metrics_listen,
                metrics_token,
            )
            .await
        }
        Cmd::Token { cmd } => token_cmd(cmd),
        Cmd::User { cmd } => user_cmd(cmd),
        Cmd::Auth { cmd } => auth_cmd(cmd),
        Cmd::Audit { limit, data_dir } => audit_cmd(limit, data_dir),
        Cmd::Export {
            format,
            since,
            until,
            user,
            machine,
            limit,
            out,
            data_dir,
        } => export_cmd(format, since, until, user, machine, limit, out, data_dir),
        Cmd::Status { data_dir, json } => status_cmd(data_dir, json),
        Cmd::Machine { cmd } => machine_cmd(cmd),
    };
    if let Err(e) = r {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_time_accepts_epoch_and_iso_date() {
        assert_eq!(parse_time("0").unwrap(), 0);
        assert_eq!(parse_time("1700000000").unwrap(), 1_700_000_000);
        assert_eq!(parse_time("1970-01-01").unwrap(), 0);
        assert_eq!(parse_time("2023-11-14").unwrap(), 1_699_920_000);
        assert!(parse_time("2023-13-01").is_err());
        assert!(parse_time("2023-01-32").is_err());
        assert!(parse_time("garbage").is_err());
    }

    #[test]
    fn iso_utc_matches_known_instants() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        // 闰日：2024-02-29 00:00:00 UTC
        assert_eq!(iso_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn csv_field_quotes_only_when_needed() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn audit_cutoff_saturates_instead_of_underflowing() {
        // 正常范围：now 减去保留天数
        assert_eq!(
            audit_cutoff(1_700_000_000, 90),
            Some(1_700_000_000 - 90 * 86400)
        );
        // 0 = 永不清理；负数同样不参与换算
        assert_eq!(audit_cutoff(1_700_000_000, 0), None);
        assert_eq!(audit_cutoff(1_700_000_000, -5), None);
        // 保留期跨过 epoch：饱和到 0（= 没有更早的行可清），不 panic、不回绕成未来时间
        assert_eq!(audit_cutoff(1000, 36500), Some(0));
        // 巨大值（上限校验前的防御）也不 panic；位模式为负的输入按负数处理（永不清理）
        assert_eq!(audit_cutoff(1000, i64::MAX), Some(0));
        assert_eq!(audit_cutoff(1000, u64::MAX as i64), None);
    }
}
