// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI 连接处理：登录 → 列表 / 会话撮合与字节桥接。

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use exvia_proto::msgs::{CliToRelay, RelayToCli, SessionTicket};
use exvia_proto::mux::MuxStream;

use crate::axum_ws::{wire_relay_ws, RelayMux};
use crate::state::{send_json, CliConn, SharedState};

const SESSION_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// 已认证 CLI 连接的空闲上限：任何入站帧都续期（含 CliHeartbeat，无业务帧时
/// 由 CLI 每 30s 发一帧保活）。与 agent 心跳判定（agent_conn.rs 90s）同节奏；
/// 测试编译时换成短时长（见下方 cfg(test)），避免单测等真实窗口。
#[cfg(not(test))]
const CLI_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// 测试窗口：清理行为与生产一致，只把 90s 换成测试可等的时长，避免单测等真实窗口。
#[cfg(test)]
const CLI_IDLE_TIMEOUT: Duration = Duration::from_millis(700);

/// 未认证阶段的应答：绝对期限内送不出去就放弃连接。控制面通道改有界后，
/// 不读应答的慢排水客户端能把出口灌满、让控制循环卡在发送上绕过登录期限——
/// 这里把发送压在同一期限下，期限一到连同连接一起断开。返回 false 即应断开。
async fn reply_unauth(
    tx: &mpsc::Sender<String>,
    msg: &RelayToCli,
    deadline: tokio::time::Instant,
) -> bool {
    tokio::time::timeout_at(deadline, send_json(tx, msg))
        .await
        .is_ok()
}

pub async fn handle_cli(
    ws: axum::extract::ws::WebSocket,
    state: SharedState,
    guard: crate::state::UnauthConnGuard,
) {
    tracing::debug!("cli ws accepted");
    let (mux, mut incoming_rx, outgoing_tx, driver) = wire_relay_ws(ws);

    let mut cli: Option<CliConn> = None;
    // 未认证连接配额：登录成功即释放，失败与断开由 Drop 兜底。
    let mut guard = Some(guard);
    // 连接代号：名下会话组随连接断开整批下线（见 loop 后的 drop_connection_state）。
    let conn_id = state.next_conn_id();

    // 未认证连接有**绝对**期限，不是空闲计时：否则持续发垃圾帧就能一直占着连接。
    // 15s 对正常登录绰绰有余（实测公网 1.5s 内完成），又能挡住慢速占坑。
    let auth_deadline = tokio::time::Instant::now() + crate::AUTH_WINDOW;
    loop {
        // 未认证：绝对期限（覆盖登录全程）；已认证：空闲超时，任何入站帧（含心跳）即续期。
        let text = if cli.is_none() {
            match tokio::time::timeout_at(auth_deadline, incoming_rx.recv()).await {
                Ok(t) => t,
                Err(_) => {
                    // 连上却一直不登录：留痕，否则排查时只能看到 CLI 侧超时
                    tracing::warn!(
                        "cli connection closed: no login within {}s",
                        crate::AUTH_WINDOW.as_secs()
                    );
                    break;
                }
            }
        } else {
            match tokio::time::timeout(CLI_IDLE_TIMEOUT, incoming_rx.recv()).await {
                Err(_) => {
                    tracing::info!(
                        "cli connection idle for {}s, disconnecting",
                        CLI_IDLE_TIMEOUT.as_secs()
                    );
                    break;
                }
                Ok(t) => t,
            }
        };
        let Some(text) = text else { break };
        let msg: CliToRelay = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                if !reply_unauth(
                    &outgoing_tx,
                    &RelayToCli::Error {
                        reason: format!("message parse failed: {e}"),
                    },
                    auth_deadline,
                )
                .await
                {
                    break;
                }
                continue;
            }
        };
        // 未登录时只受理 Login；CliHeartbeat 静默放行（无应答帧，与协议注释一致）；
        // 其余请求统一回同一 Error（守卫自各分支上提，文案不变）。
        if cli.is_none() && !matches!(msg, CliToRelay::Login { .. } | CliToRelay::CliHeartbeat) {
            if !reply_unauth(
                &outgoing_tx,
                &RelayToCli::Error {
                    reason: "not logged in".into(),
                },
                auth_deadline,
            )
            .await
            {
                break;
            }
            continue;
        }
        match msg {
            CliToRelay::Login {
                token,
                user,
                pass,
                pubkey,
                x25519_pub,
                version,
            } => {
                tracing::debug!(
                    "cli login received user={:?} token={} pass={}",
                    user.as_deref(),
                    token.is_some(),
                    pass.is_some()
                );
                // CLI 也上报版本，不兼容直接拒绝；旧版不上报则放行，由 agent 侧验签兜底。
                if let Some(v) = version.as_deref() {
                    if !exvia_proto::version_compatible(v, exvia_proto::PROTOCOL_VERSION) {
                        state.audit_write(user.as_deref(), None, "denied/version", 0, 0, 0);
                        if !reply_unauth(
                            &outgoing_tx,
                            &RelayToCli::LoginErr {
                                reason: exvia_proto::version_mismatch_hint("cli", v),
                            },
                            auth_deadline,
                        )
                        .await
                        {
                            break;
                        }
                        // 版本被拒同样保持连接：排队后立刻断开会把拒绝原因丢掉（与登录失败同理）。
                        continue;
                    }
                }
                let authed = match token.as_deref() {
                    // 会话令牌（用户/密码登录后签发）；留下原令牌供 Logout 精确吊销
                    Some(t) if t.starts_with("exvia_sess_") => state
                        .check_session_token(t)
                        .map(|(u, r)| (u, r, Some(t.to_string()))),
                    // 管理员令牌
                    Some(t) if t.starts_with("exvia_adm_") => state
                        .check_admin_token(t)
                        .then(|| ("admin".to_string(), "admin".to_string(), None)),
                    _ => None,
                }
                .or_else(|| {
                    // 用户名/密码：验证后签发会话令牌
                    match (user.as_deref(), pass.as_deref()) {
                        (Some(u), Some(p)) => state.check_user(u, p).and_then(|role| {
                            state
                                .issue_session_token(u, &role)
                                .ok()
                                .map(|t| (u.to_string(), role, Some(t)))
                        }),
                        _ => None,
                    }
                });
                tracing::debug!("cli auth resolved ok={}", authed.is_some());
                match authed {
                    Some((username, role, session_token)) => {
                        // 登录成功即清扫失败桶，避免长期运行后残留空桶
                        state.prune_login_fails();
                        cli = Some(CliConn {
                            username,
                            role,
                            x25519_pub,
                            pubkey,
                            session_token: session_token.clone(),
                            conn_id,
                            control_tx: outgoing_tx.clone(),
                            mux: mux.clone(),
                        });
                        // 上一行刚赋的 Some，此处必为 Some；取引用只为后续日志与应答
                        let c = cli.as_ref().expect("cli just authenticated above");
                        // CLI 公钥仅作溯源，不是授权依据（授权在 agent 侧验签）。
                        tracing::info!(
                            "cli login ok user={} ed25519={}...",
                            c.username,
                            c.pubkey.chars().take(12).collect::<String>()
                        );
                        send_json(
                            &outgoing_tx,
                            &RelayToCli::LoginOk {
                                role: c.role.clone(),
                                session_token,
                            },
                        )
                        .await;
                        drop(guard.take()); // 已登录，释放未认证配额
                        tracing::debug!("cli login reply queued");
                    }
                    None => {
                        // 失败限速：按尝试用户名分桶，60s 窗口内第 n 次失败延迟 n 秒（封顶 5s）
                        let key = user
                            .clone()
                            .unwrap_or_else(|| token.clone().unwrap_or_default());
                        let fails = state.register_login_fail(&key);
                        let delay = fails.min(5) as u64;
                        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                        state.audit_write(Some(key.as_str()), None, "denied/login", 0, 0, 0);
                        if !reply_unauth(
                            &outgoing_tx,
                            &RelayToCli::LoginErr {
                                reason: "invalid credentials".into(),
                            },
                            auth_deadline,
                        )
                        .await
                        {
                            break;
                        }
                        // 不能立刻 break：控制面文本帧要等适配器下次被 poll 才真正写出，
                        // 而 break 后连接马上被拆除，队列里的拒绝原因会被丢掉——CLI 只能
                        // 干等 CONTROL_TIMEOUT 后报“超时”，把「令牌错」误诊成网络问题。
                        // 保持连接，CLI 读到 LoginErr 后自行断开；未登录阶段仍有绝对期限兜底。
                        continue;
                    }
                }
            }
            CliToRelay::ListMachines => {
                let cli_conn = cli.as_ref().expect("not-logged-in requests rejected above");
                match state.machine_list() {
                    Ok(mut machines) => {
                        // user 角色只看得到被授权的机器（admin 全量）
                        if cli_conn.role != "admin" {
                            let allowed =
                                state.user_machines(&cli_conn.username).unwrap_or_default();
                            machines.retain(|m| allowed.iter().any(|x| x == &m.machine_id));
                        }
                        send_json(&outgoing_tx, &RelayToCli::MachineList { machines }).await
                    }
                    Err(e) => {
                        send_json(
                            &outgoing_tx,
                            &RelayToCli::Error {
                                reason: e.to_string(),
                            },
                        )
                        .await;
                    }
                }
            }
            CliToRelay::CreateSession {
                machine_id,
                kind,
                params,
                sid,
                ticket,
            } => {
                let cli_conn = cli.as_ref().expect("not-logged-in requests rejected above");
                // 撮合最长 10s；spawn 出去，控制循环继续处理其它请求（支持并发建会话）。
                let st = state.clone();
                let c = Arc::new(cli_conn.clone());
                let mid = machine_id.clone();
                tokio::spawn(async move {
                    create_session(st, &c, &mid, kind, params, sid, ticket).await;
                });
            }
            CliToRelay::Logout => {
                let cli_conn = cli.as_ref().expect("not-logged-in requests rejected above");
                match &cli_conn.session_token {
                    // 精确吊销本连接的会话行
                    Some(t) => match state.revoke_session(t) {
                        Ok(true) => {
                            tracing::info!(
                                "user {} logged out, session token revoked",
                                cli_conn.username
                            );
                            send_json(&outgoing_tx, &RelayToCli::LogoutOk).await;
                        }
                        _ => {
                            send_json(
                                &outgoing_tx,
                                &RelayToCli::Error {
                                    reason: "session not found or expired".into(),
                                },
                            )
                            .await;
                        }
                    },
                    // admin 令牌登录没有会话行：本地清掉令牌即完成登出
                    None => send_json(&outgoing_tx, &RelayToCli::LogoutOk).await,
                }
            }
            CliToRelay::CloseSession { sid } => {
                let cli_conn = cli.as_ref().expect("not-logged-in requests rejected above");
                // 仅本用户发起的会话可被关闭（admin 例外）；未命中（已结束）也回 ACK，保持幂等。
                let is_admin = cli_conn.role == "admin";
                if state.close_session_owned(sid, &cli_conn.username, is_admin) {
                    tracing::info!("user {} closed session sid={sid}", cli_conn.username);
                    state.audit_write(
                        Some(&cli_conn.username),
                        None,
                        "session/closed_by_user",
                        0,
                        0,
                        0,
                    );
                }
                send_json(&outgoing_tx, &RelayToCli::SessionClosed { sid }).await;
            }
            CliToRelay::ListSessions => {
                let cli_conn = cli.as_ref().expect("not-logged-in requests rejected above");
                let view = if cli_conn.role == "admin" {
                    None
                } else {
                    Some(cli_conn.username.as_str())
                };
                send_json(
                    &outgoing_tx,
                    &RelayToCli::SessionList {
                        sessions: state.list_sessions(view),
                    },
                )
                .await;
            }
            // 保活帧：空闲计时随本帧刷新（recv 循环每帧重来），无业务、无应答。
            // CLI 侧已按 30s 节奏接线，与 agent 心跳（30s/90s）一致。
            CliToRelay::CliHeartbeat => {}
        }
    }
    // 连接断开（对端关闭/登录超时/空闲超时）：名下会话组整批下线。组取消会先
    // 唤醒各桥接任务返回，控制桥收尾连带摘除回程登记；随后拆泵、关 WS，
    // 半开连接上挂着的撮合路径（open_stream/write）随底层断开拿到 Err。
    state.drop_connection_state(conn_id);
    driver.abort();
    drop(mux);
}

/// 会话撮合失败收尾：回 SessionFailed、留审计痕、清 pending。
async fn session_fail(
    state: &SharedState,
    cli: &CliConn,
    machine_id: &str,
    kind: exvia_proto::msgs::SessionKind,
    audit_user: &str,
    sid: u64,
    reason: String,
) {
    tracing::info!("session setup failed sid={sid}: {reason}");
    // 被拒会话同样留痕（审计里拒绝事件最有价值）
    state.audit_write(
        Some(audit_user),
        Some(machine_id),
        &format!("denied/{kind:?}"),
        0,
        0,
        0,
    );
    send_json(
        &cli.control_tx,
        &exvia_proto::msgs::RelayToCli::SessionFailed { sid, reason },
    )
    .await;
    state.drop_pending(sid);
}

/// 会话撮合：开 agent 侧流 → 邀请并等接受 → 开 CLI 侧流 → 桥接。
async fn create_session(
    state: SharedState,
    cli: &Arc<CliConn>,
    machine_id: &str,
    kind: exvia_proto::msgs::SessionKind,
    // 会话参数由 CLI 经 Open 帧端到端直达 agent，中继不经手
    _params: exvia_proto::msgs::SessionParams,
    sid_hint: Option<u64>,
    ticket: Option<SessionTicket>,
) {
    use exvia_proto::msgs::RelayToCli as R;

    let audit_user = cli.username.clone();
    // sid 由 CLI 生成并写进票据签名，中继只能采用；老 CLI 不上报时回退为中继生成。
    // 撞号检查覆盖 pending / reverse / 活跃会话组：重复 CreateSession 在此被明确拒绝，
    // 不至于走到后面 register_session 的 fail-closed 才报错。
    let sid = match sid_hint {
        Some(s) => {
            if s == 0
                || state.pending_contains(s)
                || state.reverse_contains(s)
                || state.session_active(s)
            {
                return session_fail(
                    &state,
                    cli,
                    machine_id,
                    kind,
                    &audit_user,
                    s,
                    "session sid conflict or invalid".into(),
                )
                .await;
            }
            s
        }
        None => loop {
            let candidate = rand::random::<u64>();
            if candidate != 0
                && !state.pending_contains(candidate)
                && !state.reverse_contains(candidate)
                && !state.session_active(candidate)
            {
                break candidate;
            }
        },
    };

    // 先取 clone 并立刻释放锁：后续 fail 路径有 await，不能拿着 agents 锁跨 await
    let agent = state.lock_agents().get(machine_id).cloned();
    let Some(agent) = agent else {
        return session_fail(
            &state,
            cli,
            machine_id,
            kind,
            &audit_user,
            sid,
            "machine offline".into(),
        )
        .await;
    };
    // user 角色只允许访问已授权机器
    if cli.role != "admin" {
        let allowed = state
            .user_machines(&cli.username)
            .map(|m| m.iter().any(|x| x == machine_id))
            .unwrap_or(false);
        if !allowed {
            return session_fail(
                &state,
                cli,
                machine_id,
                kind,
                &audit_user,
                sid,
                format!(
                    "permission denied: user {} is not authorized for machine {machine_id}",
                    cli.username
                ),
            )
            .await;
        }
    }

    let (otx, orx) = tokio::sync::oneshot::channel();
    state.register_pending(sid, machine_id, otx);

    let agent_stream = match open_sid_stream(&agent.mux, sid).await {
        Ok(s) => s,
        Err(SidStreamError::Open(e)) => {
            return session_fail(
                &state,
                cli,
                machine_id,
                kind,
                &audit_user,
                sid,
                format!("failed to open agent stream: {e}"),
            )
            .await;
        }
        Err(SidStreamError::Write(e)) => {
            return session_fail(
                &state,
                cli,
                machine_id,
                kind,
                &audit_user,
                sid,
                format!("failed to write agent stream: {e}"),
            )
            .await;
        }
    };
    // 票据原样透传，签名真实性由 agent 独立校验。
    send_json(
        &agent.control_tx,
        &exvia_proto::msgs::RelayToAgent::SessionInvite {
            sid,
            peer_pub: cli.x25519_pub.clone(),
            peer_name: cli.username.clone(),
            ticket: ticket.clone(),
        },
    )
    .await;
    match tokio::time::timeout(SESSION_SETUP_TIMEOUT, orx).await {
        Err(_) => {
            return session_fail(
                &state,
                cli,
                machine_id,
                kind,
                &audit_user,
                sid,
                "agent timed out".into(),
            )
            .await;
        }
        Ok(Err(_)) => {
            return session_fail(
                &state,
                cli,
                machine_id,
                kind,
                &audit_user,
                sid,
                "agent disconnected".into(),
            )
            .await;
        }
        Ok(Ok(Err(reason))) => {
            return session_fail(&state, cli, machine_id, kind, &audit_user, sid, reason).await;
        }
        Ok(Ok(Ok(()))) => {}
    }
    let mut cli_stream = match cli.mux.open_stream().await {
        Ok(s) => s,
        Err(e) => {
            return session_fail(
                &state,
                cli,
                machine_id,
                kind,
                &audit_user,
                sid,
                format!("failed to open cli stream: {e}"),
            )
            .await;
        }
    };
    if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut cli_stream).await {
        return session_fail(
            &state,
            cli,
            machine_id,
            kind,
            &audit_user,
            sid,
            format!("failed to flush cli stream: {e}"),
        )
        .await;
    }
    send_json(
        &cli.control_tx,
        &R::SessionReady {
            sid,
            peer_pub: agent.x25519_pub.clone(),
        },
    )
    .await;
    tracing::info!(
        "session up sid={sid} machine={machine_id} kind={kind:?} user={}",
        cli.username
    );
    // 会话组登记必须在回程登记之前：-R 的 ReverseOpen 可能在登记间隙到达，
    // 挂靠不到组就会退化成不可取消的孤儿桥。撞上活跃 sid 在此 fail-closed。
    let Some(cancel_rx) = state.register_session(
        sid,
        cli.username.clone(),
        machine_id.to_string(),
        format!("{kind:?}"),
        cli.conn_id,
    ) else {
        return session_fail(
            &state,
            cli,
            machine_id,
            kind,
            &audit_user,
            sid,
            "session sid conflict or invalid".into(),
        )
        .await;
    };
    // -R 会话登记回程表，随控制流桥接结束摘除。
    let teardown: Box<dyn FnOnce() + Send> =
        if kind == exvia_proto::msgs::SessionKind::TcpfwdReverse {
            state.register_reverse(sid, machine_id, &cli.username, cli.mux.clone());
            let st3 = state.clone();
            Box::new(move || {
                st3.remove_reverse(sid);
                // 控制桥收尾即整组下线：会话从列表消失，剩余挂靠桥随取消广播退出
                st3.unregister_session(sid);
            })
        } else {
            let st3 = state.clone();
            Box::new(move || st3.unregister_session(sid))
        };
    spawn_bridge(
        state,
        sid,
        cli.username.clone(),
        machine_id.to_string(),
        format!("{kind:?}"),
        agent_stream,
        cli_stream,
        teardown,
        cancel_rx,
    );
}

/// 纯字节桥接（端到端 Noise 在流内，中继不可读）：双向泵 + FIN 传播 + 审计。
/// up = agent→CLI，down = CLI→agent；`cancel_rx` 是会话组的取消广播，CloseSession
/// 或组摘除（控制桥先行结束）都会触发取消臂，两个泵 future 被 drop → 流关闭。
/// `teardown` 在桥接收尾时执行：控制桥摘组（并摘 -R 回程表），回程桥还名额。
#[allow(clippy::too_many_arguments)]
fn spawn_bridge(
    state: SharedState,
    sid: u64,
    owner: String,
    audit_machine: String,
    audit_kind: String,
    agent_stream: MuxStream,
    cli_stream: MuxStream,
    teardown: impl FnOnce() + Send + 'static,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) {
    let started = std::time::Instant::now();
    let st2 = state.clone();
    tokio::spawn(async move {
        let (ar, aw) = tokio::io::split(agent_stream);
        let (cr, cw) = tokio::io::split(cli_stream);
        // up = agent → CLI，down = CLI → agent；两个方向都在结束时向对端传播 FIN。
        // 取消臂：组内广播置位或取消 sender 被 drop（控制桥自然结束）都算退出。
        let (up_b, down_b) = tokio::select! {
            pair = async { tokio::join!(pump(ar, cw), pump(cr, aw)) } => {
                (pair.0, pair.1)
            }
            _ = session_cancelled(cancel_rx) => {
                tracing::info!("session sid={sid} closed, bridge cancelled");
                (0, 0)
            }
        };
        teardown();
        st2.audit_write(
            Some(&owner),
            Some(&audit_machine),
            &audit_kind,
            up_b,
            down_b,
            started.elapsed().as_millis() as u64,
        );
        tracing::debug!("bridge done sid={sid} kind={audit_kind} up={up_b}B down={down_b}B");
    });
}

/// 会话取消臂：先查当前值再挂起等待，防错过"先置位后订阅"的窗口；
/// 取消 sender 被 drop（控制桥自然结束摘组）视为随组退出。
async fn session_cancelled(mut rx: tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// 单向泵：读到 EOF/错误即停并累计字节数，结束时向对端传播 FIN（半关闭）。
/// agent → CLI 方向不传播 FIN 会让 exec/get 这类依赖 EOF 的会话在单端关闭时挂死。
async fn pump<R, W>(mut r: R, mut w: W) -> u64
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                total += n as u64;
                if w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = w.shutdown().await;
    total
}

/// 开一条 mux 流并写 8B sid 前导（会话流配对的公共前半）：对端据前导精确配对
/// sid，消除流/邀请到达顺序竞态。open 与写前导两步错误分开返回，
/// 调用方据此保留各自的报错文案。
enum SidStreamError {
    Open(yamux::ConnectionError),
    Write(std::io::Error),
}

async fn open_sid_stream(mux: &RelayMux, sid: u64) -> Result<MuxStream, SidStreamError> {
    use tokio::io::AsyncWriteExt;
    let mut stream = mux.open_stream().await.map_err(SidStreamError::Open)?;
    stream
        .write_all(&sid.to_be_bytes())
        .await
        .map_err(SidStreamError::Write)?;
    Ok(stream)
}
/// -R 回程流对：认领名额后开 agent/CLI 两条新流（各写 8B sid 前导）再桥接。
/// sid 未登记 / 机器不符 / 超限一律忽略，agent 侧等 10s 超时兜底关闭。
pub(crate) async fn open_reverse_pair(
    state: SharedState,
    agent: Arc<crate::state::AgentConn>,
    sid: u64,
) {
    let Some((username, cli_mux)) =
        state.claim_reverse(sid, &agent.machine_id, crate::state::REVERSE_STREAM_LIMIT)
    else {
        tracing::debug!(
            "reverse forward: ignore ReverseOpen sid={sid} (unregistered/machine mismatch/over limit)"
        );
        return;
    };
    // 挂靠会话组拿取消接收端；组已摘除（CloseSession/控制桥结束）则放弃名额并忽略。
    let Some(cancel_rx) = state.attach_session_bridge(sid) else {
        tracing::debug!("reverse forward: session already gone sid={sid}");
        state.release_reverse(sid);
        return;
    };
    // agent 侧回程流（前导让 agent 精确配对 sid）
    let a_stream = match open_sid_stream(&agent.mux, sid).await {
        Ok(s) => s,
        Err(SidStreamError::Open(e)) => {
            tracing::debug!("reverse forward: agent stream open failed sid={sid}: {e}");
            state.release_reverse(sid);
            return;
        }
        Err(SidStreamError::Write(e)) => {
            tracing::debug!("reverse forward: agent preamble write failed sid={sid}: {e}");
            state.release_reverse(sid);
            return;
        }
    };
    // CLI 侧回程流（CLI 据前导匹配 sid 后做 Noise initiator）
    let c_stream = match open_sid_stream(&cli_mux, sid).await {
        Ok(s) => s,
        Err(SidStreamError::Open(e)) => {
            tracing::debug!(
                "reverse forward: cli stream open failed sid={sid}: {e} (cli may have exited)"
            );
            state.release_reverse(sid);
            return;
        }
        Err(SidStreamError::Write(e)) => {
            tracing::debug!("reverse forward: cli preamble write failed sid={sid}: {e}");
            state.release_reverse(sid);
            return;
        }
    };
    // 开流 + 前导后没有控制面消息跟随（不像 create_session 有 Invite/Ready 顺带泵出），
    // 空闲连接上排队的 SYN/前导不会自己上线，必须显式 pump_now 一次。
    agent.mux.pump_now();
    cli_mux.pump_now();
    tracing::debug!("reverse forward: stream pair ready sid={sid}");
    let st4 = state.clone();
    spawn_bridge(
        state,
        sid,
        username,
        agent.machine_id.clone(),
        format!("{:?}", exvia_proto::msgs::SessionKind::TcpfwdReverse),
        a_stream,
        c_stream,
        move || st4.release_reverse(sid),
        cancel_rx,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    use crate::state::RelayState;

    type WsClient = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// 起一个只挂 CLI WS 路由的最小 relay，返回 (地址, 管理员令牌)。
    /// handle_cli 走真实 axum 升级路径，测试的是整条入站循环。
    async fn spawn_relay() -> (String, String) {
        let st: SharedState =
            std::sync::Arc::new(RelayState::in_memory().expect("in-memory relay state"));
        let token = st
            .ensure_admin_token()
            .expect("seed admin token")
            .expect("fresh state has no admin token");
        let app = axum::Router::new()
            .route(
                "/cli",
                axum::routing::get(
                    |upgrade: axum::extract::ws::WebSocketUpgrade,
                     State(st): State<SharedState>| async move {
                        let guard = st
                            .acquire_unauth("127.0.0.1".parse().expect("literal ip"))
                            .expect("test relay has unauth capacity");
                        upgrade.on_upgrade(move |ws| handle_cli(ws, st, guard))
                    },
                ),
            )
            .with_state(st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("ws://{addr}/cli"), token)
    }

    async fn connect(url: &str) -> WsClient {
        let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        ws
    }

    async fn login(url: &str, token: &str) -> WsClient {
        let mut ws = connect(url).await;
        ws.send(Message::text(
            serde_json::json!({
                "type": "login",
                "token": token,
                "pubkey": "test-pubkey",
                "x25519_pub": "test-x25519",
            })
            .to_string(),
        ))
        .await
        .unwrap();
        let reply = next_text(&mut ws).await;
        assert!(
            reply.contains("login_ok"),
            "expected login_ok, got: {reply}"
        );
        ws
    }

    /// 控制面 JSON 走 WS Text 帧；Binary 帧是 yamux 流量（本测试不开流，
    /// 只会收到 yamux 初始 ping 之类），读到 Text 为止。
    async fn next_text(ws: &mut WsClient) -> String {
        loop {
            let msg = ws
                .next()
                .await
                .expect("connection closed before a text frame arrived")
                .expect("ws read failed");
            if let Message::Text(t) = msg {
                return t.to_string();
            }
        }
    }

    /// ListMachines 往返：连接活着且已认证才有应答。
    async fn list_machines_roundtrip(ws: &mut WsClient) {
        ws.send(Message::text(r#"{"type":"list_machines"}"#))
            .await
            .unwrap();
        let reply = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("list_machines roundtrip must answer well within the test idle window")
            .unwrap()
            .unwrap();
        let text = reply.to_text().unwrap();
        assert!(
            text.contains("machine_list") || text.contains("error"),
            "unexpected reply: {text}"
        );
    }

    /// 收到心跳即续期：心跳间隔(150ms) < 空闲窗口(700ms)，持续心跳下连接
    /// 撑过 3 倍窗口仍可用，不误杀活跃连接。
    #[tokio::test]
    async fn cli_heartbeat_renews_idle_window() {
        let (url, token) = spawn_relay().await;
        let mut ws = login(&url, &token).await;
        // 每 150ms 发一帧心跳（生产等价：30s 心跳 / 90s 窗口），撑过 3 倍窗口
        for _ in 0..16 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            ws.send(Message::text(r#"{"type":"cli_heartbeat"}"#))
                .await
                .unwrap();
        }
        list_machines_roundtrip(&mut ws).await;
    }

    /// 没有心跳的空闲连接在窗口内被断开（收紧后仍会杀真正闲置的连接）。
    #[tokio::test]
    async fn cli_idle_without_heartbeat_disconnected() {
        let (url, token) = spawn_relay().await;
        let mut ws = login(&url, &token).await;
        // 登录应答之外不应再有任何帧；窗口(700ms)过后服务端断开 → 收到 Close/None
        let next = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await
            .expect("idle connection must be closed within the test window");
        match next {
            None | Some(Ok(Message::Close(_))) | Some(Err(_)) => {}
            Some(Ok(other)) => panic!("expected close on idle connection, got: {other:?}"),
        }
    }

    /// 未登录的业务请求一律回同一个 "not logged in" Error（守卫已上提到 match 之前）。
    #[tokio::test]
    async fn unauthenticated_request_gets_not_logged_in_error() {
        let (url, _token) = spawn_relay().await;
        let mut ws = connect(&url).await;
        ws.send(Message::text(r#"{"type":"list_machines"}"#))
            .await
            .unwrap();
        let reply = next_text(&mut ws).await;
        assert!(
            reply.contains(r#""reason":"not logged in""#),
            "unexpected reply: {reply}"
        );
    }
}
