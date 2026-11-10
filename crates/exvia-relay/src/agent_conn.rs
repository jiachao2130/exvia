// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! agent 连接处理：Hello/注册 → 挑战签名 → 注册表登记 → 心跳维持。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use tokio::sync::mpsc;

use exvia_proto::msgs::{AgentToRelay, RelayToAgent};

use crate::axum_ws::RelayMux;
use crate::state::{self, send_json, AgentConn, SharedState};

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

fn version_mismatch(version: &str) -> String {
    format!(
        "{}, upgrade the agent",
        exvia_proto::version_mismatch_hint("agent", version)
    )
}

pub async fn handle_agent(
    ws: axum::extract::ws::WebSocket,
    state: SharedState,
    guard: crate::state::UnauthConnGuard,
) {
    let (mux, mut incoming_rx, outgoing_tx, driver) = crate::axum_ws::wire_relay_ws(ws);

    enum Auth {
        Start,
        Challenged {
            machine_id: String,
            nonce_raw: Vec<u8>,
            version: String,
        },
    }
    let mut auth = Auth::Start;
    let mut my_handle: Option<Arc<AgentConn>> = None;
    // 未认证连接配额：认证成功（register/challenge 通过）即释放，失败与断开
    // 由 Drop 兜底。包一层 Option 是因为释放在循环的两个分支里发生。
    let mut guard = Some(guard);

    // 未注册阶段同样有绝对期限：连上不发 Hello 或只发垃圾帧的，15s 后断开。
    // enroll 成功即已认证——一次性令牌已核销，不经过挑战状态直接在线。
    let handshake_deadline = tokio::time::Instant::now() + crate::AUTH_WINDOW;
    loop {
        // 未注册：握手窗口；已注册：心跳 90s 超时即判定离线（心跳周期 30s）
        let text = if my_handle.is_none() {
            match tokio::time::timeout_at(handshake_deadline, incoming_rx.recv()).await {
                Err(_) => {
                    tracing::warn!(
                        "agent handshake timed out after {}s, disconnecting",
                        crate::AUTH_WINDOW.as_secs()
                    );
                    break;
                }
                Ok(None) => break,
                Ok(Some(t)) => t,
            }
        } else {
            match tokio::time::timeout(HEARTBEAT_TIMEOUT, incoming_rx.recv()).await {
                Err(_) => {
                    tracing::warn!("agent heartbeat timed out, disconnecting");
                    break;
                }
                Ok(None) => break,
                Ok(Some(t)) => t,
            }
        };
        let msg: AgentToRelay = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("agent control message parse failed: {e}");
                break;
            }
        };
        match (msg, &mut auth) {
            // ---- 注册（enroll，一次性令牌） ----
            (
                AgentToRelay::Register {
                    token,
                    pubkey,
                    x25519_pub,
                    hostname,
                    os,
                    arch,
                    version,
                },
                Auth::Start,
            ) => {
                if !exvia_proto::version_compatible(&version, exvia_proto::PROTOCOL_VERSION) {
                    send_json(
                        &outgoing_tx,
                        &RelayToAgent::RegisterErr {
                            reason: version_mismatch(&version),
                        },
                    )
                    .await;
                    break;
                }
                let machine_id_probe = match state::machine_id_from_pubkey(&pubkey) {
                    Ok(id) => id,
                    Err(_) => {
                        send_json(
                            &outgoing_tx,
                            &RelayToAgent::RegisterErr {
                                reason: "invalid public key format".into(),
                            },
                        )
                        .await;
                        break;
                    }
                };
                let exists = state
                    .get_machine_pubkey(&machine_id_probe)
                    .ok()
                    .flatten()
                    .is_some();
                if exists {
                    // 已存在的机器身份不允许被同 ID 覆盖（否则 x25519 公钥被替换 → 全部会话可被 MITM）
                    send_json(&outgoing_tx, &RelayToAgent::RegisterErr {
                        reason: "machine identity already enrolled; to reinstall, run exvia-relay machine del on the server first".into(),
                    })
                    .await;
                    break;
                }
                match enroll(
                    &state,
                    &token,
                    &pubkey,
                    &x25519_pub,
                    &hostname,
                    &os,
                    &arch,
                    &version,
                )
                .await
                {
                    Ok(machine_id) => {
                        send_json(
                            &outgoing_tx,
                            &RelayToAgent::RegisterOk {
                                machine_id: machine_id.clone(),
                            },
                        )
                        .await;
                        my_handle = Some(
                            register_agent(
                                &state,
                                &machine_id,
                                &x25519_pub,
                                &hostname,
                                &outgoing_tx,
                                &mux,
                            )
                            .await,
                        );
                        drop(guard.take()); // 已认证，释放未认证配额
                    }
                    Err(reason) => {
                        send_json(
                            &outgoing_tx,
                            &RelayToAgent::RegisterErr {
                                reason: reason.to_string(),
                            },
                        )
                        .await;
                        break; // 注册失败一律断开（enroll 是一次性动作）
                    }
                }
            }
            // ---- 重连认证：Hello → Challenge → ChallengeReply ----
            (
                AgentToRelay::Hello {
                    machine_id,
                    version,
                },
                Auth::Start,
            ) => {
                let nonce_raw = {
                    use rand::RngCore;
                    let mut n = vec![0u8; 16];
                    rand::thread_rng().fill_bytes(&mut n);
                    n
                };
                send_json(
                    &outgoing_tx,
                    &RelayToAgent::Challenge {
                        nonce: base64::engine::general_purpose::STANDARD.encode(&nonce_raw),
                    },
                )
                .await;
                auth = Auth::Challenged {
                    machine_id,
                    nonce_raw,
                    version,
                };
            }
            (
                AgentToRelay::ChallengeReply { sig },
                Auth::Challenged {
                    machine_id,
                    nonce_raw,
                    version,
                },
            ) => {
                let machine_id = machine_id.clone();
                let nonce_raw = nonce_raw.clone();
                let version = version.clone();
                let pubkey = match state.get_machine_pubkey(&machine_id) {
                    Ok(Some(p)) => p,
                    _ => {
                        tracing::warn!("challenge verify failed: unknown machine {machine_id}");
                        break;
                    }
                };
                match exvia_proto::Identity::verify_b64(&pubkey, &nonce_raw, &sig) {
                    Ok(()) => {
                        if let Some(mut m) = state.get_machine_full(&machine_id).ok().flatten() {
                            // 版本协商：以 Hello 上报的实时版本为准（升级后重连即自愈），并回写 DB
                            m.version = version.clone();
                            if !exvia_proto::version_compatible(
                                &version,
                                exvia_proto::PROTOCOL_VERSION,
                            ) {
                                send_json(
                                    &outgoing_tx,
                                    &RelayToAgent::Kick {
                                        code: Some(exvia_proto::msgs::KickCode::Version),
                                        reason: version_mismatch(&version),
                                    },
                                )
                                .await;
                                tracing::warn!(
                                    "machine {machine_id}: {}",
                                    version_mismatch(&version)
                                );
                                // 留一拍让 Kick 帧刷出去再断开，否则 agent 只看到连接关闭、收不到升级提示。
                                tokio::time::sleep(Duration::from_millis(200)).await;
                                break;
                            }
                            state.update_machine_version(&machine_id, &version);
                            if let Some(note) = exvia_proto::version_window_note(
                                &version,
                                exvia_proto::PROTOCOL_VERSION,
                            ) {
                                tracing::info!("machine {machine_id}: {note}");
                            }
                            my_handle = Some(
                                register_agent(
                                    &state,
                                    &machine_id,
                                    &m.x25519_pub,
                                    &m.hostname,
                                    &outgoing_tx,
                                    &mux,
                                )
                                .await,
                            );
                            drop(guard.take()); // 已认证，释放未认证配额
                        } else {
                            break;
                        }
                    }
                    Err(_) => {
                        tracing::warn!("challenge verify failed: {machine_id}");
                        break;
                    }
                }
            }
            // ---- 在线后 ----
            (AgentToRelay::Heartbeat { .. }, _) => {
                if let Some(h) = &my_handle {
                    h.last_seen.store(state::now_secs(), Ordering::Relaxed);
                    state.touch_machine(&h.machine_id);
                }
            }
            (AgentToRelay::SessionAccept { sid }, _) => {
                // 认证守卫 + 机器绑定：仅本机应答本机的会话邀请
                if let Some(h) = &my_handle {
                    state.resolve_pending(sid, &h.machine_id, Ok(()));
                }
            }
            (AgentToRelay::SessionReject { sid, reason }, _) => {
                if let Some(h) = &my_handle {
                    state.resolve_pending(sid, &h.machine_id, Err(reason));
                }
            }
            // -R 回程流请求：spawn 处理（开流/拨接可能耗时），控制循环不被阻塞
            (AgentToRelay::ReverseOpen { sid }, _) => {
                if let Some(h) = my_handle.clone() {
                    let st2 = state.clone();
                    tokio::spawn(crate::cli_conn::open_reverse_pair(st2, h, sid));
                }
            }
            (AgentToRelay::Hello { .. }, Auth::Challenged { .. }) => {
                tracing::debug!("duplicate Hello");
            }
            (AgentToRelay::ChallengeReply { .. }, Auth::Start)
            | (AgentToRelay::Register { .. }, _) => {
                tracing::debug!("unexpected auth message order");
            }
        }
    }

    // 退出清理：仅当注册表里仍是本连接时移除；并显式断开 WS（让 agent 走重连）
    if let Some(h) = my_handle {
        let mut agents = state.lock_agents();
        if agents
            .get(&h.machine_id)
            .map(|cur| Arc::ptr_eq(cur, &h))
            .unwrap_or(false)
        {
            agents.remove(&h.machine_id);
            tracing::info!("machine offline: {} ({})", h.hostname, h.machine_id);
        }
    }
    driver.abort();
    drop(mux); // 关闭底层 WS，agent 侧立即感知并重连
}

#[allow(clippy::too_many_arguments)]
async fn enroll(
    state: &SharedState,
    token: &str,
    pubkey: &str,
    x25519_pub: &str,
    hostname: &str,
    os: &str,
    arch: &str,
    version: &str,
) -> anyhow::Result<String> {
    let machine_id = state::machine_id_from_pubkey(pubkey)?;
    if !state.use_register_token(token)? {
        anyhow::bail!("enrollment token invalid or already used");
    }
    state.upsert_machine(&machine_id, pubkey, x25519_pub, hostname, os, arch, version)?;
    tracing::info!("new machine enrolled: {hostname} ({machine_id})");
    Ok(machine_id)
}

async fn register_agent(
    state: &SharedState,
    machine_id: &str,
    x25519_pub: &str,
    hostname: &str,
    outgoing_tx: &mpsc::Sender<String>,
    mux: &RelayMux,
) -> Arc<AgentConn> {
    let handle = Arc::new(AgentConn {
        machine_id: machine_id.to_string(),
        hostname: hostname.to_string(),
        x25519_pub: x25519_pub.to_string(),
        control_tx: outgoing_tx.clone(),
        mux: mux.clone(),
        last_seen: Arc::new(AtomicU64::new(state::now_secs())),
    });
    // 先落注册表并释放锁，再向被顶掉的旧连接发 Kick（有界通道 send 会 await，
    // 不能拿着 agents 锁等背压）
    let old = {
        let mut agents = state.lock_agents();
        agents.insert(machine_id.to_string(), handle.clone())
    };
    if let Some(old) = old {
        send_json(
            &old.control_tx,
            &RelayToAgent::Kick {
                code: Some(exvia_proto::msgs::KickCode::Takeover),
                reason: "new connection from the same machine took over".into(),
            },
        )
        .await;
        tracing::warn!("machine reconnected, evicting old connection: {machine_id}");
    }
    tracing::info!("machine online: {hostname} ({machine_id})");
    handle
}
