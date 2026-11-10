// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI 客户端：连接、登录与会话

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rand::RngCore as _;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use x25519_dalek::StaticSecret as XStaticSecret;

use exvia_proto::frame::{read_frame, write_frame, Frame, FrameKind};
use exvia_proto::io::TungWs;
use exvia_proto::msgs::{
    CliToRelay, CloseInfo, CtrlMsg, RelayToCli, SessionKind, SessionParams, SessionTicket,
    SESSION_TICKET_TTL,
};
use exvia_proto::mux::{Mux, MuxStream, StreamQueue};

use crate::config::ClientConfig;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const INVITE_TIMEOUT: Duration = Duration::from_secs(10);
/// 等待会话流的单次出队上限：超时后回头查错拿暂存区（别的会话可能刚存入自己的流）
const STREAM_POLL: Duration = Duration::from_millis(250);
/// 已认证 CLI 连接的空闲心跳：30s 一帧 CliHeartbeat，与 agent 心跳同节奏
/// （relay 侧 90s 无入站帧即判闲）。relay 收到任何入站帧都续期，本帧无应答。
const CLI_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

// 共用一把锁，避免「查 inbox 未命中 -> 注册 waiter」之间到达的响应丢失
struct Router {
    waiters: HashMap<u64, oneshot::Sender<RelayToCli>>,
    inbox: VecDeque<RelayToCli>,
}

struct Inner {
    identity: exvia_proto::Identity,
    /// 登录用户名，写进票据签名供 agent 留痕
    user: String,
    outgoing_tx: mpsc::UnboundedSender<String>,
    streams: Arc<StreamQueue>,
    /// 握手后发现属于别的会话的流（键 = 对端静态公钥 b64）。并发对多台机器建会话
    /// 时，中继开 CLI 侧流的顺序与 SessionReady 到达顺序可能相反，先到者会从 FIFO
    /// 拿到别人的流；暂存给真正的会话认领，批量 exec/put 不再整场失败。无人认领
    /// 的残流随连接关闭一起释放（量级 ≤ 并发会话数）。
    // 简化取舍：不做暂存流的超时回收——它只在本连接内短暂存在，连接即生命周期。
    stray_streams: tokio::sync::Mutex<HashMap<String, exvia_proto::noise::NoiseStream<MuxStream>>>,
    router: tokio::sync::Mutex<Router>,
    inbox_notify: Notify,
}

#[derive(Clone)]
pub struct Connection {
    inner: Arc<Inner>,
}

fn msg_sid(m: &RelayToCli) -> Option<u64> {
    match m {
        RelayToCli::SessionReady { sid, .. }
        | RelayToCli::SessionFailed { sid, .. }
        | RelayToCli::SessionClosed { sid } => Some(*sid),
        _ => None,
    }
}

// 必须显式拒绝 ws://，否则明文连接会绕过证书指纹固定
fn cli_url(server: &str, ws_prefix: &str) -> anyhow::Result<String> {
    if server.starts_with("ws://") {
        anyhow::bail!("plaintext ws:// rejected; use wss:// to keep fingerprint pinning");
    }
    let base = server.trim_end_matches('/').trim_start_matches("wss://");
    if base.is_empty() {
        anyhow::bail!("empty relay address");
    }
    let prefix = ws_prefix.trim_end_matches('/');
    if prefix.is_empty() || !prefix.starts_with('/') || prefix.contains("..") {
        anyhow::bail!("invalid ws path prefix: {ws_prefix}");
    }
    Ok(format!("wss://{base}{prefix}/cli"))
}

pub async fn connect_and_login(
    config: &ClientConfig,
) -> anyhow::Result<(Connection, Option<String>)> {
    let url = cli_url(&config.server, &config.ws_prefix())?;
    let request = url
        .clone()
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("failed to build request ({url}): {e}"))?;
    let cfg = exvia_proto::tls::pinned_client_config(&config.fingerprint)?;
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(Arc::new(
            (*cfg).clone(),
        ))),
    )
    .await
    .map_err(|e| {
        // 前缀不匹配时中继会把它当普通页面返回 200，原始报错只说 "HTTP error: 200 OK"，
        // 对使用者毫无指向性；这里点明真正的原因。
        let hint = match &e {
            tokio_tungstenite::tungstenite::Error::Http(resp) if resp.status().as_u16() == 200 => {
                format!(
                    " (relay returned a plain page for {url}: check that --ws-prefix matches the relay)"
                )
            }
            _ => String::new(),
        };
        anyhow::anyhow!("connection failed ({url}): {e}{hint}")
    })?;

    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<String>();
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel::<String>();
    let adapter = TungWs::new(ws, incoming_tx, outgoing_rx);
    let mux = Mux::new(adapter, yamux::Mode::Server);
    let streams = Arc::new(StreamQueue::new());
    {
        let streams = streams.clone();
        // 回调是同步的、push 是 async，必须 spawn，否则流会被 drop（yamux 回 RST）
        exvia_proto::mux::spawn_inbound_driver(mux, move |s: MuxStream| {
            let streams = streams.clone();
            tokio::spawn(async move {
                streams.push(s).await;
            });
        });
    }

    let identity = exvia_proto::Identity::import_parts(&config.ed_seed_b64, &config.x25519_b64)?;
    let conn = Connection {
        inner: Arc::new(Inner {
            identity,
            user: config.user.clone().unwrap_or_else(|| "admin".to_string()),
            outgoing_tx,
            streams,
            stray_streams: tokio::sync::Mutex::new(HashMap::new()),
            router: tokio::sync::Mutex::new(Router {
                waiters: HashMap::new(),
                inbox: VecDeque::new(),
            }),
            inbox_notify: Notify::new(),
        }),
    };
    // 按 sid 把会话响应交给对应等待者，避免并发建会话时互相抢响应
    let ri = conn.inner.clone();
    tokio::spawn(async move {
        let mut rx = incoming_rx;
        while let Some(text) = rx.recv().await {
            let Ok(msg) = serde_json::from_str::<RelayToCli>(&text) else {
                tracing::debug!("failed to parse control message: {text}");
                continue;
            };
            {
                let mut r = ri.router.lock().await;
                if let Some(sid) = msg_sid(&msg) {
                    if let Some(tx) = r.waiters.remove(&sid) {
                        let _ = tx.send(msg);
                        continue;
                    }
                }
                r.inbox.push_back(msg);
            }
            ri.inbox_notify.notify_waiters();
        }
    });
    send_json(
        &conn.inner.outgoing_tx,
        &CliToRelay::Login {
            token: config.token.clone(),
            user: config.user.clone(),
            pass: config.pass.clone(),
            pubkey: conn.inner.identity.ed25519_pub_b64(),
            x25519_pub: conn.inner.identity.x25519_pub_b64(),
            version: Some(exvia_proto::PROTOCOL_VERSION.to_string()),
        },
    );
    match conn.wait_control().await? {
        RelayToCli::LoginOk {
            role: _,
            session_token,
        } => {
            // 登录成功后启动空闲心跳（仿 agent.rs：interval + MissedTickBehavior::Delay）。
            // 持 Weak 而非 Arc：Connection 全部 drop 后 upgrade 失败，ticker 自行退出，
            // 不把 outgoing_tx 悬在任务里挡住 WS 写泵的收尾。
            let hb = Arc::downgrade(&conn.inner);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(CLI_HEARTBEAT_INTERVAL);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    let Some(inner) = hb.upgrade() else { break };
                    send_json(&inner.outgoing_tx, &CliToRelay::CliHeartbeat);
                }
            });
            Ok((conn, session_token))
        }
        RelayToCli::LoginErr { reason } => anyhow::bail!("login failed: {reason}"),
        other => anyhow::bail!("unexpected message during login: {other:?}"),
    }
}

impl Connection {
    async fn wait_control(&self) -> anyhow::Result<RelayToCli> {
        let deadline = tokio::time::Instant::now() + CONTROL_TIMEOUT;
        loop {
            let notified = self.inner.inbox_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut r = self.inner.router.lock().await;
                if let Some(pos) = r.inbox.iter().position(|m| msg_sid(m).is_none()) {
                    return Ok(r.inbox.remove(pos).unwrap());
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                anyhow::bail!("timed out waiting for relay response");
            }
        }
    }

    // 查 inbox 与注册 waiter 在同一临界区，消掉「响应先到」竞态
    async fn wait_session(&self, sid: u64) -> anyhow::Result<RelayToCli> {
        let (tx, rx) = oneshot::channel();
        {
            let mut r = self.inner.router.lock().await;
            if let Some(pos) = r.inbox.iter().position(|m| msg_sid(m) == Some(sid)) {
                return Ok(r.inbox.remove(pos).unwrap());
            }
            r.waiters.insert(sid, tx);
        }
        let res = tokio::time::timeout(CONTROL_TIMEOUT, rx).await;
        // 无论成功/超时/关闭都摘掉 waiter，避免残留 sender 占内存
        self.inner.router.lock().await.waiters.remove(&sid);
        match res {
            Err(_) => anyhow::bail!("timed out waiting for session ready"),
            Ok(Err(_)) => anyhow::bail!("relay closed the connection"),
            Ok(Ok(msg)) => Ok(msg),
        }
    }

    pub async fn list_machines(&self) -> anyhow::Result<Vec<exvia_proto::msgs::MachineInfo>> {
        send_json(&self.inner.outgoing_tx, &CliToRelay::ListMachines);
        match self.wait_control().await? {
            RelayToCli::MachineList { machines } => Ok(machines),
            RelayToCli::Error { reason } => anyhow::bail!("{reason}"),
            other => anyhow::bail!("unexpected message: {other:?}"),
        }
    }

    // 主动关闭让中继撤销桥接，不等两端自然 EOF
    pub async fn close_session(&self, sid: u64) -> anyhow::Result<()> {
        send_json(&self.inner.outgoing_tx, &CliToRelay::CloseSession { sid });
        match self.wait_session(sid).await? {
            RelayToCli::SessionClosed { .. } => Ok(()),
            RelayToCli::Error { reason } => anyhow::bail!(reason),
            other => anyhow::bail!("unexpected message while closing session: {other:?}"),
        }
    }

    /// 维护被控端的可信 CLI 白名单。
    /// 授权来自票据本身：只有白名单内的 CLI 能签出通过验签的票据。
    pub async fn trust(
        &self,
        machine_id: &str,
        action: &str,
        key: Option<&str>,
    ) -> anyhow::Result<Vec<String>> {
        let params = SessionParams {
            trust_action: Some(action.to_string()),
            trust_key: key.map(str::to_string),
            ..Default::default()
        };
        let mut noise = self
            .open_session(machine_id, SessionKind::Trust, params)
            .await?;
        loop {
            let Some(frame) = read_frame(&mut noise).await? else {
                anyhow::bail!("agent closed the trust session without a result");
            };
            match frame.kind {
                FrameKind::Ctrl => {
                    if let CtrlMsg::TrustList { keys } = frame.ctrl_msg()? {
                        return Ok(keys);
                    }
                }
                FrameKind::Close => {
                    let info = frame.close_info()?;
                    anyhow::bail!(
                        "{}",
                        info.reason
                            .unwrap_or_else(|| "agent rejected the request".into())
                    );
                }
                _ => {}
            }
        }
    }

    pub async fn list_sessions(&self) -> anyhow::Result<Vec<exvia_proto::msgs::SessionInfo>> {
        send_json(&self.inner.outgoing_tx, &CliToRelay::ListSessions);
        match self.wait_control().await? {
            RelayToCli::SessionList { sessions } => Ok(sessions),
            RelayToCli::Error { reason } => anyhow::bail!("{reason}"),
            other => anyhow::bail!("unexpected message: {other:?}"),
        }
    }

    pub async fn logout(&self) -> anyhow::Result<()> {
        send_json(&self.inner.outgoing_tx, &CliToRelay::Logout);
        match self.wait_control().await? {
            RelayToCli::LogoutOk => Ok(()),
            RelayToCli::Error { reason } => anyhow::bail!("{reason}"),
            other => anyhow::bail!("unexpected message during logout: {other:?}"),
        }
    }

    async fn open_session(
        &self,
        machine_id: &str,
        kind: SessionKind,
        params: SessionParams,
    ) -> anyhow::Result<exvia_proto::noise::NoiseStream<MuxStream>> {
        self.open_session_peer(machine_id, kind, params)
            .await
            .map(|(n, _, _)| n)
    }

    // -R 反向转发需要 sid 匹配回程流前导、公钥做逐流 TOFU
    async fn open_session_peer(
        &self,
        machine_id: &str,
        kind: SessionKind,
        params: SessionParams,
    ) -> anyhow::Result<(exvia_proto::noise::NoiseStream<MuxStream>, String, u64)> {
        // CLI 自己生成 sid 并签发票据，中继只能透传，无法改写或冒充
        let sid = loop {
            let v = rand::random::<u64>();
            if v != 0 {
                break v;
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut nonce_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let mut ticket = SessionTicket {
            machine_id: machine_id.to_string(),
            sid,
            x25519_pub: self.inner.identity.x25519_pub_b64(),
            user: self.inner.user.clone(),
            expires_at: now + SESSION_TICKET_TTL,
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
            sig: String::new(),
        };
        ticket.sig = self.inner.identity.sign_b64(&ticket.signing_bytes());
        send_json(
            &self.inner.outgoing_tx,
            &CliToRelay::CreateSession {
                machine_id: machine_id.to_string(),
                kind,
                params: params.clone(),
                sid: Some(sid),
                ticket: Some(ticket),
            },
        );
        let (ready_sid, peer_pub) = match self.wait_session(sid).await? {
            RelayToCli::SessionReady { sid, peer_pub } => (sid, peer_pub),
            // 中继失败路径带精确原因，透出给用户
            RelayToCli::SessionFailed { reason, .. } => {
                anyhow::bail!("session not ready: {reason}")
            }
            RelayToCli::Error { reason } => anyhow::bail!(reason),
            other => anyhow::bail!("session not ready: unexpected message {other:?}"),
        };
        if ready_sid != sid {
            anyhow::bail!("session sid mismatch (possible relay rewrite), refusing connection");
        }
        let sid = ready_sid;
        if !crate::config::check_known_agent(machine_id, &peer_pub)? {
            anyhow::bail!(
                "agent public key differs from the recorded one (possible mitm or reinstall), refusing connection"
            );
        }
        let static_key = self.inner.identity.x25519_private();
        let expect = base64::engine::general_purpose::STANDARD.decode(&peer_pub)?;
        // 并发对多台机器建会话时，中继开 CLI 侧流的顺序与 SessionReady 的到达顺序
        // 可能相反（各台 agent 接受邀请有快有慢），先到者会从 FIFO 拿到别人的流。
        // 握手后按对端静态公钥核对：是别人的就暂存给它认领；自己的流也可能被
        // 暂存，故出队用短轮询、每轮都先查暂存区，防双方互相等待。
        let deadline = tokio::time::Instant::now() + INVITE_TIMEOUT;
        let mut noise = loop {
            if let Some(n) = self.inner.stray_streams.lock().await.remove(&peer_pub) {
                break n;
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for session stream");
            }
            let stream = match tokio::time::timeout(STREAM_POLL, self.inner.streams.pop()).await {
                Err(_) => continue, // 队列暂时空：回头先查暂存区
                Ok(s) => s,
            };
            let candidate = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                exvia_proto::noise::handshake(
                    stream,
                    exvia_proto::noise::Role::Initiator,
                    &XStaticSecret::from(static_key),
                ),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Noise handshake timed out"))??;
            // fail-closed：拿不到对端静态公钥就断开，不能跳过 TOFU 校验
            let rs = candidate.remote_static().ok_or_else(|| {
                anyhow::anyhow!("Noise did not provide the agent static key, disconnecting")
            })?;
            if rs.as_slice() == expect.as_slice() {
                break candidate;
            }
            // 别的会话的流：按它的对端公钥暂存，真正的会话会来认领
            let other = base64::engine::general_purpose::STANDARD.encode(rs.as_slice());
            self.inner
                .stray_streams
                .lock()
                .await
                .insert(other, candidate);
        };
        // 兜底核对：认领的暂存流按对端公钥入库，正常必相等；对不上即断开
        let rs = noise.remote_static().ok_or_else(|| {
            anyhow::anyhow!("Noise did not provide the agent static key, disconnecting")
        })?;
        if rs.as_slice() != expect.as_slice() {
            anyhow::bail!("Noise peer key does not match the relay intro, disconnecting");
        }
        write_frame(&mut noise, &Frame::ctrl(&CtrlMsg::Open { kind, params })?).await?;
        Ok((noise, peer_pub, sid))
    }

    pub async fn ping(&self, machine_id: &str, count: u32) -> anyhow::Result<Vec<Duration>> {
        let mut noise = self
            .open_session(machine_id, SessionKind::Echo, SessionParams::default())
            .await?;
        let mut rtts = Vec::new();
        for i in 0..count {
            let payload: Vec<u8> = (0..64).map(|b| (b + i as u8) % 251).collect();
            let frame = Frame::data(payload.clone());
            let t0 = Instant::now();
            write_frame(&mut noise, &frame).await?;
            loop {
                let Some(back) = read_frame(&mut noise).await? else {
                    anyhow::bail!("agent closed the session");
                };
                match back.kind {
                    FrameKind::Data => {
                        if back.payload == payload {
                            rtts.push(t0.elapsed());
                            break;
                        }
                        anyhow::bail!("echo payload mismatch");
                    }
                    FrameKind::Ctrl => {}
                    FrameKind::Shutdown => {}
                    FrameKind::Close => anyhow::bail!("agent rejected the session"),
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        write_frame(&mut noise, &Frame::close(&CloseInfo::default())?).await?;
        Ok(rtts)
    }

    pub async fn exec(
        &self,
        machine_id: &str,
        cmd: &[String],
        timeout_secs: Option<u64>,
    ) -> anyhow::Result<i32> {
        self.exec_impl(machine_id, cmd, timeout_secs, None).await
    }

    /// 批量 exec 用：输出按行加 `[label] ` 前缀（多目标并发时区分来源）。
    pub async fn exec_labeled(
        &self,
        machine_id: &str,
        cmd: &[String],
        timeout_secs: Option<u64>,
        label: &str,
    ) -> anyhow::Result<i32> {
        self.exec_impl(machine_id, cmd, timeout_secs, Some(label))
            .await
    }

    async fn exec_impl(
        &self,
        machine_id: &str,
        cmd: &[String],
        timeout_secs: Option<u64>,
        label: Option<&str>,
    ) -> anyhow::Result<i32> {
        let (program, argv) = cmd
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty command"))?;
        let params = SessionParams {
            cmd: Some(program.clone()),
            argv: argv.to_vec(),
            timeout_secs,
            ..Default::default()
        };
        // 拿回 sid：agent 卡死时可请中继撤销桥接，不留悬挂会话
        let (mut noise, _, sid) = self
            .open_session_peer(machine_id, SessionKind::Exec, params)
            .await?;
        let read_all = async {
            let mut stdout = std::io::stdout();
            let mut stderr = std::io::stderr();
            let mut exit_code: i32 = -1;
            // 带标签时按行缓冲加前缀；不带标签逐字节透传（单目标脚本兼容）
            let (mut out_p, mut err_p) = match label {
                Some(l) => (
                    Some(LinePrefixer::new(l, std::io::stdout())),
                    Some(LinePrefixer::new(l, std::io::stderr())),
                ),
                None => (None, None),
            };
            while let Some(frame) = read_frame(&mut noise).await? {
                match frame.kind {
                    FrameKind::Data => {
                        let Some((&mark, body)) = frame.payload.split_first() else {
                            continue;
                        };
                        use std::io::Write;
                        let wrote = if mark == 0 {
                            match out_p.as_mut() {
                                Some(p) => p.push(body),
                                None => stdout.write_all(body).and_then(|_| stdout.flush()),
                            }
                        } else {
                            match err_p.as_mut() {
                                Some(p) => p.push(body),
                                None => stderr.write_all(body).and_then(|_| stderr.flush()),
                            }
                        };
                        wrote?;
                    }
                    FrameKind::Ctrl => {}
                    FrameKind::Shutdown => {}
                    FrameKind::Close => {
                        let info = frame.close_info()?;
                        exit_code = info.code.unwrap_or(-1);
                        break;
                    }
                }
            }
            // 会话正常结束才收尾：残余的不带换行行也补上前缀输出
            if let Some(p) = out_p.as_mut() {
                p.finish()?;
            }
            if let Some(p) = err_p.as_mut() {
                p.finish()?;
            }
            Ok::<i32, anyhow::Error>(exit_code)
        };
        // CLI 侧多放宽 5s 只作链路僵死的逃生口，避免与 agent 的正常 124 超时竞态
        let mut timed_out = false;
        let result = match timeout_secs {
            Some(secs) => {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(secs.saturating_add(5)),
                    read_all,
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        timed_out = true;
                        Ok(-1)
                    }
                }
            }
            None => read_all.await,
        };
        if timed_out {
            let _ = self.close_session(sid).await;
            let secs = timeout_secs.unwrap_or_default();
            anyhow::bail!("exec timed out after {secs}s, asked relay to close session sid={sid}");
        }
        result
    }

    pub async fn shell(&self, machine_id: &str) -> anyhow::Result<i32> {
        let params = pty_base_params();
        self.run_pty(machine_id, params).await
    }

    /// `exec -t`：命令在远端 PTY 里运行（ssh -t 语义：CRLF、TERM、resize 与 shell
    /// 一致），跑的是指定命令而非登录 shell；退出码透传，`--timeout` 语义不变
    /// （agent 到点杀掉命令回 124）。
    pub async fn exec_pty(
        &self,
        machine_id: &str,
        cmd: &[String],
        timeout_secs: Option<u64>,
    ) -> anyhow::Result<i32> {
        let params = SessionParams {
            timeout_secs,
            pty_command: Some(shell_join(cmd)),
            ..pty_base_params()
        };
        self.run_pty(machine_id, params).await
    }

    /// Pty 会话共用驱动（shell 与 exec -t）：raw mode（本地 stdin 非 tty 时内部
    /// 跳过）、stdin 泵、SIGWINCH resize、输出透传、stdin EOF 半关闭传播、退出码
    /// 随 Close 透传。带 `--timeout` 时 CLI 侧再放宽 5s 作链路逃生口——agent 卡死
    /// 或对端不处理 Pty 超时（旧版 agent）时，请中继撤销桥接，不留悬挂会话。
    async fn run_pty(&self, machine_id: &str, params: SessionParams) -> anyhow::Result<i32> {
        use crate::raw::RawGuard;
        let timeout_secs = params.timeout_secs;
        // 拿回 sid：超时逃生口要请中继撤销桥接
        let (noise, _, sid) = self
            .open_session_peer(machine_id, SessionKind::Pty, params)
            .await?;

        let run = async {
            let _raw = RawGuard::enable()?; // RAII，退出即还原终端
            let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = [0u8; 4096];
                let mut stdin = std::io::stdin();
                loop {
                    match stdin.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stdin_tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
            });

            #[cfg(unix)]
            let mut sigwinch =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok();

            let mut stdout = std::io::stdout();
            let mut exit_code: i32 = -1;
            let mut stdin_open = true;
            let (mut noise_r, mut noise_w) = tokio::io::split(noise);
            let (frames_tx, mut frames_rx) = mpsc::channel::<Frame>(16);
            tokio::spawn(async move {
                while let Ok(Some(f)) = read_frame(&mut noise_r).await {
                    if frames_tx.send(f).await.is_err() {
                        break;
                    }
                }
            });
            loop {
                tokio::select! {
                    chunk = stdin_rx.recv(), if stdin_open => match chunk {
                        Some(data) => write_frame(&mut noise_w, &Frame::data(data)).await?,
                        None => {
                            // stdin EOF（管道输入或 Ctrl-D）：向远端传播输入半关闭（ssh 语义），
                            // shell 读到 EOF 自行退出；本端继续读输出直到会话结束
                            stdin_open = false;
                            let _ = write_frame(&mut noise_w, &Frame::shutdown()).await;
                        }
                    },
                    frame = frames_rx.recv() => match frame {
                        None => break,
                        Some(Frame { kind: FrameKind::Data, payload }) => {
                            use std::io::Write;
                            stdout.write_all(&payload)?;
                            stdout.flush()?;
                        }
                        Some(Frame { kind: FrameKind::Close, payload }) => {
                            let info = serde_json::from_slice::<CloseInfo>(&payload).unwrap_or_default();
                            exit_code = info.code.unwrap_or(-1);
                            break;
                        }
                        Some(Frame { kind: FrameKind::Ctrl, .. }) => {}
                        Some(Frame { kind: FrameKind::Shutdown, .. }) => {} // pty 输入不支持半关闭
                    },
                    _ = async {
                        #[cfg(unix)]
                        { if let Some(s) = sigwinch.as_mut() { let _ = s.recv().await; } else { std::future::pending::<()>().await; } }
                        #[cfg(not(unix))]
                        { std::future::pending::<()>().await; }
                    } => {
                        if let Some((c, r)) = terminal_size::terminal_size().map(|(w, h)| (w.0, h.0)) {
                            let _ = write_frame(&mut noise_w, &Frame::ctrl(&CtrlMsg::Resize { cols: c, rows: r })?).await;
                        }
                    }
                }
            }
            Ok(exit_code)
        };
        // CLI 侧多放宽 5s 只作链路僵死的逃生口，避免与 agent 的正常 124 超时竞态
        match timeout_secs {
            Some(secs) => {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(secs.saturating_add(5)),
                    run,
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = self.close_session(sid).await;
                        anyhow::bail!(
                            "session timed out after {secs}s, asked relay to close session sid={sid}"
                        );
                    }
                }
            }
            None => run.await,
        }
    }

    pub async fn put(
        &self,
        machine_id: &str,
        local: &str,
        remote: &str,
        resume: bool,
    ) -> anyhow::Result<()> {
        self.put_impl(machine_id, local, remote, resume, None).await
    }

    /// 批量 put 用：提示行带 `[label] ` 前缀（多目标并发时区分来源）；
    /// `\r` 进度行停用，避免多路输出交错成乱码。
    pub async fn put_labeled(
        &self,
        machine_id: &str,
        local: &str,
        remote: &str,
        resume: bool,
        label: &str,
    ) -> anyhow::Result<()> {
        self.put_impl(machine_id, local, remote, resume, Some(label))
            .await
    }

    async fn put_impl(
        &self,
        machine_id: &str,
        local: &str,
        remote: &str,
        resume: bool,
        label: Option<&str>,
    ) -> anyhow::Result<()> {
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
        let meta = tokio::fs::metadata(local)
            .await
            .with_context(|| format!("cannot read local file: {local}"))?;
        let size = meta.len();
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = 0o644u32;
        let mut hasher = Sha256::new();
        let mut hf = tokio::fs::File::open(local).await?;
        let mut hbuf = vec![0u8; 256 * 1024];
        loop {
            let n = hf.read(&mut hbuf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&hbuf[..n]);
        }
        let sha = hex::encode(hasher.finalize());

        let remote = resolve_put_remote(remote, local)?;

        let params = SessionParams {
            direction: Some("put".into()),
            path: Some(remote),
            size: Some(size),
            sha256: Some(sha.clone()),
            mode: Some(mode),
            resume,
            ..Default::default()
        };
        let mut noise = self
            .open_session(machine_id, SessionKind::File, params)
            .await?;

        // 续传握手：agent 先告诉我们它手上有多少可复用的字节，再开始灌数据。
        let start = if resume {
            let frame = read_frame_with_timeout(&mut noise, "resume handshake").await?;
            match frame.kind {
                FrameKind::Ctrl => match frame.ctrl_msg()? {
                    CtrlMsg::ResumeFrom { offset, .. } => {
                        if offset > size {
                            anyhow::bail!(
                                "agent asked to resume at {offset} but the file is {size} bytes"
                            );
                        }
                        offset
                    }
                    other => anyhow::bail!("agent sent {other:?} instead of a resume offset"),
                },
                FrameKind::Close => anyhow::bail!(
                    "agent rejected the transfer: {}",
                    frame.close_info()?.reason.unwrap_or_default()
                ),
                _ => anyhow::bail!("unexpected frame during resume handshake"),
            }
        } else {
            0
        };

        let mut file = tokio::fs::File::open(local).await?;
        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start)).await?;
            match label {
                Some(l) => eprintln!(
                    "[{l}] resuming upload at {start}/{size} ({}%)",
                    start * 100 / size.max(1)
                ),
                None => eprintln!(
                    "\rresuming upload at {start}/{size} ({}%)",
                    start * 100 / size.max(1)
                ),
            }
        }
        let mut buf = vec![0u8; exvia_proto::FILE_CHUNK];
        // 批量（带标签）时停用 \r 进度行：多路 \r 交错不可读
        let mut progress = TransferProgress::new("put", label.is_none().then_some(size));
        let mut sent: u64 = start;
        let mut chunk_index: u64 = 0;
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_frame(&mut noise, &Frame::data(buf[..n].to_vec())).await?;
            sent += n as u64;
            chunk_index += 1;
            if chunk_index % 16 == 0 {
                while let Some(frame) = read_frame(&mut noise).await? {
                    match frame.kind {
                        FrameKind::Ctrl => {
                            if matches!(frame.ctrl_msg()?, CtrlMsg::Ack { .. }) {
                                break;
                            }
                        }
                        FrameKind::Close => {
                            let info = frame.close_info()?;
                            anyhow::bail!(
                                "agent rejected the transfer: {}",
                                info.reason.unwrap_or_default()
                            );
                        }
                        _ => {}
                    }
                }
            }
            progress.update(sent);
        }
        write_frame(&mut noise, &Frame::ctrl(&CtrlMsg::Eof { sha256: None })?).await?;
        loop {
            let Some(frame) = read_frame(&mut noise).await? else {
                anyhow::bail!("agent closed during verification");
            };
            if frame.kind == FrameKind::Close {
                let info = frame.close_info()?;
                if info.code == Some(0) {
                    return Ok(());
                }
                anyhow::bail!(
                    "agent verification failed: {}",
                    info.reason.unwrap_or_default()
                );
            }
        }
    }

    pub async fn get(
        &self,
        machine_id: &str,
        remote: &str,
        local: &str,
        resume: bool,
    ) -> anyhow::Result<()> {
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt as _;
        // 与 scp 习惯一致：本地目的地是目录（已存在或以 / 结尾）时自动补上远端
        // 文件名。推导不出的属于用法错误，在建立会话之前拒绝——别等整份数据落进
        // 分片、最后改名时才发现存不下（目录路径没有文件名，分片会叫成 file.exvia-part）。
        let local_is_dir = tokio::fs::metadata(local)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false);
        let dest = resolve_get_dest(local, remote, local_is_dir)?;
        // 目的地父目录不存在时提前说清楚；等分片创建失败才报错，路径里还嵌着分片名
        if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
            if tokio::fs::metadata(parent).await.is_err() {
                anyhow::bail!("local directory {} does not exist", parent.display());
            }
        }
        let part = exvia_proto::resume::part_path(&dest, None);

        // 本地分片里的字节数就是候选起点；哈希要覆盖整份文件，所以前缀得重读一遍。
        let mut start = 0u64;
        let mut hasher = Sha256::new();
        if resume {
            if let Ok(md) = tokio::fs::metadata(&part).await {
                start = md.len();
            }
            if start > 0 {
                match exvia_proto::resume::hash_prefix(&part, start).await {
                    Ok((n, h)) if n == start => hasher = h,
                    _ => {
                        let _ = tokio::fs::remove_file(&part).await;
                        start = 0;
                    }
                }
            }
        }

        // 握手可能对不上：进程被硬杀会在分片尾部留下半帧，远端内容也可能变过。
        // 前者退一个分块重试（丢掉半帧、保住已传部分），后者从头来；最多重开两次。
        let mut retries = 0u32;
        let mut noise = loop {
            let params = SessionParams {
                direction: Some("get".into()),
                path: Some(remote.to_string()),
                resume,
                resume_offset: Some(start),
                ..Default::default()
            };
            let mut session = self
                .open_session(machine_id, SessionKind::File, params)
                .await?;
            if !resume {
                break session;
            }
            let frame = read_frame_with_timeout(&mut session, "resume handshake").await?;
            let (offset, remote_prefix) = match frame.kind {
                FrameKind::Ctrl => match frame.ctrl_msg()? {
                    CtrlMsg::ResumeFrom {
                        offset,
                        prefix_sha256,
                    } => (offset, prefix_sha256),
                    other => anyhow::bail!("agent sent {other:?} instead of a resume offset"),
                },
                FrameKind::Close => anyhow::bail!(
                    "agent aborted: {}",
                    frame.close_info()?.reason.unwrap_or_default()
                ),
                _ => anyhow::bail!("unexpected frame during resume handshake"),
            };
            if offset != start {
                // 远端比上次短（或分片被截断）：以 agent 的起点为准，前缀哈希重算。
                let truncated = match tokio::fs::OpenOptions::new().write(true).open(&part).await {
                    Ok(f) => {
                        let r = f.set_len(offset).await;
                        drop(f);
                        r.is_ok()
                    }
                    Err(_) => false,
                };
                match exvia_proto::resume::hash_prefix(&part, offset).await {
                    Ok((n, h)) if truncated && n == offset => {
                        start = offset;
                        hasher = h;
                    }
                    _ => {
                        let _ = tokio::fs::remove_file(&part).await;
                        start = 0;
                        hasher = Sha256::new();
                        continue;
                    }
                }
            }
            // 前缀哈希对不上 = 本地分片不是这份文件的前缀，不能拼。
            if let Some(remote_prefix) = remote_prefix {
                if hex::encode(hasher.clone().finalize()) != remote_prefix {
                    let keep = start.saturating_sub(exvia_proto::FILE_CHUNK as u64);
                    let salvaged = if keep > 0 && retries < 2 {
                        retries += 1;
                        match exvia_proto::resume::hash_prefix(&part, keep).await {
                            Ok((n, h)) if n == keep => {
                                let f = tokio::fs::OpenOptions::new()
                                    .write(true)
                                    .open(&part)
                                    .await?;
                                f.set_len(keep).await?;
                                drop(f);
                                start = keep;
                                hasher = h;
                                true
                            }
                            _ => false,
                        }
                    } else {
                        false
                    };
                    if !salvaged {
                        let _ = tokio::fs::remove_file(&part).await;
                        start = 0;
                        hasher = Sha256::new();
                    }
                    continue;
                }
            }
            if start > 0 {
                eprintln!("\rresuming download at {start} bytes");
            }
            break session;
        };

        let part_file = if start > 0 {
            let f = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&part)
                .await
                .with_context(|| format!("cannot open partial file: {}", part.display()))?;
            f.set_len(start).await?;
            f
        } else {
            tokio::fs::File::create(&part)
                .await
                .with_context(|| format!("cannot create partial file: {}", part.display()))?
        };
        let mut file = part_file;
        let mut expect_size: Option<u64> = None;
        let mut progress = TransferProgress::new("get", None);
        let mut received: u64 = start;
        let mut chunk_index: u64 = 0;
        // 校验失败与断流要区别对待：前者分片已不可信，后者才值得留给 --resume。
        let mut corrupt = false;
        let result: anyhow::Result<()> = loop {
            let Some(frame) = read_frame(&mut noise).await? else {
                break Err(anyhow::anyhow!("agent closed during transfer"));
            };
            match frame.kind {
                FrameKind::Ctrl => match frame.ctrl_msg()? {
                    CtrlMsg::FileMeta { size, .. } => {
                        expect_size = Some(size);
                        progress.observe_total(size);
                    }
                    CtrlMsg::Eof { sha256 } => {
                        // agent 侧整文件哈希不一致就中止，不落盘
                        let got = hex::encode(hasher.finalize());
                        if let Some(expect) = sha256 {
                            if got != expect {
                                corrupt = true;
                                break Err(anyhow::anyhow!(
                                    "SHA-256 mismatch: expected {expect}, got {got}"
                                ));
                            }
                        }
                        break Ok(());
                    }
                    _ => {}
                },
                FrameKind::Data => {
                    file.write_all(&frame.payload).await?;
                    hasher.update(&frame.payload);
                    received += frame.payload.len() as u64;
                    chunk_index += 1;
                    // 每 16 块回一次 ACK，agent 据此推进，兼作进度
                    if chunk_index % 16 == 0 {
                        write_frame(&mut noise, &Frame::ctrl(&CtrlMsg::Ack { chunk_index })?)
                            .await?;
                    }
                    progress.update(received);
                }
                FrameKind::Close => {
                    let info = frame.close_info()?;
                    break Err(anyhow::anyhow!(
                        "agent aborted: {}",
                        info.reason.unwrap_or_default()
                    ));
                }
                FrameKind::Shutdown => {} // 文件会话以 Eof/Close 划界
            }
        };
        match result {
            Err(e) => {
                // 先清掉进度行，别让 "partial kept" 打在进度残留的那一行上
                progress.clear();
                // 断流才留分片给 --resume：先截到最后一个完整块，避免半帧混进续传起点。
                // 校验失败说明分片本身是错的，留着只会让下一次续传再失败一遍。
                if corrupt || received == 0 {
                    let _ = file.set_len(0).await;
                    drop(file);
                    let _ = tokio::fs::remove_file(&part).await;
                } else {
                    let _ = file.set_len(received).await;
                    let _ = file.flush().await;
                    drop(file);
                    eprintln!(
                        "\npartial kept at {} ({received} bytes); rerun with --resume",
                        part.display()
                    );
                }
                Err(e)
            }
            Ok(()) => {
                file.sync_all().await?;
                drop(file);
                if let Some(sz) = expect_size {
                    if received != sz {
                        let _ = tokio::fs::remove_file(&part).await;
                        anyhow::bail!("size mismatch: expected {sz}, got {received}");
                    }
                }
                let _ = write_frame(
                    &mut noise,
                    &Frame::close(&CloseInfo {
                        code: Some(0),
                        reason: None,
                    })?,
                )
                .await;
                std::fs::rename(&part, &dest)
                    .with_context(|| format!("failed to save file: {}", dest.display()))?;
                Ok(())
            }
        }
    }

    /// 递归/多源上传。每个源是一个根（普通文件或目录），合并成一棵清单树
    /// 走一次会话（清单在加密通道内传输）。多源中同一相对路径出现两个文件
    /// （或文件撞目录）即报错；同名目录合并。返回 (文件数, 字节数, 扫描统计)。
    pub async fn put_tree(
        &self,
        machine_id: &str,
        sources: &[String],
        remote: &str,
    ) -> anyhow::Result<(u64, u64, exvia_proto::tree::ScanStats)> {
        self.put_tree_impl(machine_id, sources, remote, None).await
    }

    /// 批量 put 用：进度行带 `[label] ` 前缀（多目标并发时区分来源）。
    pub async fn put_tree_labeled(
        &self,
        machine_id: &str,
        sources: &[String],
        remote: &str,
        label: &str,
    ) -> anyhow::Result<(u64, u64, exvia_proto::tree::ScanStats)> {
        self.put_tree_impl(machine_id, sources, remote, Some(label))
            .await
    }

    async fn put_tree_impl(
        &self,
        machine_id: &str,
        sources: &[String],
        remote: &str,
        label: Option<&str>,
    ) -> anyhow::Result<(u64, u64, exvia_proto::tree::ScanStats)> {
        // ---- 收集各根的清单（遍历是同步 IO，放阻塞线程池，避免卡住 runtime）----
        let mut rooted: Vec<(exvia_proto::msgs::TreeEntry, std::path::PathBuf)> = Vec::new();
        let mut stats = exvia_proto::tree::ScanStats::default();
        for src in sources {
            let path = std::path::PathBuf::from(src);
            let md = std::fs::symlink_metadata(&path)
                .with_context(|| format!("cannot read local path: {src}"))?;
            if md.file_type().is_symlink() {
                anyhow::bail!("symlinks are not followed: {src}");
            }
            if md.is_dir() {
                let (entries, st) = tokio::task::spawn_blocking({
                    let path = path.clone();
                    move || exvia_proto::tree::collect_tree(&path)
                })
                .await
                .context("scanner task panicked")??;
                stats.symlinks += st.symlinks;
                stats.special += st.special;
                stats.unreadable += st.unreadable;
                for entry in entries {
                    rooted.push((entry, path.clone()));
                }
            } else {
                // 单文件根：清单顶层占一个条目（rel = 文件名）；根取父目录，
                // 发送循环按 root.join(rel) 打开文件
                let name = path
                    .file_name()
                    .with_context(|| format!("source has no file name: {src}"))?;
                let root = path
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                rooted.push((
                    exvia_proto::msgs::TreeEntry {
                        rel: name.to_string_lossy().into_owned(),
                        dir: false,
                        size: md.len(),
                        mode: exvia_proto::tree::mode_of(&md),
                        mtime: exvia_proto::tree::mtime_of(&md),
                    },
                    root,
                ));
            }
        }

        // ---- 多源合并：同名文件冲突即报错，同名目录合并（子路径各自归属自己的根）----
        let mut merged: Vec<(exvia_proto::msgs::TreeEntry, std::path::PathBuf)> = Vec::new();
        let mut kinds: std::collections::BTreeMap<String, bool> = Default::default();
        for (entry, root) in rooted {
            match kinds.get(&entry.rel) {
                Some(true) if entry.dir => continue, // 目录条目合并
                Some(_) => anyhow::bail!(
                    "multiple sources provide '{}'; rename or drop one of them",
                    entry.rel
                ),
                None => {
                    kinds.insert(entry.rel.clone(), entry.dir);
                    merged.push((entry, root));
                }
            }
        }

        let params = SessionParams {
            direction: Some("put".into()),
            path: Some(remote.to_string()),
            recursive: true,
            ..Default::default()
        };
        let mut noise = self
            .open_session(machine_id, SessionKind::File, params)
            .await?;

        let (files, bytes) =
            exvia_proto::tree::send_tree_frames(&mut noise, &merged, |files, bytes| {
                // 每 16MiB 报一次；批量（带标签）时不用 \r，避免多路进度交错
                if bytes % (16 * 1024 * 1024) < exvia_proto::FILE_CHUNK as u64 {
                    match label {
                        Some(l) => eprintln!(
                            "[{l}] uploading: {files} files, {} MiB",
                            bytes / (1024 * 1024)
                        ),
                        None => {
                            eprintln!("\ruploading: {files} files, {} MiB", bytes / (1024 * 1024))
                        }
                    }
                }
            })
            .await?;

        loop {
            let Some(frame) = read_frame(&mut noise).await? else {
                anyhow::bail!("agent closed before confirming the transfer");
            };
            if frame.kind == FrameKind::Close {
                let info = frame.close_info()?;
                if info.code != Some(0) {
                    anyhow::bail!(
                        "agent rejected the transfer: {}",
                        info.reason.unwrap_or_default()
                    );
                }
                break;
            }
        }
        Ok((files, bytes, stats))
    }

    /// 递归下载目录（`get -r`）。
    pub async fn get_recursive(
        &self,
        machine_id: &str,
        remote: &str,
        local: &str,
    ) -> anyhow::Result<(u64, u64)> {
        let params = SessionParams {
            direction: Some("get".into()),
            path: Some(remote.to_string()),
            recursive: true,
            ..Default::default()
        };
        self.get_tree(machine_id, params, local).await
    }

    /// `get m 'dir/*.log' local/`：远端尾分量通配。agent 在远端路径的父目录内按
    /// 尾分量匹配（与 put 侧本地展开同一套语义：只支持尾分量、不匹配隐藏文件），
    /// 匹配结果按既有树下载路径落进 `local/`；无匹配时 agent 报错、本函数透传
    /// 为非零退出。字面路径（不含通配符）走 `get` / `get -r`，行为不变。
    pub async fn get_glob(
        &self,
        machine_id: &str,
        remote: &str,
        local: &str,
    ) -> anyhow::Result<(u64, u64)> {
        let (_, pattern) = split_remote_glob(remote)?;
        let params = SessionParams {
            direction: Some("get".into()),
            path: Some(remote.to_string()),
            recursive: true,
            pattern: Some(pattern.to_string()),
            ..Default::default()
        };
        self.get_tree(machine_id, params, local).await
    }

    /// 树下载共用尾段：建本地目录、收清单落盘、还原目录属性。
    async fn get_tree(
        &self,
        machine_id: &str,
        params: SessionParams,
        local: &str,
    ) -> anyhow::Result<(u64, u64)> {
        let dst = std::path::PathBuf::from(local);
        std::fs::create_dir_all(&dst)
            .with_context(|| format!("cannot create local directory: {local}"))?;
        let mut noise = self
            .open_session(machine_id, SessionKind::File, params)
            .await?;

        let mut warn = |msg: &str| eprintln!("warning: {msg}");
        let result = exvia_proto::tree::recv_tree_frames(
            &mut noise,
            &dst,
            "agent",
            "save",
            &mut warn,
            // 保留既有语义：reason 透传给操作者；Close 载荷解析失败则以解析错误收尾
            |frame| match frame.close_info() {
                Ok(info) => anyhow::anyhow!("agent aborted: {}", info.reason.unwrap_or_default()),
                Err(e) => e.into(),
            },
        )
        .await;
        match result {
            Err(e) => {
                let _ = write_frame(
                    &mut noise,
                    &Frame::close(&CloseInfo {
                        code: Some(1),
                        reason: Some(e.to_string()),
                    })?,
                )
                .await;
                Err(e)
            }
            Ok((files, bytes, dirs)) => {
                // 由深到浅还原目录属性
                for (p, mode, mtime) in dirs.into_iter().rev() {
                    let _ = exvia_proto::tree::apply_mode(&p, mode);
                    let _ = exvia_proto::tree::apply_mtime(&p, mtime);
                }
                let _ = write_frame(
                    &mut noise,
                    &Frame::close(&CloseInfo {
                        code: Some(0),
                        reason: None,
                    })?,
                )
                .await;
                Ok((files, bytes))
            }
        }
    }

    /// 多条转发（-L/-R 各可多条，可混用）。先全部解析并绑定，全部成功才进入
    /// 转发循环：任何一条失败都报明是哪条 spec，已建立的监听/会话全部收掉，
    /// 不留悬挂。Ctrl-C 行为由调用方的 select 决定，与本函数无关。
    pub async fn forward_multi(
        &self,
        machine_id: &str,
        l_specs: &[String],
        r_specs: &[String],
    ) -> anyhow::Result<()> {
        if l_specs.is_empty() && r_specs.is_empty() {
            anyhow::bail!("provide at least one -L or -R (see exvia forward --help)");
        }

        // ---- 阶段一：解析 + 绑定，全成才放行 ----
        let mut locals: Vec<(u16, tokio::net::TcpListener, String, u16)> = Vec::new();
        for spec in l_specs {
            let (listen_port, target_host, target_port) =
                parse_forward_spec(spec).map_err(|e| anyhow::anyhow!("-L {spec}: {e}"))?;
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", listen_port))
                .await
                .map_err(|e| {
                    anyhow::anyhow!("-L {spec}: cannot bind 127.0.0.1:{listen_port}: {e}")
                })?;
            locals.push((listen_port, listener, target_host, target_port));
        }
        let mut reverses: Vec<ReverseSetup> = Vec::new();
        for spec in r_specs {
            match self.setup_reverse(machine_id, spec).await {
                Ok(r) => reverses.push(r),
                Err(e) => {
                    // 其余已建的不留悬挂：-R 控制会话逐个请中继撤销；-L 监听随 drop 关闭
                    for r in &reverses {
                        let _ = self.close_session(r.sid).await;
                    }
                    return Err(anyhow::anyhow!("-R {spec}: {e}"));
                }
            }
        }

        // ---- 阶段二：全部就绪，开始转发（绑定冲突场景不会走到这里）----
        for (listen_port, _, target_host, target_port) in &locals {
            println!(
                "forward 127.0.0.1:{listen_port} -> {machine_id}:{target_host}:{target_port} (Ctrl-C to stop)"
            );
        }
        for r in &reverses {
            println!(
                "reverse forward {}:{} (agent listens) -> CLI dials {}:{} (Ctrl-C to stop)",
                r.bind_addr, r.bind_port, r.target_host, r.target_port
            );
        }

        let mut set = tokio::task::JoinSet::new();
        for (_, listener, target_host, target_port) in locals {
            let conn = self.clone();
            let machine_id = machine_id.to_string();
            set.spawn(async move {
                run_local_forward(conn, &machine_id, listener, &target_host, target_port).await
            });
        }
        if !reverses.is_empty() {
            let conn = self.clone();
            set.spawn(run_reverse_dispatcher(conn, reverses));
        }
        // 任一循环结束（-R 控制流断开、或某条出错）就收摊，与单条 forward 的既有行为一致
        let result = match set.join_next().await {
            Some(Ok(r)) => r,
            Some(Err(e)) => Err(anyhow::anyhow!("forward task failed: {e}")),
            None => Ok(()),
        };
        set.abort_all();
        result
    }
}

/// -L 单条监听的接受循环：每条连接一个 Tcpfwd 会话（与旧 `forward` 逐连接语义一致）
async fn run_local_forward(
    conn: Connection,
    machine_id: &str,
    listener: tokio::net::TcpListener,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        let params = SessionParams {
            target_host: Some(target_host.to_string()),
            target_port: Some(target_port),
            ..Default::default()
        };
        let session = conn
            .open_session(machine_id, SessionKind::Tcpfwd, params)
            .await;
        match session {
            Ok(noise) => {
                println!("[{peer}] connected");
                tokio::spawn(pump_forward_conn(tcp, noise, peer.to_string()));
            }
            Err(e) => {
                println!("[{peer}] session failed: {e}");
            }
        }
    }
}

/// -R 的一条已建立转发：控制流与目标信息绑定持有，控制流断开即转发终止
struct ReverseSetup {
    sid: u64,
    bind_addr: String,
    bind_port: u16,
    agent_pub: String,
    target_host: String,
    target_port: u16,
    noise: exvia_proto::noise::NoiseStream<MuxStream>,
}

/// 入站回程流的路由表项：分发器按 sid 前导精确路由
struct ReverseRoute {
    sid: u64,
    agent_pub: String,
    target_host: String,
    target_port: u16,
}

/// 所有 -R 共用一个入站流分发器：统一从流队列出队，再交给 pump_reverse_stream
/// 按 sid 前导路由。两个 -R 并存时不能各自出队——会互相抢走对方会话的回程流。
async fn run_reverse_dispatcher(
    conn: Connection,
    reverses: Vec<ReverseSetup>,
) -> anyhow::Result<()> {
    let (ctrl_gone_tx, mut ctrl_gone_rx) = mpsc::channel::<()>(1);
    let routes: Arc<Vec<ReverseRoute>> = Arc::new(
        reverses
            .iter()
            .map(|r| ReverseRoute {
                sid: r.sid,
                agent_pub: r.agent_pub.clone(),
                target_host: r.target_host.clone(),
                target_port: r.target_port,
            })
            .collect(),
    );
    for r in reverses {
        let tx = ctrl_gone_tx.clone();
        tokio::spawn(async move {
            // 控制流断开就让主循环退出，否则只在流队列上干等
            let mut noise = r.noise;
            while let Ok(Some(_)) = read_frame(&mut noise).await {}
            let _ = tx.send(()).await;
        });
    }
    drop(ctrl_gone_tx);

    let inner = conn.inner.clone();
    let mut n_conn = 0usize;
    loop {
        tokio::select! {
            _ = ctrl_gone_rx.recv() => break,
            stream = inner.streams.pop() => {
                n_conn += 1;
                tokio::spawn(pump_reverse_stream(inner.clone(), stream, routes.clone(), n_conn));
            }
        }
    }
    Ok(())
}

impl Connection {
    /// -R 的建立段：解析 spec、开控制会话（含 TOFU 校验）、让 agent 绑定并确认。
    /// 返回的控制流要一直持有（断开即转发终止）；绑定失败经 Close.reason 浮出。
    async fn setup_reverse(&self, machine_id: &str, spec: &str) -> anyhow::Result<ReverseSetup> {
        let (bind_addr, bind_port, target_host, target_port) = parse_reverse_spec(spec)?;
        // 控制会话沿用 open_session_peer 的 TOFU 校验
        let (mut noise, agent_pub, sid) = self
            .open_session_peer(
                machine_id,
                SessionKind::TcpfwdReverse,
                SessionParams::default(),
            )
            .await?;
        // 目标端点不上报 agent：它只管监听，目标由本机拨号，拿不到隧道外的访问能力
        write_frame(
            &mut noise,
            &Frame::ctrl(&CtrlMsg::TcpfwdReverse {
                bind_addr: bind_addr.clone(),
                bind_port,
            })?,
        )
        .await?;
        // 等绑定结果；失败经 Close.reason 浮出
        loop {
            let Some(frame) = read_frame(&mut noise).await? else {
                anyhow::bail!("agent closed the session during bind");
            };
            match frame.kind {
                FrameKind::Ctrl => {
                    if matches!(frame.ctrl_msg()?, CtrlMsg::Ack { chunk_index: 0 }) {
                        break;
                    }
                }
                FrameKind::Close => {
                    let info = frame.close_info()?;
                    anyhow::bail!("agent bind failed: {}", info.reason.unwrap_or_default());
                }
                _ => {}
            }
        }
        Ok(ReverseSetup {
            sid,
            bind_addr,
            bind_port,
            agent_pub,
            target_host,
            target_port,
            noise,
        })
    }
}

/// 断点续传握手必须等到 `ResumeFrom` 才动数据：旧版对端不认识 `--resume`，
/// 会一直读数据不说话，这里给出可操作的报错而不是挂到连接超时。
async fn read_frame_with_timeout<S>(io: &mut S, what: &str) -> anyhow::Result<Frame>
where
    S: tokio::io::AsyncRead + Unpin,
{
    match tokio::time::timeout(CONTROL_TIMEOUT, read_frame(io)).await {
        Ok(Ok(Some(frame))) => Ok(frame),
        Ok(Ok(None)) => anyhow::bail!("peer closed during {what}"),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => anyhow::bail!(
            "timed out waiting for {what}; the agent may predate --resume (upgrade it, or drop --resume)"
        ),
    }
}

// -L spec：本地端口:目标主机:目标端口
fn parse_forward_spec(spec: &str) -> anyhow::Result<(u16, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 3 {
        anyhow::bail!("format: local port:target host:target port");
    }
    let listen_port: u16 = parts[0].parse().context("invalid local port")?;
    let target_host = parts[1].to_string();
    let target_port: u16 = parts[2].parse().context("invalid target port")?;
    Ok((listen_port, target_host, target_port))
}

// 绑定地址缺省 127.0.0.1：绑非环回地址会把本机服务暴露给 agent 所在局域网
fn parse_reverse_spec(spec: &str) -> anyhow::Result<(String, u16, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (bind_addr, bind_port, target_host, target_port) = match parts.as_slice() {
        [p, th, tp] => ("127.0.0.1".to_string(), p, th, tp),
        [a, p, th, tp] => ((*a).to_string(), p, th, tp),
        _ => anyhow::bail!("-R format: [bind addr:]bind port:target host:target port"),
    };
    let bind_port: u16 = bind_port.parse().context("invalid bind port")?;
    let target_port: u16 = target_port.parse().context("invalid target port")?;
    Ok((bind_addr, bind_port, target_host.to_string(), target_port))
}

async fn pump_reverse_stream(
    inner: Arc<Inner>,
    stream: MuxStream,
    routes: Arc<Vec<ReverseRoute>>,
    n: usize,
) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut stream = stream;
    let mut sid_buf = [0u8; 8];
    if tokio::time::timeout(INVITE_TIMEOUT, stream.read_exact(&mut sid_buf))
        .await
        .is_err()
    {
        return Ok(()); // 前导超时
    }
    // 按 sid 前导精确路由到所属的 -R 会话；对不上就丢弃（与旧行为一致）
    let sid = u64::from_be_bytes(sid_buf);
    let Some(route) = routes.iter().find(|r| r.sid == sid) else {
        return Ok(());
    };
    let agent_pub = &route.agent_pub;
    let target_host = &route.target_host;
    let target_port = route.target_port;
    let static_key = inner.identity.x25519_private();
    let noise = tokio::time::timeout(
        Duration::from_secs(10),
        exvia_proto::noise::handshake(
            stream,
            exvia_proto::noise::Role::Initiator,
            &XStaticSecret::from(static_key),
        ),
    )
    .await;
    let mut noise = match noise {
        Ok(Ok(n)) => n,
        _ => {
            eprintln!("[rev-{n}] return stream handshake failed, dropped");
            return Ok(());
        }
    };
    // TOFU：回程流对端公钥须与控制会话固定的 agent 公钥一致，取不到就丢弃（fail-closed）
    let Some(rs) = noise.remote_static() else {
        eprintln!("[rev-{n}] return stream missing peer static key, dropped");
        return Ok(());
    };
    let expect_ok = base64::engine::general_purpose::STANDARD
        .decode(agent_pub)
        .map(|expect| rs.as_slice() == expect.as_slice())
        .unwrap_or(false);
    if !expect_ok {
        eprintln!("[rev-{n}] return stream peer key mismatch (possible mitm), dropped");
        return Ok(());
    }
    // 连目标失败时给 Close 带原因，agent 侧接入连接随即被关
    let addr = format!("{target_host}:{target_port}");
    let target = match tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            let reason = format!("connection to {addr} failed: {e}");
            let _ = write_frame(
                &mut noise,
                &Frame::close(&CloseInfo {
                    code: Some(1),
                    reason: Some(reason.clone()),
                })?,
            )
            .await;
            eprintln!("[rev-{n}] {reason}");
            return Ok(());
        }
        Err(_) => {
            let reason = format!("connection to {addr} failed: timed out");
            let _ = write_frame(
                &mut noise,
                &Frame::close(&CloseInfo {
                    code: Some(1),
                    reason: Some(reason.clone()),
                })?,
            )
            .await;
            eprintln!("[rev-{n}] {reason}");
            return Ok(());
        }
    };
    println!("[rev-{n}] connected");
    pump_forward_conn(target, noise, format!("rev-{n}")).await;
    Ok(())
}

// 本地 EOF 只发 Shutdown 半关，继续排空回程；远端 Close/流结束才整条收尾
async fn pump_forward_conn(
    tcp: tokio::net::TcpStream,
    noise: exvia_proto::noise::NoiseStream<MuxStream>,
    label: String,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut rr, mut wr) = tokio::io::split(tcp);
    // 读泵任务化（cancel-safe）：select 取消不得丢已消费的帧字节
    let (mut noise_r, mut noise_w) = tokio::io::split(noise);
    let (frames_tx, mut frames_rx) = mpsc::channel::<Frame>(16);
    let read_pump = tokio::spawn(async move {
        while let Ok(Some(f)) = read_frame(&mut noise_r).await {
            if frames_tx.send(f).await.is_err() {
                break;
            }
        }
    });
    let mut buf_c = [0u8; 16 * 1024];
    let mut local_eof = false; // 本地 TCP 读到 EOF，读臂停用
    let mut peer_eof = false; // 对端传播了写侧关闭（-R 回程桥会发，-L 不发）
    loop {
        tokio::select! {
            n = rr.read(&mut buf_c), if !local_eof => match n {
                Ok(0) => {
                    local_eof = true;
                    let _ = write_frame(&mut noise_w, &Frame::shutdown()).await;
                    if peer_eof { break; }
                }
                Err(_) => break,
                Ok(n) => {
                    if write_frame(&mut noise_w, &Frame::data(buf_c[..n].to_vec())).await.is_err() { break; }
                }
            },
            frame = frames_rx.recv() => match frame {
                None => break,
                Some(Frame { kind: FrameKind::Data, payload }) => { if wr.write_all(&payload).await.is_err() { break; } }
                Some(Frame { kind: FrameKind::Close, payload }) => {
                    if let Ok(info) = serde_json::from_slice::<CloseInfo>(&payload) {
                        if let Some(reason) = info.reason.filter(|r| !r.is_empty()) {
                            eprintln!("[{label}] forward connection closed: {reason}");
                        }
                    }
                    break;
                }
                Some(Frame { kind: FrameKind::Ctrl, .. }) => {}
                // 对端写侧关闭（-R 回程桥的早 FIN）：向本地 TCP 传播 FIN，双向都关才收尾
                Some(Frame { kind: FrameKind::Shutdown, .. }) => {
                    peer_eof = true;
                    if wr.shutdown().await.is_err() { break; }
                    if local_eof { break; }
                }
            },
        }
    }
    // 终止读泵释放 noise_r，否则 yamux 流永不 FIN
    read_pump.abort();
    println!("[{label}] forward connection closed");
}

use anyhow::Context as _;

pub(crate) fn send_json<T: serde::Serialize>(tx: &mpsc::UnboundedSender<String>, msg: &T) {
    let _ = tx.send(serde_json::to_string(msg).expect("failed to serialize control message"));
}

/// 批量 exec 的输出行前缀：按行缓冲，凑齐换行才带 `[label] ` 写出；
/// `finish` 把结尾不带换行的残余行也补前缀吐出。泛型出参让测试可以用 Vec<u8>。
struct LinePrefixer<W: std::io::Write> {
    prefix: String,
    buf: Vec<u8>,
    out: W,
}

impl<W: std::io::Write> LinePrefixer<W> {
    fn new(label: &str, out: W) -> Self {
        Self {
            prefix: format!("[{label}] "),
            buf: Vec::new(),
            out,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        self.buf.extend_from_slice(chunk);
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            self.out.write_all(self.prefix.as_bytes())?;
            self.out.write_all(&line)?;
            self.out.flush()?;
        }
        Ok(())
    }

    fn finish(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        self.out.write_all(self.prefix.as_bytes())?;
        self.out.write_all(&self.buf)?;
        self.out.write_all(b"\n")?;
        self.out.flush()?;
        self.buf.clear();
        Ok(())
    }
}

const MIB: u64 = 1024 * 1024;

/// 单文件传输的 stderr 进度行（如 `put 12.3/45.6 MiB (27%)`）。
/// 文件 >1MiB 才启用；每传输 1MiB 刷新一次——分块数是确定的，管道与重定向
/// 下也能拿到可复现的输出（比按时间刷新更可测）。
/// 简化取舍：不做速率估算与 ETA；需要更平滑的刷新时再加 0.5s 定时器。
struct TransferProgress {
    enabled: bool,
    label: &'static str,
    total: u64,
    reported: u64,
    printed_len: usize,
}

impl TransferProgress {
    fn new(label: &'static str, total: Option<u64>) -> Self {
        Self {
            enabled: total.is_some_and(|t| t > MIB),
            label,
            total: total.unwrap_or(0),
            reported: 0,
            printed_len: 0,
        }
    }

    // get 的总大小要等 FileMeta 到达才知道
    fn observe_total(&mut self, total: u64) {
        self.total = total;
        if total > MIB {
            self.enabled = true;
        }
    }

    fn update(&mut self, done: u64) {
        if !self.enabled || self.total == 0 || done < self.reported + MIB {
            return;
        }
        let line = progress_line(self.label, done, self.total);
        self.printed_len = line.len();
        eprint!("{line}"); // stderr 无缓冲，立即可见
        self.reported = done;
    }

    /// 清掉屏幕上的进度行，让后续输出（uploaded:/partial kept/error:）从干净的一行开始
    fn clear(&mut self) {
        if self.printed_len > 0 {
            eprint!("\r{}\r", " ".repeat(self.printed_len));
            self.printed_len = 0;
        }
    }
}

impl Drop for TransferProgress {
    fn drop(&mut self) {
        self.clear();
    }
}

fn progress_line(label: &str, done: u64, total: u64) -> String {
    let pct = (done * 100).checked_div(total).unwrap_or(100).min(100);
    format!(
        "\r{label} {:.1}/{:.1} MiB ({}%)",
        done as f64 / MIB as f64,
        total as f64 / MIB as f64,
        pct
    )
}

/// put 的远端目标：以 / 结尾视为目录，补上本地文件名（scp 习惯）。
/// 本地路径取不出文件名属于用法错误，在建立会话前拒绝。
fn resolve_put_remote(remote: &str, local: &str) -> anyhow::Result<String> {
    match remote.strip_suffix('/') {
        Some(dir) => {
            let name = std::path::Path::new(local).file_name().ok_or_else(|| {
                anyhow::anyhow!("cannot infer a file name from local path {local:?}")
            })?;
            Ok(format!("{dir}/{}", name.to_string_lossy()))
        }
        None => Ok(remote.to_string()),
    }
}

/// get 的本地目的地：目录形态（已存在或以 / 结尾）用远端文件名补全，
/// 与 scp 的目标语义一致。文件名推导不出来时报错，让调用方在传输前拦住。
fn resolve_get_dest(
    local: &str,
    remote: &str,
    local_is_dir: bool,
) -> anyhow::Result<std::path::PathBuf> {
    let mut dest = std::path::PathBuf::from(local);
    if local_is_dir || local.ends_with('/') {
        let name = std::path::Path::new(remote.trim_end_matches('/'))
            .file_name()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot infer a file name from remote path {remote:?}; give the local file name explicitly"
                )
            })?;
        dest.push(name);
    }
    Ok(dest)
}

/// Pty 会话的基础参数（shell 与 exec -t 共用）：本终端尺寸 + TERM 环境变量；
/// 非 tty / 未设置时回退 80x24 与 None。
fn pty_base_params() -> SessionParams {
    let (cols, rows) = terminal_size::terminal_size()
        .map(|(w, h)| (w.0, h.0))
        .unwrap_or((80, 24));
    SessionParams {
        cols: Some(cols),
        rows: Some(rows),
        term: std::env::var("TERM").ok(),
        ..Default::default()
    }
}

/// 把 argv 拼回一条 `sh -c` 命令串（`exec -t` 的 `pty_command`）：安全字符直通，
/// 其余用单引号包裹（内嵌 `'` 写作 `'\''`，POSIX 规则）。`--` 后的参数本就是
/// 独立 argv，拼串后交给远端 `sh -c` 与 exec 的 execvp 形式语义一致。
fn shell_join(cmd: &[String]) -> String {
    fn plain(s: &str) -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "%+,/:=@._-".contains(c))
    }
    cmd.iter()
        .map(|a| {
            if plain(a) {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// 拆远端通配串：`dir/*.log` → ("dir", "*.log")。父目录分量带 `*`/`?` → 报错
/// （与 put 侧展开同一套语义：只支持尾分量）。父目录本身不回传——agent 在
/// 原始串的父目录内自行匹配。
fn split_remote_glob(remote: &str) -> anyhow::Result<(&str, &str)> {
    let (dir, pattern) = match remote.rsplit_once('/') {
        Some((d, p)) => (d, p),
        None => ("", remote),
    };
    if dir.contains('*') || dir.contains('?') {
        anyhow::bail!("wildcards are only supported in the last path component: {remote}");
    }
    Ok((dir, pattern))
}

#[cfg(test)]
mod tests {
    use super::cli_url;

    // ---- 批量 exec 的输出行前缀 ----
    #[test]
    fn line_prefixer_frames_complete_lines_and_flushes_remainder() {
        let mut p = super::LinePrefixer::new("m1", Vec::new());
        p.push(b"hello ").unwrap();
        p.push(b"world\nsec").unwrap();
        // 凑齐换行的才带前缀写出；残余 "sec" 还在缓冲里
        assert_eq!(p.out, b"[m1] hello world\n");
        p.finish().unwrap();
        assert_eq!(p.out, b"[m1] hello world\n[m1] sec\n");
    }

    #[test]
    fn line_prefixer_passes_multibyte_and_empty_lines() {
        let mut p = super::LinePrefixer::new("机器", Vec::new());
        p.push("中文\n\n".as_bytes()).unwrap(); // 空行也要带前缀
        p.finish().unwrap();
        assert_eq!(p.out, "[机器] 中文\n[机器] \n".as_bytes());
    }

    // ---- 单文件传输进度行 ----
    #[test]
    fn progress_line_formats_mib_and_caps_pct() {
        assert_eq!(
            super::progress_line("put", 12 * 1048576 + 300000, 456 * 1048576),
            "\rput 12.3/456.0 MiB (2%)"
        );
        assert_eq!(
            super::progress_line("get", 2 * 1048576, 2 * 1048576),
            "\rget 2.0/2.0 MiB (100%)"
        );
    }

    #[test]
    fn transfer_progress_only_for_large_files_and_throttles_by_mib() {
        // 小文件（≤1MiB）完全不显示
        let mut p = super::TransferProgress::new("put", Some(1024 * 1024));
        p.update(1024 * 1024);
        assert_eq!(p.printed_len, 0);
        // 大文件每 1MiB 才刷一次，1MiB 之内的抖动不产生输出
        let mut p = super::TransferProgress::new("put", Some(4 * super::MIB));
        p.update(1048575);
        assert_eq!(p.printed_len, 0);
        p.update(2 * 1048576);
        assert!(p.printed_len > 0);
        assert_eq!(p.reported, 2 * 1048576);
        p.update(2 * 1048576 + 5000);
        assert_eq!(p.reported, 2 * 1048576); // 不足 1MiB 不再刷
                                             // get 的总大小后知后觉：FileMeta 到达才启用
        let mut g = super::TransferProgress::new("get", None);
        g.update(4 * 1048576);
        assert_eq!(g.printed_len, 0);
        g.observe_total(8 * 1048576);
        g.update(4 * 1048576);
        assert!(g.printed_len > 0);
    }

    // ---- get 本地目的地解析 ----
    #[test]
    fn get_dest_dir_joins_remote_basename() {
        // 已存在目录：./ 与 普通目录 两种形态都拼远端文件名
        let d = super::resolve_get_dest("./", "Downloads/f.rpm", true).unwrap();
        assert_eq!(d, std::path::Path::new("./f.rpm"));
        let d = super::resolve_get_dest("out", "/home/chao/x.tar.gz", true).unwrap();
        assert_eq!(d, std::path::Path::new("out/x.tar.gz"));
        // 目录不存在但以 / 结尾：同样按目录意图处理
        let d = super::resolve_get_dest("newdir/", "~/y.bin", false).unwrap();
        assert_eq!(d, std::path::Path::new("newdir/y.bin"));
        // 远端路径收尾带 / 也不影响取名
        let d = super::resolve_get_dest("out", "/a/b/", true).unwrap();
        assert_eq!(d, std::path::Path::new("out/b"));
    }

    #[test]
    fn get_dest_plain_file_unchanged() {
        let d = super::resolve_get_dest("keep.me", "/any/remote", false).unwrap();
        assert_eq!(d, std::path::Path::new("keep.me"));
    }

    #[test]
    fn get_dest_cannot_infer_name_is_usage_error() {
        // 远端路径没有可取名分量：推导不出本地文件名，明确报错而非瞎猜
        assert!(super::resolve_get_dest("./", "/", true).is_err());
        assert!(super::resolve_get_dest("./", "..", true).is_err());
    }

    // ---- put 远端目标解析 ----
    #[test]
    fn put_remote_trailing_slash_joins_local_basename() {
        assert_eq!(
            super::resolve_put_remote("/tmp/", "a/f.rpm").unwrap(),
            "/tmp/f.rpm"
        );
        // 根目录收尾：补出来仍是绝对路径
        assert_eq!(super::resolve_put_remote("/", "f.rpm").unwrap(), "/f.rpm");
        // 不以 / 结尾：原样，由 agent 决定是文件还是已存在目录
        assert_eq!(
            super::resolve_put_remote("/tmp/f.rpm", "a/f.rpm").unwrap(),
            "/tmp/f.rpm"
        );
    }

    #[test]
    fn put_remote_cannot_infer_name_is_usage_error() {
        assert!(super::resolve_put_remote("/tmp/", "..").is_err());
        assert!(super::resolve_put_remote("/tmp/", "/").is_err());
    }

    // ---- -L spec 解析 ----
    #[test]
    fn parse_forward_spec_accepts_host_port_triple() {
        let (p, h, t) = super::parse_forward_spec("18222:127.0.0.1:18223").unwrap();
        assert_eq!((p, h.as_str(), t), (18222, "127.0.0.1", 18223));
        assert!(super::parse_forward_spec("bad").is_err());
        assert!(super::parse_forward_spec("1:2").is_err());
        assert!(super::parse_forward_spec("99999:x:1").is_err());
        assert!(super::parse_forward_spec("1:x:notaport").is_err());
    }

    // ---- exec -t 的 argv 拼串 ----
    #[test]
    fn shell_join_quotes_only_unsafe_args() {
        assert_eq!(
            super::shell_join(&["echo".into(), "pty-ok".into()]),
            "echo pty-ok"
        );
        assert_eq!(
            super::shell_join(&["sh".into(), "-c".into(), "echo hi; exit 5".into()]),
            "sh -c 'echo hi; exit 5'"
        );
        // 内嵌单引号按 POSIX 规则转义
        assert_eq!(
            super::shell_join(&["echo".into(), "it's".into()]),
            "echo 'it'\\''s'"
        );
        // 空参数必须显式引起来，否则拼串后就消失了
        assert_eq!(
            super::shell_join(&["echo".into(), String::new()]),
            "echo ''"
        );
    }

    // ---- get 远端通配的尾分量拆分 ----
    #[test]
    fn split_remote_glob_takes_the_last_component_only() {
        assert_eq!(
            super::split_remote_glob("dir/*.log").unwrap(),
            ("dir", "*.log")
        );
        assert_eq!(super::split_remote_glob("*.log").unwrap(), ("", "*.log"));
        assert_eq!(
            super::split_remote_glob("/var/log/app-?.log").unwrap(),
            ("/var/log", "app-?.log")
        );
        // 中间分量通配 → 报错（只支持尾分量，与 put 侧展开一致）
        let err = super::split_remote_glob("a/*/b.log")
            .unwrap_err()
            .to_string();
        assert!(err.contains("last path component"), "{err}");
        let err = super::split_remote_glob("a?/b.log")
            .unwrap_err()
            .to_string();
        assert!(err.contains("last path component"), "{err}");
    }

    #[test]
    fn cli_url_normalizes_and_rejects_plaintext() {
        assert_eq!(
            cli_url("wss://h:8443", "/_exvia").unwrap(),
            "wss://h:8443/_exvia/cli"
        );
        assert_eq!(
            cli_url("h:8443/", "/api/v2/sync").unwrap(),
            "wss://h:8443/api/v2/sync/cli"
        );
        assert!(cli_url("ws://h:8443", "/_exvia").is_err());
        assert!(cli_url("", "/_exvia").is_err());
        assert!(cli_url("h:8443", "bad").is_err());
        assert!(cli_url("h:8443", "/../x").is_err());
    }
}
