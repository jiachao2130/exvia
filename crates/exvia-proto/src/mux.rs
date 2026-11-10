// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! yamux 封装：一条连接上的多路会话流。
//!
//! 模式约定：relay 一侧为 `Mode::Client`（打开的流为奇数 ID），
//! agent / cli 一侧为 `Mode::Server`；relay 负责打开所有会话流，
//! 两端只接受入向流。
//!
//! yamux 0.14 是纯 poll 状态机（无 Control 句柄）：流上的 write 只把帧命令入队，
//! 落盘要等连接被 poll；空闲连接无人唤醒时排队帧会滞留（-R 回程流尤甚），SYN 惰性挂在首个出站帧上。
//! 故 `open_stream()` 写 0 字节 Data 顶出 SYN，入向驱动按节拍兜底泵连接。
//!
//! yamux 使用 futures-io trait，经 tokio-util Compat 桥接，
//! 对外暴露的流都是 tokio trait。

use std::collections::VecDeque;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Context;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// 面向 tokio 代码的 yamux 流别名。
pub type MuxStream = Compat<yamux::Stream>;

pub struct Mux<T> {
    /// 每连接一把状态锁：毒化也只影响单连接，不触发 relay 全局 fail-fast。
    conn: Mutex<yamux::Connection<Compat<T>>>,
}

impl<T> Mux<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(io: T, mode: yamux::Mode) -> Arc<Self> {
        let conn = yamux::Connection::new(io.compat(), yamux::Config::default(), mode);
        Arc::new(Self {
            conn: Mutex::new(conn),
        })
    }

    pub async fn open_stream(&self) -> yamux::Result<MuxStream> {
        use tokio::io::AsyncWriteExt;
        let stream = poll_fn(|cx: &mut Context<'_>| {
            let mut guard = self.conn.lock().unwrap();
            guard.poll_new_outbound(cx).map(|r| r.map(|s| s.compat()))
        })
        .await?;
        let mut stream = stream;
        poll_fn(|cx: &mut Context<'_>| Pin::new(&mut stream).poll_write(cx, &[])).await?;
        stream.flush().await?;
        Ok(stream)
    }

    /// 显式泵一次连接，顶出滞留出站帧；仅中继侧用，Server 端入向流回声可丢。
    pub fn pump_now(&self) {
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut guard = self.conn.lock().unwrap();
        let _ = guard.poll_next_inbound(&mut cx);
    }
}

/// 入向驱动兜底 poll 连接的节拍。
const PUMP_TICK: std::time::Duration = std::time::Duration::from_millis(50);

/// 后台轮询入向流并交付；兼作连接写泵，按 PUMP_TICK 节拍兜底 poll。
pub fn spawn_inbound_driver<T>(
    mux: Arc<Mux<T>>,
    on_inbound: impl Fn(MuxStream) + Send + 'static,
) -> JoinHandle<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            // poll_fn 取消安全：Pending 时进度留在 Connection，取消后原样续跑
            let next = tokio::select! {
                next = poll_fn(|cx: &mut Context<'_>| {
                    let mut guard = mux.conn.lock().unwrap();
                    guard.poll_next_inbound(cx)
                }) => next,
                _ = tokio::time::sleep(PUMP_TICK) => continue,
            };
            match next {
                Some(Ok(stream)) => on_inbound(stream.compat()),
                Some(Err(e)) => {
                    tracing::debug!("yamux connection ended: {e}");
                    break;
                }
                None => break,
            }
        }
    })
}

/// 入向流 FIFO 队列：入向驱动 push，业务循环 pop（两端共用）。
#[derive(Default)]
pub struct StreamQueue {
    q: AsyncMutex<VecDeque<MuxStream>>,
    notify: Notify,
}

impl StreamQueue {
    pub fn new() -> Self {
        Self {
            q: AsyncMutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }
    /// 取消安全：锁内同步 pop，取消只会原样睡回。
    pub async fn pop(&self) -> MuxStream {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            if let Some(s) = self.q.lock().await.pop_front() {
                return s;
            }
            notified.await;
        }
    }

    pub async fn push(&self, s: MuxStream) {
        self.q.lock().await.push_back(s);
        self.notify.notify_one();
    }
}
