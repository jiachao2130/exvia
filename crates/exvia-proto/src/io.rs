// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! WebSocket 消息流 → `AsyncRead + AsyncWrite` 字节流适配。
//!
//! - Binary 帧 → 字节流（供 yamux / Noise 使用）
//! - Text 帧 → 控制面 JSON：入向交付给 `TextSink`，出向从 `TextSource` 取
//!
//! 一个 WS 连接上的所有收发都经由此适配器，避免双读者问题；
//! 发送侧统一在 `poll_drive` 里驱动，Pending 时状态保留、下次继续。
//! 控制面通道有界（`BoundedTextSink`）：满时背压而非丢消息，
//! 未认证连接灌帧的攻击面由配合的空闲超时收口。

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::PollSender;

use crate::Result;

/// 控制面 Text 帧的投递端（适配器收到 Text 帧后由此交给控制循环）。
///
/// 有界通道满时返回 `Pending` 形成背压——适配器暂存该帧，容量空出后续传，不丢消息；
/// 无界实现立即送达（兼容尚未迁移的调用方）。接收端已关闭返回 `Ready(Err(()))`。
pub trait TextSink: Send {
    fn poll_send_text(
        &mut self,
        cx: &mut Context<'_>,
        text: &str,
    ) -> Poll<std::result::Result<(), ()>>;
}

impl TextSink for UnboundedSender<String> {
    fn poll_send_text(
        &mut self,
        _cx: &mut Context<'_>,
        text: &str,
    ) -> Poll<std::result::Result<(), ()>> {
        Poll::Ready(self.send(text.to_owned()).map_err(|_| ()))
    }
}

/// 有界控制面通道的投递端：`mpsc::Sender` 的 poll 化封装，满时背压。
pub struct BoundedTextSink(PollSender<String>);

impl BoundedTextSink {
    pub fn new(tx: Sender<String>) -> Self {
        Self(PollSender::new(tx))
    }
}

impl TextSink for BoundedTextSink {
    fn poll_send_text(
        &mut self,
        cx: &mut Context<'_>,
        text: &str,
    ) -> Poll<std::result::Result<(), ()>> {
        match self.0.poll_reserve(cx) {
            Poll::Ready(Ok(())) => match self.0.send_item(text.to_owned()) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(_) => Poll::Ready(Err(())),
            },
            Poll::Ready(Err(_)) => Poll::Ready(Err(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// 控制面 Text 帧的取出端（`poll_drive` 从这里取应答帧发送）。
pub trait TextSource: Send {
    fn poll_recv_text(&mut self, cx: &mut Context<'_>) -> Poll<Option<String>>;
}

impl TextSource for UnboundedReceiver<String> {
    fn poll_recv_text(&mut self, cx: &mut Context<'_>) -> Poll<Option<String>> {
        self.poll_recv(cx)
    }
}

impl TextSource for Receiver<String> {
    fn poll_recv_text(&mut self, cx: &mut Context<'_>) -> Poll<Option<String>> {
        self.poll_recv(cx)
    }
}

/// 消息类型的归一化视图（各 WebSocket 实现各自提供）。
pub trait WsMessage: Sized {
    fn binary_from(data: &[u8]) -> Self;
    fn text_from(t: String) -> Self;
    fn close() -> Self;
    fn into_parts(self) -> WsMsgParts;
}

pub enum WsMsgParts {
    Text(String),
    Binary(Vec<u8>),
    /// Ping/Pong/Close 等对字节流无意义的帧。
    Ignore,
}

/// 二进制缓冲超过此长度时，poll_write 顺手驱动一次发送。
const OUT_FLUSH_THRESHOLD: usize = 32 * 1024;

pub struct WsByteStream<S, M, E> {
    ws: S,
    incoming_tx: Box<dyn TextSink>,
    outgoing_rx: Option<Box<dyn TextSource>>,
    /// 取出但尚未 start_send 的消息（发送背压时暂存）。
    pending_msg: Option<M>,
    /// 控制面通道满时暂存的入向 Text 帧（背压，容量空出后由通道唤醒续传）。
    pending_text: Option<String>,
    in_buf: BytesMut,
    in_eof: bool,
    out_buf: BytesMut,
    close_sent: bool,
    /// 控制面发送失败会被粘住，后续 poll_* 一律返回，避免 start_send 丢错误被误判成功。
    send_error: Option<String>,
    _pd: PhantomData<fn() -> E>,
}

impl<S, M, E> WsByteStream<S, M, E>
where
    S: Stream<Item = std::result::Result<M, E>> + Sink<M, Error = E> + Unpin,
    M: WsMessage + Unpin,
    E: std::fmt::Display,
{
    pub fn new(
        ws: S,
        incoming_tx: impl TextSink + 'static,
        outgoing_rx: impl TextSource + 'static,
    ) -> Self {
        Self {
            ws,
            incoming_tx: Box::new(incoming_tx),
            outgoing_rx: Some(Box::new(outgoing_rx)),
            pending_msg: None,
            pending_text: None,
            in_buf: BytesMut::new(),
            in_eof: false,
            out_buf: BytesMut::new(),
            close_sent: false,
            send_error: None,
            _pd: PhantomData,
        }
    }

    /// 驱动发送队列：控制面 Text 优先，其次二进制缓冲。
    fn poll_drive(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(e) = &self.send_error {
            return Poll::Ready(Err(std::io::Error::other(e.clone())));
        }
        loop {
            if let Some(msg) = self.pending_msg.take() {
                match Pin::new(&mut self.ws).poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        if let Err(e) = Pin::new(&mut self.ws).start_send(msg) {
                            self.send_error = Some(format!("control plane send failed: {e}"));
                            return Poll::Ready(Err(std::io::Error::other(
                                self.send_error.clone().unwrap(),
                            )));
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        self.send_error = Some(format!("websocket send channel failed: {e}"));
                        return Poll::Ready(Err(std::io::Error::other(
                            self.send_error.clone().unwrap(),
                        )));
                    }
                    Poll::Pending => {
                        self.pending_msg = Some(msg);
                        return Poll::Pending;
                    }
                }
            }
            if let Some(rx) = &mut self.outgoing_rx {
                match rx.poll_recv_text(cx) {
                    Poll::Ready(Some(text)) => {
                        self.pending_msg = Some(M::text_from(text));
                        continue;
                    }
                    Poll::Ready(None) => self.outgoing_rx = None,
                    Poll::Pending => {}
                }
            }
            if !self.out_buf.is_empty() {
                let chunk = std::mem::take(&mut self.out_buf).freeze();
                self.pending_msg = Some(M::binary_from(&chunk));
                continue;
            }
            return Poll::Ready(Ok(()));
        }
    }

    /// 投递暂存的控制面 Text 帧；通道满时保留暂存并返回 Pending（背压，不丢消息）。
    fn poll_flush_text(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(text) = self.pending_text.as_deref() else {
            return Poll::Ready(());
        };
        match self.incoming_tx.poll_send_text(cx, text) {
            Poll::Ready(Ok(())) => {
                self.pending_text = None;
                Poll::Ready(())
            }
            Poll::Ready(Err(())) => {
                self.pending_text = None;
                tracing::warn!("control plane receiver closed, dropping a text message");
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S, M, E> AsyncRead for WsByteStream<S, M, E>
where
    S: Stream<Item = std::result::Result<M, E>> + Sink<M, Error = E> + Unpin,
    M: WsMessage + Unpin,
    E: std::fmt::Display,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // 顺手驱动发送侧；失败必须传播，静默吞掉会丢控制面消息
        if let Poll::Ready(Err(e)) = this.poll_drive(cx) {
            return Poll::Ready(Err(e));
        }
        loop {
            // 先投递背压期间暂存的控制面帧；仍满则整条读路径 Pending，
            // 容量空出时通道会唤醒（连接泵的节拍兜底）再继续
            if this.poll_flush_text(cx) == Poll::Pending {
                return Poll::Pending;
            }
            if !this.in_buf.is_empty() {
                let n = buf.remaining().min(this.in_buf.len());
                let chunk = this.in_buf.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if this.in_eof {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.ws).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.in_eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                }
                Poll::Ready(Some(Ok(m))) => match m.into_parts() {
                    WsMsgParts::Binary(b) => this.in_buf.extend_from_slice(&b),
                    WsMsgParts::Text(t) => {
                        this.pending_text = Some(t);
                        if this.poll_flush_text(cx) == Poll::Pending {
                            return Poll::Pending;
                        }
                    }
                    WsMsgParts::Ignore => {}
                },
            }
        }
    }
}

impl<S, M, E> AsyncWrite for WsByteStream<S, M, E>
where
    S: Stream<Item = std::result::Result<M, E>> + Sink<M, Error = E> + Unpin,
    M: WsMessage + Unpin,
    E: std::fmt::Display,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.close_sent {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            )));
        }
        this.out_buf.extend_from_slice(buf);
        if this.out_buf.len() >= OUT_FLUSH_THRESHOLD {
            if let Poll::Ready(Err(e)) = this.poll_drive(cx) {
                return Poll::Ready(Err(e));
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drive(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut this.ws)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.close_sent {
            match Pin::new(&mut *this).poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
            match Pin::new(&mut this.ws).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let _ = Pin::new(&mut this.ws).start_send(M::close());
                    this.close_sent = true;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.ws)
            .poll_close(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

/// tokio-tungstenite 预置别名（agent / cli 用）。
pub type TungWs<S> =
    WsByteStream<S, tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>;

impl WsMessage for tokio_tungstenite::tungstenite::Message {
    fn binary_from(data: &[u8]) -> Self {
        Self::Binary(Bytes::copy_from_slice(data))
    }
    fn text_from(t: String) -> Self {
        Self::Text(t.into())
    }
    fn close() -> Self {
        Self::Close(None)
    }
    fn into_parts(self) -> WsMsgParts {
        use tokio_tungstenite::tungstenite::Message as M;
        match self {
            M::Text(t) => WsMsgParts::Text(t.to_string()),
            M::Binary(b) => WsMsgParts::Binary(b.to_vec()),
            _ => WsMsgParts::Ignore,
        }
    }
}

/// axum 服务端 WebSocket（`axum-ws` feature，中继使用）。
#[cfg(feature = "axum-ws")]
impl WsMessage for axum::extract::ws::Message {
    fn binary_from(data: &[u8]) -> Self {
        Self::Binary(Bytes::copy_from_slice(data))
    }
    fn text_from(t: String) -> Self {
        Self::Text(t.into())
    }
    fn close() -> Self {
        Self::Close(None)
    }
    fn into_parts(self) -> WsMsgParts {
        use axum::extract::ws::Message as M;
        match self {
            M::Text(t) => WsMsgParts::Text(t.to_string()),
            M::Binary(b) => WsMsgParts::Binary(b.to_vec()),
            _ => WsMsgParts::Ignore,
        }
    }
}

/// 读一条 u16 长度前缀记录（Noise 握手期使用）。
pub async fn read_record<R: AsyncRead + Unpin>(io: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    io.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    Ok(payload)
}

/// 写一条 u16 长度前缀记录。
pub async fn write_record<W: AsyncWrite + Unpin>(io: &mut W, data: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(data.len() + 2);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    io.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::noop_waker_ref;

    fn ctx() -> Context<'static> {
        Context::from_waker(noop_waker_ref())
    }

    #[test]
    fn unbounded_sink_delivers_immediately() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut sink: Box<dyn TextSink> = Box::new(tx);
        assert!(matches!(
            sink.poll_send_text(&mut ctx(), "hi"),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(rx.try_recv().unwrap(), "hi");
    }

    #[test]
    fn bounded_sink_backpressures_when_full_and_recovers() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1);
        let mut sink: Box<dyn TextSink> = Box::new(BoundedTextSink::new(tx));
        assert!(matches!(
            sink.poll_send_text(&mut ctx(), "a"),
            Poll::Ready(Ok(()))
        ));
        // 满时背压：Pending、不丢消息（"b" 由适配器暂存重试）
        assert!(matches!(
            sink.poll_send_text(&mut ctx(), "b"),
            Poll::Pending
        ));
        // 容量空出后重试即送达
        assert_eq!(rx.try_recv().unwrap(), "a");
        assert!(matches!(
            sink.poll_send_text(&mut ctx(), "b"),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(rx.try_recv().unwrap(), "b");
    }

    #[test]
    fn sink_reports_closed_receiver() {
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(1);
        let mut sink: Box<dyn TextSink> = Box::new(BoundedTextSink::new(tx));
        drop(rx);
        assert!(matches!(
            sink.poll_send_text(&mut ctx(), "x"),
            Poll::Ready(Err(()))
        ));
    }

    #[test]
    fn sources_poll_recv_for_bounded_and_unbounded() {
        let mut cx = ctx();
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(2);
        let mut src: Box<dyn TextSource> = Box::new(rx);
        assert!(matches!(src.poll_recv_text(&mut cx), Poll::Pending));
        tx.try_send("m".into()).unwrap();
        assert!(matches!(src.poll_recv_text(&mut cx), Poll::Ready(Some(_))));
        let (tx2, rx2) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut src2: Box<dyn TextSource> = Box::new(rx2);
        tx2.send("u".into()).unwrap();
        assert!(matches!(src2.poll_recv_text(&mut cx), Poll::Ready(Some(_))));
    }
}
