// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 会话流上的 Noise 端到端加密。
//!
//! - 模式：`Noise_XX_25519_ChaChaPoly_SHA256`，每条会话流独立握手
//! - 握手期：u16 长度前缀的明文记录（XX 的 3 条消息）
//! - 传输期：u16 长度前缀的密文记录，整条会话流（含帧头）都在加密之内
//!
//! `remote_static()` 返回对端 x25519 静态公钥，供 TOFU 指纹固定。

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use x25519_dalek::StaticSecret as XStaticSecret;

use crate::io::{read_record, write_record};
use crate::{Result, NOISE_CHUNK};

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// XX 握手完成后包装出的加密流。
pub struct NoiseStream<T> {
    inner: T,
    state: snow::TransportState,
    remote_static: Option<[u8; 32]>,
    // 读侧状态机（全部状态跨 Pending 保留，恢复后不得重置）
    header: [u8; 2],
    header_pos: usize,
    in_body: bool,
    rec_len: usize,
    rec_filled: usize,
    rec_cipher: BytesMut,
    plain_buf: BytesMut,
    in_eof: bool,
    // 写侧
    enc_buf: BytesMut,
    enc_pos: usize,
    shutdown_started: bool,
}

pub async fn handshake<T>(io: T, role: Role, local_static: &XStaticSecret) -> Result<NoiseStream<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let static_key = local_static.to_bytes();
    let builder = snow::Builder::new(NOISE_PATTERN.parse()?).local_private_key(&static_key);
    let mut hs = match role {
        Role::Initiator => builder.build_initiator()?,
        Role::Responder => builder.build_responder()?,
    };
    let mut buf = vec![0u8; 65535];
    let mut io = io;
    match role {
        Role::Initiator => {
            let n = hs.write_message(&[], &mut buf)?;
            write_record(&mut io, &buf[..n]).await?;
            let m2 = read_record(&mut io).await?;
            let _ = hs.read_message(&m2, &mut buf)?;
            let n = hs.write_message(&[], &mut buf)?;
            write_record(&mut io, &buf[..n]).await?;
        }
        Role::Responder => {
            let m1 = read_record(&mut io).await?;
            let _ = hs.read_message(&m1, &mut buf)?;
            let n = hs.write_message(&[], &mut buf)?;
            write_record(&mut io, &buf[..n]).await?;
            let m3 = read_record(&mut io).await?;
            let _ = hs.read_message(&m3, &mut buf)?;
        }
    }
    let state = hs.into_transport_mode()?;
    let remote_static = state
        .get_remote_static()
        .and_then(|b| <[u8; 32]>::try_from(b).ok());
    Ok(NoiseStream {
        inner: io,
        state,
        remote_static,
        header: [0u8; 2],
        header_pos: 0,
        in_body: false,
        rec_len: 0,
        rec_filled: 0,
        rec_cipher: BytesMut::new(),
        plain_buf: BytesMut::new(),
        in_eof: false,
        enc_buf: BytesMut::new(),
        enc_pos: 0,
        shutdown_started: false,
    })
}

impl<T> NoiseStream<T> {
    pub fn remote_static(&self) -> Option<&[u8; 32]> {
        self.remote_static.as_ref()
    }
}

impl<T> AsyncRead for NoiseStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.plain_buf.is_empty() {
                let n = buf.remaining().min(this.plain_buf.len());
                let chunk = this.plain_buf.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if this.in_eof {
                return Poll::Ready(Ok(()));
            }
            // 帧头：仅在新记录开始时读取（header_pos 跨 Pending 保留）
            if !this.in_body {
                while this.header_pos < 2 {
                    let mut tmp = [0u8; 2];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                this.in_eof = true;
                                if this.header_pos != 0 {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "record header truncated",
                                    )));
                                }
                                return Poll::Ready(Ok(()));
                            }
                            this.header[this.header_pos..this.header_pos + n]
                                .copy_from_slice(rb.filled());
                            this.header_pos += n;
                        }
                    }
                }
                this.rec_len = u16::from_be_bytes(this.header) as usize;
                this.rec_cipher.resize(this.rec_len, 0);
                this.rec_filled = 0;
                this.in_body = true;
            }
            // 密文体：从 rec_filled 续读（Pending 恢复安全，绝不重置进度）
            while this.rec_filled < this.rec_len {
                let mut rb = ReadBuf::new(&mut this.rec_cipher[this.rec_filled..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "record body truncated",
                            )));
                        }
                        this.rec_filled += n;
                    }
                }
            }
            let mut plain = vec![0u8; this.rec_len];
            let n = this
                .state
                .read_message(&this.rec_cipher[..], &mut plain)
                .map_err(|e| std::io::Error::other(format!("noise decrypt failed: {e}")))?;
            this.plain_buf.extend_from_slice(&plain[..n]);
            this.header_pos = 0;
            this.in_body = false;
        }
    }
}

impl<T> AsyncWrite for NoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.shutdown_started {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            )));
        }
        let mut written = 0;
        while written < buf.len() {
            let end = (written + NOISE_CHUNK).min(buf.len());
            let mut enc = vec![0u8; end - written + 16];
            let n = this
                .state
                .write_message(&buf[written..end], &mut enc)
                .map_err(|e| std::io::Error::other(format!("noise encrypt failed: {e}")))?;
            this.enc_buf.extend_from_slice(&(n as u16).to_be_bytes());
            this.enc_buf.extend_from_slice(&enc[..n]);
            written = end;
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.enc_pos < this.enc_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.enc_buf[this.enc_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => this.enc_pos += n,
            }
        }
        this.enc_buf.clear();
        this.enc_pos = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.shutdown_started = true;
        match Pin::new(&mut *this).poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn xx_handshake_and_bidirectional() {
        let (a_io, b_io) = duplex(1024 * 1024);
        let k1 = XStaticSecret::from([7u8; 32]);
        let k2 = XStaticSecret::from([9u8; 32]);

        let (r1, r2) = tokio::join!(
            handshake(a_io, Role::Initiator, &k1),
            handshake(b_io, Role::Responder, &k2),
        );
        let initiator = r1.unwrap();
        let mut responder = r2.unwrap();

        // 对端静态公钥可见（TOFU 指纹用）
        let expect: [u8; 32] = x25519_dalek::PublicKey::from(&k2).to_bytes();
        assert_eq!(*initiator.remote_static().unwrap(), expect);

        // 双向大流量（跨多条记录，触发分片与缓冲）
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let payload_len = payload.len();
        let writer = {
            let mut init = initiator;
            tokio::spawn(async move {
                init.write_all(&payload).await.unwrap();
                init.flush().await.unwrap();
                let mut back = vec![0u8; payload_len];
                init.read_exact(&mut back).await.unwrap();
                back
            })
        };
        let mut echoed = Vec::new();
        let mut tmp = vec![0u8; 8192];
        while echoed.len() < payload_len {
            let n = responder.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            echoed.extend_from_slice(&tmp[..n]);
        }
        {
            responder.write_all(&echoed[..payload_len]).await.unwrap();
            responder.flush().await.unwrap();
        }
        let got = writer.await.unwrap();
        assert_eq!(got, expected);
    }
}

#[cfg(test)]
mod frame_flow_tests {
    use super::*;
    use crate::frame::{read_frame, write_frame, Frame, FrameKind};
    use crate::msgs::{CloseInfo, CtrlMsg, SessionKind, SessionParams};
    use tokio::io::duplex;
    use x25519_dalek::StaticSecret as XStaticSecret;

    #[tokio::test]
    async fn handshake_then_big_frames() {
        let (a_io, b_io) = duplex(1024 * 1024);
        let k1 = XStaticSecret::from([7u8; 32]);
        let k2 = XStaticSecret::from([9u8; 32]);
        let (r1, r2) = tokio::join!(
            handshake(a_io, Role::Initiator, &k1),
            handshake(b_io, Role::Responder, &k2),
        );
        let cli = r1.unwrap();
        let mut agent = r2.unwrap();

        // 模拟 put 的 Open（~194B）与 64KB 数据块
        let mut open_payload = vec![b'x'; 190];
        open_payload[0] = 1; // Ctrl
        let open = Frame {
            kind: FrameKind::Ctrl,
            payload: open_payload,
        };
        let chunk1 = Frame::data(vec![7u8; 60_000]);
        let chunk1_expect = chunk1.payload.clone();
        assert_eq!(chunk1.payload.len(), crate::FILE_CHUNK);

        let writer = {
            let mut cli = cli;
            tokio::spawn(async move {
                write_frame(&mut cli, &open).await.unwrap();
                write_frame(&mut cli, &chunk1).await.unwrap();
                read_frame(&mut cli).await.unwrap().unwrap()
            })
        };
        let f = read_frame(&mut agent).await.unwrap().unwrap();
        assert_eq!(f.kind, FrameKind::Ctrl);
        let c = read_frame(&mut agent).await.unwrap().unwrap();
        if c.payload != chunk1_expect {
            let diff = c
                .payload
                .iter()
                .zip(chunk1_expect.iter())
                .position(|(a, b)| a != b);
            eprintln!(
                "[diff] len rx={} expect={} first_diff={:?}",
                c.payload.len(),
                chunk1_expect.len(),
                diff
            );
            if let Some(d) = diff {
                eprintln!(
                    "[diff] rx[{}]={:02x} expect={:02x}; rx[d+1..d+5]={:02x?}",
                    d,
                    c.payload[d],
                    chunk1_expect[d],
                    &c.payload[d + 1..d + 5]
                );
            }
            panic!("payload mismatch");
        }
        write_frame(&mut agent, &Frame::data(vec![9u8; 100]))
            .await
            .unwrap();
        let got = writer.await.unwrap();
        assert_eq!(got.payload, vec![9u8; 100]);
    }

    /// 复现真实会话流：握手 → Open 帧 → 两个 ping → echo。
    #[tokio::test]
    async fn handshake_then_frames() {
        let (a_io, b_io) = duplex(1024 * 1024);
        let k1 = XStaticSecret::from([7u8; 32]);
        let k2 = XStaticSecret::from([9u8; 32]);
        let (r1, r2) = tokio::join!(
            handshake(a_io, Role::Initiator, &k1),
            handshake(b_io, Role::Responder, &k2),
        );
        let cli = r1.unwrap();
        let mut agent = r2.unwrap();

        // CLI：Open + 两个 ping（真实尺寸）
        let open = Frame::ctrl(&CtrlMsg::Open {
            kind: SessionKind::Echo,
            params: SessionParams::default(),
        })
        .unwrap();
        let ping1 = Frame::data(vec![1u8; 64]);
        let ping1_expect = ping1.payload.clone();
        let ping2 = Frame::data(vec![2u8; 64]);
        let ping2_expect = ping2.payload.clone();

        let writer = {
            let mut cli = cli;
            tokio::spawn(async move {
                write_frame(&mut cli, &open).await.unwrap();
                write_frame(&mut cli, &ping1).await.unwrap();
                write_frame(&mut cli, &ping2).await.unwrap();
                // 读回两个 echo
                let e1 = read_frame(&mut cli).await.unwrap().unwrap();
                let e2 = read_frame(&mut cli).await.unwrap().unwrap();
                (e1, e2)
            })
        };

        // agent：Open → echo ×2
        let f = read_frame(&mut agent).await.unwrap().unwrap();
        assert_eq!(f.kind, FrameKind::Ctrl);
        let p1 = read_frame(&mut agent).await.unwrap().unwrap();
        assert_eq!(p1.kind, FrameKind::Data);
        write_frame(&mut agent, &Frame::data(p1.payload.clone()))
            .await
            .unwrap();
        let p2 = read_frame(&mut agent).await.unwrap().unwrap();
        assert_eq!(p2.kind, FrameKind::Data);
        write_frame(&mut agent, &Frame::data(p2.payload.clone()))
            .await
            .unwrap();

        let (e1, e2) = writer.await.unwrap();
        assert_eq!(e1.payload, ping1_expect);
        assert_eq!(e2.payload, ping2_expect);
    }

    /// 半关闭只关写侧，对端仍可回发数据。
    #[tokio::test]
    async fn shutdown_then_reverse_flow() {
        let (a_io, b_io) = duplex(1024 * 1024);
        let k1 = XStaticSecret::from([7u8; 32]);
        let k2 = XStaticSecret::from([9u8; 32]);
        let (r1, r2) = tokio::join!(
            handshake(a_io, Role::Initiator, &k1),
            handshake(b_io, Role::Responder, &k2),
        );
        let mut a = r1.unwrap();
        let mut b = r2.unwrap();

        write_frame(&mut a, &Frame::data(b"ping".to_vec()))
            .await
            .unwrap();
        write_frame(&mut a, &Frame::shutdown()).await.unwrap();

        // B 侧：收到 Data 后回发 pong + Close（Shutdown 不整条关流）
        let f = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(f.kind, FrameKind::Data);
        assert_eq!(f.payload, b"ping");
        write_frame(&mut b, &Frame::data(b"pong".to_vec()))
            .await
            .unwrap();
        write_frame(
            &mut b,
            &Frame::close(&CloseInfo {
                code: Some(0),
                reason: None,
            })
            .unwrap(),
        )
        .await
        .unwrap();

        // A 侧：先收到回程 pong，再收到关闭
        let pong = read_frame(&mut a).await.unwrap().unwrap();
        assert_eq!(pong.kind, FrameKind::Data);
        assert_eq!(pong.payload, b"pong");
        let close = read_frame(&mut a).await.unwrap().unwrap();
        assert_eq!(close.kind, FrameKind::Close);
    }
}
