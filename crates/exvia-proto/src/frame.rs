// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 会话内统一帧：`[1B kind][u16 BE len][payload]`。
//!
//! 帧写在 Noise 加密层之内（见 `noise::NoiseStream`），中继只见密文。
//! Data 帧的 payload 语义由会话类型约定：
//! - pty：纯字节
//! - exec：首字节 0=stdout / 1=stderr，其余为输出
//! - file / tcpfwd：纯字节

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{CloseInfo, CtrlMsg, MAX_FRAME_PAYLOAD};

pub const FRAME_HEADER_LEN: usize = 3;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame too large: {0}")]
    TooLarge(usize),
    #[error("unknown frame kind: {0}")]
    UnknownKind(u8),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Data = 0,
    Ctrl = 1,
    Close = 2,
    /// 半关闭：本流上发送方不再发 Data；接收方应向下游传播写侧关闭
    /// （TCP shutdown write），读侧继续排空，可继续回发数据。
    Shutdown = 3,
}

impl FrameKind {
    pub fn from_u8(v: u8) -> Result<Self, FrameError> {
        match v {
            0 => Ok(Self::Data),
            1 => Ok(Self::Ctrl),
            2 => Ok(Self::Close),
            3 => Ok(Self::Shutdown),
            other => Err(FrameError::UnknownKind(other)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn data(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind: FrameKind::Data,
            payload: payload.into(),
        }
    }

    pub fn shutdown() -> Self {
        Self {
            kind: FrameKind::Shutdown,
            payload: Vec::new(),
        }
    }

    pub fn ctrl(msg: &CtrlMsg) -> Result<Self, FrameError> {
        Ok(Self {
            kind: FrameKind::Ctrl,
            payload: serde_json::to_vec(msg).map_err(|_| {
                FrameError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ctrl encode failed",
                ))
            })?,
        })
    }

    pub fn close(info: &CloseInfo) -> Result<Self, FrameError> {
        Ok(Self {
            kind: FrameKind::Close,
            payload: serde_json::to_vec(info).map_err(|_| {
                FrameError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "close encode failed",
                ))
            })?,
        })
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        if self.payload.len() > MAX_FRAME_PAYLOAD {
            return Err(FrameError::TooLarge(self.payload.len()));
        }
        out.push(self.kind as u8);
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut buf = Vec::with_capacity(self.payload.len() + FRAME_HEADER_LEN);
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    #[cfg(test)]
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), FrameError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete frame header",
            )));
        }
        let kind = FrameKind::from_u8(buf[0])?;
        let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let total = FRAME_HEADER_LEN + len;
        if buf.len() < total {
            return Err(FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete frame body",
            )));
        }
        Ok((
            Self {
                kind,
                payload: buf[FRAME_HEADER_LEN..total].to_vec(),
            },
            total,
        ))
    }

    pub fn ctrl_msg(&self) -> Result<CtrlMsg, FrameError> {
        serde_json::from_slice(&self.payload).map_err(|_| {
            FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ctrl decode failed",
            ))
        })
    }

    pub fn close_info(&self) -> Result<CloseInfo, FrameError> {
        serde_json::from_slice(&self.payload).map_err(|_| {
            FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "close decode failed",
            ))
        })
    }
}

/// 从流上读一帧；对端干净关闭（帧边界处 EOF）时返回 None。
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>, FrameError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    let kind = FrameKind::from_u8(header[0])?;
    Ok(Some(Frame { kind, payload }))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame: &Frame,
) -> Result<(), FrameError> {
    let buf = frame.encode()?;
    w.write_all(&buf).await?;
    // 分层写侧先缓冲，flush 才落盘，否则帧滞留
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::{SessionKind, SessionParams};

    #[tokio::test]
    async fn frame_roundtrip() {
        let cases = vec![
            Frame::data(vec![1u8; 100]),
            Frame::data(vec![]),
            Frame::ctrl(&CtrlMsg::Open {
                kind: SessionKind::Pty,
                params: SessionParams {
                    cols: Some(80),
                    rows: Some(24),
                    ..Default::default()
                },
            })
            .unwrap(),
            Frame::close(&CloseInfo {
                code: Some(0),
                reason: Some("done".into()),
            })
            .unwrap(),
        ];
        for f in cases {
            let mut buf = Vec::new();
            f.encode_into(&mut buf).unwrap();
            let (back, used) = Frame::decode(&buf).unwrap();
            assert_eq!(used, buf.len());
            assert_eq!(back.kind, f.kind);
            assert_eq!(back.payload, f.payload);
        }
    }

    #[tokio::test]
    async fn stream_frames() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let frames = vec![
            Frame::data(b"hello".to_vec()),
            Frame::ctrl(&CtrlMsg::Resize {
                cols: 120,
                rows: 40,
            })
            .unwrap(),
            Frame::close(&CloseInfo::default()).unwrap(),
        ];
        let writer = tokio::spawn(async move {
            for f in &frames {
                write_frame(&mut client, f).await.unwrap();
            }
        });
        let mut read_back = Vec::new();
        while let Some(f) = read_frame(&mut server).await.unwrap() {
            read_back.push(f);
        }
        writer.await.unwrap();
        assert_eq!(read_back.len(), 3);
        assert_eq!(read_back[0].payload, b"hello");
        assert!(matches!(
            read_back[1].ctrl_msg().unwrap(),
            CtrlMsg::Resize {
                cols: 120,
                rows: 40
            }
        ));
    }

    /// 解码器不得因任意字节串 panic 或越界分配。
    /// 用确定性伪随机覆盖崩溃边界（没有 cargo-fuzz 时的最低保障）。
    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 64) as usize;
            let buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            if let Ok((frame, used)) = Frame::decode(&buf) {
                // 成功解析时必须自洽：消耗量不超过输入，且与声明长度一致
                assert!(used <= buf.len());
                assert_eq!(used, FRAME_HEADER_LEN + frame.payload.len());
            }
        }
    }

    /// 编码-解码往返：任意合法载荷与任意 kind 都还原原样。
    #[test]
    fn encode_decode_roundtrip_for_random_payloads() {
        let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let kinds = [
            FrameKind::Data,
            FrameKind::Ctrl,
            FrameKind::Close,
            FrameKind::Shutdown,
        ];
        for i in 0..2_000 {
            // 覆盖空载荷、1 字节、恰好上限与随机长度
            let len = match i % 4 {
                0 => 0,
                1 => 1,
                2 => MAX_FRAME_PAYLOAD,
                _ => (next() as usize) % MAX_FRAME_PAYLOAD,
            };
            let payload: Vec<u8> = (0..len.min(4096)).map(|_| (next() & 0xff) as u8).collect();
            let frame = Frame {
                kind: kinds[(next() % 4) as usize],
                payload,
            };
            let encoded = frame.encode().unwrap();
            let (back, used) = Frame::decode(&encoded).unwrap();
            assert_eq!(used, encoded.len());
            assert_eq!(back.kind, frame.kind);
            assert_eq!(back.payload, frame.payload);
        }
        // 超限载荷必须被拒绝，而不是截断后发出去
        let too_big = Frame::data(vec![0u8; MAX_FRAME_PAYLOAD + 1]);
        assert!(too_big.encode().is_err());
    }
}
