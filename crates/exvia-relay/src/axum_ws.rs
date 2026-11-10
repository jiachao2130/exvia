// Copyright (c) 2026 Jia Chao
// exvia is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 中继侧 WebSocket 适配别名与连接公共接线；归一化实现在 proto 的 `axum-ws` feature 里。

use tokio::sync::mpsc;

use exvia_proto::io::{BoundedTextSink, WsByteStream};
use exvia_proto::mux::{Mux, MuxStream};

pub type AxumWs =
    WsByteStream<axum::extract::ws::WebSocket, axum::extract::ws::Message, axum::Error>;

pub type RelayMux = std::sync::Arc<exvia_proto::mux::Mux<AxumWs>>;

/// agent / cli 控制面连接的公共接线：控制面通道对 → AxumWs → Mux → 入向驱动。
/// 返回 (mux, 入向文本流, 出向文本口, 入向驱动句柄)。incoming_tx 的所有权交给
/// 适配器，对端关闭时控制循环的 recv() 才能立刻返回 None；relay 只在该连接上
/// 打开流，入向流（回声）一律即弃。
pub fn wire_relay_ws(
    ws: axum::extract::ws::WebSocket,
) -> (
    RelayMux,
    mpsc::Receiver<String>,
    mpsc::Sender<String>,
    tokio::task::JoinHandle<()>,
) {
    let (incoming_tx, incoming_rx) = mpsc::channel::<String>(crate::state::CONTROL_QUEUE);
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<String>(crate::state::CONTROL_QUEUE);
    let adapter = AxumWs::new(ws, BoundedTextSink::new(incoming_tx), outgoing_rx);
    let mux: RelayMux = Mux::new(adapter, yamux::Mode::Client);
    let driver =
        exvia_proto::mux::spawn_inbound_driver(mux.clone(), |stream: MuxStream| drop(stream));
    (mux, incoming_rx, outgoing_tx, driver)
}
