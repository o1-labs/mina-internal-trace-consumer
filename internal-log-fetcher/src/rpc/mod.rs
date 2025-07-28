// Copyright (c) Viable Systems
// SPDX-License-Identifier: Apache-2.0

pub mod filters;
pub mod handlers;

use tokio::task::JoinHandle;

use crate::{SharedAvailableNodes, SharedManager};

pub fn spawn_rpc_server(
    rpc_port: u16,
    shared_manager: SharedManager,
    available_nodes: SharedAvailableNodes,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let api = filters::filters(shared_manager, available_nodes);

        warp::serve(api).run(([0, 0, 0, 0], rpc_port)).await;
    })
}
