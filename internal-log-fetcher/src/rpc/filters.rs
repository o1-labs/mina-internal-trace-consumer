// Copyright (c) Viable Systems
// SPDX-License-Identifier: Apache-2.0

use warp::Filter;

use crate::{SharedAvailableNodes, SharedManager};

use super::handlers::{
    freeze_nodes_handle, get_nodes_handle, reset_nodes_handle, unfreeze_nodes_handle,
};

pub fn filters(
    shared_manager: SharedManager,
    available_nodes: SharedAvailableNodes,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    // Allow cors from any origin
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type"])
        .allow_methods(vec!["GET"]);

    get_nodes(available_nodes)
        .or(reset_nodes(shared_manager.clone()))
        .or(freeze_nodes(shared_manager.clone()))
        .or(unfreeze_nodes(shared_manager))
        .with(cors)
}

fn get_nodes(
    available_nodes: SharedAvailableNodes,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("nodes")
        .and(warp::get())
        .and(with_shared_data(available_nodes))
        .and_then(get_nodes_handle)
}

fn reset_nodes(
    manager: SharedManager,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("reset")
        .and(warp::post())
        .and(with_shared_manager(manager))
        .and_then(reset_nodes_handle)
}

fn freeze_nodes(
    manager: SharedManager,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("freeze")
        .and(warp::post())
        .and(with_shared_manager(manager))
        .and_then(freeze_nodes_handle)
}

fn unfreeze_nodes(
    manager: SharedManager,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("unfreeze")
        .and(warp::post())
        .and(with_shared_manager(manager))
        .and_then(unfreeze_nodes_handle)
}

fn with_shared_data(
    available_nodes: SharedAvailableNodes,
) -> impl Filter<Extract = (SharedAvailableNodes,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || available_nodes.clone())
}

fn with_shared_manager(
    shared_manager: SharedManager,
) -> impl Filter<Extract = (SharedManager,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || shared_manager.clone())
}
