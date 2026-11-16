//! Server endpoints used by `agentslam hook prompt|stop` and `agentslam watch`. Bearer-authenticated
//! like `/mcp`; the session key comes from the host's stdin (session id).

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::core::Shared;
use crate::identity::auth::{caller_from_headers, unauthorized};
use crate::rooms::service;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/hook/prompt", post(prompt))
        .route("/hook/stop", post(stop))
        .route("/hook/wait", post(wait))
}

#[derive(Deserialize)]
pub struct WaitRequest {
    pub session_id: String,
    #[serde(default = "default_wait_s")]
    pub timeout_s: u64,
}

fn default_wait_s() -> u64 {
    45
}

/// Long poll for `agentslam watch`: the session's attached rooms, cursors
/// advance on delivery (same as room_wait without `rooms`).
async fn wait(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<WaitRequest>,
) -> Response {
    let caller = match caller_from_headers(&state, &headers).await {
        Ok(Some(c)) => c,
        Ok(None) => return unauthorized(&state, true),
        Err(e) => return e.into_response(),
    };
    let session = match service::validate_session(req.session_id.trim()) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    match service::wait(&state, &caller, session, None, req.timeout_s).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
pub struct HookRequest {
    pub session_id: String,
}

async fn prompt(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<HookRequest>,
) -> Response {
    let caller = match caller_from_headers(&state, &headers).await {
        Ok(Some(c)) => c,
        Ok(None) => return unauthorized(&state, true),
        Err(e) => return e.into_response(),
    };
    let session = match service::validate_session(req.session_id.trim()) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    match service::unread(&state, &caller, session, true).await {
        Ok(msgs) => Json(json!({"messages": msgs})).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn stop(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<HookRequest>,
) -> Response {
    let caller = match caller_from_headers(&state, &headers).await {
        Ok(Some(c)) => c,
        Ok(None) => return unauthorized(&state, true),
        Err(e) => return e.into_response(),
    };
    let session = match service::validate_session(req.session_id.trim()) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    match service::unread(&state, &caller, session, false).await {
        Ok(msgs) => {
            let mut by_room = std::collections::BTreeMap::<String, usize>::new();
            for m in &msgs {
                *by_room.entry(m.room.clone()).or_default() += 1;
            }
            Json(json!({"unread": msgs.len(), "by_room": by_room})).into_response()
        }
        Err(e) => e.into_response(),
    }
}
