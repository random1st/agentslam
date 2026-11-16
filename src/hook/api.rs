//! Server endpoints used by `agentslam hook prompt|stop`. Bearer-authenticated
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
