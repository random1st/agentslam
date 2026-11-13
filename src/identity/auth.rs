//! Bearer authentication for `/mcp` (and the hook endpoints). The caller is
//! derived from the token only (inv.agentslam.identity-from-token) and the
//! token is checked against the store on every request, so revocation is
//! immediate.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::core::{Result, Shared};
use crate::identity::Caller;
use crate::identity::people::touch_agent;
use crate::identity::tokens::{caller_for_hash, hash};

pub fn prm_url(state: &Shared) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource/mcp",
        state.config.issuer()
    )
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() {
        Some(token.trim())
    } else {
        None
    }
}

/// Resolve the bearer token in `headers` to a caller and record presence.
pub async fn caller_from_headers(state: &Shared, headers: &HeaderMap) -> Result<Option<Caller>> {
    let Some(token) = bearer(headers) else {
        return Ok(None);
    };
    let token_hash = hash(token);
    let resource = state.config.mcp_resource();
    let now = state.clock.now();
    state
        .db
        .call(move |c| {
            let caller = caller_for_hash(c, &token_hash, &resource, now)?;
            if let Some(caller) = &caller {
                touch_agent(c, caller.agent_id, now)?;
            }
            Ok(caller)
        })
        .await
}

/// Is the token behind `caller` still valid right now?
pub async fn still_valid(state: &Shared, caller: &Caller) -> Result<bool> {
    let token_hash = caller.token_hash.clone();
    let resource = state.config.mcp_resource();
    let now = state.clock.now();
    state
        .db
        .call(move |c| Ok(caller_for_hash(c, &token_hash, &resource, now)?.is_some()))
        .await
}

pub fn unauthorized(state: &Shared, invalid_token: bool) -> Response {
    let mut value = format!("Bearer resource_metadata=\"{}\"", prm_url(state));
    if invalid_token {
        value.push_str(", error=\"invalid_token\"");
    }
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": "unauthorized"})),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&value) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    resp
}

/// axum middleware in front of the rmcp service.
pub async fn mcp_auth(State(state): State<Shared>, mut req: Request, next: Next) -> Response {
    let has_token = bearer(req.headers()).is_some();
    match caller_from_headers(&state, req.headers()).await {
        Ok(Some(caller)) => {
            req.extensions_mut().insert(caller);
            next.run(req).await
        }
        Ok(None) => unauthorized(&state, has_token),
        Err(e) => e.into_response(),
    }
}
