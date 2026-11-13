//! Web UI: embedded static page + JSON API (cookie session) + SSE.
//! Every POST is an owner/person action and requires the `X-CSRF-Token`
//! header (B12, inv.agentslam.human-only-admission).

pub mod sse;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::core::{Error, Result, Shared};
use crate::identity::people;
use crate::identity::session::{MaybeSession, WebUser, check_csrf};
use crate::identity::tokens;
use crate::rooms::notify::Event;
use crate::rooms::service::{self, Person};

const INDEX_HTML: &str = include_str!("../../web/index.html");
const APP_JS: &str = include_str!("../../web/app.js");
const STYLE_CSS: &str = include_str!("../../web/style.css");

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/", get(index))
        .route(
            "/static/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }),
        )
        .route(
            "/static/style.css",
            get(|| async { asset("text/css; charset=utf-8", STYLE_CSS) }),
        )
        .route("/api/me", get(me))
        .route("/api/requests", get(requests))
        .route("/api/rooms", get(rooms))
        .route("/api/rooms/{name}", get(room))
        .route("/api/rooms/{name}/events", get(sse::events))
        .route("/api/rooms/{name}/requests/{id}/confirm", post(confirm))
        .route("/api/rooms/{name}/requests/{id}/reject", post(reject))
        .route("/api/rooms/{name}/members/{agent_id}/remove", post(remove))
        .route("/api/rooms/{name}/archive", post(archive))
        .route("/api/rooms/{name}/unarchive", post(unarchive))
        .route("/api/rooms/{name}/delete", post(delete))
        .route("/api/agent-tokens", post(mint_token))
        .route("/api/credentials/{family}/revoke", post(revoke))
        .route("/api/admin/link", post(admin_link))
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn index(MaybeSession(sess): MaybeSession) -> Response {
    match sess {
        Some(s) if s.person_id.is_some() => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            INDEX_HTML
                .replace(
                    "/static/style.css\"",
                    &format!(
                        "/static/style.css?v={}\"",
                        *crate::core::html::ASSET_VERSION
                    ),
                )
                .replace(
                    "/static/app.js\"",
                    &format!("/static/app.js?v={}\"", *crate::core::html::ASSET_VERSION),
                ),
        )
            .into_response(),
        // Signed out, or a session from before names were derived: sign in.
        _ => Redirect::to("/login").into_response(),
    }
}

pub fn person(user: &WebUser) -> Person {
    Person {
        person_id: user.person_id,
        is_admin: user.session.is_admin,
    }
}

async fn me(State(state): State<Shared>, user: WebUser) -> Result<Json<serde_json::Value>> {
    let now = state.clock.now();
    let pid = user.person_id;
    let agents = state
        .db
        .call(move |c| people::agents_of_person(c, pid, now))
        .await?;
    Ok(Json(json!({
        "handle": user.handle,
        "is_admin": user.session.is_admin,
        "csrf": user.session.csrf,
        "identity": {"issuer": user.session.identity.issuer, "sub": user.session.identity.sub, "provider": user.session.identity.provider_id, "email": user.session.identity.email},
        "agents": agents,
        "mcp_url": state.config.mcp_resource(),
    })))
}

/// Pending join requests in every room the person governs (owner; admin: all),
/// so they can be the first thing on the page (B11).
async fn requests(State(state): State<Shared>, user: WebUser) -> Result<Json<serde_json::Value>> {
    let pending = service::pending_requests(&state, person(&user)).await?;
    Ok(Json(json!({"requests": pending})))
}

async fn rooms(State(state): State<Shared>, user: WebUser) -> Result<Json<serde_json::Value>> {
    let rooms = service::visible_rooms(&state, person(&user)).await?;
    Ok(Json(json!({"rooms": rooms})))
}

async fn room(
    State(state): State<Shared>,
    user: WebUser,
    Path(name): Path<String>,
) -> Result<Json<service::RoomDetail>> {
    Ok(Json(
        service::room_detail(&state, person(&user), name).await?,
    ))
}

fn ok() -> Json<serde_json::Value> {
    Json(json!({"ok": true}))
}

async fn confirm(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path((name, id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    service::confirm_request(&state, person(&user), name, id).await?;
    Ok(ok())
}

async fn reject(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path((name, id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    service::reject_request(&state, person(&user), name, id).await?;
    Ok(ok())
}

async fn remove(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path((name, agent_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    service::remove_member(&state, person(&user), name, agent_id).await?;
    Ok(ok())
}

async fn lifecycle(
    state: Shared,
    user: WebUser,
    headers: HeaderMap,
    name: String,
    target: &'static str,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    service::set_state(&state, person(&user), name, target).await?;
    Ok(ok())
}

async fn archive(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    lifecycle(state, user, headers, name, "archived").await
}

async fn unarchive(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    lifecycle(state, user, headers, name, "active").await
}

async fn delete(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    lifecycle(state, user, headers, name, "deleted").await
}

#[derive(Deserialize)]
struct MintRequest {
    label: String,
}

/// B3: mint a headless agent token. The raw token is returned once and
/// only its hash is stored.
async fn mint_token(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Json(req): Json<MintRequest>,
) -> Result<Response> {
    check_csrf(&user.session, &headers, None)?;
    let now = state.clock.now();
    let pid = user.person_id;
    let resource = state.config.mcp_resource();
    let label = req.label.clone();
    let (raw, family) = state
        .db
        .call(move |c| {
            let agent_id = people::agent_get_or_create(c, pid, &label, now)?;
            tokens::mint_agent_token(c, agent_id, &resource, now)
        })
        .await?;
    let mut resp = (
        StatusCode::CREATED,
        Json(json!({
            "agent": format!("{}/{}", user.handle, req.label),
            "token": raw,
            "family_id": family,
            "note": "shown once; store it in your secret manager",
        })),
    )
        .into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

/// Revoke a credential (headless token or OAuth grant) of one of the
/// person's agents (admins: any). Ends that agent's open waits at once.
async fn revoke(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    let now = state.clock.now();
    let pid = user.person_id;
    let admin = user.session.is_admin;
    let agent_id = state
        .db
        .call(move |c| {
            let owner: Option<i64> = rusqlite::OptionalExtension::optional(c.query_row(
                "SELECT a.person_id FROM tokens t JOIN agents a ON a.id = t.agent_id WHERE t.family_id = ?1 LIMIT 1",
                [&family],
                |r| r.get(0),
            ))?;
            match owner {
                None => Err(Error::NotFound),
                Some(o) if o != pid && !admin => Err(Error::Forbidden("not your agent".into())),
                Some(_) => tokens::revoke_family(c, &family, now),
            }
        })
        .await?;
    if let Some(agent_id) = agent_id {
        state.hub.publish(Event::AccessChanged {
            agent_id,
            room_id: None,
        });
    }
    Ok(ok())
}

#[derive(Deserialize)]
struct LinkRequest {
    issuer: String,
    sub: String,
    handle: String,
}

/// B1: the admin links a second provider identity to an existing person.
async fn admin_link(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Json(req): Json<LinkRequest>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    if !user.session.is_admin {
        return Err(Error::Forbidden("admin only".into()));
    }
    state
        .db
        .call(move |c| people::link_identity(c, &req.issuer, &req.sub, &req.handle))
        .await?;
    Ok(ok())
}
