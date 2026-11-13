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
        .route("/api/rooms/{name}/topic", post(set_topic))
        .route("/api/agent-tokens", post(mint_token))
        .route("/api/credentials/{family}/revoke", post(revoke))
        .route("/api/admin/link", post(admin_link))
        .route("/api/org", get(org_info))
        .route("/api/org/admins", post(org_add_admin))
        .route("/api/org/okta", post(org_add_okta))
        .route(
            "/api/org/service-accounts",
            get(service_accounts).post(create_service_account),
        )
        .route(
            "/api/org/service-accounts/{name}/tokens",
            post(mint_service_token),
        )
        .route("/api/operator/orgs", get(operator_orgs))
        .route(
            "/api/operator/orgs/{id}/disable",
            post(operator_disable_org),
        )
        .route("/api/operator/orgs/{id}/enable", post(operator_enable_org))
        .route("/api/operator/orgs/{id}/admins", post(operator_add_admin))
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
        // Signed in but the organization does not exist yet: offer to create it.
        Some(s) if s.identity.org_key.is_some() && s.identity.person_id.is_none() => {
            Redirect::to("/org/create").into_response()
        }
        // Signed out, or a session from before names were derived: sign in.
        _ => Redirect::to("/login").into_response(),
    }
}

pub fn person(user: &WebUser) -> Person {
    Person {
        person_id: user.person_id,
        org_id: user.org_id,
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
        "is_operator": user.session.is_operator,
        "org": {"name": user.org_name},
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
struct TopicRequest {
    topic: String,
}

/// B4: the owner or an org admin changes the room topic.
async fn set_topic(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(req): Json<TopicRequest>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    service::set_topic(&state, person(&user), name, &req.topic).await?;
    Ok(ok())
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
    mint_for(&state, user.person_id, &user.handle, req.label).await
}

/// The one token path for people and service accounts: get or create the
/// agent `<owner>/<label>` of `person_id`, mint a headless token, return it
/// once (`no-store`).
async fn mint_for(state: &Shared, pid: i64, owner: &str, label: String) -> Result<Response> {
    let now = state.clock.now();
    let resource = state.config.mcp_resource();
    let l = label.clone();
    let (raw, family) = state
        .db
        .call(move |c| {
            let agent_id = people::agent_get_or_create(c, pid, &l, now)?;
            tokens::mint_agent_token(c, agent_id, &resource, now)
        })
        .await?;
    let mut resp = (
        StatusCode::CREATED,
        Json(json!({
            "agent": format!("{owner}/{label}"),
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
    let org_id = user.org_id;
    let agent_id = state
        .db
        .call(move |c| {
            // Scoped to the caller's organization: another org's credential is "not found".
            let owner: Option<i64> = rusqlite::OptionalExtension::optional(c.query_row(
                "SELECT a.person_id FROM tokens t JOIN agents a ON a.id = t.agent_id
                 JOIN persons p ON p.id = a.person_id
                 WHERE t.family_id = ?1 AND p.org_id = ?2 LIMIT 1",
                rusqlite::params![family, org_id],
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
    let org_id = user.org_id;
    state
        .db
        .call(move |c| people::link_identity(c, org_id, &req.issuer, &req.sub, &req.handle))
        .await?;
    Ok(ok())
}

// ---------------------------------------------------------------- organization (B13)

/// The person's organization: name, admins, connected Okta (never its secret).
async fn org_info(State(state): State<Shared>, user: WebUser) -> Result<Json<serde_json::Value>> {
    let org_id = user.org_id;
    let (admins, okta): (Vec<String>, Vec<serde_json::Value>) = state
        .db
        .call(move |c| {
            let admins = {
                let mut s = c.prepare(
                    "SELECT p.handle FROM org_admins a JOIN persons p ON p.id = a.person_id
                     WHERE a.org_id = ?1 ORDER BY p.handle",
                )?;
                s.query_map([org_id], |r| r.get(0))?
                    .collect::<rusqlite::Result<Vec<String>>>()?
            };
            let okta = {
                let mut s = c.prepare(
                    "SELECT id, issuer, client_id, created_at FROM okta_connections WHERE org_id = ?1 ORDER BY id",
                )?;
                s.query_map([org_id], |r| {
                    let id: i64 = r.get(0)?;
                    Ok(json!({
                        "id": id,
                        "issuer": r.get::<_, String>(1)?,
                        "client_id": r.get::<_, String>(2)?,
                        "created_at": r.get::<_, i64>(3)?,
                        "sign_in_path": format!("/login/okta/{id}"),
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
            };
            Ok((admins, okta))
        })
        .await?;
    Ok(Json(json!({
        "name": user.org_name,
        "is_admin": user.session.is_admin,
        "admins": admins,
        "okta_connections": okta,
        "can_store_secrets": state.config.secret_key.is_some(),
    })))
}

fn require_org_admin(user: &WebUser) -> Result<()> {
    if user.session.is_admin {
        Ok(())
    } else {
        Err(Error::Forbidden(
            "only an admin of your organization can do this".into(),
        ))
    }
}

#[derive(Deserialize)]
struct AdminRequest {
    handle: String,
}

/// An org admin names another person of the same organization as admin.
async fn org_add_admin(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Json(req): Json<AdminRequest>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    require_org_admin(&user)?;
    let org_id = user.org_id;
    let now = state.clock.now();
    state
        .db
        .call(move |c| {
            let pid: i64 = rusqlite::OptionalExtension::optional(c.query_row(
                "SELECT id FROM persons WHERE handle = ?1 AND org_id = ?2 AND is_service = 0",
                rusqlite::params![req.handle, org_id],
                |r| r.get(0),
            ))?
            .ok_or(Error::NotFound)?;
            crate::identity::orgs::add_admin(c, org_id, pid, now)
        })
        .await?;
    Ok(ok())
}

#[derive(Deserialize)]
struct OktaRequest {
    issuer: String,
    client_id: String,
    client_secret: String,
}

/// An org admin connects the organization's Okta. The secret is stored
/// AES-GCM encrypted and no API returns it.
async fn org_add_okta(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Json(req): Json<OktaRequest>,
) -> Result<Response> {
    check_csrf(&user.session, &headers, None)?;
    require_org_admin(&user)?;
    let Some(key) = state.config.secret_key else {
        return Err(Error::BadRequest(
            "this server cannot store secrets: AGENTSLAM_SECRET_KEY is not set".into(),
        ));
    };
    let issuer = req.issuer.trim().trim_end_matches('/').to_string();
    let parsed = url::Url::parse(&issuer)
        .map_err(|_| Error::BadRequest("the Okta address must be a URL".into()))?;
    if parsed.scheme() != "https" && !state.config.allow_insecure_http_for_tests {
        return Err(Error::BadRequest(
            "the Okta address must start with https://".into(),
        ));
    }
    if req.client_id.trim().is_empty() || req.client_secret.is_empty() {
        return Err(Error::BadRequest(
            "client ID and client secret are required".into(),
        ));
    }
    let enc = crate::identity::orgs::encrypt_secret(&key, &req.client_secret)?;
    let org_id = user.org_id;
    let now = state.clock.now();
    let client_id = req.client_id.trim().to_string();
    let id: i64 = state
        .db
        .call(move |c| {
            c.execute(
                "INSERT INTO okta_connections (org_id, issuer, client_id, secret_enc, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![org_id, issuer, client_id, enc, now],
            )?;
            Ok(c.last_insert_rowid())
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "sign_in_path": format!("/login/okta/{id}")})),
    )
        .into_response())
}

// ---------------------------------------------------------------- service accounts (B13a)

#[derive(Deserialize)]
struct ServiceAccountRequest {
    name: String,
}

/// An org admin creates a service account: a person of the organization
/// with no sign-in identity, for agents that run on servers.
async fn create_service_account(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Json(req): Json<ServiceAccountRequest>,
) -> Result<Response> {
    check_csrf(&user.session, &headers, None)?;
    require_org_admin(&user)?;
    let org_id = user.org_id;
    let now = state.clock.now();
    let name = req.name.trim().to_string();
    let n = name.clone();
    state
        .db
        .call(move |c| people::create_service_account(c, org_id, &n, now))
        .await?;
    Ok((StatusCode::CREATED, Json(json!({"name": name}))).into_response())
}

/// The organization's service accounts with their agents (org admins only).
async fn service_accounts(
    State(state): State<Shared>,
    user: WebUser,
) -> Result<Json<serde_json::Value>> {
    require_org_admin(&user)?;
    let org_id = user.org_id;
    let now = state.clock.now();
    let accounts: Vec<serde_json::Value> = state
        .db
        .call(move |c| {
            let mut out = Vec::new();
            for (pid, name, created_at) in people::service_accounts(c, org_id)? {
                let agents = people::agents_of_person(c, pid, now)?;
                out.push(json!({"name": name, "created_at": created_at, "agents": agents}));
            }
            Ok(out)
        })
        .await?;
    Ok(Json(json!({"service_accounts": accounts})))
}

#[derive(Deserialize)]
struct ServiceTokenRequest {
    agent: String,
}

/// Mint a headless token for an agent of a service account (shown once).
/// Revocation is the normal credential revoke, which org admins may use.
async fn mint_service_token(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(req): Json<ServiceTokenRequest>,
) -> Result<Response> {
    check_csrf(&user.session, &headers, None)?;
    require_org_admin(&user)?;
    let org_id = user.org_id;
    let n = name.clone();
    let pid = state
        .db
        .call(move |c| people::service_account_id(c, org_id, &n))
        .await?;
    mint_for(&state, pid, &name, req.agent.trim().to_string()).await
}

/// Instance operators (config `admins`, the super admins, B13) list
/// organizations, disable or re-enable one and name an admin in any of them.
/// They never read another organization's rooms or messages: every room view
/// stays scoped to the operator's own organization.
fn require_operator(user: &WebUser) -> Result<()> {
    if user.session.is_operator {
        Ok(())
    } else {
        Err(Error::Forbidden("instance operators only".into()))
    }
}

async fn operator_orgs(
    State(state): State<Shared>,
    user: WebUser,
) -> Result<Json<serde_json::Value>> {
    require_operator(&user)?;
    let orgs: Vec<serde_json::Value> = state
        .db
        .call(|c| {
            let mut s = c.prepare(
                "SELECT o.id, o.name, o.key_kind, o.disabled_at IS NOT NULL,
                   (SELECT group_concat(handle, ', ') FROM (SELECT p.handle FROM org_admins a
                      JOIN persons p ON p.id = a.person_id WHERE a.org_id = o.id ORDER BY p.handle))
                 FROM organizations o ORDER BY o.name",
            )?;
            Ok(s.query_map([], |r| {
                let admins: Option<String> = r.get(4)?;
                let admins: Vec<&str> = admins
                    .as_deref()
                    .map(|a| a.split(", ").collect())
                    .unwrap_or_default();
                Ok(
                    json!({"id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
                          "kind": r.get::<_, String>(2)?, "disabled": r.get::<_, bool>(3)?,
                          "admins": admins}),
                )
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await?;
    Ok(Json(json!({"organizations": orgs})))
}

async fn operator_enable_org(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    require_operator(&user)?;
    state
        .db
        .call(move |c| {
            let n = c.execute(
                "UPDATE organizations SET disabled_at = NULL WHERE id = ?1 AND disabled_at IS NOT NULL",
                [id],
            )?;
            if n == 0 {
                return Err(Error::NotFound);
            }
            Ok(())
        })
        .await?;
    Ok(ok())
}

/// An operator names an existing person of organization `id` as its admin.
async fn operator_add_admin(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<AdminRequest>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    require_operator(&user)?;
    let now = state.clock.now();
    state
        .db
        .call(move |c| {
            let pid: i64 = rusqlite::OptionalExtension::optional(c.query_row(
                "SELECT id FROM persons WHERE handle = ?1 AND org_id = ?2 AND is_service = 0",
                rusqlite::params![req.handle.trim(), id],
                |r| r.get(0),
            ))?
            .ok_or(Error::NotFound)?;
            crate::identity::orgs::add_admin(c, id, pid, now)
        })
        .await?;
    Ok(ok())
}

async fn operator_disable_org(
    State(state): State<Shared>,
    user: WebUser,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>> {
    check_csrf(&user.session, &headers, None)?;
    require_operator(&user)?;
    let now = state.clock.now();
    let agents: Vec<i64> = state
        .db
        .call(move |c| {
            let n = c.execute(
                "UPDATE organizations SET disabled_at = ?2 WHERE id = ?1 AND disabled_at IS NULL",
                rusqlite::params![id, now],
            )?;
            if n == 0 {
                return Err(Error::NotFound);
            }
            let mut s = c.prepare(
                "SELECT a.id FROM agents a JOIN persons p ON p.id = a.person_id WHERE p.org_id = ?1",
            )?;
            Ok(s.query_map([id], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<i64>>>()?)
        })
        .await?;
    // Open waits of that organization's agents re-check and end (tokens no longer resolve).
    for agent_id in agents {
        state.hub.publish(Event::AccessChanged {
            agent_id,
            room_id: None,
        });
    }
    Ok(ok())
}
