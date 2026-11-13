//! OAuth 2.1 authorization server for MCP clients plus the upstream sign-in
//! flow: PRM (RFC 9728), AS metadata (RFC 8414), /authorize with CIMD
//! allowlist + redirect validation, sign-in (the person and its name are
//! derived at first sign-in, B1), consent with the agent name, and /token
//! (PKCE S256, single-use codes, rotating refresh tokens, RFC 8707 resource
//! binding).

use std::collections::HashMap;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::{OptionalExtension, params};
use serde_json::json;

use crate::core::config::{ProviderConfig, ProviderKind};
use crate::core::html::{error_page_action, esc, html_response};
use crate::core::{Error, Result, Shared};
use crate::identity::cimd::{CimdError, redirect_allowed};
use crate::identity::oidc::LoginError;
use crate::identity::orgs;
use crate::identity::people;
use crate::identity::session::{
    self, LOGIN_COOKIE, MaybeSession, WebSession, check_csrf, read_cookie, set_cookie,
};
use crate::identity::tokens::{self, IssueParams, hash, pkce_s256, random_token};

const OAUTH_REQUEST_TTL_S: i64 = 900;
const LOGIN_STATE_TTL_S: i64 = 600;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(prm))
        .route("/.well-known/oauth-protected-resource/mcp", get(prm))
        .route("/.well-known/oauth-authorization-server", get(as_metadata))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/login", get(login_page))
        .route("/login/{provider}", get(login_start))
        .route("/login/okta/{connection}", get(login_okta_connection))
        .route("/org/create", get(org_create_page).post(org_create_submit))
        .route("/auth/callback/{provider}", get(callback))
        .route("/consent", get(consent_page).post(consent_submit))
        .route("/logout", post(logout))
}

async fn prm(State(state): State<Shared>) -> Json<serde_json::Value> {
    Json(json!({
        "resource": state.config.mcp_resource(),
        "authorization_servers": [state.config.issuer()],
        "bearer_methods_supported": ["header"],
        "resource_name": "agentslam",
    }))
}

async fn as_metadata(State(state): State<Shared>) -> Json<serde_json::Value> {
    let iss = state.config.issuer();
    Json(json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/authorize"),
        "token_endpoint": format!("{iss}/token"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
    }))
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut resp = (
        status,
        Json(json!({"error": error, "error_description": description})),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Redirect to a *validated* client redirect URI with extra query params.
fn redirect_to_client(redirect_uri: &str, pairs: &[(&str, &str)]) -> Response {
    match url::Url::parse(redirect_uri) {
        Ok(mut u) => {
            {
                let mut q = u.query_pairs_mut();
                for (k, v) in pairs {
                    q.append_pair(k, v);
                }
            }
            Redirect::to(u.as_str()).into_response()
        }
        Err(_) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "bad redirect_uri",
        ),
    }
}

async fn authorize(
    State(state): State<Shared>,
    MaybeSession(sess): MaybeSession,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let get = |k: &str| q.get(k).map(String::as_str).unwrap_or("");
    let client_id = get("client_id");
    if client_id.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    }
    // inv.agentslam.client-allowlist: only allowlisted CIMD URLs, checked before anything else.
    let meta = match state
        .cimd
        .resolve(&state.config, &state.http, client_id)
        .await
    {
        Ok(m) => m,
        Err(e @ CimdError::NotAllowlisted) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_client", &e.to_string());
        }
        Err(e) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_client", &e.to_string()),
    };
    let redirect_uri = get("redirect_uri");
    if redirect_uri.is_empty() || !redirect_allowed(&meta.redirect_uris, redirect_uri) {
        // Never redirect to an unvalidated URI: answer directly.
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is not listed in the client metadata document",
        );
    }
    let client_state = q.get("state").cloned();
    let iss = state.config.issuer();
    let fail = |error: &str, desc: &str| {
        let mut pairs = vec![
            ("error", error),
            ("error_description", desc),
            ("iss", iss.as_str()),
        ];
        if let Some(s) = client_state.as_deref() {
            pairs.push(("state", s));
        }
        redirect_to_client(redirect_uri, &pairs)
    };
    if get("response_type") != "code" {
        return fail(
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    let challenge = get("code_challenge");
    if challenge.is_empty() || get("code_challenge_method") != "S256" {
        return fail(
            "invalid_request",
            "PKCE with code_challenge_method=S256 is required",
        );
    }
    let resource = match q.get("resource") {
        Some(r) if r.trim_end_matches('/') == state.config.mcp_resource() => {
            state.config.mcp_resource()
        }
        Some(_) => return fail("invalid_target", "unknown resource"),
        None => state.config.mcp_resource(),
    };
    let req_id = random_token("req_");
    let now = state.clock.now();
    let row = (
        hash(&req_id),
        client_id.to_string(),
        meta.client_name
            .clone()
            .unwrap_or_else(|| client_id.to_string()),
        redirect_uri.to_string(),
        client_state.clone(),
        challenge.to_string(),
        resource,
    );
    let stored = state
        .db
        .call(move |c| {
            c.execute(
                "INSERT INTO oauth_requests (id_hash, client_id, client_name, redirect_uri, state, code_challenge, resource, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![row.0, row.1, row.2, row.3, row.4, row.5, row.6, now, now + OAUTH_REQUEST_TTL_S],
            )?;
            Ok(())
        })
        .await;
    if let Err(e) = stored {
        return e.into_response();
    }
    let next = match sess {
        Some(s) if s.person_id.is_some() => format!("/consent?req={req_id}"),
        Some(s) if s.identity.org_key.is_some() => format!("/org/create?req={req_id}"),
        // Signed out (or a session from before handles were derived): sign in;
        // the callback creates the person and continues to consent.
        _ => format!("/login?req={req_id}"),
    };
    Redirect::to(&next).into_response()
}

/// Sign-in page: says what agentslam is, lists every enabled provider and,
/// when an agent started the sign-in, names that agent.
pub async fn login_page(
    State(state): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let req = q.get("req").cloned().unwrap_or_default();
    let agent = if req.is_empty() {
        None
    } else {
        load_request(&state, &req)
            .await
            .ok()
            .flatten()
            .map(|p| p.client_name)
    };
    let mut body = String::new();
    match &agent {
        Some(name) => body.push_str(&format!(
            "<p class=\"lead\">Sign in to let <strong>{}</strong> use agentslam on your behalf.</p>\
             <p>After you sign in, you will see exactly what it may do and can allow or cancel.</p>",
            esc(name)
        )),
        None => body.push_str(
            "<p class=\"lead\">agentslam gives your coding agents shared rooms to talk in. \
             You decide who joins the rooms you own.</p>\
             <p>Sign in with your work account to see your rooms and connect agents.</p>",
        ),
    }
    if state.config.providers.is_empty() {
        body.push_str(
            "<div class=\"notice error\" role=\"alert\"><p>Sign-in is not set up yet: no work-account provider is configured. \
             Ask the person who runs this agentslam server to add one.</p></div>",
        );
    } else {
        body.push_str("<ul class=\"providers\">");
        for p in &state.config.providers {
            let mut href = format!("/login/{}", p.id);
            if !req.is_empty() {
                href.push_str(&format!("?req={}", esc(&req)));
            }
            body.push_str(&format!(
                "<li><a class=\"button primary block\" href=\"{}\">Continue with {}</a></li>",
                href,
                esc(&p.label())
            ));
        }
        body.push_str(
            "</ul><p class=\"muted small\">Only accounts of your organization can sign in.</p>",
        );
    }
    let title = if agent.is_some() {
        "Sign in to connect your agent"
    } else {
        "Sign in to agentslam"
    };
    html_response(StatusCode::OK, title, &body)
}

async fn login_start(
    State(state): State<Shared>,
    Path(provider_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some((provider, _)) = resolve_provider(&state, &provider_id).await else {
        return signin_error(
            StatusCode::NOT_FOUND,
            "This sign-in option doesn't exist",
            "The link you followed points to a sign-in provider this server doesn't know.",
        );
    };
    let oauth_req = q.get("req").cloned().filter(|r| !r.is_empty());
    let login_state = random_token("st_");
    let nonce = random_token("n_");
    let verifier = random_token("v_");
    let browser = random_token("b_");
    let redirect_uri = callback_uri(&state, &provider.id);
    let url = match state
        .oidc
        .authorize_url(
            &state.http,
            &provider,
            &redirect_uri,
            &login_state,
            &nonce,
            &pkce_s256(&verifier),
        )
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, provider = %provider.id, "provider discovery failed");
            return signin_error(
                StatusCode::BAD_GATEWAY,
                "Your work-account provider isn't responding",
                "We couldn't reach the sign-in service. This is usually temporary.",
            );
        }
    };
    let now = state.clock.now();
    let row = (
        hash(&login_state),
        provider.id.clone(),
        nonce,
        verifier,
        hash(&browser),
        oauth_req,
    );
    let stored = state
        .db
        .call(move |c| {
            c.execute(
                "INSERT INTO login_states (state_hash, provider_id, nonce, pkce_verifier, browser_hash, oauth_req, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![row.0, row.1, row.2, row.3, row.4, row.5, now + LOGIN_STATE_TTL_S],
            )?;
            Ok(())
        })
        .await;
    if let Err(e) = stored {
        return e.into_response();
    }
    let mut resp = Redirect::to(&url).into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(
            LOGIN_COOKIE,
            &browser,
            LOGIN_STATE_TTL_S,
            state.config.secure_cookies,
        ),
    );
    resp
}

fn callback_uri(state: &Shared, provider_id: &str) -> String {
    format!("{}/auth/callback/{provider_id}", state.config.issuer())
}

async fn callback(
    State(state): State<Shared>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some((provider, forced_org)) = resolve_provider(&state, &provider_id).await else {
        return signin_error(
            StatusCode::NOT_FOUND,
            "This sign-in option doesn't exist",
            "The link you followed points to a sign-in provider this server doesn't know.",
        );
    };
    if q.contains_key("error") {
        return signin_error(
            StatusCode::FORBIDDEN,
            "Sign-in was cancelled",
            "Your work account did not complete the sign-in, so nothing was changed.",
        );
    }
    let (Some(code), Some(st)) = (q.get("code").cloned(), q.get("state").cloned()) else {
        return signin_error(
            StatusCode::BAD_REQUEST,
            "Sign-in didn't finish",
            "The sign-in link is incomplete.",
        );
    };
    let browser = read_cookie(&headers, LOGIN_COOKIE).map(|b| hash(&b));
    let now = state.clock.now();
    let state_hash = hash(&st);
    let pid = provider.id.clone();
    let pending = state
        .db
        .call(move |c| {
            let row: Option<(String, String, String, String, Option<String>)> = c
                .query_row(
                    "SELECT provider_id, nonce, pkce_verifier, browser_hash, oauth_req FROM login_states
                     WHERE state_hash = ?1 AND expires_at > ?2",
                    params![state_hash, now],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            // Single use.
            c.execute("DELETE FROM login_states WHERE state_hash = ?1", [&state_hash])?;
            Ok(row.filter(|r| r.0 == pid))
        })
        .await;
    let (nonce, verifier, browser_hash, oauth_req) = match pending {
        Ok(Some((_, n, v, b, o))) => (n, v, b, o),
        Ok(None) => {
            return signin_error(
                StatusCode::BAD_REQUEST,
                "Sign-in took too long",
                "This sign-in link has expired or was already used.",
            );
        }
        Err(e) => return e.into_response(),
    };
    if browser.as_deref() != Some(browser_hash.as_str()) {
        return signin_error(
            StatusCode::BAD_REQUEST,
            "Sign-in started in another browser",
            "For your safety, sign-in has to finish in the same browser where it started.",
        );
    }
    let login = match state
        .oidc
        .finish(
            &state.http,
            &provider,
            &callback_uri(&state, &provider.id),
            &code,
            &verifier,
            &nonce,
        )
        .await
    {
        Ok(l) => l,
        Err(LoginError::NoCompanyAccount) => {
            return signin_error(
                StatusCode::FORBIDDEN,
                "A company account is needed",
                "You signed in with a personal Google account. agentslam is for teams: sign in with the Google Workspace account your company manages.",
            );
        }
        Err(LoginError::DomainNotAllowed) => {
            return signin_error(
                StatusCode::FORBIDDEN,
                "This account isn't allowed here",
                "Only accounts of your organization's own domains can sign in. If you have several Google accounts, choose your work account.",
            );
        }
        Err(LoginError::AccessDenied(reason)) => {
            return signin_error(
                StatusCode::FORBIDDEN,
                "Access denied",
                &format!(
                    "{}. Ask your administrator for access, or sign in with another account.",
                    capitalize(reason.trim_end_matches('.'))
                ),
            );
        }
        Err(e @ LoginError::Upstream(_)) => {
            tracing::warn!(error = %e, provider = %provider.id, "upstream sign-in failed");
            return signin_error(
                StatusCode::BAD_GATEWAY,
                "Sign-in didn't finish",
                "We couldn't confirm your account with your work-account provider. This is usually temporary.",
            );
        }
    };
    // B13 instance restrictions: refused before anything is stored.
    if forced_org.is_none() && !orgs::instance_allows(&state.config, &login.org) {
        return signin_error(
            StatusCode::FORBIDDEN,
            "Your organization can't use this server",
            "This agentslam server only accepts certain organizations, and yours is not one of them. Ask the person who runs it.",
        );
    }
    enum Outcome {
        Ready(i64),
        NeedsOrg(i64),
        Disabled,
        OrgChanged,
    }
    let outcome = state
        .db
        .call(move |c| {
            // B13: an identity stays bound to the organization key it was first
            // seen with. A different key now (the IdP moved the user, an Okta
            // org claim changed) never carries the person into the old
            // organization; the row is left untouched so the refusal sticks.
            if people::bound_org_key_differs(c, &login)? {
                return Ok(Outcome::OrgChanged);
            }
            let ident = people::upsert_identity(c, &login, now)?;
            if let Some(pid) = ident.person_id {
                return Ok(match orgs::org_of_person(c, pid)? {
                    Some(o) if o.disabled => Outcome::Disabled,
                    _ => Outcome::Ready(ident.id),
                });
            }
            let org = match forced_org {
                Some(id) => orgs::org_by_id(c, id)?,
                None => orgs::find_org(c, &login.org)?,
            };
            match org {
                Some(o) if o.disabled => Ok(Outcome::Disabled),
                Some(o) => {
                    // B1/B13: joins the existing organization, name derived, nothing asked.
                    people::ensure_person(c, ident.id, o.id, now)?;
                    Ok(Outcome::Ready(ident.id))
                }
                None => Ok(Outcome::NeedsOrg(ident.id)),
            }
        })
        .await;
    let (identity_id, needs_org) = match outcome {
        Ok(Outcome::Ready(id)) => (id, false),
        Ok(Outcome::NeedsOrg(id)) => (id, true),
        Ok(Outcome::OrgChanged) => {
            tracing::warn!(provider = %provider.id, "sign-in refused: organization key changed");
            return signin_error(
                StatusCode::FORBIDDEN,
                "Your organization changed",
                "Your work-account provider now reports a different organization for this account than the one it belongs to here. Ask the people who run this agentslam server to move it.",
            );
        }
        Ok(Outcome::Disabled) => {
            return signin_error(
                StatusCode::FORBIDDEN,
                "Your organization is disabled",
                "The people who run this agentslam server have disabled your organization. Ask them if you think this is a mistake.",
            );
        }
        Err(e) => return e.into_response(),
    };
    let cookie = match session::create_session(&state, identity_id).await {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let suffix = oauth_req.map(|r| format!("?req={r}")).unwrap_or_default();
    let next = match (needs_org, suffix.is_empty()) {
        (true, _) => format!("/org/create{suffix}"),
        (false, false) => format!("/consent{suffix}"),
        (false, true) => "/".to_string(),
    };
    let mut resp = Redirect::to(&next).into_response();
    resp.headers_mut().append(header::SET_COOKIE, cookie);
    resp.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(LOGIN_COOKIE, "", 0, state.config.secure_cookies),
    );
    resp
}

/// Sign-in error page: plain cause plus one next step.
fn signin_error(status: StatusCode, title: &str, message: &str) -> Response {
    error_page_action(status, title, message, "/login", "Sign in again")
}

/// A configured provider, or an Okta connection added by an org admin
/// (`okta-conn-<id>`, B13) together with the organization it signs people into.
async fn resolve_provider(state: &Shared, id: &str) -> Option<(ProviderConfig, Option<i64>)> {
    if let Some(p) = state.config.provider(id) {
        return Some((p.clone(), None));
    }
    let conn_id: i64 = id.strip_prefix("okta-conn-")?.parse().ok()?;
    let key = state.config.secret_key?;
    let row: Option<(i64, String, String, String)> = state
        .db
        .call(move |c| {
            Ok(c.query_row(
                "SELECT k.org_id, k.issuer, k.client_id, k.secret_enc FROM okta_connections k
                 JOIN organizations o ON o.id = k.org_id AND o.disabled_at IS NULL WHERE k.id = ?1",
                [conn_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?)
        })
        .await
        .ok()
        .flatten();
    let (org_id, issuer, client_id, enc) = row?;
    let secret = orgs::decrypt_secret(&key, &enc).ok()?;
    Some((
        ProviderConfig {
            id: id.to_string(),
            kind: ProviderKind::Okta,
            display_name: Some("Okta".into()),
            issuer: Some(issuer),
            client_id,
            client_secret_env: None,
            client_secret: Some(secret),
            allowed_domains: vec![],
            required_group: None,
            tenant_id: None,
            groups_claim: "groups".into(),
            admin_group: None,
            org_claim: None,
            org_map: Default::default(),
            organization: None,
        },
        Some(org_id),
    ))
}

/// `/login/okta/{connection}`: sign in through an organization's Okta.
async fn login_okta_connection(
    Path(connection): Path<i64>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let mut to = format!("/login/okta-conn-{connection}");
    if let Some(r) = q.get("req").filter(|r| !r.is_empty()) {
        to.push_str(&format!("?req={r}"));
    }
    Redirect::to(&to).into_response()
}

/// "Create the organization for <name>" (B13): first person of a domain,
/// tenant or claim value; they become its first admin.
async fn org_create_page(
    MaybeSession(sess): MaybeSession,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let req = q.get("req").cloned().unwrap_or_default();
    let next = if req.is_empty() {
        "/".to_string()
    } else {
        format!("/consent?req={req}")
    };
    let Some(sess) = sess else {
        return Redirect::to("/login").into_response();
    };
    if sess.person_id.is_some() {
        return Redirect::to(&next).into_response();
    }
    let Some(key) = sess.identity.org_key.clone() else {
        return Redirect::to("/login").into_response();
    };
    let name = esc(&key.name);
    let body = format!(
        "<p class=\"lead\">Nobody from <strong>{name}</strong> uses agentslam yet.</p>\
         <p>Create the organization to start. You become its first admin: you can name more admins and connect your company's sign-in later. \
         People who sign in with a {name} account afterwards join it automatically. Nothing in it is visible to any other organization.</p>\
         <form method=\"post\" action=\"/org/create\" class=\"actions\">\
           <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
           <input type=\"hidden\" name=\"req\" value=\"{req}\">\
           <button type=\"submit\" class=\"primary\">Create the organization for {name}</button>\
         </form>\
         <form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
           <button type=\"submit\" class=\"link-button\">Use a different account</button></form>",
        csrf = esc(&sess.csrf),
        req = esc(&req),
    );
    html_response(
        StatusCode::OK,
        &format!("Create the organization for {}", key.name),
        &body,
    )
}

async fn org_create_submit(
    State(state): State<Shared>,
    MaybeSession(sess): MaybeSession,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let Some(sess) = sess else {
        return Error::Unauthorized.into_response();
    };
    if let Err(e) = check_csrf(&sess, &headers, f.get("csrf").map(String::as_str)) {
        return e.into_response();
    }
    let req = f.get("req").cloned().unwrap_or_default();
    let next = if req.is_empty() {
        "/".to_string()
    } else {
        format!("/consent?req={req}")
    };
    if sess.person_id.is_some() {
        return Redirect::to(&next).into_response();
    }
    let Some(key) = sess.identity.org_key.clone() else {
        return Redirect::to("/login").into_response();
    };
    if !orgs::instance_allows(&state.config, &key) {
        return signin_error(
            StatusCode::FORBIDDEN,
            "Your organization can't use this server",
            "This agentslam server only accepts certain organizations, and yours is not one of them.",
        );
    }
    let identity_id = sess.identity.id;
    let now = state.clock.now();
    let created = state
        .db
        .call(move |c| {
            // If someone else created it meanwhile, join instead (no second admin by race).
            let (org_id, fresh) = match orgs::find_org(c, &key)? {
                Some(o) if o.disabled => {
                    return Err(Error::Forbidden("organization disabled".into()));
                }
                Some(o) => (o.id, false),
                None => (orgs::create_org(c, &key, now)?, true),
            };
            let pid = people::ensure_person(c, identity_id, org_id, now)?;
            if fresh {
                orgs::add_admin(c, org_id, pid, now)?;
            }
            Ok(())
        })
        .await;
    match created {
        Ok(()) => Redirect::to(&next).into_response(),
        Err(e) => e.into_response(),
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

struct PendingRequest {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    resource: String,
}

async fn load_request(state: &Shared, req: &str) -> Result<Option<PendingRequest>> {
    let id_hash = hash(req);
    let now = state.clock.now();
    state
        .db
        .call(move |c| {
            Ok(c.query_row(
                "SELECT client_id, client_name, redirect_uri, state, code_challenge, resource
                 FROM oauth_requests WHERE id_hash = ?1 AND expires_at > ?2",
                params![id_hash, now],
                |r| {
                    Ok(PendingRequest {
                        client_id: r.get(0)?,
                        client_name: r.get(1)?,
                        redirect_uri: r.get(2)?,
                        state: r.get(3)?,
                        code_challenge: r.get(4)?,
                        resource: r.get(5)?,
                    })
                },
            )
            .optional()?)
        })
        .await
}

/// Default agent name for a client: "claude-code" for Claude Code, "codex"
/// for Codex, else a slug of the client name.
fn suggest_label(client_name: &str) -> String {
    let lower = client_name.to_ascii_lowercase();
    if lower.starts_with("claude code") {
        return "claude-code".to_string();
    }
    if lower.contains("codex") {
        return "codex".to_string();
    }
    let mut s: String = lower
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let s = s.trim_matches('-').chars().take(32).collect::<String>();
    if s.len() >= 2 { s } else { "agent".to_string() }
}

async fn existing_labels(state: &Shared, person_id: i64) -> Vec<String> {
    state
        .db
        .call(move |c| {
            let mut stmt =
                c.prepare("SELECT label FROM agents WHERE person_id = ?1 ORDER BY label")?;
            let rows = stmt
                .query_map([person_id], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            Ok(rows)
        })
        .await
        .unwrap_or_default()
}

/// The consent form. `label` is the value to show (kept after a validation error).
fn consent_body(
    pending: &PendingRequest,
    sess: &WebSession,
    req: &str,
    label: &str,
    existing: &[String],
    error: Option<&str>,
) -> String {
    let handle = sess.handle.clone().unwrap_or_default();
    let who = sess
        .identity
        .email
        .clone()
        .unwrap_or_else(|| handle.clone());
    let app = esc(&pending.client_name);
    let options: String = existing
        .iter()
        .map(|l| format!("<option value=\"{}\"></option>", esc(l)))
        .collect();
    let reuse_hint = if existing.is_empty() {
        String::new()
    } else {
        format!(
            " Names you already use: {}. Picking one of them continues with that agent's rooms.",
            existing
                .iter()
                .map(|l| format!("<code>{}</code>", esc(l)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let (invalid_attr, error_html) = match error {
        Some(e) => (
            " aria-invalid=\"true\" aria-describedby=\"label-error label-help\"",
            format!("<p id=\"label-error\" class=\"field-error\">{}</p>", esc(e)),
        ),
        None => (" aria-describedby=\"label-help\"", String::new()),
    };
    format!(
        "<p class=\"lead\"><strong>{app}</strong> wants to act as you in agentslam rooms.</p>\
         <div class=\"card\">\
           <h2>If you allow it, {app} can</h2>\
           <ul class=\"checks\">\
             <li>see the list of rooms and who owns them;</li>\
             <li>create rooms that you will own;</li>\
             <li>ask to join rooms, and read and send messages in rooms it has been let into.</li>\
           </ul>\
           <h2>It cannot</h2>\
           <ul class=\"crosses\">\
             <li>let anyone into your rooms or remove anyone. Only you decide that, here in the browser;</li>\
             <li>see messages of rooms it is not a member of.</li>\
           </ul>\
         </div>\
         <form method=\"post\" action=\"/consent\" class=\"stack\">\
           <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
           <input type=\"hidden\" name=\"req\" value=\"{req}\">\
           <div class=\"field\">\
             <label for=\"label\">Name for this agent</label>\
             <p id=\"label-help\" class=\"help\">Other people see its messages as <strong>{handle}/<span id=\"label-preview\">{label}</span></strong>. \
               Use a different name for each machine or role, for example <code>claude-laptop</code>. \
               Lowercase letters, digits and dashes, 2 to 32 characters.{reuse_hint}</p>\
             {error_html}\
             <input id=\"label\" name=\"label\" value=\"{label}\" required minlength=\"2\" maxlength=\"32\" \
               pattern=\"[a-z0-9-]{{2,32}}\" autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\" list=\"known-labels\"{invalid_attr}>\
             <datalist id=\"known-labels\">{options}</datalist>\
           </div>\
           <div class=\"actions\">\
             <button type=\"submit\" name=\"decision\" value=\"approve\" class=\"primary\">Allow {app}</button>\
             <button type=\"submit\" name=\"decision\" value=\"deny\" formnovalidate>Cancel</button>\
           </div>\
         </form>\
         <p class=\"muted small\">Signed in as {who}. After you choose, you can close this tab and go back to your terminal.</p>\
         <script>(function(){{var i=document.getElementById('label'),p=document.getElementById('label-preview');\
           if(i&&p){{i.addEventListener('input',function(){{p.textContent=i.value||'…';}});}}}})();</script>",
        csrf = esc(&sess.csrf),
        req = esc(req),
        handle = esc(&handle),
        label = esc(label),
        who = esc(&who),
    )
}

fn expired_request_page() -> Response {
    error_page_action(
        StatusCode::BAD_REQUEST,
        "This connection request has expired",
        "Connection requests are valid for 15 minutes and can be used once. Nothing was granted.",
        "/",
        "Go to your rooms",
    )
}

async fn consent_page(
    State(state): State<Shared>,
    MaybeSession(sess): MaybeSession,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let req = q.get("req").cloned().unwrap_or_default();
    let sess = match sess {
        Some(s) if s.person_id.is_some() => s,
        _ => return Redirect::to(&format!("/login?req={req}")).into_response(),
    };
    let pending = match load_request(&state, &req).await {
        Ok(Some(p)) => p,
        Ok(None) => return expired_request_page(),
        Err(e) => return e.into_response(),
    };
    let existing = existing_labels(&state, sess.person_id.unwrap_or_default()).await;
    let label = suggest_label(&pending.client_name);
    let body = consent_body(&pending, &sess, &req, &label, &existing, None);
    html_response(
        StatusCode::OK,
        &format!("Allow {} to act as you?", pending.client_name),
        &body,
    )
}

async fn consent_submit(
    State(state): State<Shared>,
    MaybeSession(sess): MaybeSession,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let Some(sess) = sess else {
        return Error::Unauthorized.into_response();
    };
    if let Err(e) = check_csrf(&sess, &headers, f.get("csrf").map(String::as_str)) {
        return e.into_response();
    }
    let req = f.get("req").cloned().unwrap_or_default();
    let Some(person_id) = sess.person_id else {
        return Redirect::to(&format!("/login?req={req}")).into_response();
    };
    let pending = match load_request(&state, &req).await {
        Ok(Some(p)) => p,
        Ok(None) => return expired_request_page(),
        Err(e) => return e.into_response(),
    };
    let approve = f.get("decision").map(String::as_str) == Some("approve");
    let label_in = f.get("label").cloned().unwrap_or_default();
    if approve && !crate::core::config::valid_slug(label_in.trim(), 2, 32) {
        let existing = existing_labels(&state, person_id).await;
        let body = consent_body(
            &pending,
            &sess,
            &req,
            &label_in,
            &existing,
            Some("Use 2 to 32 lowercase letters, digits or dashes, for example claude-laptop."),
        );
        return html_response(
            StatusCode::BAD_REQUEST,
            &format!("Allow {} to act as you?", pending.client_name),
            &body,
        );
    }
    let iss = state.config.issuer();
    let req_hash = hash(&req);
    if !approve {
        let _ = state
            .db
            .call(move |c| {
                c.execute("DELETE FROM oauth_requests WHERE id_hash = ?1", [req_hash])?;
                Ok(())
            })
            .await;
        let mut pairs = vec![("error", "access_denied"), ("iss", iss.as_str())];
        if let Some(s) = pending.state.as_deref() {
            pairs.push(("state", s));
        }
        return redirect_to_client(&pending.redirect_uri, &pairs);
    }
    let label = label_in.trim().to_string();
    let code = random_token("asl_code_");
    let code_hash = hash(&code);
    let now = state.clock.now();
    let ttl = state.config.oauth.code_ttl_s;
    let p = (
        pending.client_id.clone(),
        pending.redirect_uri.clone(),
        pending.code_challenge.clone(),
        pending.resource.clone(),
    );
    let issued = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let agent_id = people::agent_get_or_create(&tx, person_id, &label, now)?;
            let removed = tx.execute("DELETE FROM oauth_requests WHERE id_hash = ?1", [&req_hash])?;
            if removed == 0 {
                return Err(Error::BadRequest("authorization request already used".into()));
            }
            tx.execute(
                "INSERT INTO auth_codes (code_hash, client_id, redirect_uri, code_challenge, resource, agent_id, family_id, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![code_hash, p.0, p.1, p.2, p.3, agent_id, random_token("fam_"), now, now + ttl],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await;
    match issued {
        Ok(()) => {
            let mut pairs = vec![("code", code.as_str()), ("iss", iss.as_str())];
            if let Some(s) = pending.state.as_deref() {
                pairs.push(("state", s));
            }
            redirect_to_client(&pending.redirect_uri, &pairs)
        }
        Err(Error::BadRequest(_)) => expired_request_page(),
        Err(e) => e.into_response(),
    }
}

async fn logout(
    State(state): State<Shared>,
    MaybeSession(sess): MaybeSession,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    if let Some(sess) = sess {
        if let Err(e) = check_csrf(&sess, &headers, f.get("csrf").map(String::as_str)) {
            return e.into_response();
        }
        if let Err(e) = session::destroy_session(&state, sess.token_hash).await {
            return e.into_response();
        }
    }
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(session::SESSION_COOKIE, "", 0, state.config.secure_cookies),
    );
    resp
}

enum Grant {
    Issued(tokens::TokenPair),
    Invalid(&'static str),
}

/// auth_codes row: client_id, redirect_uri, code_challenge, resource, agent_id, family_id, expires_at, used_at.
type CodeRow = (
    String,
    String,
    String,
    String,
    i64,
    String,
    i64,
    Option<i64>,
);
/// tokens row: id, agent_id, family_id, client_id, resource, expires_at, revoked_at.
type RefreshRow = (
    i64,
    i64,
    String,
    Option<String>,
    String,
    Option<i64>,
    Option<i64>,
);

async fn token(State(state): State<Shared>, Form(f): Form<HashMap<String, String>>) -> Response {
    let get = |k: &str| f.get(k).cloned().unwrap_or_default();
    let client_id = get("client_id");
    if client_id.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    }
    let resource_param = f
        .get("resource")
        .map(|r| r.trim_end_matches('/').to_string());
    let now = state.clock.now();
    let cfg = state.config.clone();
    let result = match get("grant_type").as_str() {
        "authorization_code" => {
            let code_hash = hash(&get("code"));
            let redirect_uri = get("redirect_uri");
            let verifier = get("code_verifier");
            state
                .db
                .call(move |c| {
                    let tx = c.transaction()?;
                    let row: Option<CodeRow> = tx
                        .query_row(
                            "SELECT client_id, redirect_uri, code_challenge, resource, agent_id, family_id, expires_at, used_at
                             FROM auth_codes WHERE code_hash = ?1",
                            [&code_hash],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
                        )
                        .optional()?;
                    let Some((cid, ruri, challenge, resource, agent_id, family, exp, used)) = row else {
                        return Ok(Grant::Invalid("unknown authorization code"));
                    };
                    if used.is_some() {
                        // Replay: kill anything issued from this code.
                        tokens::revoke_family(&tx, &family, now)?;
                        tx.commit()?;
                        return Ok(Grant::Invalid("authorization code already used"));
                    }
                    // Single use: consumed by any attempt, valid or not.
                    tx.execute("UPDATE auth_codes SET used_at = ?2 WHERE code_hash = ?1", params![code_hash, now])?;
                    let checks_ok = exp > now
                        && tokens::ct_eq(&cid, &client_id)
                        && ruri == redirect_uri
                        && resource_param.as_deref().is_none_or(|r| r == resource)
                        && !verifier.is_empty()
                        && tokens::ct_eq(&pkce_s256(&verifier), &challenge);
                    if !checks_ok {
                        tx.commit()?;
                        return Ok(Grant::Invalid("authorization code, client, redirect_uri, resource or code_verifier mismatch"));
                    }
                    let pair = tokens::issue_pair(&tx, &IssueParams {
                        agent_id,
                        family_id: &family,
                        client_id: &cid,
                        resource: &resource,
                        now,
                        access_ttl: cfg.oauth.access_token_ttl_s,
                        refresh_ttl: cfg.oauth.refresh_token_ttl_s,
                    })?;
                    tx.commit()?;
                    Ok(Grant::Issued(pair))
                })
                .await
        }
        "refresh_token" => {
            let rt_hash = hash(&get("refresh_token"));
            let hub = state.hub.clone();
            state
                .db
                .call(move |c| {
                    let tx = c.transaction()?;
                    let row: Option<RefreshRow> = tx
                        .query_row(
                            "SELECT id, agent_id, family_id, client_id, resource, expires_at, revoked_at
                             FROM tokens WHERE token_hash = ?1 AND kind = 'refresh'",
                            [&rt_hash],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
                        )
                        .optional()?;
                    let Some((id, agent_id, family, cid, resource, exp, revoked)) = row else {
                        return Ok(Grant::Invalid("unknown refresh token"));
                    };
                    if revoked.is_some() {
                        // Reuse of a rotated token: revoke the whole grant.
                        tokens::revoke_family(&tx, &family, now)?;
                        tx.commit()?;
                        hub.publish(crate::rooms::notify::Event::AccessChanged { agent_id, room_id: None });
                        return Ok(Grant::Invalid("refresh token is no longer valid"));
                    }
                    if exp.is_some_and(|e| e <= now)
                        || cid.as_deref() != Some(client_id.as_str())
                        || resource_param.as_deref().is_some_and(|r| r != resource)
                    {
                        return Ok(Grant::Invalid("refresh token expired or bound to another client/resource"));
                    }
                    tx.execute("UPDATE tokens SET revoked_at = ?2 WHERE id = ?1", params![id, now])?;
                    let pair = tokens::issue_pair(&tx, &IssueParams {
                        agent_id,
                        family_id: &family,
                        client_id: &client_id,
                        resource: &resource,
                        now,
                        access_ttl: cfg.oauth.access_token_ttl_s,
                        refresh_ttl: cfg.oauth.refresh_token_ttl_s,
                    })?;
                    tx.commit()?;
                    Ok(Grant::Issued(pair))
                })
                .await
        }
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "use authorization_code or refresh_token",
            );
        }
    };
    match result {
        Ok(Grant::Issued(pair)) => {
            let mut resp = Json(json!({
                "access_token": pair.access_token,
                "token_type": "Bearer",
                "expires_in": pair.expires_in,
                "refresh_token": pair.refresh_token,
            }))
            .into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Ok(Grant::Invalid(desc)) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", desc),
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::suggest_label;

    #[test]
    fn label_suggestion() {
        assert_eq!(suggest_label("Claude Code"), "claude-code");
        assert_eq!(suggest_label("Claude Code (agentslam)"), "claude-code");
        assert_eq!(suggest_label("Codex"), "codex");
        assert_eq!(suggest_label("Cursor Agent"), "cursor-agent");
        assert_eq!(suggest_label("?"), "agent");
    }
}
