//! Web sessions (cookie), CSRF tokens and request extractors.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, header};
use rusqlite::{OptionalExtension, params};

use crate::core::{Error, Result, Shared};
use crate::identity::people::{self, Identity};
use crate::identity::tokens::{ct_eq, hash, random_token};

pub const SESSION_COOKIE: &str = "agentslam_session";
pub const LOGIN_COOKIE: &str = "agentslam_login";
pub const SESSION_TTL_S: i64 = 12 * 3600;
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Build a Set-Cookie value: always HttpOnly + SameSite=Lax; Secure unless
/// explicitly disabled for localhost development.
pub fn set_cookie(name: &str, value: &str, max_age: i64, secure: bool) -> HeaderValue {
    let mut s = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if secure {
        s.push_str("; Secure");
    }
    HeaderValue::from_str(&s).unwrap_or_else(|_| HeaderValue::from_static(""))
}

pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

#[derive(Debug, Clone)]
pub struct WebSession {
    pub token_hash: String,
    pub identity: Identity,
    pub person_id: Option<i64>,
    pub handle: Option<String>,
    pub csrf: String,
    pub is_admin: bool,
}

/// Create a session for an identity; returns the Set-Cookie header value.
pub async fn create_session(state: &Shared, identity_id: i64) -> Result<HeaderValue> {
    let raw = random_token("asl_ws_");
    let csrf = random_token("");
    let now = state.clock.now();
    let token_hash = hash(&raw);
    state
        .db
        .call(move |c| {
            c.execute(
                "INSERT INTO web_sessions (token_hash, identity_id, csrf, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![token_hash, identity_id, csrf, now, now + SESSION_TTL_S],
            )?;
            Ok(())
        })
        .await?;
    Ok(set_cookie(
        SESSION_COOKIE,
        &raw,
        SESSION_TTL_S,
        state.config.secure_cookies,
    ))
}

pub async fn load_session(state: &Shared, headers: &HeaderMap) -> Result<Option<WebSession>> {
    let Some(raw) = read_cookie(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let token_hash = hash(&raw);
    let now = state.clock.now();
    let cfg = state.config.clone();
    state
        .db
        .call(move |c| {
            let row: Option<(i64, String)> = c
                .query_row(
                    "SELECT identity_id, csrf FROM web_sessions WHERE token_hash = ?1 AND expires_at > ?2",
                    params![token_hash, now],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((identity_id, csrf)) = row else {
                return Ok(None);
            };
            let Some(identity) = people::identity_by_id(c, identity_id)? else {
                return Ok(None);
            };
            let handle = match identity.person_id {
                Some(pid) => people::person_handle(c, pid)?,
                None => None,
            };
            let is_admin = people::is_admin(&cfg, &identity);
            Ok(Some(WebSession {
                token_hash,
                person_id: identity.person_id,
                identity,
                handle,
                csrf,
                is_admin,
            }))
        })
        .await
}

pub async fn destroy_session(state: &Shared, token_hash: String) -> Result<()> {
    state
        .db
        .call(move |c| {
            c.execute(
                "DELETE FROM web_sessions WHERE token_hash = ?1",
                [token_hash],
            )?;
            Ok(())
        })
        .await
}

/// CSRF check for owner POSTs: token from the `X-CSRF-Token` header or a form field.
pub fn check_csrf(
    session: &WebSession,
    headers: &HeaderMap,
    form_value: Option<&str>,
) -> Result<()> {
    let presented = headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .or(form_value)
        .unwrap_or("");
    if !presented.is_empty() && ct_eq(presented, &session.csrf) {
        Ok(())
    } else {
        Err(Error::Forbidden("missing or invalid CSRF token".into()))
    }
}

/// Optional session (pages that render differently when signed out).
pub struct MaybeSession(pub Option<WebSession>);

impl FromRequestParts<Shared> for MaybeSession {
    type Rejection = Error;
    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self> {
        Ok(MaybeSession(load_session(state, &parts.headers).await?))
    }
}

/// A signed-in person (identity with a chosen handle). JSON 401 otherwise.
pub struct WebUser {
    pub session: WebSession,
    pub person_id: i64,
    pub handle: String,
}

impl FromRequestParts<Shared> for WebUser {
    type Rejection = Error;
    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self> {
        let session = load_session(state, &parts.headers)
            .await?
            .ok_or(Error::Unauthorized)?;
        match (session.person_id, session.handle.clone()) {
            (Some(person_id), Some(handle)) => Ok(WebUser {
                session,
                person_id,
                handle,
            }),
            // Sessions created before names were derived (B1): signing in again creates the person.
            _ => Err(Error::Unauthorized),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_attributes() {
        let v = set_cookie("a", "b", 10, true);
        let s = v.to_str().unwrap_or_default();
        assert!(s.contains("HttpOnly") && s.contains("SameSite=Lax") && s.contains("Secure"));
        let v = set_cookie("a", "b", 10, false);
        assert!(!v.to_str().unwrap_or_default().contains("Secure"));
    }
}
