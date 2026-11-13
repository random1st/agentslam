//! People, identities, handles, agents and admins.
//!
//! A person is keyed by (issuer, sub) of a provider that passed its company
//! check; email and name are display data and never select or merge a person
//! (inv.agentslam.identity-key). Only an admin can link a second identity.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::core::config::{Config, valid_slug};
use crate::core::{Error, Result};

#[derive(Debug, Clone, Serialize)]
pub struct Identity {
    pub id: i64,
    pub issuer: String,
    pub sub: String,
    pub provider_id: String,
    pub person_id: Option<i64>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub group_admin: bool,
}

pub struct VerifiedLogin {
    pub issuer: String,
    pub sub: String,
    pub provider_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub group_admin: bool,
}

fn row_identity(r: &rusqlite::Row<'_>) -> rusqlite::Result<Identity> {
    Ok(Identity {
        id: r.get(0)?,
        issuer: r.get(1)?,
        sub: r.get(2)?,
        provider_id: r.get(3)?,
        person_id: r.get(4)?,
        email: r.get(5)?,
        name: r.get(6)?,
        group_admin: r.get::<_, i64>(7)? != 0,
    })
}

const IDENTITY_COLS: &str = "id, issuer, sub, provider_id, person_id, email, name, group_admin";

/// Insert or refresh the identity row for (issuer, sub). Never looks at email.
pub fn upsert_identity(conn: &Connection, login: &VerifiedLogin, now: i64) -> Result<Identity> {
    conn.execute(
        "INSERT INTO identities (issuer, sub, provider_id, email, name, group_admin, created_at, last_login_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
         ON CONFLICT (issuer, sub) DO UPDATE SET email = excluded.email, name = excluded.name,
           group_admin = excluded.group_admin, last_login_at = excluded.last_login_at",
        params![
            login.issuer,
            login.sub,
            login.provider_id,
            login.email,
            login.name,
            login.group_admin as i64,
            now
        ],
    )?;
    let ident = conn.query_row(
        &format!("SELECT {IDENTITY_COLS} FROM identities WHERE issuer = ?1 AND sub = ?2"),
        params![login.issuer, login.sub],
        row_identity,
    )?;
    Ok(ident)
}

pub fn identity_by_id(conn: &Connection, id: i64) -> Result<Option<Identity>> {
    Ok(conn
        .query_row(
            &format!("SELECT {IDENTITY_COLS} FROM identities WHERE id = ?1"),
            [id],
            row_identity,
        )
        .optional()?)
}

pub fn person_handle(conn: &Connection, person_id: i64) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT handle FROM persons WHERE id = ?1",
            [person_id],
            |r| r.get(0),
        )
        .optional()?)
}

pub const MAX_HANDLE_LEN: usize = 32;

/// Handle base from an email (B1): the local part, lowercased, characters
/// outside `[a-z0-9-]` replaced by `-`, leading/trailing `-` trimmed, cut to
/// 32. Shorter than 2 (or no email) → "user". The email only *names* the
/// handle; it never selects or merges a person.
pub fn handle_base(email: Option<&str>) -> String {
    let local = email
        .and_then(|e| e.split('@').next())
        .unwrap_or_default()
        .to_lowercase();
    let replaced: String = local
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed: String = replaced
        .trim_matches('-')
        .chars()
        .take(MAX_HANDLE_LEN)
        .collect();
    let trimmed = trimmed.trim_end_matches('-').to_string();
    if trimmed.len() < 2 {
        "user".to_string()
    } else {
        trimmed
    }
}

/// First sign-in: create the person for an identity with a derived handle
/// (`base`, then `base-2`, `base-3`, ... on collision). Idempotent: an
/// identity that already has a person keeps it.
pub fn ensure_person(conn: &mut Connection, identity_id: i64, now: i64) -> Result<i64> {
    let tx = conn.transaction()?;
    let row: Option<(Option<i64>, Option<String>)> = tx
        .query_row(
            "SELECT person_id, email FROM identities WHERE id = ?1",
            [identity_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (existing, email) = row.ok_or(Error::NotFound)?;
    if let Some(pid) = existing {
        return Ok(pid);
    }
    let base = handle_base(email.as_deref());
    let mut n: u32 = 1;
    let handle = loop {
        let candidate = if n == 1 {
            base.clone()
        } else {
            let suffix = format!("-{n}");
            let keep: String = base.chars().take(MAX_HANDLE_LEN - suffix.len()).collect();
            format!("{}{suffix}", keep.trim_end_matches('-'))
        };
        let taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM persons WHERE handle = ?1)",
            [&candidate],
            |r| r.get(0),
        )?;
        if !taken {
            break candidate;
        }
        n += 1;
    };
    tx.execute(
        "INSERT INTO persons (handle, created_at) VALUES (?1, ?2)",
        params![handle, now],
    )?;
    let person_id = tx.last_insert_rowid();
    tx.execute(
        "UPDATE identities SET person_id = ?1 WHERE id = ?2",
        params![person_id, identity_id],
    )?;
    tx.commit()?;
    Ok(person_id)
}

/// Admin action: attach the identity (issuer, sub) to an existing person.
pub fn link_identity(conn: &Connection, issuer: &str, sub: &str, handle: &str) -> Result<()> {
    let person_id: i64 = conn
        .query_row("SELECT id FROM persons WHERE handle = ?1", [handle], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let n = conn.execute(
        "UPDATE identities SET person_id = ?1 WHERE issuer = ?2 AND sub = ?3",
        params![person_id, issuer, sub],
    )?;
    if n == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

pub fn agent_get_or_create(
    conn: &Connection,
    person_id: i64,
    label: &str,
    now: i64,
) -> Result<i64> {
    if !valid_slug(label, 2, 32) {
        return Err(Error::BadRequest(
            "agent label must match [a-z0-9-]{2,32}".to_string(),
        ));
    }
    conn.execute(
        "INSERT INTO agents (person_id, label, created_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (person_id, label) DO NOTHING",
        params![person_id, label, now],
    )?;
    Ok(conn.query_row(
        "SELECT id FROM agents WHERE person_id = ?1 AND label = ?2",
        params![person_id, label],
        |r| r.get(0),
    )?)
}

/// Admin = configured (issuer, sub) pair or admin-group member at last sign-in.
pub fn is_admin(cfg: &Config, ident: &Identity) -> bool {
    ident.group_admin
        || cfg
            .admins
            .iter()
            .any(|a| a.issuer.trim_end_matches('/') == ident.issuer && a.sub == ident.sub)
}

#[derive(Debug, Serialize)]
pub struct AgentView {
    pub id: i64,
    pub label: String,
    pub online: bool,
    pub credentials: Vec<CredentialView>,
}

#[derive(Debug, Serialize)]
pub struct CredentialView {
    pub family_id: String,
    pub kind: String,
    pub client_id: Option<String>,
    pub created_at: i64,
}

pub const PRESENCE_WINDOW_S: i64 = 120;

/// A person's agents with their active credentials (token families).
pub fn agents_of_person(conn: &Connection, person_id: i64, now: i64) -> Result<Vec<AgentView>> {
    let mut stmt = conn.prepare(
        "SELECT id, label, last_seen_at FROM agents WHERE person_id = ?1 ORDER BY label",
    )?;
    let agents: Vec<(i64, String, Option<i64>)> = stmt
        .query_map([person_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut cred_stmt = conn.prepare(
        "SELECT family_id, MIN(kind), client_id, MIN(created_at) FROM tokens
         WHERE agent_id = ?1 AND revoked_at IS NULL AND kind IN ('agent', 'refresh')
           AND (expires_at IS NULL OR expires_at > ?2)
         GROUP BY family_id ORDER BY MIN(created_at)",
    )?;
    let mut out = Vec::new();
    for (id, label, seen) in agents {
        let credentials = cred_stmt
            .query_map(params![id, now], |r| {
                let kind: String = r.get(1)?;
                Ok(CredentialView {
                    family_id: r.get(0)?,
                    kind: if kind == "agent" {
                        "agent-token".into()
                    } else {
                        "oauth".into()
                    },
                    client_id: r.get(2)?,
                    created_at: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        out.push(AgentView {
            id,
            label,
            online: seen.is_some_and(|s| now - s < PRESENCE_WINDOW_S),
            credentials,
        });
    }
    Ok(out)
}

/// Record that the agent called the server (presence).
pub fn touch_agent(conn: &Connection, agent_id: i64, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE agents SET last_seen_at = ?2 WHERE id = ?1",
        params![agent_id, now],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::db::Db;

    #[test]
    fn handle_base_derivation() {
        assert_eq!(handle_base(Some("rvoronin@example.com")), "rvoronin");
        assert_eq!(handle_base(Some("R.Voronin+Test@x.io")), "r-voronin-test");
        assert_eq!(handle_base(Some("__Ölga__@x.io")), "lga");
        assert_eq!(handle_base(Some("-.-@x.io")), "user");
        assert_eq!(handle_base(Some("a@x.io")), "user");
        assert_eq!(handle_base(None), "user");
        let long = format!("{}@x.io", "a".repeat(40));
        assert_eq!(handle_base(Some(&long)), "a".repeat(32));
        // Cut at 32 must not leave a trailing dash.
        let dashy = format!("{}-b@x.io", "a".repeat(31));
        assert_eq!(handle_base(Some(&dashy)), "a".repeat(31));
    }

    fn login(sub: &str, email: &str) -> VerifiedLogin {
        VerifiedLogin {
            issuer: "https://idp.example".into(),
            sub: sub.into(),
            provider_id: "google".into(),
            email: Some(email.into()),
            name: None,
            group_admin: false,
        }
    }

    #[tokio::test]
    async fn ensure_person_suffixes_collisions_and_is_idempotent() {
        let db = Db::open(":memory:").expect("db");
        let handles = db
            .call(|c| {
                let mut out = Vec::new();
                for (sub, email) in [
                    ("1", "r.voronin@example.com"),
                    ("2", "r_voronin@other.com"),
                    ("3", "R-Voronin@third.com"),
                ] {
                    let ident = upsert_identity(c, &login(sub, email), 1)?;
                    let pid = ensure_person(c, ident.id, 1)?;
                    assert_eq!(ensure_person(c, ident.id, 2)?, pid, "idempotent");
                    out.push(person_handle(c, pid)?.unwrap_or_default());
                }
                // A 32-char base with a suffix stays within 32 chars.
                let long = format!("{}@x.io", "b".repeat(32));
                for sub in ["4", "5"] {
                    let ident = upsert_identity(c, &login(sub, &long), 1)?;
                    let pid = ensure_person(c, ident.id, 1)?;
                    out.push(person_handle(c, pid)?.unwrap_or_default());
                }
                Ok(out)
            })
            .await
            .expect("db call");
        assert_eq!(handles[0], "r-voronin");
        assert_eq!(handles[1], "r-voronin-2");
        assert_eq!(handles[2], "r-voronin-3");
        assert_eq!(handles[3], "b".repeat(32));
        assert_eq!(handles[4], format!("{}-2", "b".repeat(30)));
        assert!(handles.iter().all(|h| h.len() <= MAX_HANDLE_LEN));
    }
}
