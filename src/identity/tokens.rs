//! Opaque tokens and codes. Only SHA-256 hashes are stored
//! (inv.agentslam.secrets-hashed); raw values leave the server exactly once.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::core::Result;
use crate::identity::Caller;

/// 256-bit random value, base64url, with a readable prefix.
pub fn random_token(prefix: &str) -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn hash(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// RFC 7636 S256: base64url(sha256(verifier)).
pub fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Constant-time string comparison.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

pub struct IssueParams<'a> {
    pub agent_id: i64,
    pub family_id: &'a str,
    pub client_id: &'a str,
    pub resource: &'a str,
    pub now: i64,
    pub access_ttl: i64,
    pub refresh_ttl: i64,
}

/// Issue an access + refresh token pair in one OAuth grant family.
pub fn issue_pair(conn: &Connection, p: &IssueParams<'_>) -> Result<TokenPair> {
    let access = random_token("asl_at_");
    let refresh = random_token("asl_rt_");
    let mut stmt = conn.prepare(
        "INSERT INTO tokens (token_hash, kind, agent_id, family_id, client_id, resource, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    stmt.execute(params![
        hash(&access),
        "access",
        p.agent_id,
        p.family_id,
        p.client_id,
        p.resource,
        p.now,
        p.now + p.access_ttl
    ])?;
    stmt.execute(params![
        hash(&refresh),
        "refresh",
        p.agent_id,
        p.family_id,
        p.client_id,
        p.resource,
        p.now,
        p.now + p.refresh_ttl
    ])?;
    Ok(TokenPair {
        access_token: access,
        refresh_token: refresh,
        expires_in: p.access_ttl,
    })
}

/// Mint a headless agent token (no expiry, revocable). Returns (raw, family_id).
pub fn mint_agent_token(
    conn: &Connection,
    agent_id: i64,
    resource: &str,
    now: i64,
) -> Result<(String, String)> {
    let raw = random_token("asl_ag_");
    let family = random_token("fam_");
    conn.execute(
        "INSERT INTO tokens (token_hash, kind, agent_id, family_id, client_id, resource, created_at)
         VALUES (?1, 'agent', ?2, ?3, NULL, ?4, ?5)",
        params![hash(&raw), agent_id, family, resource, now],
    )?;
    Ok((raw, family))
}

/// Resolve a bearer token to its caller. Valid = access or agent token, not
/// revoked, not expired, bound to `resource`.
pub fn caller_for_hash(
    conn: &Connection,
    token_hash: &str,
    resource: &str,
    now: i64,
) -> Result<Option<Caller>> {
    let caller = conn
        .query_row(
            "SELECT a.id, a.person_id, p.handle, a.label, p.org_id
             FROM tokens t JOIN agents a ON a.id = t.agent_id JOIN persons p ON p.id = a.person_id
             JOIN organizations o ON o.id = p.org_id AND o.disabled_at IS NULL
             WHERE t.token_hash = ?1 AND t.kind IN ('access', 'agent') AND t.revoked_at IS NULL
               AND (t.expires_at IS NULL OR t.expires_at > ?2) AND t.resource = ?3",
            params![token_hash, now, resource],
            |r| {
                Ok(Caller {
                    agent_id: r.get(0)?,
                    person_id: r.get(1)?,
                    handle: r.get(2)?,
                    label: r.get(3)?,
                    org_id: r.get(4)?,
                    token_hash: token_hash.to_string(),
                })
            },
        )
        .optional()?;
    Ok(caller)
}

/// Revoke every token of a family. Returns the agent id when something was revoked.
pub fn revoke_family(conn: &Connection, family_id: &str, now: i64) -> Result<Option<i64>> {
    let agent: Option<i64> = conn
        .query_row(
            "SELECT agent_id FROM tokens WHERE family_id = ?1 LIMIT 1",
            [family_id],
            |r| r.get(0),
        )
        .optional()?;
    conn.execute(
        "UPDATE tokens SET revoked_at = ?2 WHERE family_id = ?1 AND revoked_at IS NULL",
        params![family_id, now],
    )?;
    Ok(agent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_rfc7636_vector() {
        assert_eq!(
            pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn tokens_are_random_and_hash_is_hex() {
        let a = random_token("x_");
        assert_ne!(a, random_token("x_"));
        assert_eq!(hash(&a).len(), 64);
        assert!(ct_eq("abc", "abc") && !ct_eq("abc", "abd") && !ct_eq("a", "ab"));
    }
}
