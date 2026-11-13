//! Organizations (B13): self-registered, fully isolated tenants.
//!
//! An organization is keyed by a verified value from the ID token:
//! `google_hd` (Workspace domain), `entra_tid` (tenant id), `oidc`
//! (issuer + org claim value or its `org_map` target), `okta` (operator-configured
//! Okta issuer), or `default` (people that existed before organizations and
//! had no verified key). Okta connected by an org admin points straight at its
//! organization.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::core::config::{Config, ProviderKind};
use crate::core::{Error, Result};

/// A verified organization key from sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgKey {
    pub kind: String,
    pub value: String,
    /// Human name shown on the "create the organization" page.
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Org {
    pub id: i64,
    pub name: String,
    pub key_kind: String,
    #[serde(skip)]
    pub key_value: String,
    pub disabled: bool,
}

fn row_org(r: &rusqlite::Row<'_>) -> rusqlite::Result<Org> {
    Ok(Org {
        id: r.get(0)?,
        name: r.get(1)?,
        key_kind: r.get(2)?,
        key_value: r.get(3)?,
        disabled: r.get::<_, Option<i64>>(4)?.is_some(),
    })
}

const ORG_COLS: &str = "id, name, key_kind, key_value, disabled_at";

pub fn find_org(conn: &Connection, key: &OrgKey) -> Result<Option<Org>> {
    Ok(conn
        .query_row(
            &format!("SELECT {ORG_COLS} FROM organizations WHERE key_kind = ?1 AND key_value = ?2"),
            params![key.kind, key.value],
            row_org,
        )
        .optional()?)
}

pub fn org_by_id(conn: &Connection, id: i64) -> Result<Option<Org>> {
    Ok(conn
        .query_row(
            &format!("SELECT {ORG_COLS} FROM organizations WHERE id = ?1"),
            [id],
            row_org,
        )
        .optional()?)
}

pub fn org_of_person(conn: &Connection, person_id: i64) -> Result<Option<Org>> {
    Ok(conn
        .query_row(
            "SELECT o.id, o.name, o.key_kind, o.key_value, o.disabled_at FROM organizations o
             JOIN persons p ON p.org_id = o.id WHERE p.id = ?1",
            [person_id],
            row_org,
        )
        .optional()?)
}

/// Create the organization for `key` (or return the existing one).
pub fn create_org(conn: &Connection, key: &OrgKey, now: i64) -> Result<i64> {
    conn.execute(
        "INSERT INTO organizations (key_kind, key_value, name, created_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (key_kind, key_value) DO NOTHING",
        params![key.kind, key.value, key.name, now],
    )?;
    Ok(conn.query_row(
        "SELECT id FROM organizations WHERE key_kind = ?1 AND key_value = ?2",
        params![key.kind, key.value],
        |r| r.get(0),
    )?)
}

pub fn add_admin(conn: &Connection, org_id: i64, person_id: i64, now: i64) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO org_admins (org_id, person_id, created_at) VALUES (?1, ?2, ?3)",
        params![org_id, person_id, now],
    )?;
    Ok(())
}

pub fn is_org_admin(conn: &Connection, org_id: i64, person_id: i64) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM org_admins WHERE org_id = ?1 AND person_id = ?2)",
        params![org_id, person_id],
        |r| r.get(0),
    )?)
}

/// Instance restrictions (`allowed_domains`, `allowed_tenants`; empty = open).
pub fn instance_allows(cfg: &Config, key: &OrgKey) -> bool {
    match key.kind.as_str() {
        "google_hd" => {
            cfg.allowed_domains.is_empty()
                || cfg
                    .allowed_domains
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(&key.value))
        }
        "entra_tid" => {
            cfg.allowed_tenants.is_empty() || cfg.allowed_tenants.iter().any(|t| t == &key.value)
        }
        _ => true,
    }
}

/// Person id, first identity's provider id, email, issuer, stored org key.
type BackfillRow = (
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Startup backfill for rows from before organizations: every person without
/// an organization joins the one of its verified key (Google: the email
/// domain of a Workspace identity, whose `hd` was checked at sign-in; Entra:
/// the tid in the configured issuer), else a "default" organization of its
/// own (one per person, never shared). Rooms follow their
/// owner. Idempotent; nothing is deleted.
pub fn backfill(conn: &mut Connection, cfg: &Config, now: i64) -> Result<usize> {
    let tx = conn.transaction()?;
    let people: Vec<BackfillRow> = {
        let mut stmt = tx.prepare(
            "SELECT p.id,
               (SELECT i.provider_id FROM identities i WHERE i.person_id = p.id ORDER BY i.id LIMIT 1),
               (SELECT i.email FROM identities i WHERE i.person_id = p.id ORDER BY i.id LIMIT 1),
               (SELECT i.issuer FROM identities i WHERE i.person_id = p.id ORDER BY i.id LIMIT 1),
               (SELECT i.org_key_kind || char(31) || i.org_key_value FROM identities i
                  WHERE i.person_id = p.id AND i.org_key_kind IS NOT NULL ORDER BY i.id LIMIT 1)
             FROM persons p WHERE p.org_id IS NULL ORDER BY p.id",
        )?;
        stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<rusqlite::Result<_>>()?
    };
    let n = people.len();
    for (person_id, provider_id, email, issuer, stored) in people {
        let key = stored
            .and_then(|s| {
                s.split_once('\u{1f}')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .map(|(kind, value)| OrgKey {
                name: value.clone(),
                kind,
                value,
            })
            .or_else(|| {
                let p = cfg.provider(provider_id.as_deref()?)?;
                match p.kind {
                    ProviderKind::Google => {
                        let domain = email.as_deref()?.rsplit_once('@')?.1.to_lowercase();
                        Some(OrgKey {
                            kind: "google_hd".into(),
                            value: domain.clone(),
                            name: domain,
                        })
                    }
                    ProviderKind::Entra => {
                        let iss = issuer.as_deref()?;
                        let tid = iss
                            .strip_prefix("https://login.microsoftonline.com/")?
                            .split('/')
                            .next()?
                            .to_string();
                        Some(OrgKey {
                            kind: "entra_tid".into(),
                            value: tid.clone(),
                            name: tid,
                        })
                    }
                    ProviderKind::Okta => Some(OrgKey {
                        kind: "okta".into(),
                        value: p.issuer(),
                        name: p.issuer(),
                    }),
                    ProviderKind::Oidc => None,
                }
            })
            // No verified key: an organization of its own, never a shared
            // bucket. Unrelated people must not land in one tenant (and the
            // first of them must not become admin over the rest).
            .unwrap_or_else(|| OrgKey {
                kind: "default".into(),
                value: format!("person-{person_id}"),
                name: "default".into(),
            });
        let org_id = create_org(&tx, &key, now)?;
        tx.execute(
            "UPDATE persons SET org_id = ?2 WHERE id = ?1",
            params![person_id, org_id],
        )?;
        // People are visited oldest first: the earliest person of an
        // organization formed here becomes its admin, as its creator would
        // have on a fresh sign-in. Otherwise a migrated organization has none.
        let has_admin: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM org_admins WHERE org_id = ?1)",
            [org_id],
            |r| r.get(0),
        )?;
        if !has_admin {
            add_admin(&tx, org_id, person_id, now)?;
        }
    }
    tx.execute(
        "UPDATE rooms SET org_id = (SELECT p.org_id FROM persons p WHERE p.id = rooms.owner_person_id)
         WHERE org_id IS NULL",
        [],
    )?;
    tx.commit()?;
    Ok(n)
}

// ------------------------------------------------------------ secrets

/// AES-256-GCM: base64(nonce(12) || ciphertext).
pub fn encrypt_secret(key: &[u8; 32], plain: &str) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Internal(anyhow::anyhow!("bad secret key")))?;
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(&Nonce::from(nonce), plain.as_bytes())
        .map_err(|_| Error::Internal(anyhow::anyhow!("encryption failed")))?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(STANDARD.encode(out))
}

pub fn decrypt_secret(key: &[u8; 32], enc: &str) -> Result<String> {
    let raw = STANDARD
        .decode(enc)
        .map_err(|_| Error::Internal(anyhow::anyhow!("stored secret is corrupt")))?;
    if raw.len() < 13 {
        return Err(Error::Internal(anyhow::anyhow!("stored secret is corrupt")));
    }
    let (nonce, ct) = raw.split_at(12);
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| Error::Internal(anyhow::anyhow!("stored secret is corrupt")))?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Internal(anyhow::anyhow!("bad secret key")))?;
    let plain = cipher.decrypt(&Nonce::from(nonce), ct).map_err(|_| {
        Error::Internal(anyhow::anyhow!(
            "stored secret cannot be decrypted with this key"
        ))
    })?;
    String::from_utf8(plain)
        .map_err(|_| Error::Internal(anyhow::anyhow!("stored secret is corrupt")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backfill_moves_existing_people_and_rooms() {
        let cfg = Config::from_toml(
            "public_url='http://127.0.0.1:1'\n\
             [[providers]]\nid='google'\nkind='google'\nclient_id='c'\n\
             [[providers]]\nid='entra'\nkind='entra'\nclient_id='c'\n",
        )
        .expect("cfg");
        let db = crate::core::db::Db::open(":memory:").expect("db");
        let (orgs, room_org, n) = db
            .call(move |c| {
                // Pre-organization rows: persons and a room without org_id.
                c.execute_batch(
                    "INSERT INTO persons (id, handle, created_at) VALUES (1, 'roman', 0), (2, 'eve', 0), (3, 'lone', 0), (4, 'ghost', 0);
                     INSERT INTO identities (issuer, sub, provider_id, person_id, email, created_at, last_login_at) VALUES
                       ('https://accounts.google.com', 'g1', 'google', 1, 'roman@example.org', 0, 0),
                       ('https://login.microsoftonline.com/tid-9/v2.0', 'e1', 'entra', 2, 'eve@contoso.com', 0, 0);
                     INSERT INTO rooms (id, name, owner_person_id, state, last_seq, created_at) VALUES (1, 'ios', 1, 'active', 0, 0);",
                )?;
                let n = backfill(c, &cfg, 5)?;
                let orgs: Vec<(String, String, String)> = {
                    let mut s = c.prepare(
                        "SELECT p.handle, o.key_kind, o.key_value FROM persons p JOIN organizations o ON o.id = p.org_id ORDER BY p.id",
                    )?;
                    s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                        .collect::<rusqlite::Result<_>>()?
                };
                let room_org: String = c.query_row(
                    "SELECT o.key_value FROM rooms r JOIN organizations o ON o.id = r.org_id WHERE r.id = 1",
                    [],
                    |r| r.get(0),
                )?;
                // Idempotent.
                assert_eq!(backfill(c, &cfg, 6)?, 0);
                let admins: Vec<String> = {
                    let mut s = c.prepare(
                        "SELECT p.handle FROM org_admins a JOIN persons p ON p.id = a.person_id ORDER BY p.id",
                    )?;
                    s.query_map([], |r| r.get(0))?
                        .collect::<rusqlite::Result<_>>()?
                };
                assert_eq!(
                    admins,
                    vec!["roman".to_string(), "eve".into(), "lone".into(), "ghost".into()],
                    "the earliest person of each migrated organization becomes its admin"
                );
                Ok((orgs, room_org, n))
            })
            .await
            .expect("db");
        assert_eq!(n, 4);
        assert_eq!(
            orgs,
            vec![
                ("roman".into(), "google_hd".into(), "example.org".into()),
                ("eve".into(), "entra_tid".into(), "tid-9".into()),
                ("lone".into(), "default".into(), "person-3".into()),
                ("ghost".into(), "default".into(), "person-4".into()),
            ]
        );
        assert_eq!(room_org, "example.org", "rooms follow their owner");
    }

    #[test]
    fn secret_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let enc = encrypt_secret(&key, "s3cr3t").expect("enc");
        assert!(!enc.contains("s3cr3t"));
        assert_ne!(
            enc,
            encrypt_secret(&key, "s3cr3t").expect("enc"),
            "random nonce"
        );
        assert_eq!(decrypt_secret(&key, &enc).expect("dec"), "s3cr3t");
        assert!(decrypt_secret(&[8u8; 32], &enc).is_err(), "wrong key");
    }
}
