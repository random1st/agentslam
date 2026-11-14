//! SQLite store.
//!
//! Choice: rusqlite + one serialized connection driven through
//! `spawn_blocking`, not sqlx. agentslam is single-replica (spec: Store) and
//! every statement is short; one connection behind a mutex removes
//! SQLITE_BUSY handling entirely, makes multi-statement transactions trivial
//! (`&mut Connection`), and keeps blocking I/O off the async runtime.
//! Migrations are embedded with `include_str!` and tracked by `PRAGMA user_version`.

use std::sync::{Arc, Mutex};

use anyhow::Context;
use rusqlite::Connection;

use crate::core::error::{Error, Result};

const MIGRATIONS: &[&str] = &[
    include_str!("../../migrations/0001_init.sql"),
    include_str!("../../migrations/0002_drop_hook_session_key.sql"),
    include_str!("../../migrations/0003_room_summaries.sql"),
    include_str!("../../migrations/0004_organizations.sql"),
    include_str!("../../migrations/0005_room_topic_join_requests.sql"),
    include_str!("../../migrations/0006_service_accounts.sql"),
    include_str!("../../migrations/0007_invites.sql"),
];

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Open (or create) the database at `path` (`:memory:` for tests), enable
    /// WAL, apply pending migrations with foreign keys off (table rebuilds need
    /// it), verify foreign keys, then enable them.
    pub fn open(path: &str) -> anyhow::Result<Db> {
        let mut conn = if path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open(path)
        }
        .with_context(|| format!("open sqlite database {path}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("enable WAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "OFF")?;
        migrate(&mut conn)?;
        let violations: i64 =
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })?;
        anyhow::ensure!(
            violations == 0,
            "database has {violations} foreign key violations after migration"
        );
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enable foreign keys")?;
        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Run `f` on the calling thread (startup only, before the runtime serves requests).
    pub fn blocking<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T>,
    {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| Error::Internal(anyhow::anyhow!("database mutex poisoned")))?;
        f(&mut guard)
    }

    /// Run `f` with exclusive access to the connection on the blocking pool.
    pub async fn call<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn
                .lock()
                .map_err(|_| Error::Internal(anyhow::anyhow!("database mutex poisoned")))?;
            f(&mut guard)
        })
        .await
        .map_err(|e| Error::Internal(anyhow::anyhow!("database task failed: {e}")))?
    }
}

fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    for (idx, sql) in MIGRATIONS.iter().enumerate() {
        let version = idx as i64 + 1;
        if version <= current {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(sql)
            .with_context(|| format!("apply migration {version}"))?;
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
    Ok(())
}
