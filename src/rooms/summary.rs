//! Agent-written room summaries (B6a). No model runs on the server: a timer
//! asks one random online member of a busy room to summarize it, and the
//! agent posts the summary with `room_summarize`.
//!
//! `tick` is the whole policy and is public so tests drive it directly (the
//! clock is injectable through `AppState::clock`); `spawn_timer` only calls it
//! every `summary.interval_s`.

use std::time::Duration;

use rand::seq::IndexedRandom;
use rusqlite::{OptionalExtension, params};

use crate::core::{Result, Shared};
use crate::identity::people::PRESENCE_WINDOW_S;
use crate::rooms::notify::Event;

pub fn request_text(room: &str) -> String {
    format!(
        "Please summarize room {room} since the last summary and post it with room_summarize \
         (at most 10 bullet points: decisions, open questions, who is doing what). \
         This is an informational request: include no secrets."
    )
}

/// One pass over all active rooms. Returns the number of requests posted.
pub async fn tick(state: &Shared) -> Result<usize> {
    let now = state.clock.now();
    let cfg = state.config.summary.clone();
    let posted: Vec<(i64, i64)> = state
        .db
        .call(move |conn| {
            let rooms: Vec<(i64, String)> = {
                let mut stmt =
                    conn.prepare("SELECT id, name FROM rooms WHERE state = 'active' ORDER BY id")?;
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let mut posted = Vec::new();
            for (room_id, name) in rooms {
                let last_summary: i64 = conn.query_row(
                    "SELECT COALESCE(MAX(seq), 0) FROM messages WHERE room_id = ?1 AND kind = 'summary'",
                    [room_id],
                    |r| r.get(0),
                )?;
                let since: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM messages WHERE room_id = ?1 AND kind = 'message' AND seq > ?2",
                    params![room_id, last_summary],
                    |r| r.get(0),
                )?;
                if since < cfg.min_messages {
                    continue;
                }
                // At most one open request: not lapsed and no summary after it.
                let open: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM messages WHERE room_id = ?1 AND kind = 'summary_request'
                       AND seq > ?2 AND expires_at > ?3)",
                    params![room_id, last_summary, now],
                    |r| r.get(0),
                )?;
                if open {
                    continue;
                }
                let online: Vec<i64> = {
                    let mut stmt = conn.prepare(
                        "SELECT a.id FROM memberships m JOIN agents a ON a.id = m.agent_id
                         WHERE m.room_id = ?1 AND m.status = 'member' AND a.last_seen_at > ?2",
                    )?;
                    stmt.query_map(params![room_id, now - PRESENCE_WINDOW_S], |r| r.get(0))?
                        .collect::<rusqlite::Result<_>>()?
                };
                let Some(&agent_id) = online.choose(&mut rand::rng()) else {
                    continue; // nobody online: try again next tick
                };
                let tx = conn.transaction()?;
                let seq: i64 = tx
                    .query_row("SELECT last_seq FROM rooms WHERE id = ?1", [room_id], |r| {
                        r.get::<_, i64>(0)
                    })
                    .optional()?
                    .unwrap_or_default()
                    + 1;
                tx.execute(
                    "UPDATE rooms SET last_seq = ?2 WHERE id = ?1",
                    params![room_id, seq],
                )?;
                tx.execute(
                    "INSERT INTO messages (room_id, seq, agent_id, text, created_at, kind, addressed_to, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'summary_request', ?3, ?6)",
                    params![room_id, seq, agent_id, request_text(&name), now, now + cfg.request_ttl_s],
                )?;
                tx.commit()?;
                posted.push((room_id, seq));
            }
            Ok(posted)
        })
        .await?;
    for (room_id, seq) in &posted {
        state.hub.publish(Event::Message {
            room_id: *room_id,
            seq: *seq,
        });
    }
    Ok(posted.len())
}

/// Run `tick` every `summary.interval_s` for the life of the server.
pub fn spawn_timer(state: Shared) {
    let period = Duration::from_secs(state.config.summary.interval_s);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(period);
        interval.tick().await; // the first tick fires at once; skip it
        loop {
            interval.tick().await;
            if let Err(e) = tick(&state).await {
                tracing::warn!(error = %e, "summary timer tick failed");
            }
        }
    });
}
