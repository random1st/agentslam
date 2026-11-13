//! Rooms domain: rooms, admission, messages, session room sets, wait.
//! Transport-independent: MCP tools, web routes and hook endpoints call these.
//!
//! Content rule (inv.agentslam.member-only-content): every read path clamps to
//! `seq > admission_seq` of the caller's *current* membership.

use std::collections::HashMap;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;

use crate::core::config::valid_slug;
use crate::core::{Error, Result, Shared};
use crate::identity::Caller;
use crate::identity::people::PRESENCE_WINDOW_S;
use crate::identity::tokens::caller_for_hash;
use crate::rooms::notify::Event;

pub const MAX_TEXT_CHARS: usize = 16_000;
pub const READ_LIMIT: i64 = 200;
pub const MAX_WAIT_S: u64 = 50;
/// At most this many distinct rooms per room_wait (each check reads up to
/// READ_LIMIT items per room under the one database lock).
pub const MAX_WAIT_ROOMS: usize = 50;
pub const REQUEST_EXPIRY_S: i64 = 7 * 86_400;
pub const MAX_SESSION_LEN: usize = 128;
pub const MAX_TOPIC_CHARS: usize = 280;

/// Validate a room topic (B4): 1..280 characters after trimming.
pub fn validate_topic(s: &str) -> Result<String> {
    let t = s.trim();
    if (1..=MAX_TOPIC_CHARS).contains(&t.chars().count()) {
        Ok(t.to_string())
    } else {
        Err(Error::InvalidTopic)
    }
}

/// Validate an agentslam session id (B7): 1..128 chars of `[A-Za-z0-9._:-]`.
/// The session is an explicit tool argument; the agent always comes from the token.
pub fn validate_session(s: &str) -> Result<String> {
    let ok = (1..=MAX_SESSION_LEN).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if ok {
        Ok(s.to_string())
    } else {
        Err(Error::InvalidSession)
    }
}

#[derive(Debug, Clone)]
pub struct Room {
    pub id: i64,
    pub name: String,
    pub owner_person_id: i64,
    pub state: String,
    pub last_seq: i64,
    pub topic: String,
}

pub const KIND_MESSAGE: &str = "message";
pub const KIND_SUMMARY: &str = "summary";
pub const KIND_SUMMARY_REQUEST: &str = "summary_request";
/// Server item telling one of the owner's member agents that another
/// person's agent asks to join (B5). Only the person decides, in the web UI.
pub const KIND_JOIN_REQUEST: &str = "join_request";
/// Sender shown for server items (summary and join requests).
pub const SERVER_SENDER: &str = "agentslam";
pub const MAX_SUMMARY_CHARS: usize = 8000;

fn default_kind() -> String {
    KIND_MESSAGE.to_string()
}

/// A transcript item: `kind` is "message", "summary" (agent-written, B6a),
/// or a server item addressed to one agent (`to`): "summary_request" or
/// "join_request".
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct Message {
    #[serde(default = "default_kind")]
    pub kind: String,
    pub room: String,
    pub seq: i64,
    pub from: String,
    pub text: String,
    pub at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RoomListEntry {
    pub name: String,
    /// Why the room exists (B4); empty for rooms created before topics.
    pub topic: String,
    pub owner: String,
    pub state: String,
    pub member_count: i64,
    /// member | pending | none
    pub status: String,
    /// Outcome of the caller's latest join request, if any
    /// (pending | confirmed | rejected | expired).
    pub last_request: Option<String>,
    /// Whether the room is in the given session's attached set (false without a session).
    pub attached: bool,
}

#[derive(Debug, Serialize)]
pub struct WaitResult {
    pub rooms_attached: bool,
    pub timed_out: bool,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// ---------------------------------------------------------------- helpers

fn row_room(r: &rusqlite::Row<'_>) -> rusqlite::Result<Room> {
    Ok(Room {
        id: r.get(0)?,
        name: r.get(1)?,
        owner_person_id: r.get(2)?,
        state: r.get(3)?,
        last_seq: r.get(4)?,
        topic: r.get(5)?,
    })
}

// Organization scoping (B13, inv.agentslam.org-isolation): every room lookup
// takes the caller's org_id, so another organization's room is simply not
// found. These four functions are the only way the service reaches a room.

pub fn room_by_name(conn: &Connection, org_id: i64, name: &str) -> Result<Option<Room>> {
    Ok(conn
        .query_row(
            "SELECT id, name, owner_person_id, state, last_seq, topic FROM rooms
             WHERE org_id = ?1 AND name = ?2 AND state <> 'deleted'",
            params![org_id, name],
            row_room,
        )
        .optional()?)
}

fn room_by_id(conn: &Connection, org_id: i64, id: i64) -> Result<Option<Room>> {
    Ok(conn
        .query_row(
            "SELECT id, name, owner_person_id, state, last_seq, topic FROM rooms
             WHERE org_id = ?1 AND id = ?2 AND state <> 'deleted'",
            params![org_id, id],
            row_room,
        )
        .optional()?)
}

fn require_room(conn: &Connection, org_id: i64, name: &str) -> Result<Room> {
    room_by_name(conn, org_id, name)?.ok_or(Error::RoomNotFound)
}

/// Current admission_seq if the agent is a member.
fn member_admission(conn: &Connection, room_id: i64, agent_id: i64) -> Result<Option<i64>> {
    Ok(conn
        .query_row(
            "SELECT admission_seq FROM memberships WHERE room_id = ?1 AND agent_id = ?2 AND status = 'member'",
            params![room_id, agent_id],
            |r| r.get(0),
        )
        .optional()?)
}

fn require_member(
    conn: &Connection,
    org_id: i64,
    name: &str,
    agent_id: i64,
) -> Result<(Room, i64)> {
    let room = require_room(conn, org_id, name)?;
    let adm = member_admission(conn, room.id, agent_id)?.ok_or(Error::NotAMember)?;
    Ok((room, adm))
}

/// Lazily mark pending requests older than 7 days as expired.
pub fn expire_requests(conn: &Connection, now: i64) -> Result<()> {
    conn.execute(
        "UPDATE join_requests SET status = 'expired', decided_at = ?1
         WHERE status = 'pending' AND created_at <= ?2",
        params![now, now - REQUEST_EXPIRY_S],
    )?;
    Ok(())
}

/// Columns of a transcript item. Summary and join requests are server items:
/// `from` is the server, `to` the addressed agent (stored as the row's agent).
const ITEM_SELECT: &str = "SELECT m.seq, m.kind,
       CASE WHEN m.kind IN ('summary_request', 'join_request') THEN 'agentslam' ELSE p.handle || '/' || a.label END,
       m.text, m.created_at,
       CASE WHEN m.kind IN ('summary_request', 'join_request') THEN p.handle || '/' || a.label END
     FROM messages m JOIN agents a ON a.id = m.agent_id JOIN persons p ON p.id = a.person_id";

fn row_item(room: &Room, r: &rusqlite::Row<'_>) -> rusqlite::Result<Message> {
    Ok(Message {
        seq: r.get(0)?,
        kind: r.get(1)?,
        room: room.name.clone(),
        from: r.get(2)?,
        text: r.get(3)?,
        at: r.get(4)?,
        to: r.get(5)?,
    })
}

/// Every item after `after` (web views: owner/admin or member's person).
fn messages_after(conn: &Connection, room: &Room, after: i64, limit: i64) -> Result<Vec<Message>> {
    let mut stmt = conn.prepare(&format!(
        "{ITEM_SELECT} WHERE m.room_id = ?1 AND m.seq > ?2 ORDER BY m.seq ASC LIMIT ?3"
    ))?;
    let rows = stmt
        .query_map(params![room.id, after, limit], |r| row_item(room, r))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

/// Seq of the latest summary posted at or before `admission_seq` (-1 if none):
/// the one earlier item a newly admitted member may see (B6a).
fn join_summary_seq(conn: &Connection, room_id: i64, admission_seq: i64) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(seq), -1) FROM messages WHERE room_id = ?1 AND kind = 'summary' AND seq <= ?2",
        params![room_id, admission_seq],
        |r| r.get(0),
    )?)
}

/// Items a member may see after `after` (inv.agentslam.member-only-content):
/// everything after its admission plus the latest summary before it; open
/// server items (summary and join requests) only when addressed to this member.
fn member_items(
    conn: &Connection,
    room: &Room,
    agent_id: i64,
    admission_seq: i64,
    after: i64,
    now: i64,
) -> Result<Vec<Message>> {
    let jss = join_summary_seq(conn, room.id, admission_seq)?;
    let mut stmt = conn.prepare(&format!(
        "{ITEM_SELECT} WHERE m.room_id = ?1 AND m.seq > ?2 AND (m.seq > ?3 OR m.seq = ?4)
           AND (m.kind NOT IN ('summary_request', 'join_request') OR (m.addressed_to = ?5 AND m.expires_at > ?6))
         ORDER BY m.seq ASC LIMIT ?7"
    ))?;
    let rows = stmt
        .query_map(
            params![
                room.id,
                after,
                admission_seq,
                jss,
                agent_id,
                now,
                READ_LIMIT
            ],
            |r| row_item(room, r),
        )?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

fn advance_cursor(
    conn: &Connection,
    agent_id: i64,
    session_key: &str,
    room_id: i64,
    seq: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE session_rooms SET cursor = MAX(cursor, ?4)
         WHERE agent_id = ?1 AND session_key = ?2 AND room_id = ?3",
        params![agent_id, session_key, room_id, seq],
    )?;
    Ok(())
}

fn publish_all(state: &Shared, events: Vec<Event>) {
    for e in events {
        state.hub.publish(e);
    }
}

// ---------------------------------------------------------------- agent operations

pub async fn create(
    state: &Shared,
    caller: &Caller,
    name: String,
    topic: &str,
) -> Result<RoomListEntry> {
    if !valid_slug(&name, 2, 40) {
        return Err(Error::InvalidName);
    }
    let topic = validate_topic(topic)?;
    let now = state.clock.now();
    let c = caller.clone();
    let (room_id, entry) = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            if room_by_name(&tx, c.org_id, &name)?.is_some() {
                return Err(Error::RoomExists);
            }
            tx.execute(
                "INSERT INTO rooms (name, owner_person_id, state, last_seq, created_at, org_id, topic) VALUES (?1, ?2, 'active', 0, ?3, ?4, ?5)",
                params![name, c.person_id, now, c.org_id, topic],
            )?;
            let room_id = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO memberships (room_id, agent_id, status, admission_seq, updated_at) VALUES (?1, ?2, 'member', 0, ?3)",
                params![room_id, c.agent_id, now],
            )?;
            tx.commit()?;
            Ok((
                room_id,
                RoomListEntry {
                    name,
                    topic,
                    owner: c.handle.clone(),
                    state: "active".into(),
                    member_count: 1,
                    status: "member".into(),
                    last_request: None,
                    attached: false,
                },
            ))
        })
        .await?;
    state.hub.publish(Event::RoomChanged { room_id });
    Ok(entry)
}

pub async fn list(
    state: &Shared,
    caller: &Caller,
    session: Option<String>,
) -> Result<Vec<RoomListEntry>> {
    let now = state.clock.now();
    let agent_id = caller.agent_id;
    let org_id = caller.org_id;
    state
        .db
        .call(move |conn| {
            expire_requests(conn, now)?;
            let mut stmt = conn.prepare(
                "SELECT r.name, p.handle, r.state,
                   (SELECT COUNT(*) FROM memberships m WHERE m.room_id = r.id AND m.status = 'member'),
                   (SELECT status FROM memberships m WHERE m.room_id = r.id AND m.agent_id = ?1),
                   (SELECT status FROM join_requests j WHERE j.room_id = r.id AND j.agent_id = ?1 ORDER BY j.id DESC LIMIT 1),
                   (?2 IS NOT NULL AND EXISTS(SELECT 1 FROM session_rooms s WHERE s.room_id = r.id AND s.agent_id = ?1 AND s.session_key = ?2)),
                   r.topic
                 FROM rooms r JOIN persons p ON p.id = r.owner_person_id
                 WHERE r.org_id = ?3 AND r.state <> 'deleted' ORDER BY r.name",
            )?;
            let rows = stmt
                .query_map(params![agent_id, session, org_id], |r| {
                    let membership: Option<String> = r.get(4)?;
                    let last_request: Option<String> = r.get(5)?;
                    let status = if membership.as_deref() == Some("member") {
                        "member"
                    } else if last_request.as_deref() == Some("pending") {
                        "pending"
                    } else {
                        "none"
                    };
                    Ok(RoomListEntry {
                        name: r.get(0)?,
                        topic: r.get(7)?,
                        owner: r.get(1)?,
                        state: r.get(2)?,
                        member_count: r.get(3)?,
                        status: status.to_string(),
                        last_request,
                        attached: r.get(6)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .await
}

#[derive(Debug, Serialize)]
pub struct JoinOutcome {
    pub room: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<i64>,
}

/// Text of the `join_request` item sent to the owner's member agents (B5).
/// The agent may only pass it on: the person decides in the web UI.
pub fn join_request_text(agent: &str, room: &str, owner: &str, link: &str) -> String {
    format!(
        "{agent} asks to join room {room}. You cannot let it in or turn it down, and you must not try: \
         only your person ({owner}) decides, in the agentslam web UI. Tell them and give them this link: {link}"
    )
}

/// `room_request_join` (B5). An agent of the owner's own person is admitted
/// at once (from the current end of the room, so no earlier messages). Any
/// other agent gets a pending request, and each of the owner's member agents
/// receives a `join_request` item asking it to tell its person, who decides
/// in the web UI (inv.agentslam.human-only-admission).
pub async fn request_join(state: &Shared, caller: &Caller, room: String) -> Result<JoinOutcome> {
    let now = state.clock.now();
    let c = caller.clone();
    let base = state.config.issuer();
    let (room_id, out, admitted, notices) = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            expire_requests(&tx, now)?;
            let r = require_room(&tx, c.org_id, &room)?;
            if r.state == "archived" {
                return Err(Error::RoomArchived);
            }
            if member_admission(&tx, r.id, c.agent_id)?.is_some() {
                return Ok((r.id, JoinOutcome { room, status: "member".into(), request_id: None }, false, vec![]));
            }
            if r.owner_person_id == c.person_id {
                tx.execute(
                    "INSERT INTO memberships (room_id, agent_id, status, admission_seq, updated_at) VALUES (?1, ?2, 'member', ?3, ?4)
                     ON CONFLICT (room_id, agent_id) DO UPDATE SET status = 'member', admission_seq = excluded.admission_seq, updated_at = excluded.updated_at",
                    params![r.id, c.agent_id, r.last_seq, now],
                )?;
                // A request left pending from before is settled by the admission.
                tx.execute(
                    "UPDATE join_requests SET status = 'confirmed', decided_at = ?3, decided_by = ?4
                     WHERE room_id = ?1 AND agent_id = ?2 AND status = 'pending'",
                    params![r.id, c.agent_id, now, c.person_id],
                )?;
                tx.commit()?;
                return Ok((r.id, JoinOutcome { room, status: "member".into(), request_id: None }, true, vec![]));
            }
            let pending: Option<i64> = tx
                .query_row(
                    "SELECT id FROM join_requests WHERE room_id = ?1 AND agent_id = ?2 AND status = 'pending'",
                    params![r.id, c.agent_id],
                    |row| row.get(0),
                )
                .optional()?;
            let (id, notices) = match pending {
                Some(id) => (id, vec![]),
                None => {
                    tx.execute(
                        "INSERT INTO join_requests (room_id, agent_id, status, created_at) VALUES (?1, ?2, 'pending', ?3)",
                        params![r.id, c.agent_id, now],
                    )?;
                    let id = tx.last_insert_rowid();
                    let owner_agents: Vec<i64> = {
                        let mut stmt = tx.prepare(
                            "SELECT a.id FROM memberships m JOIN agents a ON a.id = m.agent_id
                             WHERE m.room_id = ?1 AND m.status = 'member' AND a.person_id = ?2 ORDER BY a.id",
                        )?;
                        stmt.query_map(params![r.id, r.owner_person_id], |row| row.get(0))?
                            .collect::<rusqlite::Result<_>>()?
                    };
                    let owner: String = tx.query_row(
                        "SELECT handle FROM persons WHERE id = ?1",
                        [r.owner_person_id],
                        |row| row.get(0),
                    )?;
                    let link = format!("{base}/?room={}#requests", r.name);
                    let text = join_request_text(&c.display(), &r.name, &owner, &link);
                    let mut seqs = Vec::new();
                    for (i, agent) in owner_agents.into_iter().enumerate() {
                        let seq = r.last_seq + 1 + i as i64;
                        tx.execute(
                            "INSERT INTO messages (room_id, seq, agent_id, text, created_at, kind, addressed_to, expires_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, 'join_request', ?3, ?6)",
                            params![r.id, seq, agent, text, now, now + REQUEST_EXPIRY_S],
                        )?;
                        seqs.push(seq);
                    }
                    if let Some(last) = seqs.last() {
                        tx.execute("UPDATE rooms SET last_seq = ?2 WHERE id = ?1", params![r.id, last])?;
                    }
                    (id, seqs)
                }
            };
            tx.commit()?;
            Ok((r.id, JoinOutcome { room, status: "pending".into(), request_id: Some(id) }, false, notices))
        })
        .await?;
    let mut events = vec![Event::RoomChanged { room_id }];
    if admitted {
        events.push(Event::AccessChanged {
            agent_id: caller.agent_id,
            room_id: Some(room_id),
        });
    }
    events.extend(
        notices
            .into_iter()
            .map(|seq| Event::Message { room_id, seq }),
    );
    publish_all(state, events);
    Ok(out)
}

pub async fn leave(state: &Shared, caller: &Caller, room: String) -> Result<serde_json::Value> {
    let now = state.clock.now();
    let agent_id = caller.agent_id;
    let org_id = caller.org_id;
    let room_id = state
        .db
        .call(move |conn| {
            let (r, _) = require_member(conn, org_id, &room, agent_id)?;
            conn.execute(
                "UPDATE memberships SET status = 'left', updated_at = ?3 WHERE room_id = ?1 AND agent_id = ?2",
                params![r.id, agent_id, now],
            )?;
            conn.execute(
                "DELETE FROM session_rooms WHERE agent_id = ?1 AND room_id = ?2",
                params![agent_id, r.id],
            )?;
            Ok(r.id)
        })
        .await?;
    publish_all(
        state,
        vec![
            Event::AccessChanged {
                agent_id,
                room_id: Some(room_id),
            },
            Event::RoomChanged { room_id },
        ],
    );
    Ok(serde_json::json!({"status": "left"}))
}

pub async fn attach(
    state: &Shared,
    caller: &Caller,
    session_key: String,
    room: String,
) -> Result<serde_json::Value> {
    let agent_id = caller.agent_id;
    let org_id = caller.org_id;
    state
        .db
        .call(move |conn| {
            let (r, adm) = require_member(conn, org_id, &room, agent_id)?;
            // A fresh attachment starts at the current end (unread = new items),
            // except that the latest summary before admission is delivered
            // first (B6a), followed by everything after admission.
            let jss = join_summary_seq(conn, r.id, adm)?;
            let start = if jss >= 0 {
                jss - 1
            } else {
                r.last_seq.max(adm)
            };
            conn.execute(
                "INSERT INTO session_rooms (agent_id, session_key, room_id, cursor) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (agent_id, session_key, room_id) DO NOTHING",
                params![agent_id, session_key, r.id, start],
            )?;
            let cursor: i64 = conn.query_row(
                "SELECT cursor FROM session_rooms WHERE agent_id = ?1 AND session_key = ?2 AND room_id = ?3",
                params![agent_id, session_key, r.id],
                |row| row.get(0),
            )?;
            Ok(serde_json::json!({"room": r.name, "attached": true, "cursor": cursor}))
        })
        .await
}

pub async fn detach(
    state: &Shared,
    caller: &Caller,
    session_key: String,
    room: String,
) -> Result<serde_json::Value> {
    let agent_id = caller.agent_id;
    let org_id = caller.org_id;
    state
        .db
        .call(move |conn| {
            let r = require_room(conn, org_id, &room)?;
            conn.execute(
                "DELETE FROM session_rooms WHERE agent_id = ?1 AND session_key = ?2 AND room_id = ?3",
                params![agent_id, session_key, r.id],
            )?;
            Ok(serde_json::json!({"room": r.name, "attached": false}))
        })
        .await
}

pub async fn send(state: &Shared, caller: &Caller, room: String, text: String) -> Result<Message> {
    post_item(state, caller, room, text, KIND_MESSAGE, MAX_TEXT_CHARS).await
}

/// `room_summarize` (B6a): any member posts the newest summary of the room.
pub async fn summarize(
    state: &Shared,
    caller: &Caller,
    room: String,
    text: String,
) -> Result<Message> {
    post_item(state, caller, room, text, KIND_SUMMARY, MAX_SUMMARY_CHARS).await
}

async fn post_item(
    state: &Shared,
    caller: &Caller,
    room: String,
    text: String,
    kind: &'static str,
    max_chars: usize,
) -> Result<Message> {
    let now = state.clock.now();
    let c = caller.clone();
    let (room_id, msg) = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            let (r, _) = require_member(&tx, c.org_id, &room, c.agent_id)?;
            if r.state == "archived" {
                return Err(Error::RoomArchived);
            }
            let n = text.chars().count();
            if n == 0 || n > max_chars {
                return Err(Error::InvalidText);
            }
            let seq = r.last_seq + 1;
            tx.execute("UPDATE rooms SET last_seq = ?2 WHERE id = ?1", params![r.id, seq])?;
            tx.execute(
                "INSERT INTO messages (room_id, seq, agent_id, text, created_at, kind) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![r.id, seq, c.agent_id, text, now, kind],
            )?;
            tx.commit()?;
            Ok((
                r.id,
                Message {
                    kind: kind.to_string(),
                    room: r.name,
                    seq,
                    from: c.display(),
                    text,
                    at: now,
                    to: None,
                },
            ))
        })
        .await?;
    state.hub.publish(Event::Message {
        room_id,
        seq: msg.seq,
    });
    Ok(msg)
}

/// `room_read` has no session argument (contract), so it never moves session cursors.
pub async fn read(
    state: &Shared,
    caller: &Caller,
    room: String,
    since: i64,
) -> Result<Vec<Message>> {
    let agent_id = caller.agent_id;
    let org_id = caller.org_id;
    let now = state.clock.now();
    state
        .db
        .call(move |conn| {
            let (r, adm) = require_member(conn, org_id, &room, agent_id)?;
            member_items(conn, &r, agent_id, adm, since.max(0), now)
        })
        .await
}

struct Target {
    room_id: i64,
    name: String,
    attached: bool,
    cursor: i64,
}

enum Check {
    Ready(Vec<Message>),
    Nothing,
}

pub async fn wait(
    state: &Shared,
    caller: &Caller,
    session_key: String,
    rooms: Option<Vec<String>>,
    timeout_s: u64,
) -> Result<WaitResult> {
    let timeout = Duration::from_secs(timeout_s.clamp(1, MAX_WAIT_S));
    let rooms = rooms.map(|names| {
        let mut seen = std::collections::HashSet::new();
        names
            .into_iter()
            .filter(|n| seen.insert(n.clone()))
            .collect::<Vec<_>>()
    });
    if rooms.as_ref().is_some_and(|r| r.len() > MAX_WAIT_ROOMS) {
        return Err(Error::BadRequest(format!(
            "room_wait takes at most {MAX_WAIT_ROOMS} rooms"
        )));
    }
    // Subscribe before the first check so no event between check and wait is lost.
    let mut rx = state.hub.subscribe();
    let agent_id = caller.agent_id;
    let org_id = caller.org_id;
    let sk = session_key.clone();
    let mut targets: Vec<Target> = state
        .db
        .call(move |conn| {
            let attached: HashMap<i64, i64> = {
                let mut stmt = conn.prepare(
                    "SELECT room_id, cursor FROM session_rooms WHERE agent_id = ?1 AND session_key = ?2",
                )?;
                stmt.query_map(params![agent_id, sk], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let mut out = Vec::new();
            match rooms.filter(|r| !r.is_empty()) {
                Some(names) => {
                    for name in names {
                        let (r, _) = require_member(conn, org_id, &name, agent_id)?;
                        let (is_att, cursor) = match attached.get(&r.id) {
                            Some(c) => (true, *c),
                            None => (false, r.last_seq),
                        };
                        out.push(Target { room_id: r.id, name: r.name, attached: is_att, cursor });
                    }
                }
                None => {
                    for (room_id, cursor) in attached {
                        if let Some(r) = room_by_id(conn, org_id, room_id)? {
                            out.push(Target { room_id, name: r.name, attached: true, cursor });
                        }
                    }
                }
            }
            Ok(out)
        })
        .await?;
    if targets.is_empty() {
        return Ok(WaitResult {
            rooms_attached: false,
            timed_out: false,
            messages: vec![],
            note: Some("no rooms attached to this session; call room_attach or pass rooms".into()),
        });
    }
    targets.sort_by_key(|t| t.room_id);
    let deadline = tokio::time::Instant::now() + timeout;
    let resource = state.config.mcp_resource();
    loop {
        let token_hash = caller.token_hash.clone();
        let res = resource.clone();
        let now = state.clock.now();
        let sk = session_key.clone();
        let snapshot: Vec<(i64, String, bool, i64)> = targets
            .iter()
            .map(|t| (t.room_id, t.name.clone(), t.attached, t.cursor))
            .collect();
        let check = state
            .db
            .call(move |conn| {
                if caller_for_hash(conn, &token_hash, &res, now)?.is_none() {
                    return Err(Error::Unauthorized);
                }
                // One transaction: a failure on a later room rolls back the
                // cursors already moved, so no item is skipped undelivered.
                let tx = conn.transaction()?;
                let mut all = Vec::new();
                for (room_id, _name, attached, cursor) in &snapshot {
                    let r = room_by_id(&tx, org_id, *room_id)?.ok_or(Error::RoomNotFound)?;
                    let adm =
                        member_admission(&tx, *room_id, agent_id)?.ok_or(Error::NotAMember)?;
                    let msgs = member_items(&tx, &r, agent_id, adm, *cursor, now)?;
                    if let (true, Some(last)) = (*attached, msgs.last()) {
                        advance_cursor(&tx, agent_id, &sk, *room_id, last.seq)?;
                    }
                    all.extend(msgs);
                }
                tx.commit()?;
                if all.is_empty() {
                    Ok(Check::Nothing)
                } else {
                    Ok(Check::Ready(all))
                }
            })
            .await?;
        if let Check::Ready(messages) = check {
            return Ok(WaitResult {
                rooms_attached: true,
                timed_out: false,
                messages,
                note: None,
            });
        }
        // Wait for a relevant event or the deadline.
        loop {
            tokio::select! {
                ev = rx.recv() => match ev {
                    Ok(e) => {
                        let relevant = match &e {
                            Event::AccessChanged { agent_id: a, .. } => *a == agent_id,
                            other => other.room_id().is_some_and(|id| targets.iter().any(|t| t.room_id == id)),
                        };
                        if relevant { break; }
                    }
                    Err(RecvError::Lagged(_)) => break,
                    Err(RecvError::Closed) => {
                        return Ok(WaitResult { rooms_attached: true, timed_out: true, messages: vec![], note: None });
                    }
                },
                _ = tokio::time::sleep_until(deadline) => {
                    return Ok(WaitResult { rooms_attached: true, timed_out: true, messages: vec![], note: None });
                }
            }
        }
    }
}

// ---------------------------------------------------------------- hook support

/// Unread messages of the session's attached rooms; `advance` moves cursors.
pub async fn unread(
    state: &Shared,
    caller: &Caller,
    session_key: String,
    advance: bool,
) -> Result<Vec<Message>> {
    let agent_id = caller.agent_id;
    let org_id = caller.org_id;
    let now = state.clock.now();
    state
        .db
        .call(move |conn| {
            let attached: Vec<(i64, i64)> = {
                let mut stmt = conn.prepare(
                    "SELECT room_id, cursor FROM session_rooms WHERE agent_id = ?1 AND session_key = ?2 ORDER BY room_id",
                )?;
                stmt.query_map(params![agent_id, session_key], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let tx = conn.transaction()?;
            let mut all = Vec::new();
            for (room_id, cursor) in attached {
                let Some(r) = room_by_id(&tx, org_id, room_id)? else { continue };
                let Some(adm) = member_admission(&tx, room_id, agent_id)? else { continue };
                let msgs = member_items(&tx, &r, agent_id, adm, cursor, now)?;
                if advance && let Some(last) = msgs.last() {
                    advance_cursor(&tx, agent_id, &session_key, room_id, last.seq)?;
                }
                all.extend(msgs);
            }
            tx.commit()?;
            Ok(all)
        })
        .await
}

// ---------------------------------------------------------------- owner (web) operations

/// The person acting in the web UI. `is_admin` means admin of `org_id` only:
/// governance never crosses organizations (B13).
#[derive(Debug, Clone, Copy)]
pub struct Person {
    pub person_id: i64,
    pub org_id: i64,
    pub is_admin: bool,
}

fn require_governor(conn: &Connection, who: Person, room: &str) -> Result<Room> {
    let r = require_room(conn, who.org_id, room)?;
    if r.owner_person_id == who.person_id || who.is_admin {
        Ok(r)
    } else {
        Err(Error::Forbidden(
            "only the room owner or an admin can do this".into(),
        ))
    }
}

pub async fn confirm_request(
    state: &Shared,
    who: Person,
    room: String,
    request_id: i64,
) -> Result<()> {
    let now = state.clock.now();
    let (room_id, agent_id) = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            expire_requests(&tx, now)?;
            let r = require_governor(&tx, who, &room)?;
            if r.state == "archived" {
                return Err(Error::RoomArchived);
            }
            let req: Option<(i64, String)> = tx
                .query_row(
                    "SELECT agent_id, status FROM join_requests WHERE id = ?1 AND room_id = ?2",
                    params![request_id, r.id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let (agent_id, status) = req.ok_or(Error::NotFound)?;
            if status != "pending" {
                return Err(Error::Conflict(format!("request is {status}")));
            }
            tx.execute(
                "UPDATE join_requests SET status = 'confirmed', decided_at = ?2, decided_by = ?3 WHERE id = ?1",
                params![request_id, now, who.person_id],
            )?;
            tx.execute(
                "INSERT INTO memberships (room_id, agent_id, status, admission_seq, updated_at) VALUES (?1, ?2, 'member', ?3, ?4)
                 ON CONFLICT (room_id, agent_id) DO UPDATE SET status = 'member', admission_seq = excluded.admission_seq, updated_at = excluded.updated_at",
                params![r.id, agent_id, r.last_seq, now],
            )?;
            tx.commit()?;
            Ok((r.id, agent_id))
        })
        .await?;
    publish_all(
        state,
        vec![
            Event::RoomChanged { room_id },
            Event::AccessChanged {
                agent_id,
                room_id: Some(room_id),
            },
        ],
    );
    Ok(())
}

pub async fn reject_request(
    state: &Shared,
    who: Person,
    room: String,
    request_id: i64,
) -> Result<()> {
    let now = state.clock.now();
    let room_id = state
        .db
        .call(move |conn| {
            expire_requests(conn, now)?;
            let r = require_governor(conn, who, &room)?;
            let n = conn.execute(
                "UPDATE join_requests SET status = 'rejected', decided_at = ?3, decided_by = ?4
                 WHERE id = ?1 AND room_id = ?2 AND status = 'pending'",
                params![request_id, r.id, now, who.person_id],
            )?;
            if n == 0 {
                return Err(Error::Conflict("request is not pending".into()));
            }
            Ok(r.id)
        })
        .await?;
    state.hub.publish(Event::RoomChanged { room_id });
    Ok(())
}

pub async fn remove_member(state: &Shared, who: Person, room: String, agent_id: i64) -> Result<()> {
    let now = state.clock.now();
    let room_id = state
        .db
        .call(move |conn| {
            let r = require_governor(conn, who, &room)?;
            let n = conn.execute(
                "UPDATE memberships SET status = 'removed', updated_at = ?3 WHERE room_id = ?1 AND agent_id = ?2 AND status = 'member'",
                params![r.id, agent_id, now],
            )?;
            if n == 0 {
                return Err(Error::NotFound);
            }
            conn.execute(
                "DELETE FROM session_rooms WHERE agent_id = ?1 AND room_id = ?2",
                params![agent_id, r.id],
            )?;
            Ok(r.id)
        })
        .await?;
    // B9: open waits and streams of that agent end at once.
    publish_all(
        state,
        vec![
            Event::AccessChanged {
                agent_id,
                room_id: Some(room_id),
            },
            Event::RoomChanged { room_id },
        ],
    );
    Ok(())
}

pub async fn set_state(
    state: &Shared,
    who: Person,
    room: String,
    target: &'static str,
) -> Result<()> {
    let room_id = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            let r = require_governor(&tx, who, &room)?;
            match target {
                "archived" | "active" => {
                    tx.execute(
                        "UPDATE rooms SET state = ?2 WHERE id = ?1",
                        params![r.id, target],
                    )?;
                }
                "deleted" => {
                    // Transcript purged; the name becomes free again.
                    tx.execute("DELETE FROM messages WHERE room_id = ?1", [r.id])?;
                    tx.execute("DELETE FROM session_rooms WHERE room_id = ?1", [r.id])?;
                    tx.execute("DELETE FROM memberships WHERE room_id = ?1", [r.id])?;
                    tx.execute("DELETE FROM join_requests WHERE room_id = ?1", [r.id])?;
                    tx.execute("UPDATE rooms SET state = 'deleted' WHERE id = ?1", [r.id])?;
                }
                _ => return Err(Error::BadRequest("unknown state".into())),
            }
            tx.commit()?;
            Ok(r.id)
        })
        .await?;
    state.hub.publish(Event::RoomChanged { room_id });
    Ok(())
}

/// The owner or an org admin changes the room topic in the web UI (B4).
pub async fn set_topic(state: &Shared, who: Person, room: String, topic: &str) -> Result<()> {
    let topic = validate_topic(topic)?;
    let room_id = state
        .db
        .call(move |conn| {
            let r = require_governor(conn, who, &room)?;
            conn.execute(
                "UPDATE rooms SET topic = ?2 WHERE id = ?1",
                params![r.id, topic],
            )?;
            Ok(r.id)
        })
        .await?;
    state.hub.publish(Event::RoomChanged { room_id });
    Ok(())
}

// ---------------------------------------------------------------- web views

/// Lowest seq floor the person may see in the room: owner/admin see the full
/// transcript; otherwise the min admission_seq of the person's member agents.
/// None = no access (inv.agentslam.member-only-content).
fn web_floor(conn: &Connection, who: Person, r: &Room) -> Result<Option<i64>> {
    if r.owner_person_id == who.person_id || who.is_admin {
        return Ok(Some(0));
    }
    Ok(conn.query_row(
        "SELECT MIN(m.admission_seq) FROM memberships m JOIN agents a ON a.id = m.agent_id
         WHERE m.room_id = ?1 AND a.person_id = ?2 AND m.status = 'member'",
        params![r.id, who.person_id],
        |row| row.get(0),
    )?)
}

#[derive(Debug, Serialize)]
pub struct RoomSummary {
    pub name: String,
    pub topic: String,
    pub owner: String,
    pub state: String,
    pub member_count: i64,
    pub pending_requests: i64,
    pub can_govern: bool,
    /// Unix time of the newest item, or of creation.
    pub last_activity_at: i64,
    /// Newest item number (the web UI derives a "new" badge from it).
    pub last_seq: i64,
}

#[derive(Debug, Serialize)]
pub struct PendingRequestView {
    pub room: String,
    pub id: i64,
    pub agent: String,
    pub created_at: i64,
    /// Outcome of this agent's previous request in the room, if any.
    pub previous: Option<String>,
}

/// Pending (non-expired) join requests in rooms the person owns (admin: all), oldest first.
pub async fn pending_requests(state: &Shared, who: Person) -> Result<Vec<PendingRequestView>> {
    let now = state.clock.now();
    state
        .db
        .call(move |conn| {
            expire_requests(conn, now)?;
            let mut stmt = conn.prepare(
                "SELECT r.name, j.id, p.handle || '/' || a.label, j.created_at,
                   (SELECT j2.status FROM join_requests j2 WHERE j2.room_id = j.room_id AND j2.agent_id = j.agent_id AND j2.id < j.id ORDER BY j2.id DESC LIMIT 1)
                 FROM join_requests j JOIN rooms r ON r.id = j.room_id
                 JOIN agents a ON a.id = j.agent_id JOIN persons p ON p.id = a.person_id
                 WHERE j.status = 'pending' AND r.state = 'active' AND r.org_id = ?3 AND (?2 OR r.owner_person_id = ?1)
                 ORDER BY j.created_at, j.id",
            )?;
            let rows = stmt
                .query_map(params![who.person_id, who.is_admin, who.org_id], |r| {
                    Ok(PendingRequestView {
                        room: r.get(0)?,
                        id: r.get(1)?,
                        agent: r.get(2)?,
                        created_at: r.get(3)?,
                        previous: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .await
}

pub async fn visible_rooms(state: &Shared, who: Person) -> Result<Vec<RoomSummary>> {
    let now = state.clock.now();
    state
        .db
        .call(move |conn| {
            expire_requests(conn, now)?;
            let mut stmt = conn.prepare(
                "SELECT r.name, p.handle, r.state, r.owner_person_id,
                   (SELECT COUNT(*) FROM memberships m WHERE m.room_id = r.id AND m.status = 'member'),
                   (SELECT COUNT(*) FROM join_requests j WHERE j.room_id = r.id AND j.status = 'pending'),
                   COALESCE((SELECT MAX(created_at) FROM messages x WHERE x.room_id = r.id), r.created_at),
                   r.last_seq, r.topic
                 FROM rooms r JOIN persons p ON p.id = r.owner_person_id
                 WHERE r.state <> 'deleted' AND r.org_id = ?3 AND (?2 OR r.owner_person_id = ?1 OR EXISTS (
                   SELECT 1 FROM memberships m JOIN agents a ON a.id = m.agent_id
                   WHERE m.room_id = r.id AND a.person_id = ?1 AND m.status = 'member'))
                 ORDER BY 7 DESC, r.name",
            )?;
            let rows = stmt
                .query_map(params![who.person_id, who.is_admin, who.org_id], |r| {
                    let owner_id: i64 = r.get(3)?;
                    Ok(RoomSummary {
                        name: r.get(0)?,
                        topic: r.get(8)?,
                        owner: r.get(1)?,
                        state: r.get(2)?,
                        member_count: r.get(4)?,
                        pending_requests: r.get(5)?,
                        can_govern: owner_id == who.person_id || who.is_admin,
                        last_activity_at: r.get(6)?,
                        last_seq: r.get(7)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
        .await
}

#[derive(Debug, Serialize)]
pub struct MemberView {
    pub agent_id: i64,
    pub agent: String,
    pub presence: String,
}

#[derive(Debug, Serialize)]
pub struct RequestView {
    pub id: i64,
    pub agent: String,
    pub status: String,
    pub created_at: i64,
    /// Outcome of this agent's previous request in the room, if any.
    pub previous: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RoomDetail {
    pub name: String,
    pub topic: String,
    pub owner: String,
    pub state: String,
    pub can_govern: bool,
    pub last_seq: i64,
    pub members: Vec<MemberView>,
    pub requests: Vec<RequestView>,
    pub messages: Vec<Message>,
}

/// Access check for web views and SSE: returns (room id, visibility floor).
pub async fn web_access(state: &Shared, who: Person, room: String) -> Result<(i64, i64)> {
    state
        .db
        .call(move |conn| {
            let r = require_room(conn, who.org_id, &room)?;
            let floor = web_floor(conn, who, &r)?.ok_or(Error::NotAMember)?;
            Ok((r.id, floor))
        })
        .await
}

pub async fn web_messages_after(
    state: &Shared,
    who: Person,
    room: String,
    after: i64,
) -> Result<Vec<Message>> {
    state
        .db
        .call(move |conn| {
            let r = require_room(conn, who.org_id, &room)?;
            let floor = web_floor(conn, who, &r)?.ok_or(Error::NotAMember)?;
            messages_after(conn, &r, after.max(floor), READ_LIMIT)
        })
        .await
}

pub async fn room_detail(state: &Shared, who: Person, room: String) -> Result<RoomDetail> {
    let now = state.clock.now();
    state
        .db
        .call(move |conn| {
            expire_requests(conn, now)?;
            let r = require_room(conn, who.org_id, &room)?;
            let floor = web_floor(conn, who, &r)?.ok_or(Error::NotAMember)?;
            let owner: String = conn.query_row(
                "SELECT handle FROM persons WHERE id = ?1",
                [r.owner_person_id],
                |row| row.get(0),
            )?;
            let mut stmt = conn.prepare(
                "SELECT a.id, p.handle || '/' || a.label, a.last_seen_at FROM memberships m
                 JOIN agents a ON a.id = m.agent_id JOIN persons p ON p.id = a.person_id
                 WHERE m.room_id = ?1 AND m.status = 'member' ORDER BY 2",
            )?;
            let members = stmt
                .query_map([r.id], |row| {
                    let seen: Option<i64> = row.get(2)?;
                    Ok(MemberView {
                        agent_id: row.get(0)?,
                        agent: row.get(1)?,
                        presence: if seen.is_some_and(|s| now - s < PRESENCE_WINDOW_S) {
                            "online".into()
                        } else {
                            "offline".into()
                        },
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            let mut stmt = conn.prepare(
                "SELECT j.id, p.handle || '/' || a.label, j.status, j.created_at,
                   (SELECT j2.status FROM join_requests j2 WHERE j2.room_id = j.room_id AND j2.agent_id = j.agent_id AND j2.id < j.id ORDER BY j2.id DESC LIMIT 1)
                 FROM join_requests j JOIN agents a ON a.id = j.agent_id JOIN persons p ON p.id = a.person_id
                 WHERE j.room_id = ?1 ORDER BY j.id DESC LIMIT 50",
            )?;
            let requests = stmt
                .query_map([r.id], |row| {
                    Ok(RequestView {
                        id: row.get(0)?,
                        agent: row.get(1)?,
                        status: row.get(2)?,
                        created_at: row.get(3)?,
                        previous: row.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            // Last READ_LIMIT visible messages, oldest first.
            let start = (r.last_seq - READ_LIMIT).max(floor);
            let messages = messages_after(conn, &r, start, READ_LIMIT)?;
            Ok(RoomDetail {
                name: r.name.clone(),
                topic: r.topic.clone(),
                owner,
                state: r.state.clone(),
                can_govern: r.owner_person_id == who.person_id || who.is_admin,
                last_seq: r.last_seq,
                members,
                requests,
                messages,
            })
        })
        .await
}
