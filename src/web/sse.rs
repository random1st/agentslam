//! Live room stream over SSE. Access is checked before the stream opens and
//! re-checked on every relevant event and every keep-alive tick: the web
//! session is read again (expiry, logout, a disabled organization, a revoked
//! admin flag), then room access. Losing either closes the stream (B9).

use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::core::{Result, Shared};
use crate::identity::session::{WebUser, load_session_by_hash};
use crate::rooms::notify::Event;
use crate::rooms::service::{self, Person};
use crate::web::person;

type Tx = mpsc::Sender<std::result::Result<SseEvent, Infallible>>;

async fn emit(tx: &Tx, name: &str, data: String) -> bool {
    tx.send(Ok(SseEvent::default().event(name).data(data)))
        .await
        .is_ok()
}

pub async fn events(
    State(state): State<Shared>,
    user: WebUser,
    Path(name): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Sse<impl futures::Stream<Item = std::result::Result<SseEvent, Infallible>>>> {
    let mut who = person(&user);
    let token_hash = user.session.token_hash.clone();
    // Refuse before opening the stream when the person has no access.
    let (room_id, _floor) = service::web_access(&state, who, name.clone()).await?;
    let mut rx = state.hub.subscribe();
    let mut after = match q.get("after").and_then(|a| a.parse::<i64>().ok()) {
        Some(a) => a,
        None => {
            service::room_detail(&state, who, name.clone())
                .await?
                .last_seq
        }
    };
    let (tx, out) = mpsc::channel(64);
    tokio::spawn(async move {
        if !emit(
            &tx,
            "ready",
            serde_json::json!({"room": name, "after": after}).to_string(),
        )
        .await
        {
            return;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            let ev = tokio::select! {
                ev = rx.recv() => ev,
                _ = tick.tick() => {
                    if tx.is_closed() { return; }
                    if current_person(&state, &token_hash, who).await.is_none() {
                        let _ = emit(&tx, "closed", serde_json::json!({"reason": "access_lost"}).to_string()).await;
                        return;
                    }
                    continue;
                }
            };
            let (relevant, is_message) = match &ev {
                Ok(Event::Message { room_id: r, .. }) => (*r == room_id, true),
                Ok(Event::RoomChanged { room_id: r }) => (*r == room_id, false),
                Ok(Event::AccessChanged { room_id: r, .. }) => {
                    (r.is_none_or(|r| r == room_id), false)
                }
                Err(RecvError::Lagged(_)) => (true, true),
                Err(RecvError::Closed) => return,
            };
            if !relevant {
                continue;
            }
            let fresh = current_person(&state, &token_hash, who).await;
            if let Some(p) = fresh {
                who = p;
            }
            if fresh.is_none()
                || service::web_access(&state, who, name.clone())
                    .await
                    .is_err()
            {
                let _ = emit(
                    &tx,
                    "closed",
                    serde_json::json!({"reason": "access_lost"}).to_string(),
                )
                .await;
                return;
            }
            if is_message {
                match service::web_messages_after(&state, who, name.clone(), after).await {
                    Ok(msgs) => {
                        for m in msgs {
                            after = after.max(m.seq);
                            let data = serde_json::to_string(&m).unwrap_or_default();
                            if !emit(&tx, "message", data).await {
                                return;
                            }
                        }
                    }
                    Err(_) => return,
                }
            } else if !emit(&tx, "update", "{}".to_string()).await {
                return;
            }
        }
    });
    Ok(Sse::new(ReceiverStream::new(out)).keep_alive(KeepAlive::default()))
}

/// The stream's person as the session says now; None when the session expired
/// or was logged out, the organization was disabled, or the session now
/// belongs to another person or organization.
async fn current_person(
    state: &crate::core::Shared,
    token_hash: &str,
    was: Person,
) -> Option<Person> {
    let sess = load_session_by_hash(state, token_hash.to_string())
        .await
        .ok()
        .flatten()?;
    let org = sess.org.as_ref()?;
    if sess.person_id != Some(was.person_id) || org.id != was.org_id {
        return None;
    }
    Some(Person {
        person_id: was.person_id,
        org_id: was.org_id,
        is_admin: sess.is_admin,
    })
}
