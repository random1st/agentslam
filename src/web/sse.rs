//! Live room stream over SSE. Access is checked before the stream opens and
//! re-checked on every relevant event; losing access (removal, deletion)
//! closes the stream at once (B9).

use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::core::{Result, Shared};
use crate::identity::session::WebUser;
use crate::rooms::notify::Event;
use crate::rooms::service;
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
    let who = person(&user);
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
            if service::web_access(&state, who, name.clone())
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
