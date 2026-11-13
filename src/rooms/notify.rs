//! In-process wait/notify. Every state change publishes an [`Event`] on a
//! broadcast channel; `room_wait` and SSE streams subscribe *before* checking
//! the database and re-check on any relevant event, so no wake-up is lost.
//! A lagged receiver simply re-checks the database.

use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum Event {
    /// A message was stored in a room.
    Message { room_id: i64, seq: i64 },
    /// Membership, join requests or lifecycle state of a room changed.
    RoomChanged { room_id: i64 },
    /// An agent lost access (removal, leave) — `room_id` None means all rooms
    /// (token revocation). Open waits and streams must re-check at once.
    AccessChanged { agent_id: i64, room_id: Option<i64> },
}

impl Event {
    pub fn room_id(&self) -> Option<i64> {
        match self {
            Event::Message { room_id, .. } | Event::RoomChanged { room_id } => Some(*room_id),
            Event::AccessChanged { room_id, .. } => *room_id,
        }
    }
}

#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<Event>,
}

impl Default for Hub {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Hub { tx }
    }
}

impl Hub {
    pub fn publish(&self, event: Event) {
        // No receivers is fine.
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}
