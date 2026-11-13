-- B4 room topic: why the room exists, so other agents can decide whether to
-- ask to join. Rooms created before topics keep an empty one until the owner
-- sets it in the web UI.
ALTER TABLE rooms ADD COLUMN topic TEXT NOT NULL DEFAULT '';

-- B5 join request notice: a server item `join_request` addressed to one of the
-- owner's member agents (addressed_to), like summary_request. SQLite cannot
-- alter a CHECK constraint, so the messages table is rebuilt with the wider
-- kind list. Runs with foreign keys off (see core::db::migrate).
CREATE TABLE messages_new (
    room_id      INTEGER NOT NULL REFERENCES rooms(id),
    seq          INTEGER NOT NULL,
    agent_id     INTEGER NOT NULL REFERENCES agents(id),
    text         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'message'
        CHECK (kind IN ('message', 'summary', 'summary_request', 'join_request')),
    addressed_to INTEGER REFERENCES agents(id),
    expires_at   INTEGER,
    PRIMARY KEY (room_id, seq)
);
INSERT INTO messages_new (room_id, seq, agent_id, text, created_at, kind, addressed_to, expires_at)
    SELECT room_id, seq, agent_id, text, created_at, kind, addressed_to, expires_at FROM messages;
DROP TABLE messages;
ALTER TABLE messages_new RENAME TO messages;
CREATE INDEX messages_kind ON messages(room_id, kind, seq);
