-- B6a agent-written room summaries. Summaries and summary requests are items
-- in the room transcript (same per-room seq) distinguished by `kind`.
-- summary_request: a server item addressed to one member agent (addressed_to),
-- open until expires_at or until a later summary is posted.
ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'message'
    CHECK (kind IN ('message', 'summary', 'summary_request'));
ALTER TABLE messages ADD COLUMN addressed_to INTEGER REFERENCES agents(id);
ALTER TABLE messages ADD COLUMN expires_at INTEGER;
CREATE INDEX messages_kind ON messages(room_id, kind, seq);
