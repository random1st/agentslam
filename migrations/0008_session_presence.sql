-- 0.4.1: the session that wrote an item (two sessions of one agent are told
-- apart), and when each session last touched a room (presence).
ALTER TABLE messages ADD COLUMN session_key TEXT;
ALTER TABLE session_rooms ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX session_rooms_presence ON session_rooms (room_id, last_seen_at);
