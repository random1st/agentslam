-- 0.5.1: server-held random keys that must survive a restart (the watch link
-- signature). A key, not a token: it never leaves the server.
CREATE TABLE server_keys (
    name        TEXT PRIMARY KEY,
    key         BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);
