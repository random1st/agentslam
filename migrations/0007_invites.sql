-- B5a invite links (same organization only). Only the token hash is stored.
CREATE TABLE room_invites (
    id          INTEGER PRIMARY KEY,
    room_id     INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_by  INTEGER NOT NULL REFERENCES persons(id),
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    max_uses    INTEGER NOT NULL,
    uses        INTEGER NOT NULL DEFAULT 0,
    revoked_at  INTEGER
);
CREATE INDEX room_invites_room ON room_invites(room_id);

-- A person who pressed Join on a valid invite: their agents are admitted at
-- once, like the owner's. Removal of a member withdraws its person's grant.
CREATE TABLE room_grants (
    room_id     INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    person_id   INTEGER NOT NULL REFERENCES persons(id),
    invite_id   INTEGER REFERENCES room_invites(id),
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (room_id, person_id)
);
