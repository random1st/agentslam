-- agentslam v1 schema. Applied once, tracked by PRAGMA user_version.
-- Every token, code and pending-request id column holds a SHA-256 hex hash,
-- never the raw value (inv.agentslam.secrets-hashed).

CREATE TABLE persons (
    id          INTEGER PRIMARY KEY,
    handle      TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);

-- A person is keyed by (issuer, sub); email/name are display data only.
CREATE TABLE identities (
    id            INTEGER PRIMARY KEY,
    issuer        TEXT NOT NULL,
    sub           TEXT NOT NULL,
    provider_id   TEXT NOT NULL,
    person_id     INTEGER REFERENCES persons(id),
    email         TEXT,
    name          TEXT,
    group_admin   INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL,
    UNIQUE (issuer, sub)
);

CREATE TABLE agents (
    id               INTEGER PRIMARY KEY,
    person_id        INTEGER NOT NULL REFERENCES persons(id),
    label            TEXT NOT NULL,
    last_seen_at     INTEGER,
    hook_session_key TEXT,
    created_at       INTEGER NOT NULL,
    UNIQUE (person_id, label)
);

-- kind: access | refresh | agent. family_id groups one OAuth grant (all its
-- rotated access/refresh tokens) or one headless agent token.
CREATE TABLE tokens (
    id          INTEGER PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL CHECK (kind IN ('access', 'refresh', 'agent')),
    agent_id    INTEGER NOT NULL REFERENCES agents(id),
    family_id   TEXT NOT NULL,
    client_id   TEXT,
    resource    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    revoked_at  INTEGER
);
CREATE INDEX tokens_family ON tokens(family_id);
CREATE INDEX tokens_agent ON tokens(agent_id);

CREATE TABLE auth_codes (
    code_hash       TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    code_challenge  TEXT NOT NULL,
    resource        TEXT NOT NULL,
    agent_id        INTEGER NOT NULL REFERENCES agents(id),
    family_id       TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER
);

-- An authorization request that passed client + redirect validation and
-- waits for sign-in and consent.
CREATE TABLE oauth_requests (
    id_hash         TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    client_name     TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    state           TEXT,
    code_challenge  TEXT NOT NULL,
    resource        TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);

-- Upstream OIDC login in flight. browser_hash binds it to the browser that
-- started it (login CSRF protection).
CREATE TABLE login_states (
    state_hash      TEXT PRIMARY KEY,
    provider_id     TEXT NOT NULL,
    nonce           TEXT NOT NULL,
    pkce_verifier   TEXT NOT NULL,
    browser_hash    TEXT NOT NULL,
    oauth_req       TEXT,
    expires_at      INTEGER NOT NULL
);

CREATE TABLE web_sessions (
    token_hash   TEXT PRIMARY KEY,
    identity_id  INTEGER NOT NULL REFERENCES identities(id),
    csrf         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);

CREATE TABLE rooms (
    id               INTEGER PRIMARY KEY,
    name             TEXT NOT NULL,
    owner_person_id  INTEGER NOT NULL REFERENCES persons(id),
    state            TEXT NOT NULL CHECK (state IN ('active', 'archived', 'deleted')),
    last_seq         INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL
);
CREATE UNIQUE INDEX rooms_live_name ON rooms(name) WHERE state <> 'deleted';

-- status: member | removed | left. admission_seq = room.last_seq at the
-- moment of the current admission; content is visible only for seq > it.
CREATE TABLE memberships (
    room_id        INTEGER NOT NULL REFERENCES rooms(id),
    agent_id       INTEGER NOT NULL REFERENCES agents(id),
    status         TEXT NOT NULL CHECK (status IN ('member', 'removed', 'left')),
    admission_seq  INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    PRIMARY KEY (room_id, agent_id)
);

-- status: pending | confirmed | rejected | expired
CREATE TABLE join_requests (
    id           INTEGER PRIMARY KEY,
    room_id      INTEGER NOT NULL REFERENCES rooms(id),
    agent_id     INTEGER NOT NULL REFERENCES agents(id),
    status       TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'rejected', 'expired')),
    created_at   INTEGER NOT NULL,
    decided_at   INTEGER,
    decided_by   INTEGER REFERENCES persons(id)
);
CREATE INDEX join_requests_room ON join_requests(room_id, status);

CREATE TABLE messages (
    room_id     INTEGER NOT NULL REFERENCES rooms(id),
    seq         INTEGER NOT NULL,
    agent_id    INTEGER NOT NULL REFERENCES agents(id),
    text        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (room_id, seq)
);

-- Session room set per (agent, session_key) with read cursors.
CREATE TABLE session_rooms (
    agent_id     INTEGER NOT NULL REFERENCES agents(id),
    session_key  TEXT NOT NULL,
    room_id      INTEGER NOT NULL REFERENCES rooms(id),
    cursor       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, session_key, room_id)
);
