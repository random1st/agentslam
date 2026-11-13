-- B13 organizations. Every person (and through it every agent), room,
-- membership and message belongs to exactly one organization. Existing rows
-- are assigned by a startup backfill (core::orgs::backfill) that needs the
-- provider config; nothing is deleted.

CREATE TABLE organizations (
    id          INTEGER PRIMARY KEY,
    -- google_hd | entra_tid | oidc | okta | default
    key_kind    TEXT NOT NULL,
    key_value   TEXT NOT NULL,
    name        TEXT NOT NULL,
    disabled_at INTEGER,
    created_at  INTEGER NOT NULL,
    UNIQUE (key_kind, key_value)
);

CREATE TABLE org_admins (
    org_id     INTEGER NOT NULL REFERENCES organizations(id),
    person_id  INTEGER NOT NULL REFERENCES persons(id),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (org_id, person_id)
);

-- Okta connected by an org admin. The client secret is AES-256-GCM encrypted
-- with AGENTSLAM_SECRET_KEY (nonce || ciphertext, base64); never returned.
CREATE TABLE okta_connections (
    id          INTEGER PRIMARY KEY,
    org_id      INTEGER NOT NULL REFERENCES organizations(id),
    issuer      TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    secret_enc  TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

-- Names are unique per organization: rebuild persons (UNIQUE(handle) → UNIQUE(org_id, handle)).
-- Runs with foreign keys off (see core::db::migrate); references by name stay valid.
CREATE TABLE persons_new (
    id          INTEGER PRIMARY KEY,
    handle      TEXT NOT NULL,
    org_id      INTEGER REFERENCES organizations(id),
    created_at  INTEGER NOT NULL,
    UNIQUE (org_id, handle)
);
INSERT INTO persons_new (id, handle, org_id, created_at) SELECT id, handle, NULL, created_at FROM persons;
DROP TABLE persons;
ALTER TABLE persons_new RENAME TO persons;

-- The verified organization key seen at the identity's last sign-in.
ALTER TABLE identities ADD COLUMN org_key_kind TEXT;
ALTER TABLE identities ADD COLUMN org_key_value TEXT;
ALTER TABLE identities ADD COLUMN org_key_name TEXT;

ALTER TABLE rooms ADD COLUMN org_id INTEGER REFERENCES organizations(id);
DROP INDEX rooms_live_name;
CREATE UNIQUE INDEX rooms_live_name ON rooms(org_id, name) WHERE state <> 'deleted';
