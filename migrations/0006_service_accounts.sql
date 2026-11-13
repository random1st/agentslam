-- B13a service accounts: a person of an organization created by an org admin,
-- flagged as a service. It has no identity rows, so no sign-in path resolves
-- to it and it never gets a web session; its agents use headless tokens only.
ALTER TABLE persons ADD COLUMN is_service INTEGER NOT NULL DEFAULT 0;
