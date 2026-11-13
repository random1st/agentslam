-- B7 revision: the session is an explicit tool argument; there is no
-- "last session registered by the hook" fallback any more.
ALTER TABLE agents DROP COLUMN hook_session_key;
