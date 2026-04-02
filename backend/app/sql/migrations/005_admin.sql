-- 005_admin.sql — Admin settings, invites, access logs, and bandwidth tracking

-------------------------------------------------
-- ADMIN SETTINGS (runtime-configurable key-value store)
-- Default values are NOT seeded here. They are read from application config
-- (config.py / environment variables) and inserted on startup via
-- database.seed_admin_settings() using INSERT ... ON CONFLICT DO NOTHING.
-- This ensures config.py is the single source of truth for defaults.
-------------------------------------------------
CREATE TABLE admin_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-------------------------------------------------
-- INVITES (single-use registration tokens)
-- Only the SHA-256 hash of the raw token is stored. The plaintext token
-- is returned once at creation and never persisted.
-------------------------------------------------
CREATE TABLE invites (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    token_hash  TEXT NOT NULL UNIQUE,
    created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    used_by_ip  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invites_created_by ON invites(created_by);
CREATE INDEX idx_invites_expires    ON invites(expires_at);

-------------------------------------------------
-- INVITE SHORT LINKS (root-level slugs → /register/<token>)
-- Stores the raw token temporarily so the slug resolver can redirect without
-- encoding the token in the slug. Deleted automatically on invite use/revoke.
-------------------------------------------------
CREATE TABLE invite_short_links (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    invite_id   TEXT NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
    token       TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invsl_slug    ON invite_short_links(slug);
CREATE INDEX idx_invsl_expires ON invite_short_links(expires_at);
CREATE INDEX idx_invsl_invite  ON invite_short_links(invite_id);

-------------------------------------------------
-- ACCESS LOGS (append-only audit trail)
-- DB-layer triggers enforce immutability: rows can only be inserted,
-- never updated or deleted.
-------------------------------------------------
CREATE TABLE access_logs (
    id         TEXT PRIMARY KEY,
    file_id    TEXT,
    user_id    TEXT,
    share_id   TEXT,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    action     TEXT NOT NULL CHECK(action IN ('view', 'download', 'upload', 'delete', 'share')),
    timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alog_file      ON access_logs(file_id);
CREATE INDEX idx_alog_user      ON access_logs(user_id);
CREATE INDEX idx_alog_share     ON access_logs(share_id);
CREATE INDEX idx_alog_timestamp ON access_logs(timestamp);

CREATE OR REPLACE FUNCTION _prevent_access_log_mutation()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'access_logs is append-only';
END;
$$;

CREATE TRIGGER prevent_access_log_update
    BEFORE UPDATE ON access_logs
    FOR EACH ROW EXECUTE FUNCTION _prevent_access_log_mutation();

CREATE TRIGGER prevent_access_log_delete
    BEFORE DELETE ON access_logs
    FOR EACH ROW EXECUTE FUNCTION _prevent_access_log_mutation();

-------------------------------------------------
-- BANDWIDTH LOG
-------------------------------------------------
CREATE TABLE bandwidth_log (
    id        TEXT PRIMARY KEY,
    user_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
    bytes     BIGINT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('upload', 'download')),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bwlog_user      ON bandwidth_log(user_id);
CREATE INDEX idx_bwlog_timestamp ON bandwidth_log(timestamp);
