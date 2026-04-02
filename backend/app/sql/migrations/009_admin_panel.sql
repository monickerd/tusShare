-- 009_admin_panel.sql — Admin settings table and invite-based registration
--
-- admin_settings was already created in 003_access_logs.sql.
-- This migration seeds additional defaults (ON CONFLICT DO NOTHING) and
-- creates the invites table.

-------------------------------------------------
-- ADMIN SETTINGS — seed additional defaults
-------------------------------------------------
INSERT INTO admin_settings (key, value) VALUES
    ('open_registration',     'false'),
    ('global_max_file_size',  '0'),
    ('global_bandwidth_limit','0'),
    ('disk_warning_threshold','65'),
    ('default_chunk_size',    '5242880')
    ON CONFLICT DO NOTHING;

-------------------------------------------------
-- INVITES
-------------------------------------------------
CREATE TABLE IF NOT EXISTS invites (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    token_hash  TEXT NOT NULL UNIQUE,
    created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    used_by_ip  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by);
CREATE INDEX IF NOT EXISTS idx_invites_expires    ON invites(expires_at);
