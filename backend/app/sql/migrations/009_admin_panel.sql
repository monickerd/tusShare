-- 009_admin_panel.sql — Admin settings table and invite-based registration
--
-- admin_settings: key/value store for admin-configurable server settings.
--   Stored in bytes for size values so arithmetic is unambiguous.
--   A value of 0 means "no limit" for size/bandwidth fields.
--
-- invites: single-use registration tokens (24-hour expiry).
--   The server stores only the SHA-256 hash of the raw token.
--   Raw token is returned once at creation time and never stored.

-------------------------------------------------
-- ADMIN SETTINGS
-------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Seed defaults:
--   open_registration     : false   — invite-only unless changed
--   global_max_file_size  : 0       — 0 = no global limit (bytes)
--   global_bandwidth_limit: 0       — 0 = no global limit (bytes/second)
--   disk_warning_threshold: 65      — warn admin when filesystem ≥ 65% full
--   default_chunk_size    : 5242880 — 5 MB; informational (frontend uses Config.upload.defaultChunkSize)
INSERT OR IGNORE INTO admin_settings (key, value) VALUES
    ('open_registration',     'false'),
    ('global_max_file_size',  '0'),
    ('global_bandwidth_limit','0'),
    ('disk_warning_threshold','65'),
    ('default_chunk_size',    '5242880');

-------------------------------------------------
-- INVITES
-- Single-use registration tokens. Expires 24 hours after creation.
-- used_at and used_by_ip are set atomically when the invite is consumed.
-------------------------------------------------
CREATE TABLE IF NOT EXISTS invites (
    id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    token_hash  TEXT NOT NULL UNIQUE,
    created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    used_by_ip  TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by);
CREATE INDEX IF NOT EXISTS idx_invites_expires    ON invites(expires_at);
