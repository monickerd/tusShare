-- 009_public_device.sql — Public/shared device login (B4)
--
-- Adds is_public_device flag to refresh_tokens so the server can:
--   1. Issue shorter-lived tokens for public device sessions.
--   2. Surface the flag in admin audit logs / future policy engine (Phase E3).

ALTER TABLE refresh_tokens
    ADD COLUMN is_public_device INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN refresh_tokens.is_public_device IS
    'Set to 1 when the user checked "Public Device" at login. '
    'Session has a shorter refresh token TTL and key material is session-only.';
