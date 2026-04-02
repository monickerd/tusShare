-- Track last network activity per session for idle timeout enforcement.
--
-- last_active_at is updated (throttled to once per minute) on every
-- authenticated request. The token cleanup task revokes sessions where
-- last_active_at has not advanced within SESSION_IDLE_TIMEOUT_MINUTES.
--
-- Existing rows are backfilled from created_at so they are not immediately
-- expired on first deploy.

ALTER TABLE refresh_tokens ADD COLUMN last_active_at TEXT;

UPDATE refresh_tokens SET last_active_at = created_at;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_idle
    ON refresh_tokens (revoked, last_active_at);
