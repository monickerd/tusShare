-- 011_session_idle.sql — Track last network activity per session for idle timeout.

ALTER TABLE refresh_tokens ADD COLUMN last_active_at TIMESTAMPTZ;

UPDATE refresh_tokens SET last_active_at = created_at;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_idle
    ON refresh_tokens (revoked, last_active_at);
