-- OPAQUE password recovery sessions
-- Issued by recover/start, consumed atomically at recover/finish.
-- No server_state column needed — OPAQUE registration is stateless on the server
-- between rounds (server_finish_registration is a pure function of the upload).
CREATE TABLE opaque_recovery_sessions (
    id          TEXT        PRIMARY KEY,   -- UUID session token
    username    CITEXT      NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_opaque_recovery_expiry ON opaque_recovery_sessions(expires_at);
