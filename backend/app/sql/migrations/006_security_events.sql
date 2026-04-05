-- Migration 006: Security events log
--
-- Append-only table for auth and security events (step-up grants/failures,
-- lockouts, etc.). Separate from access_logs (file/share operations) since
-- security events have no file_id or share_id.
--
-- Immutability: same pattern as access_logs — BEFORE UPDATE/DELETE triggers
-- raise exceptions so rows can only be inserted, never modified or deleted.

CREATE TABLE security_events (
    id          TEXT        PRIMARY KEY,
    user_id     TEXT,
    ip_address  TEXT        NOT NULL,
    user_agent  TEXT,
    event_type  TEXT        NOT NULL,   -- step_up_granted, step_up_failed, step_up_lockout, …
    action_key  TEXT,                   -- sensitive function key, when applicable
    detail      TEXT,                   -- JSON string with event-specific context
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sevt_user      ON security_events(user_id);
CREATE INDEX idx_sevt_type      ON security_events(event_type);
CREATE INDEX idx_sevt_timestamp ON security_events(timestamp);

CREATE OR REPLACE FUNCTION _prevent_security_event_mutation()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'security_events is append-only';
END;
$$;

CREATE TRIGGER prevent_security_event_update
    BEFORE UPDATE ON security_events
    FOR EACH ROW EXECUTE FUNCTION _prevent_security_event_mutation();

CREATE TRIGGER prevent_security_event_delete
    BEFORE DELETE ON security_events
    FOR EACH ROW EXECUTE FUNCTION _prevent_security_event_mutation();
