-- 008_f2_emergency_revocation.sql — Phase F2: Emergency revocation + event bus schema
--
-- Changes:
--   • files: transfer_locked_at / transfer_locked_by columns
--   • security_events: SIEM-canonical columns (severity, outcome, actor_session_id,
--     target_type, target_id, target_name, admin_actor_id)
--   • admin_settings seed: notify_escrow_on_revocation (default disabled)

-------------------------------------------------
-- TRANSFER LOCK ON FILES
-- transfer_locked_at: set by emergency revocation; NULL = not locked
-- transfer_locked_by: admin user_id who applied the lock
-------------------------------------------------
ALTER TABLE files ADD COLUMN transfer_locked_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE files ADD COLUMN transfer_locked_by TEXT REFERENCES users(id) DEFAULT NULL;

-------------------------------------------------
-- EXTEND security_events WITH SIEM CANONICAL FIELDS
-- All new columns are nullable so existing inserts (which omit them) continue
-- to work without modification. The event_bus (F2) populates them going forward.
-------------------------------------------------
ALTER TABLE security_events ADD COLUMN severity         TEXT NOT NULL DEFAULT 'info';
ALTER TABLE security_events ADD COLUMN outcome          TEXT;
ALTER TABLE security_events ADD COLUMN actor_session_id TEXT;
ALTER TABLE security_events ADD COLUMN target_type      TEXT;
ALTER TABLE security_events ADD COLUMN target_id        TEXT;
ALTER TABLE security_events ADD COLUMN target_name      TEXT;
ALTER TABLE security_events ADD COLUMN admin_actor_id   TEXT REFERENCES users(id);

CREATE INDEX IF NOT EXISTS idx_sevt_severity ON security_events(severity);

-------------------------------------------------
-- ADMIN SETTINGS SEED
-- notify_escrow_on_revocation: when '1', F2 emergency revocation will push a
-- rotation_requested SSE event to enrolled escrow agents so they can complete
-- team key rotation without manual intervention. Default is '0' (disabled) —
-- escrow agents must be manually triggered.
-------------------------------------------------
INSERT INTO admin_settings (key, value)
VALUES ('notify_escrow_on_revocation', '0')
ON CONFLICT (key) DO NOTHING;
