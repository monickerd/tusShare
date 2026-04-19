-- 011_notification_channels.sql — Phase G1: Operational notification system
--
-- Changes:
--   • notification_channels: outbound push webhook config with HMAC secrets
--   • api_keys: pull endpoint authentication keys (SHA-256 hashed)
--   • operational_events: persisted op event log (SSE/poll source)
--   • admin_settings seeds for G1 tunables

-------------------------------------------------
-- NOTIFICATION CHANNELS
-- secret_enc: AES-GCM encrypted signing secret; NULL = unsigned delivery
-- event_filter: JSON array of dot-segment prefix strings
-- batch_size:       NULL = count trigger disabled (fire on timer only)
-- batch_interval_s: NULL = timer trigger disabled (fire when count hit)
-------------------------------------------------
CREATE TABLE IF NOT EXISTS notification_channels (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    endpoint_url     TEXT NOT NULL,
    secret_enc       TEXT,
    event_filter     TEXT NOT NULL DEFAULT '[]',
    batch_size       INTEGER,
    batch_interval_s INTEGER,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ DEFAULT now()
);

-------------------------------------------------
-- API KEYS (pull endpoint auth)
-- key_hash: SHA-256 hex of the raw "tss_..." key — never store plaintext
-- scopes:   JSON array of scope strings (e.g. ["events.read"])
-------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL DEFAULT '["events.read"]',
    created_by   TEXT NOT NULL REFERENCES users(id),
    created_at   TIMESTAMPTZ DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ
);

-------------------------------------------------
-- OPERATIONAL EVENTS (persisted log)
-- Indexed for descending-time pagination and type-filtered queries.
-------------------------------------------------
CREATE TABLE IF NOT EXISTS operational_events (
    id         TEXT PRIMARY KEY,
    event_id   TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity   TEXT NOT NULL,
    source     TEXT NOT NULL,
    data_json  TEXT NOT NULL,
    server_id  TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_op_events_created ON operational_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_op_events_type    ON operational_events(event_type, created_at DESC);

-------------------------------------------------
-- ADMIN SETTINGS SEEDS (ON CONFLICT DO NOTHING — never overwrite existing values)
-------------------------------------------------
INSERT INTO admin_settings (key, value) VALUES ('server_id',                '') ON CONFLICT DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('op_event_retention_days',  '30') ON CONFLICT DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('api_key_expiry_warn_days', '30') ON CONFLICT DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('upload_quota_warn_pct',    '90') ON CONFLICT DO NOTHING;
