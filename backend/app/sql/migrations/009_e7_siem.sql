-- 009_e7_siem.sql — E7: SIEM output destinations + audit retention policy
--
-- Changes:
--   • siem_destinations table — syslog and webhook output path config
--   • admin_settings seed: audit_retention_days (default 365)

-------------------------------------------------
-- SIEM DESTINATIONS
-- Each row is one output path (syslog or webhook).
-- Secrets (webhook HMAC key) are AES-GCM encrypted using the same
-- key derivation as idp_crypto.py.
-------------------------------------------------
CREATE TABLE siem_destinations (
    id             TEXT PRIMARY KEY DEFAULT (gen_random_uuid()::TEXT),
    name           TEXT NOT NULL,
    type           TEXT NOT NULL CHECK (type IN ('syslog', 'webhook')),
    is_active      INTEGER NOT NULL DEFAULT 1,

    -- syslog-specific (nullable for webhook rows)
    host           TEXT,
    port           INTEGER,
    protocol       TEXT CHECK (protocol IN ('udp', 'tcp', 'tls')),
    syslog_format  TEXT CHECK (syslog_format IN ('rfc5424', 'cef', 'leef')),
    facility       INTEGER NOT NULL DEFAULT 16,   -- 16 = LOCAL0

    -- webhook-specific (nullable for syslog rows)
    url            TEXT,
    secret_enc     TEXT,   -- AES-GCM encrypted HMAC-SHA256 signing key
    batch_size     INTEGER NOT NULL DEFAULT 1,

    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_siem_type_active ON siem_destinations(type, is_active);

-------------------------------------------------
-- ADMIN SETTINGS SEEDS
-------------------------------------------------
INSERT INTO admin_settings (key, value)
VALUES ('audit_retention_days', '365')
ON CONFLICT (key) DO NOTHING;

INSERT INTO admin_settings (key, value)
VALUES ('notify_escrow_on_revocation', '0')
ON CONFLICT (key) DO NOTHING;
