-- 007_f7_mfa.sql — Phase F7: TOTP + WebAuthn MFA
--
-- Adds:
--   • user_mfa_credentials  — per-user MFA method rows (TOTP, WebAuthn, recovery)
--   • totp_used_codes        — replay protection; rows pruned after 90 s on each verify
--   • webauthn_challenges    — short-lived nonces (5-min TTL) for reg/auth/unlock
--   • mfa_pending_tokens     — one-time tokens bridging OPAQUE login → MFA challenge
--   • users.mfa_reset_required / mfa_banner_dismissed columns
--   • admin_settings seed rows for mfa_enforcement and mfa_oidc_exempt
--   • role_permission_flags: can_manage_user_mfa (Tier 2+)
--   • role_permissions:      can_manage_user_mfa = 1 for server_admin and org_admin

-------------------------------------------------
-- MFA CREDENTIALS
-- credential TEXT = AES-GCM-encrypted JSON (encrypted with server MFA key):
--   totp:     { "secret_b32": "..." }
--   webauthn: { "credential_id": "...", "public_key_cbor": "...", "sign_count": N,
--               "aaguid": "...", "transports": [...] }
--   recovery: { "codes": ["bcrypt_hash_1", ...] }  (one row per enrollment cycle)
-------------------------------------------------
CREATE TABLE user_mfa_credentials (
    id           TEXT    PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method       TEXT    NOT NULL CHECK(method IN ('totp', 'webauthn', 'recovery')),
    name         TEXT    NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
    created_at   BIGINT  NOT NULL,
    last_used_at BIGINT,
    credential   TEXT    NOT NULL,
    is_active    INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_mfa_creds_user   ON user_mfa_credentials(user_id);
CREATE INDEX idx_mfa_creds_active ON user_mfa_credentials(user_id, is_active);

-------------------------------------------------
-- TOTP REPLAY PROTECTION
-- Prune rows older than 90 s on each TOTP verification call.
-------------------------------------------------
CREATE TABLE totp_used_codes (
    user_id  TEXT   NOT NULL,
    code     TEXT   NOT NULL,
    used_at  BIGINT NOT NULL,
    PRIMARY KEY (user_id, code)
);

-------------------------------------------------
-- WEBAUTHN CHALLENGES
-- Deleted on use; swept by the background cleanup task every 2 min.
-------------------------------------------------
CREATE TABLE webauthn_challenges (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    purpose    TEXT    NOT NULL CHECK(purpose IN ('registration', 'authentication', 'step_up', 'unlock')),
    challenge  TEXT    NOT NULL,
    created_at BIGINT  NOT NULL
);

CREATE INDEX idx_webauthn_challenges_user ON webauthn_challenges(user_id);

-------------------------------------------------
-- MFA PENDING TOKENS
-- Issued by login/finish when the authenticated user has active MFA credentials.
-- Row exists = token valid and unclaimed.  Deleted on consumption.
-- is_public_device mirrors the value from the preceding OPAQUE login so that
-- cookie TTL is correct when session cookies are finally issued after MFA.
-------------------------------------------------
CREATE TABLE mfa_pending_tokens (
    jti              TEXT    PRIMARY KEY,
    user_id          TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at       BIGINT  NOT NULL,
    expires_at       BIGINT  NOT NULL,
    is_public_device INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_mfa_pending_user    ON mfa_pending_tokens(user_id);
CREATE INDEX idx_mfa_pending_expires ON mfa_pending_tokens(expires_at);

-------------------------------------------------
-- EXTEND USERS TABLE
-------------------------------------------------
ALTER TABLE users ADD COLUMN mfa_reset_required  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN mfa_banner_dismissed INTEGER NOT NULL DEFAULT 0;

-------------------------------------------------
-- ADMIN SETTINGS — MFA enforcement policy
-- mfa_enforcement : 'off' | 'optional' | 'required'
-- mfa_oidc_exempt : '1' (default) — OIDC/LDAP users bypass enforcement
-- mfa_allowed_methods is NULL by default (any registered method counts);
-- stored as a JSON array when an admin restricts it, e.g. '["totp","webauthn"]'
-------------------------------------------------
INSERT INTO admin_settings (key, value) VALUES
    ('mfa_enforcement', 'off'),
    ('mfa_oidc_exempt',  '1')
ON CONFLICT (key) DO NOTHING;

-------------------------------------------------
-- PERMISSION FLAG: can_manage_user_mfa
-------------------------------------------------
INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES
    ('can_manage_user_mfa', 'View and remove MFA credentials for other users (admin)', 'security', 1);

INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('server_admin', 'can_manage_user_mfa', '1'),
    ('org_admin',    'can_manage_user_mfa', '1'),
    ('role_admin',   'can_manage_user_mfa', '1');
