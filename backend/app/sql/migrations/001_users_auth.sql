-- 001_users_auth.sql — User accounts and authentication sessions

CREATE EXTENSION IF NOT EXISTS citext;

-------------------------------------------------
-- USERS
-- CITEXT provides case-insensitive storage and comparison for usernames.
-- All users authenticate via OPAQUE aPAKE — password never reaches the server.
-- E2E encryption key material is stored per-user and never leaves the server
-- in plaintext.
-------------------------------------------------
CREATE TABLE users (
    id                      TEXT PRIMARY KEY,
    username                CITEXT NOT NULL UNIQUE
                                CHECK(length(username) BETWEEN 1 AND 64),
    auth_method             TEXT NOT NULL DEFAULT 'opaque'
                                CHECK(auth_method IN ('opaque')),
    opaque_registration_record  BYTEA,
    is_admin                INTEGER NOT NULL DEFAULT 0,
    is_active               INTEGER NOT NULL DEFAULT 1,

    -- Per-user storage limits (NULL = inherit global admin_settings value)
    max_file_size           BIGINT DEFAULT NULL,
    disk_quota              BIGINT DEFAULT NULL,
    bandwidth_limit         BIGINT DEFAULT NULL,
    disk_used               BIGINT NOT NULL DEFAULT 0,

    -- Symmetric key wrapping (OPAQUE exportKey-derived KEK wraps the master key so
    -- password changes don't re-encrypt all file keys)
    wrapped_master_key      TEXT,
    wrapped_master_key_iv   TEXT,
    recovery_key_wrapped    TEXT,
    recovery_key_iv         TEXT,
    recovery_key_hash       TEXT,

    -- Asymmetric keys for PQ-KEM direct sharing (X25519 + ML-KEM-768)
    x25519_public_key       TEXT,
    mlkem768_public_key     TEXT,
    x25519_private_wrapped  TEXT,
    mlkem768_private_wrapped TEXT,
    asymmetric_key_iv       TEXT,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_has_pq_keys ON users(x25519_public_key)
    WHERE x25519_public_key IS NOT NULL;

-------------------------------------------------
-- REFRESH TOKENS
-- last_active_at is updated on each authenticated request (throttled) so
-- idle sessions can be detected and revoked automatically.
-------------------------------------------------
CREATE TABLE refresh_tokens (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    expires_at      TIMESTAMPTZ NOT NULL,
    last_active_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_reftok_user   ON refresh_tokens(user_id);
CREATE INDEX idx_reftok_hash   ON refresh_tokens(token_hash);
CREATE INDEX idx_reftok_expiry ON refresh_tokens(expires_at);
CREATE INDEX idx_reftok_idle   ON refresh_tokens(revoked, last_active_at);

-------------------------------------------------
-- OPAQUE IN-FLIGHT LOGIN SESSIONS
-- server_state  — bincode-serialized ServerLogin<TusShareCipherSuite>
--                 (~128 bytes; session_key + expected_mac, both SHA-512 outputs)
-- expires_at    — NOW() + INTERVAL '60 seconds' set by the application
-- Rows consumed atomically at login finish; background task sweeps expired rows.
-------------------------------------------------
CREATE TABLE opaque_login_sessions (
    id           TEXT        PRIMARY KEY,
    username     CITEXT      NOT NULL,
    server_state BYTEA       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_opaque_sessions_expiry ON opaque_login_sessions(expires_at);
