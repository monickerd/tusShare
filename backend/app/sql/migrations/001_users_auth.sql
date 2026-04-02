-- 001_users_auth.sql — User accounts and authentication sessions

CREATE EXTENSION IF NOT EXISTS citext;

-------------------------------------------------
-- USERS
-- CITEXT provides case-insensitive storage and comparison for usernames.
-- E2E encryption key material is stored per-user and never leaves the server
-- in plaintext.
-------------------------------------------------
CREATE TABLE users (
    id                      TEXT PRIMARY KEY,
    username                CITEXT NOT NULL UNIQUE
                                CHECK(length(username) BETWEEN 1 AND 64),
    password_hash           TEXT NOT NULL,
    encryption_salt         TEXT NOT NULL,
    is_admin                INTEGER NOT NULL DEFAULT 0,
    is_active               INTEGER NOT NULL DEFAULT 1,

    -- Per-user storage limits (NULL = inherit global admin_settings value)
    max_file_size           BIGINT DEFAULT NULL,
    disk_quota              BIGINT DEFAULT NULL,
    bandwidth_limit         BIGINT DEFAULT NULL,
    disk_used               BIGINT NOT NULL DEFAULT 0,

    -- Symmetric key wrapping (password-derived KEK wraps the master key so
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
