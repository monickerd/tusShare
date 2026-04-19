-- 001_core_schema.sql — Full foundational schema (consolidates legacy 001-009)
--
-- Tables:
--   users, refresh_tokens, opaque_login_sessions, opaque_recovery_sessions
--   folders, files, file_chunks, permissions, tus_uploads
--   shares, share_items, short_links
--   roles, user_roles, teams, user_team_keys, file_team_keys, team_folders
--   admin_settings, invites, invite_short_links
--   access_logs (append-only, mutation triggers)
--   security_events (append-only, mutation triggers)
--   bandwidth_log

CREATE EXTENSION IF NOT EXISTS citext;

-------------------------------------------------
-- USERS
-------------------------------------------------
CREATE TABLE users (
    id                       TEXT PRIMARY KEY,
    username                 CITEXT NOT NULL UNIQUE
                                 CHECK(length(username) BETWEEN 1 AND 64),
    auth_method              TEXT NOT NULL DEFAULT 'opaque'
                                 CHECK(auth_method IN ('opaque')),
    opaque_registration_record BYTEA,
    is_admin                 INTEGER NOT NULL DEFAULT 0,
    is_active                INTEGER NOT NULL DEFAULT 1,

    -- Per-user storage limits (NULL = inherit global admin_settings value)
    max_file_size            BIGINT DEFAULT NULL,
    disk_quota               BIGINT DEFAULT NULL,
    bandwidth_limit          BIGINT DEFAULT NULL,
    disk_used                BIGINT NOT NULL DEFAULT 0,

    -- Symmetric key wrapping (OPAQUE exportKey-derived KEK wraps the master key)
    wrapped_master_key       TEXT,
    wrapped_master_key_iv    TEXT,
    recovery_key_wrapped     TEXT,
    recovery_key_iv          TEXT,
    recovery_key_hash        TEXT,

    -- Asymmetric keys for PQ-KEM direct sharing (X25519 + ML-KEM-768)
    x25519_public_key        TEXT,
    mlkem768_public_key      TEXT,
    x25519_private_wrapped   TEXT,
    mlkem768_private_wrapped TEXT,
    asymmetric_key_iv        TEXT,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_has_pq_keys ON users(x25519_public_key)
    WHERE x25519_public_key IS NOT NULL;

-------------------------------------------------
-- REFRESH TOKENS
-- is_public_device: set to 1 when the user checked "Public Device" at login.
-- Session has a shorter TTL and key material is session-only (B4).
-------------------------------------------------
CREATE TABLE refresh_tokens (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash       TEXT NOT NULL UNIQUE,
    expires_at       TIMESTAMPTZ NOT NULL,
    last_active_at   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked          INTEGER NOT NULL DEFAULT 0,
    is_public_device INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_reftok_user   ON refresh_tokens(user_id);
CREATE INDEX idx_reftok_hash   ON refresh_tokens(token_hash);
CREATE INDEX idx_reftok_expiry ON refresh_tokens(expires_at);
CREATE INDEX idx_reftok_idle   ON refresh_tokens(revoked, last_active_at);

-------------------------------------------------
-- OPAQUE IN-FLIGHT LOGIN SESSIONS
-- server_state  — bincode-serialized ServerLogin<TusShareCipherSuite>
-- expires_at    — NOW() + 60 seconds; consumed atomically at login finish
-------------------------------------------------
CREATE TABLE opaque_login_sessions (
    id           TEXT        PRIMARY KEY,
    username     CITEXT      NOT NULL,
    server_state BYTEA       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_opaque_sessions_expiry ON opaque_login_sessions(expires_at);

-------------------------------------------------
-- OPAQUE PASSWORD RECOVERY SESSIONS
-- Issued by recover/start, consumed atomically at recover/finish.
-------------------------------------------------
CREATE TABLE opaque_recovery_sessions (
    id         TEXT        PRIMARY KEY,
    username   CITEXT      NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_opaque_recovery_expiry ON opaque_recovery_sessions(expires_at);

-------------------------------------------------
-- FOLDERS
-------------------------------------------------
CREATE TABLE folders (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 255),
    parent_id  TEXT REFERENCES folders(id) ON DELETE CASCADE,
    owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_shared  INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_folders_parent ON folders(parent_id);
CREATE INDEX idx_folders_owner  ON folders(owner_id);
CREATE UNIQUE INDEX idx_folders_unique_name ON folders(parent_id, owner_id, name);

-------------------------------------------------
-- FILES
-------------------------------------------------
CREATE TABLE files (
    id                 TEXT PRIMARY KEY,
    original_name      TEXT NOT NULL,
    sanitized_name     TEXT NOT NULL,
    storage_key        TEXT NOT NULL UNIQUE,
    folder_id          TEXT REFERENCES folders(id) ON DELETE SET NULL,
    owner_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mime_type          TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes         BIGINT NOT NULL DEFAULT 0,
    encrypted_size     BIGINT NOT NULL DEFAULT 0,
    chunk_size         BIGINT NOT NULL DEFAULT 5242880,
    total_chunks       INTEGER NOT NULL DEFAULT 0,
    encrypted_file_key TEXT NOT NULL,
    key_iv             TEXT NOT NULL,
    checksum_sha256    TEXT,
    upload_complete    INTEGER NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_files_folder      ON files(folder_id);
CREATE INDEX idx_files_owner       ON files(owner_id);
CREATE INDEX idx_files_storage_key ON files(storage_key);

-------------------------------------------------
-- FILE CHUNKS (per-chunk IVs for streaming decryption)
-------------------------------------------------
CREATE TABLE file_chunks (
    id          TEXT PRIMARY KEY,
    file_id     TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    iv          TEXT NOT NULL,
    size_bytes  BIGINT NOT NULL,
    "offset"    BIGINT NOT NULL,
    UNIQUE(file_id, chunk_index)
);

CREATE INDEX idx_chunks_file ON file_chunks(file_id);

-------------------------------------------------
-- PERMISSIONS
-- granted_by is nullable here; recreated in E3 to add policy_effect_id.
-------------------------------------------------
CREATE TABLE permissions (
    id            TEXT PRIMARY KEY,
    resource_type TEXT NOT NULL CHECK(resource_type IN ('file', 'folder')),
    resource_id   TEXT NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission    TEXT NOT NULL CHECK(permission IN ('read', 'write', 'admin')),
    recursive     INTEGER NOT NULL DEFAULT 0,
    granted_by    TEXT NOT NULL REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_perm_resource ON permissions(resource_type, resource_id);
CREATE INDEX idx_perm_user     ON permissions(user_id);
CREATE UNIQUE INDEX idx_perm_unique ON permissions(resource_type, resource_id, user_id);

-------------------------------------------------
-- TUS UPLOADS (in-progress chunked uploads)
-------------------------------------------------
CREATE TABLE tus_uploads (
    id             TEXT PRIMARY KEY,
    file_id        TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    total_size     BIGINT NOT NULL,
    current_offset BIGINT NOT NULL DEFAULT 0,
    next_chunk     INTEGER NOT NULL DEFAULT 0,
    metadata_json  TEXT,
    expires_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tus_user    ON tus_uploads(user_id);
CREATE INDEX idx_tus_expires ON tus_uploads(expires_at);

-------------------------------------------------
-- SHARES
-------------------------------------------------
CREATE TABLE shares (
    id               TEXT PRIMARY KEY,
    token            TEXT NOT NULL UNIQUE,
    created_by       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_type       TEXT NOT NULL CHECK(share_type IN ('link', 'user', 'short')),
    target_user_id   TEXT REFERENCES users(id) ON DELETE CASCADE,
    expires_at       TIMESTAMPTZ,
    is_active        INTEGER NOT NULL DEFAULT 1,
    password_hash    TEXT,
    max_downloads    INTEGER,
    download_count   INTEGER NOT NULL DEFAULT 0,
    allow_upload     INTEGER NOT NULL DEFAULT 0,
    target_folder_id TEXT REFERENCES folders(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_shares_token         ON shares(token);
CREATE INDEX idx_shares_creator       ON shares(created_by);
CREATE INDEX idx_shares_target        ON shares(target_user_id);
CREATE INDEX idx_shares_expires       ON shares(expires_at);
CREATE INDEX idx_shares_target_folder ON shares(target_folder_id);

-------------------------------------------------
-- SHARE ITEMS
-- KEM fields support PQ-KEM encrypted direct shares (user-type shares only).
-------------------------------------------------
CREATE TABLE share_items (
    id                   TEXT PRIMARY KEY,
    share_id             TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    resource_type        TEXT NOT NULL CHECK(resource_type IN ('file', 'folder')),
    resource_id          TEXT NOT NULL,
    encrypted_file_key   TEXT,
    key_iv               TEXT,
    ephemeral_x25519_pub TEXT,
    kem_ciphertext       TEXT,
    UNIQUE(share_id, resource_type, resource_id)
);

CREATE INDEX idx_sitems_share ON share_items(share_id);

-------------------------------------------------
-- SHORT LINKS (memorable 3-word slugs for link-type shares)
-------------------------------------------------
CREATE TABLE short_links (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    share_id   TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    share_key  TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_shortlinks_slug    ON short_links(slug);
CREATE INDEX idx_shortlinks_expires ON short_links(expires_at);
CREATE INDEX idx_shortlinks_creator ON short_links(created_by);

-------------------------------------------------
-- ROLES
-- Seeded with the legacy 3-tier team roles for compatibility with
-- E1 migration (002), which deletes them and inserts the 6-tier hierarchy.
-------------------------------------------------
CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 64),
    description TEXT NOT NULL DEFAULT '',
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO roles (id, name, description, is_system) VALUES
    ('role_admin',      'admin',           'System administrator — management only, no file operations', 1),
    ('role_user',       'user',            'Regular user — file storage and sharing', 1),
    ('team_owner',      'Team Owner',      'Full control: manage members, folders, and delete team', 0),
    ('team_supervisor', 'Team Supervisor', 'Invite and remove members, manage team folders', 0),
    ('team_member',     'Team Member',     'Read/write access to team folders', 0);

-------------------------------------------------
-- USER ↔ ROLE MAPPING
-------------------------------------------------
CREATE TABLE user_roles (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_type TEXT DEFAULT NULL CHECK(scope_type IS NULL OR scope_type IN ('folder', 'team')),
    scope_id   TEXT DEFAULT NULL,
    granted_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_roles_user  ON user_roles(user_id);
CREATE INDEX idx_user_roles_role  ON user_roles(role_id);
CREATE INDEX idx_user_roles_scope ON user_roles(scope_type, scope_id);

CREATE UNIQUE INDEX idx_user_roles_global_unique
    ON user_roles(user_id, role_id)
    WHERE scope_type IS NULL;

CREATE UNIQUE INDEX idx_user_roles_scoped_unique
    ON user_roles(user_id, role_id, scope_type, scope_id)
    WHERE scope_type IS NOT NULL;

-------------------------------------------------
-- TEAMS
-------------------------------------------------
CREATE TABLE teams (
    id               TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    owner_id         TEXT NOT NULL REFERENCES users(id),
    pre_public_key   TEXT NOT NULL,
    rotation_pending INTEGER NOT NULL DEFAULT 0,
    created_at       BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))::BIGINT,
    updated_at       BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))::BIGINT,
    UNIQUE(owner_id, name)
);

CREATE INDEX idx_teams_owner ON teams(owner_id);

-------------------------------------------------
-- PER-MEMBER WRAPPED TEAM KEY
-------------------------------------------------
CREATE TABLE user_team_keys (
    id                   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    team_id              TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ephemeral_x25519_pub TEXT NOT NULL,
    kem_ciphertext       TEXT NOT NULL,
    encrypted_sk         TEXT NOT NULL,
    sk_iv                TEXT NOT NULL,
    created_at           BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))::BIGINT,
    UNIQUE(team_id, user_id)
);

CREATE INDEX idx_user_team_keys_team ON user_team_keys(team_id);
CREATE INDEX idx_user_team_keys_user ON user_team_keys(user_id);

-------------------------------------------------
-- PER-FILE PRE CIPHERTEXT (proxy re-encryption for team file sharing)
-------------------------------------------------
CREATE TABLE file_team_keys (
    id                 TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    team_id            TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    file_id            TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    pre_c1             TEXT NOT NULL,
    encrypted_file_key TEXT NOT NULL,
    key_iv             TEXT NOT NULL,
    created_at         BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))::BIGINT,
    UNIQUE(team_id, file_id)
);

CREATE INDEX idx_file_team_keys_team ON file_team_keys(team_id);
CREATE INDEX idx_file_team_keys_file ON file_team_keys(file_id);

-------------------------------------------------
-- TEAM FOLDER MEMBERSHIP
-------------------------------------------------
CREATE TABLE team_folders (
    id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    folder_id  TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    added_by   TEXT NOT NULL REFERENCES users(id),
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))::BIGINT,
    UNIQUE(team_id, folder_id)
);

CREATE INDEX idx_team_folders_team   ON team_folders(team_id);
CREATE INDEX idx_team_folders_folder ON team_folders(folder_id);

-------------------------------------------------
-- ADMIN SETTINGS (runtime-configurable key-value store)
-------------------------------------------------
CREATE TABLE admin_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-------------------------------------------------
-- INVITES (single-use registration tokens)
-- Only the SHA-256 hash of the raw token is stored.
-------------------------------------------------
CREATE TABLE invites (
    id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    used_by_ip TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invites_created_by ON invites(created_by);
CREATE INDEX idx_invites_expires    ON invites(expires_at);

-------------------------------------------------
-- INVITE SHORT LINKS (root-level slugs → /register/<token>)
-------------------------------------------------
CREATE TABLE invite_short_links (
    id        TEXT PRIMARY KEY,
    slug      TEXT NOT NULL UNIQUE,
    invite_id TEXT NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
    token     TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invsl_slug    ON invite_short_links(slug);
CREATE INDEX idx_invsl_expires ON invite_short_links(expires_at);
CREATE INDEX idx_invsl_invite  ON invite_short_links(invite_id);

-------------------------------------------------
-- ACCESS LOGS (append-only audit trail)
-- BEFORE UPDATE/DELETE triggers enforce immutability at the DB layer.
-------------------------------------------------
CREATE TABLE access_logs (
    id         TEXT PRIMARY KEY,
    file_id    TEXT,
    user_id    TEXT,
    share_id   TEXT,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    action     TEXT NOT NULL CHECK(action IN ('view', 'download', 'upload', 'delete', 'share')),
    timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alog_file      ON access_logs(file_id);
CREATE INDEX idx_alog_user      ON access_logs(user_id);
CREATE INDEX idx_alog_share     ON access_logs(share_id);
CREATE INDEX idx_alog_timestamp ON access_logs(timestamp);

CREATE OR REPLACE FUNCTION _prevent_access_log_mutation()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'access_logs is append-only';
END;
$$;

CREATE TRIGGER prevent_access_log_update
    BEFORE UPDATE ON access_logs
    FOR EACH ROW EXECUTE FUNCTION _prevent_access_log_mutation();

CREATE TRIGGER prevent_access_log_delete
    BEFORE DELETE ON access_logs
    FOR EACH ROW EXECUTE FUNCTION _prevent_access_log_mutation();

-------------------------------------------------
-- BANDWIDTH LOG
-------------------------------------------------
CREATE TABLE bandwidth_log (
    id        TEXT PRIMARY KEY,
    user_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
    bytes     BIGINT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('upload', 'download')),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bwlog_user      ON bandwidth_log(user_id);
CREATE INDEX idx_bwlog_timestamp ON bandwidth_log(timestamp);

-------------------------------------------------
-- SECURITY EVENTS (append-only, separate from access_logs)
-- BEFORE UPDATE/DELETE triggers enforce immutability at the DB layer.
-------------------------------------------------
CREATE TABLE security_events (
    id         TEXT        PRIMARY KEY,
    user_id    TEXT,
    ip_address TEXT        NOT NULL,
    user_agent TEXT,
    event_type TEXT        NOT NULL,
    action_key TEXT,
    detail     TEXT,
    timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
