-- schema.sql — Complete database schema
--
-- Run once on a fresh install; tracked as 'schema_v1' in _migrations.
--
-- Table inventory:
--   Identity:   identity_providers, identity_provider_users, oidc_states
--   Users:      users, refresh_tokens, opaque_login_sessions, opaque_recovery_sessions
--   MFA:        user_mfa_credentials, totp_used_codes, webauthn_challenges, mfa_pending_tokens
--   Roles:      roles, role_permission_flags, role_permissions
--   Files:      folders, files, file_chunks, tus_uploads
--   Sharing:    shares, share_items, short_links
--   Teams:      teams, file_team_keys, team_folders, team_roles, team_role_permissions,
--               team_role_assignments, team_ephemeral_slots
--   Policy:     policy_field_definitions, admin_scope_conditions, policies,
--               policy_conditions, policy_effects, policy_team_grants, policy_folder_grants
--   ACL:        user_roles, user_team_keys, permissions
--   Admin:      admin_settings, invites, invite_short_links
--   Audit:      access_logs, bandwidth_log, security_events
--   SIEM:       siem_destinations
--   Storage:    storage_volumes, file_storage_locations
--   Operations: notification_channels, api_keys, operational_events
--   Escrow:     folder_escrow_policies, folder_escrow_policy_agents
--   Sharing rules: sharing_rules, sharing_rule_conditions

CREATE EXTENSION IF NOT EXISTS citext;

-------------------------------------------------
-- IDENTITY PROVIDERS
-- config_enc: AES-GCM encrypted JSON (shape varies by provider_type)
--   LDAP: { server_uri, bind_dn, bind_password, base_dn, user_filter, tls, username_attr }
--   OIDC: { issuer_url, client_id, client_secret, scopes, redirect_uri }
-- claim_mode: OIDC only — 'at_login' (cached) or 'live_refetch' (always current)
-------------------------------------------------
CREATE TABLE identity_providers (
    id            TEXT    PRIMARY KEY,
    provider_type TEXT    NOT NULL CHECK(provider_type IN ('ldap', 'oidc')),
    name          TEXT    NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    claim_mode    TEXT    CHECK(claim_mode IN ('at_login', 'live_refetch')),
    config_enc    TEXT    NOT NULL,
    created_at    BIGINT  NOT NULL,
    updated_at    BIGINT  NOT NULL
);

CREATE UNIQUE INDEX idx_idp_name   ON identity_providers(name);
CREATE INDEX        idx_idp_active ON identity_providers(is_active);

-------------------------------------------------
-- USERS
-- identity_provider_id: FK to provider that authenticated this user; NULL = local OPAQUE account.
-- oidc_claims_cache: JSON blob of raw claims from last OIDC login.
-- oidc_refresh_token_enc: AES-GCM encrypted OIDC refresh token (live_refetch mode only).
-- policy_last_evaluated_at: debounce timestamp for background policy evaluation.
-------------------------------------------------
CREATE TABLE users (
    id                       TEXT PRIMARY KEY,
    username                 CITEXT NOT NULL UNIQUE
                                 CHECK(length(username) BETWEEN 1 AND 64),
    auth_method              TEXT NOT NULL DEFAULT 'opaque'
                                 CHECK(auth_method IN ('opaque', 'ldap', 'oidc', 'service')),
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

    -- Identity provider link
    identity_provider_id     TEXT REFERENCES identity_providers(id),
    oidc_claims_cache        TEXT,
    oidc_refresh_token_enc   TEXT,

    -- MFA state
    mfa_reset_required       INTEGER NOT NULL DEFAULT 0,
    mfa_banner_dismissed     INTEGER NOT NULL DEFAULT 0,

    -- Policy evaluation debounce timestamp
    policy_last_evaluated_at TEXT,

    -- Per-user UI preferences (JSON)
    ui_prefs                 TEXT DEFAULT NULL,

    -- Human-readable description (used primarily for service accounts)
    description              TEXT DEFAULT NULL,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_username  ON users(username);
CREATE INDEX idx_users_has_pq_keys ON users(x25519_public_key)
    WHERE x25519_public_key IS NOT NULL;
CREATE INDEX idx_users_idp ON users(identity_provider_id)
    WHERE identity_provider_id IS NOT NULL;

-------------------------------------------------
-- IDENTITY PROVIDER USERS
-- Maps a tusShare user to their external identity at a given provider.
-- external_id: OIDC sub claim, or the value of username_attr for LDAP.
-------------------------------------------------
CREATE TABLE identity_provider_users (
    id          TEXT NOT NULL PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    UNIQUE (provider_id, user_id),
    UNIQUE (provider_id, external_id)
);

CREATE INDEX idx_idp_users_user     ON identity_provider_users(user_id);
CREATE INDEX idx_idp_users_provider ON identity_provider_users(provider_id);

-------------------------------------------------
-- SERVICE ACCOUNT KEYS
-- One bearer key per service account (1:1 enforced by UNIQUE on service_account_id).
-- key_hash:   SHA-256 hex of the raw bearer token (sa_<32 url-safe base64 chars>).
-- key_prefix: first 12 chars of the raw key, shown in the admin UI for identification.
-- Raw key is returned exactly once (creation / rotation) and never stored.
-------------------------------------------------
CREATE TABLE service_account_keys (
    id                   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    service_account_id   TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    key_hash             TEXT NOT NULL UNIQUE,
    key_prefix           TEXT NOT NULL,
    created_by           TEXT NOT NULL REFERENCES users(id),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ,
    last_used_at         TIMESTAMPTZ
);

CREATE INDEX idx_sak_hash ON service_account_keys(key_hash);

-------------------------------------------------
-- OIDC STATE NONCES
-- One row per in-flight OIDC authorization request.
-- id        = the state parameter (cryptographically random, 32 bytes URL-safe)
-- nonce     = bound to the ID token's nonce claim to prevent replay attacks
-- Rows are deleted on use; background sweep removes any that expire unused.
-------------------------------------------------
CREATE TABLE oidc_states (
    id          TEXT    PRIMARY KEY,
    provider_id TEXT    NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    redirect_to TEXT,
    nonce       TEXT,
    created_at  BIGINT  NOT NULL,
    expires_at  BIGINT  NOT NULL
);

CREATE INDEX idx_oidc_states_expires  ON oidc_states(expires_at);
CREATE INDEX idx_oidc_states_provider ON oidc_states(provider_id);

-------------------------------------------------
-- REFRESH TOKENS
-- is_public_device: set to 1 when the user checked "Public Device" at login
-- (shorter TTL, session-only key material).
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
-- Row exists = token valid and unclaimed. Deleted on consumption.
-- is_public_device mirrors the value from the preceding OPAQUE login so that
-- cookie TTL is correct when session cookies are issued after MFA.
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
-- ROLES
-------------------------------------------------
CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 64),
    description TEXT NOT NULL DEFAULT '',
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-------------------------------------------------
-- PERMISSION FLAG DEFINITIONS
-------------------------------------------------
CREATE TABLE role_permission_flags (
    flag         TEXT    PRIMARY KEY,
    description  TEXT    NOT NULL DEFAULT '',
    category     TEXT    NOT NULL DEFAULT 'general',
    is_sensitive INTEGER NOT NULL DEFAULT 0
);

-------------------------------------------------
-- PERMISSION FLAG ASSIGNMENTS PER ROLE
-- value is TEXT to allow future non-binary support (e.g. max durations, counts).
-- Current binary convention: '1' = granted, '0' = denied.
-- When a user holds multiple global roles the max value across roles wins.
-------------------------------------------------
CREATE TABLE role_permissions (
    role_id         TEXT    NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    flag            TEXT    NOT NULL REFERENCES role_permission_flags(flag) ON DELETE CASCADE,
    value           TEXT    NOT NULL DEFAULT '0',
    is_locked       BOOLEAN NOT NULL DEFAULT FALSE,
    locked_min_tier INTEGER,
    PRIMARY KEY (role_id, flag)
);

CREATE INDEX idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_flag ON role_permissions(flag);

-------------------------------------------------
-- FOLDERS
-------------------------------------------------
CREATE TABLE folders (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 255),
    parent_id            TEXT REFERENCES folders(id) ON DELETE CASCADE,
    owner_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_shared            INTEGER NOT NULL DEFAULT 0,
    restrict_permissions BOOLEAN NOT NULL DEFAULT FALSE,

    -- Soft-delete / trash
    deleted_at           TIMESTAMPTZ DEFAULT NULL,
    deleted_by           TEXT REFERENCES users(id) ON DELETE SET NULL DEFAULT NULL,

    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_folders_parent     ON folders(parent_id);
CREATE INDEX idx_folders_owner      ON folders(owner_id);
CREATE INDEX idx_folders_deleted_at ON folders(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE UNIQUE INDEX idx_folders_unique_name ON folders(COALESCE(parent_id, ''), owner_id, name) WHERE deleted_at IS NULL;

-------------------------------------------------
-- FILES
-- transfer_locked_at/by: set by emergency revocation; NULL = not locked.
-- last_accessed_at: updated on every successful download (used by tiering).
-- av_scan_status/av_scanned_at: server-side AV verdict tracking.
-- escrow_ephemeral_pk/escrow_encrypted_key/escrow_key_iv: client-encrypted copies
--   of the file key for server-side decryption via ECDH/P-256 escrow key pair.
-------------------------------------------------
CREATE TABLE files (
    id                  TEXT PRIMARY KEY,
    original_name       TEXT NOT NULL,
    sanitized_name      TEXT NOT NULL,
    storage_key         TEXT NOT NULL,
    folder_id           TEXT REFERENCES folders(id) ON DELETE SET NULL,
    owner_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mime_type           TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes          BIGINT NOT NULL DEFAULT 0,
    encrypted_size      BIGINT NOT NULL DEFAULT 0,
    chunk_size          BIGINT NOT NULL DEFAULT 5242880,
    total_chunks        INTEGER NOT NULL DEFAULT 0,
    encrypted_file_key  TEXT NOT NULL,
    key_iv              TEXT NOT NULL,
    checksum_sha256     TEXT,
    upload_complete     INTEGER NOT NULL DEFAULT 0,

    -- Transfer lock (emergency revocation)
    transfer_locked_at  TIMESTAMPTZ DEFAULT NULL,
    transfer_locked_by  TEXT REFERENCES users(id) DEFAULT NULL,

    -- Storage tiering
    last_accessed_at    TIMESTAMPTZ DEFAULT NULL,

    -- Antivirus scan state
    av_scan_status      TEXT,
    av_scanned_at       TEXT,

    -- Escrow-encrypted file key (populated by client when server escrow key is configured)
    escrow_ephemeral_pk   TEXT,
    escrow_encrypted_key  TEXT,
    escrow_key_iv         TEXT,

    -- Soft-delete / trash
    deleted_at          TIMESTAMPTZ DEFAULT NULL,
    deleted_by          TEXT REFERENCES users(id) ON DELETE SET NULL DEFAULT NULL,

    -- Browser File.lastModified (ms since epoch); NULL for pre-migration rows
    last_modified_ms    BIGINT DEFAULT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_files_folder      ON files(folder_id);
CREATE INDEX idx_files_owner       ON files(owner_id);
CREATE INDEX idx_files_storage_key ON files(storage_key);
CREATE INDEX idx_files_deleted_at  ON files(deleted_at) WHERE deleted_at IS NOT NULL;

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
-- TUS UPLOADS (in-progress chunked uploads)
-- part_tags: JSON array of provider etags for S3-compatible multipart finalization.
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
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    part_tags      TEXT DEFAULT NULL
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
    key_type         TEXT,
    upload_max_bytes BIGINT NOT NULL DEFAULT 104857600,
    total_uploaded_bytes BIGINT NOT NULL DEFAULT 0,
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
    resource_type        TEXT NOT NULL CHECK(resource_type IN ('file', 'folder')), -- NOSONAR
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
-- CUSTOM TEAM ROLES
-- Global team roles (team_admin/team_manager/team_member) are stored in user_roles
-- with scope_type='team'. This table holds only custom roles created by team admins.
-------------------------------------------------
CREATE TABLE team_roles (
    id          TEXT PRIMARY KEY,
    team_id     TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')) -- NOSONAR
);

CREATE INDEX idx_team_roles_team ON team_roles(team_id);

-------------------------------------------------
-- MOVE PERMISSION FLAGS PER TEAM ROLE
-- Valid flags:
--   move_own_files_out_of_team    — may move files where owner_id = self
--   move_others_files_out_of_team — may move files owned by another user
-------------------------------------------------
CREATE TABLE team_role_permissions (
    team_role_id TEXT NOT NULL REFERENCES team_roles(id) ON DELETE CASCADE,
    flag         TEXT NOT NULL,
    value        TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (team_role_id, flag)
);

CREATE INDEX idx_team_role_perms_role ON team_role_permissions(team_role_id);

-------------------------------------------------
-- USER → TEAM ROLE ASSIGNMENTS
-------------------------------------------------
CREATE TABLE team_role_assignments (
    id           TEXT PRIMARY KEY,
    team_role_id TEXT NOT NULL REFERENCES team_roles(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id      TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    granted_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    granted_at   TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE (team_role_id, user_id)
);

CREATE INDEX idx_team_role_assign_user_team ON team_role_assignments(user_id, team_id);
CREATE INDEX idx_team_role_assign_role      ON team_role_assignments(team_role_id);

-------------------------------------------------
-- TEAM EPHEMERAL SLOTS
-- One-time-use invite slots for new members who arrive before any existing
-- team member has fulfilled their pending key grant.
--
-- Link format: https://app/#/join/{team_id}/{slot_id}/{k_ephemeral_b64url}
-- k_ephemeral (256-bit AES key) lives ONLY in the URL fragment — never stored.
-- sk_wrapped = AES-GCM(k_ephemeral, sk_team_bytes)
-------------------------------------------------
CREATE TABLE team_ephemeral_slots (
    id         TEXT NOT NULL PRIMARY KEY,
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    sk_wrapped TEXT NOT NULL,
    sk_iv      TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    expires_at TEXT NOT NULL,
    consumed   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_ephemeral_slots_team ON team_ephemeral_slots(team_id);
CREATE INDEX idx_ephemeral_slots_active
    ON team_ephemeral_slots(expires_at)
    WHERE consumed = 0;

-------------------------------------------------
-- POLICY FIELD DEFINITIONS
-- source='internal': fields drawn from local DB (always available; seeded below).
-- source='ldap'/'oidc': requires can_define_policy_fields permission.
-------------------------------------------------
CREATE TABLE policy_field_definitions (
    name          TEXT    PRIMARY KEY,
    display_label TEXT    NOT NULL,
    source        TEXT    NOT NULL DEFAULT 'ldap'
                          CHECK(source IN ('internal', 'ldap', 'oidc')), -- NOSONAR
    data_type     TEXT    NOT NULL DEFAULT 'string' -- NOSONAR
                          CHECK(data_type IN ('string', 'boolean')), -- NOSONAR
    claim_path    TEXT,
    created_by    TEXT    REFERENCES users(id) ON DELETE SET NULL,
    created_at    TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

-------------------------------------------------
-- ADMIN SCOPE CONDITIONS
-- Restricts the universe of users an admin can target with policies.
-------------------------------------------------
CREATE TABLE admin_scope_conditions (
    id          TEXT NOT NULL PRIMARY KEY,
    holder_type TEXT NOT NULL CHECK(holder_type IN ('user', 'role')),
    holder_id   TEXT NOT NULL,
    field       TEXT NOT NULL REFERENCES policy_field_definitions(name) ON DELETE RESTRICT,
    operator    TEXT NOT NULL,
    value       TEXT NOT NULL
);

CREATE INDEX idx_admin_scope_cond_holder ON admin_scope_conditions(holder_type, holder_id);

-------------------------------------------------
-- POLICIES
-- scope_id=NULL for org-scoped; team_id for team-scoped.
-------------------------------------------------
CREATE TABLE policies (
    id             TEXT    NOT NULL PRIMARY KEY,
    name           TEXT    NOT NULL,
    scope_type     TEXT    NOT NULL DEFAULT 'org' CHECK(scope_type IN ('org', 'team')),
    scope_id       TEXT,
    escrow_enabled INTEGER NOT NULL DEFAULT 0,
    created_by     TEXT    REFERENCES users(id) ON DELETE SET NULL,
    created_at     TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX idx_policies_scope ON policies(scope_type, scope_id);

-------------------------------------------------
-- POLICY CONDITIONS
-- All conditions on a policy are ANDed together.
-- inherited_scope_id links to the originating admin_scope_condition.
-- scope_detached=1 means that condition was deleted (orphaned but still evaluates).
-------------------------------------------------
CREATE TABLE policy_conditions (
    id                 TEXT    NOT NULL PRIMARY KEY,
    policy_id          TEXT    NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    field              TEXT    NOT NULL REFERENCES policy_field_definitions(name) ON DELETE RESTRICT,
    operator           TEXT    NOT NULL
                               CHECK(operator IN ('=','!=','contains','starts_with','ends_with','in')),
    value              TEXT    NOT NULL,
    inherited_scope_id TEXT    REFERENCES admin_scope_conditions(id) ON DELETE SET NULL,
    scope_detached     INTEGER NOT NULL DEFAULT 0,
    strict             INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_policy_conditions_policy ON policy_conditions(policy_id);

-- When an admin_scope_condition is deleted (ON DELETE SET NULL nulls
-- inherited_scope_id), mark the affected policy_conditions row as scope_detached=1.
CREATE OR REPLACE FUNCTION fn_policy_scope_detach()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.inherited_scope_id IS NOT NULL AND NEW.inherited_scope_id IS NULL THEN
        UPDATE policy_conditions
        SET scope_detached = 1
        WHERE id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_policy_scope_detach
    AFTER UPDATE OF inherited_scope_id ON policy_conditions
    FOR EACH ROW
    EXECUTE FUNCTION fn_policy_scope_detach();

-------------------------------------------------
-- POLICY EFFECTS
-- One row per grant configured on a policy.
--
-- effect_type = 'team_member'
--   target_id = team_id; role_level = roles.id
--   Writes: user_roles + policy_team_grants
--
-- effect_type = 'folder_acl'
--   target_id = folder_id; permission = read|write|admin
--   Writes: permissions + policy_folder_grants
--
-- effect_type = 'team_escrow'
--   target_id = team_id; escrow_override overrides policy-level escrow_enabled.
-------------------------------------------------
CREATE TABLE policy_effects (
    id              TEXT    NOT NULL PRIMARY KEY,
    policy_id       TEXT    NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    effect_type     TEXT    NOT NULL CHECK(effect_type IN ('team_member', 'folder_acl', 'team_escrow')),
    target_id       TEXT    NOT NULL,
    role_level      TEXT    REFERENCES roles(id) ON DELETE RESTRICT,
    permission      TEXT    CHECK(permission IS NULL OR permission IN ('read', 'write', 'admin')), -- NOSONAR
    recursive       INTEGER NOT NULL DEFAULT 1,
    escrow_override INTEGER,
    created_at      TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX idx_policy_effects_policy ON policy_effects(policy_id);
CREATE INDEX idx_policy_effects_target ON policy_effects(effect_type, target_id);

-------------------------------------------------
-- POLICY TEAM GRANTS
-- Materialised per-user tracking for team_member effects.
-- key_wrapped=0 → user_team_keys row not yet written; pending client key wrapping.
-------------------------------------------------
CREATE TABLE policy_team_grants (
    id          TEXT    NOT NULL PRIMARY KEY,
    effect_id   TEXT    NOT NULL REFERENCES policy_effects(id) ON DELETE CASCADE,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_wrapped INTEGER NOT NULL DEFAULT 0,
    granted_at  TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE(effect_id, user_id)
);

CREATE INDEX idx_policy_team_grants_user   ON policy_team_grants(user_id);
CREATE INDEX idx_policy_team_grants_effect ON policy_team_grants(effect_id);

-------------------------------------------------
-- POLICY FOLDER GRANTS
-- acl_written=1 → permissions row was written by this effect.
-- acl_written=0 → manual row already existed (ON CONFLICT DO NOTHING skipped it).
-- key_wrapped=0 → user_team_keys row not yet written (folder in team subtree).
-------------------------------------------------
CREATE TABLE policy_folder_grants (
    id          TEXT    NOT NULL PRIMARY KEY,
    effect_id   TEXT    NOT NULL REFERENCES policy_effects(id) ON DELETE CASCADE,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id   TEXT    NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    acl_written INTEGER NOT NULL DEFAULT 0,
    key_wrapped INTEGER NOT NULL DEFAULT 0,
    granted_at  TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    UNIQUE(effect_id, user_id, folder_id)
);

CREATE INDEX idx_policy_folder_grants_user   ON policy_folder_grants(user_id);
CREATE INDEX idx_policy_folder_grants_folder ON policy_folder_grants(folder_id);
CREATE INDEX idx_policy_folder_grants_effect ON policy_folder_grants(effect_id);

-------------------------------------------------
-- USER ↔ ROLE MAPPING
-- policy_effect_id: NULL = manually granted; NOT NULL = policy-sourced.
-------------------------------------------------
CREATE TABLE user_roles (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id          TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_type       TEXT DEFAULT NULL CHECK(scope_type IS NULL OR scope_type IN ('folder', 'team')),
    scope_id         TEXT DEFAULT NULL,
    granted_by       TEXT REFERENCES users(id) ON DELETE SET NULL,
    policy_effect_id TEXT REFERENCES policy_effects(id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_roles_user         ON user_roles(user_id);
CREATE INDEX idx_user_roles_role         ON user_roles(role_id);
CREATE INDEX idx_user_roles_scope        ON user_roles(scope_type, scope_id);
CREATE INDEX idx_user_roles_policy_effect ON user_roles(policy_effect_id);

CREATE UNIQUE INDEX idx_user_roles_global_unique
    ON user_roles(user_id, role_id)
    WHERE scope_type IS NULL;

CREATE UNIQUE INDEX idx_user_roles_scoped_unique
    ON user_roles(user_id, role_id, scope_type, scope_id)
    WHERE scope_type IS NOT NULL;

-------------------------------------------------
-- PER-MEMBER WRAPPED TEAM KEY
-- key_confirmed: set to 1 when the member submits a valid Schnorr PoK via
--   POST /teams/{id}/key-confirmation.
-- policy_effect_id: NULL = manually granted; NOT NULL = policy-sourced.
-------------------------------------------------
CREATE TABLE user_team_keys (
    id                   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    team_id              TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ephemeral_x25519_pub TEXT NOT NULL,
    kem_ciphertext       TEXT NOT NULL,
    encrypted_sk         TEXT NOT NULL,
    sk_iv                TEXT NOT NULL,
    key_confirmed        INTEGER NOT NULL DEFAULT 0,
    policy_effect_id     TEXT REFERENCES policy_effects(id) ON DELETE CASCADE,
    created_at           BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))::BIGINT,
    UNIQUE(team_id, user_id)
);

CREATE INDEX idx_user_team_keys_team          ON user_team_keys(team_id);
CREATE INDEX idx_user_team_keys_user          ON user_team_keys(user_id);
CREATE INDEX idx_user_team_keys_policy_effect ON user_team_keys(policy_effect_id);
CREATE INDEX idx_user_team_keys_unconfirmed
    ON user_team_keys(team_id)
    WHERE key_confirmed = 0;

-------------------------------------------------
-- PERMISSIONS
-- granted_by: nullable — NULL for policy-sourced rows.
-- policy_effect_id: NULL = manually granted; NOT NULL = policy-sourced with cascade delete.
-------------------------------------------------
CREATE TABLE permissions (
    id               TEXT    NOT NULL PRIMARY KEY,
    resource_type    TEXT    NOT NULL CHECK(resource_type IN ('file', 'folder')),
    resource_id      TEXT    NOT NULL,
    user_id          TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission       TEXT    NOT NULL CHECK(permission IN ('read', 'write', 'admin', 'download', 'delete', 'rename', 'manage_permissions', 'deny')), -- NOSONAR
    recursive        INTEGER NOT NULL DEFAULT 0,
    granted_by       TEXT    REFERENCES users(id) ON DELETE SET NULL,
    created_at       TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    policy_effect_id TEXT    REFERENCES policy_effects(id) ON DELETE CASCADE
);

CREATE INDEX idx_perm_resource             ON permissions(resource_type, resource_id);
CREATE INDEX idx_perm_user                 ON permissions(user_id);
CREATE UNIQUE INDEX idx_perm_unique        ON permissions(resource_type, resource_id, user_id);
CREATE INDEX idx_permissions_policy_effect ON permissions(policy_effect_id);

-------------------------------------------------
-- TEAM FOLDER ROLE LEVELS (Phase 1)
-- Per-team override: what folder permission level each team role grants.
-- Rows absent here fall back to _TEAM_ROLE_DEFAULTS in _access.py.
-------------------------------------------------
CREATE TABLE IF NOT EXISTS team_folder_role_levels (
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    level      TEXT NOT NULL CHECK(level IN ('admin', 'write', 'read', 'none')),
    updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, role_id)
);

-------------------------------------------------
-- ADMIN SCOPE GRANTS (Phase 1)
-- Individual permission-flag grants scoped to a specific team, without
-- a full role assignment.  Loaded alongside scoped role rows at login.
-------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_scope_grants (
    id         TEXT NOT NULL PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    flag       TEXT NOT NULL REFERENCES role_permission_flags(flag) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK(scope_type IN ('team')),
    scope_id   TEXT NOT NULL,
    granted_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, flag, scope_type, scope_id)
);

CREATE INDEX idx_admin_scope_grants_user  ON admin_scope_grants(user_id);
CREATE INDEX idx_admin_scope_grants_scope ON admin_scope_grants(scope_type, scope_id);

-------------------------------------------------
-- ADMIN SETTINGS (runtime-configurable key-value store)
-- is_locked / locked_min_tier: used by escrow defaults and sharing rules to
--   prevent lower-tier admins from overriding critical settings.
-------------------------------------------------
CREATE TABLE admin_settings (
    key            TEXT    PRIMARY KEY,
    value          TEXT    NOT NULL,
    is_locked      BOOLEAN NOT NULL DEFAULT FALSE,
    locked_min_tier INTEGER,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-------------------------------------------------
-- INVITES (single-use registration tokens)
-- Only the SHA-256 hash of the raw token is stored.
-------------------------------------------------
CREATE TABLE invites (
    id               TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    token_hash       TEXT NOT NULL UNIQUE,
    created_by       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at       TIMESTAMPTZ NOT NULL,
    used_at          TIMESTAMPTZ,
    used_by_ip       TEXT,
    used_by_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_invites_created_by ON invites(created_by);
CREATE INDEX idx_invites_expires    ON invites(expires_at);

-------------------------------------------------
-- INVITE SHORT LINKS (root-level slugs → /register/<token>)
-------------------------------------------------
CREATE TABLE invite_short_links (
    id         TEXT PRIMARY KEY,
    slug       TEXT NOT NULL UNIQUE,
    invite_id  TEXT NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
    token      TEXT NOT NULL,
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
    id                TEXT PRIMARY KEY,
    file_id           TEXT,
    user_id           TEXT,
    actor_username    TEXT,      -- denormalised: actual username or 'external' for anonymous share access
    actor_auth_method TEXT,      -- denormalised: 'opaque' | 'ldap' | 'oidc' | 'service' | NULL for anonymous
    share_id          TEXT,
    ip_address        TEXT NOT NULL,
    user_agent        TEXT,
    action            TEXT NOT NULL CHECK(action IN ('view', 'download', 'upload', 'delete', 'share')),
    timestamp         TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
-- SIEM canonical columns: severity, outcome, actor_session_id,
--   target_type, target_id, target_name, admin_actor_id.
-------------------------------------------------
CREATE TABLE security_events (
    id                TEXT        PRIMARY KEY,
    user_id           TEXT,
    actor_username    TEXT,      -- denormalised: preserved even if user is later deleted
    actor_auth_method TEXT,      -- denormalised: 'opaque' | 'ldap' | 'oidc' | 'service' | NULL for unauthenticated
    ip_address        TEXT        NOT NULL,
    user_agent        TEXT,
    event_type        TEXT        NOT NULL,
    action_key        TEXT,
    detail            TEXT,
    severity          TEXT        NOT NULL DEFAULT 'info',
    outcome           TEXT,
    actor_session_id  TEXT,
    target_type       TEXT,
    target_id         TEXT,
    target_name       TEXT,
    admin_actor_id    TEXT REFERENCES users(id),
    timestamp         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sevt_user      ON security_events(user_id);
CREATE INDEX idx_sevt_type      ON security_events(event_type);
CREATE INDEX idx_sevt_timestamp ON security_events(timestamp);
CREATE INDEX idx_sevt_severity  ON security_events(severity);

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

-------------------------------------------------
-- SIEM DESTINATIONS
-- Each row is one output path (syslog or webhook).
-- Secrets (webhook HMAC key) are AES-GCM encrypted.
-- filter_profile: 'high_security' | 'recommended' | 'relaxed' | 'custom'
-- filter_custom_json: used when filter_profile = 'custom'
--   e.g. {"event_type_globs": [...], "min_severity": "info"}
-------------------------------------------------
CREATE TABLE siem_destinations (
    id                TEXT    PRIMARY KEY DEFAULT (gen_random_uuid()::TEXT),
    name              TEXT    NOT NULL,
    type              TEXT    NOT NULL CHECK (type IN ('syslog', 'webhook')),
    is_active         INTEGER NOT NULL DEFAULT 1,

    -- syslog-specific (nullable for webhook rows)
    host              TEXT,
    port              INTEGER,
    protocol          TEXT    CHECK (protocol IN ('udp', 'tcp', 'tls')),
    syslog_format     TEXT    CHECK (syslog_format IN ('rfc5424', 'cef', 'leef')),
    facility          INTEGER NOT NULL DEFAULT 16,   -- 16 = LOCAL0

    -- webhook-specific (nullable for syslog rows)
    url               TEXT,
    secret_enc        TEXT,   -- AES-GCM encrypted HMAC-SHA256 signing key
    batch_size        INTEGER NOT NULL DEFAULT 1,

    -- event filter
    filter_profile    TEXT    NOT NULL DEFAULT 'recommended'
                              CHECK (filter_profile IN ('high_security', 'recommended', 'relaxed', 'custom')),
    filter_custom_json TEXT,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_siem_type_active ON siem_destinations(type, is_active);

-------------------------------------------------
-- STORAGE VOLUMES
-- config_enc: AES-GCM encrypted JSON for provider credentials
--   local  → {"files_dir": "...", "uploads_dir": "..."}
--   s3     → {"endpoint_url": "...", "bucket": "...",
--              "access_key_id": "...", "secret_access_key": "...", "region": "..."}
-- tier: hot = primary/fast, warm = nearline, cold = archive/cheap
-- is_default: exactly one volume should have is_default=1; used for new uploads
-------------------------------------------------
CREATE TABLE storage_volumes (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    provider    TEXT NOT NULL CHECK (provider IN ('local', 's3', 'azure', 'gcs', 'b2')),
    config_enc  TEXT,
    tier        TEXT NOT NULL DEFAULT 'hot' CHECK (tier IN ('hot', 'warm', 'cold')),
    is_default  INTEGER NOT NULL DEFAULT 0,
    priority    INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_storage_volumes_default ON storage_volumes(is_default);

-------------------------------------------------
-- FILE STORAGE LOCATIONS
-- One row per (file, volume) pair. A file with two mirror volumes has two rows.
-- is_primary: 1 for the authoritative write target; 0 for async replicas.
-- migration_state: idle | migrating | failed
-------------------------------------------------
CREATE TABLE file_storage_locations (
    file_id              TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    volume_id            TEXT NOT NULL REFERENCES storage_volumes(id),
    is_primary           INTEGER NOT NULL DEFAULT 1,
    migration_state      TEXT NOT NULL DEFAULT 'idle'
                             CHECK (migration_state IN ('idle', 'migrating', 'failed')),
    migration_started_at TIMESTAMPTZ,
    stored_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified        TIMESTAMPTZ,
    PRIMARY KEY (file_id, volume_id)
);

CREATE INDEX idx_fsl_volume          ON file_storage_locations(volume_id);
CREATE INDEX idx_fsl_migration_state ON file_storage_locations(migration_state)
    WHERE migration_state != 'idle';

-------------------------------------------------
-- NOTIFICATION CHANNELS (outbound push webhook config)
-- secret_enc: AES-GCM encrypted signing secret; NULL = unsigned delivery
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
-- key_hash:            SHA-256 hex of the raw "tss_..." key — never store plaintext
-- scopes:              JSON array of scope strings, e.g. ["audit_read"]
-- filter_event_types:  Optional comma-separated glob patterns (e.g. "auth.*,admin.*").
--                      When set, audit/op-events endpoints only return matching events,
--                      regardless of query-param filters — lets an ops SIEM key be
--                      scoped to only the events it needs.
-- filter_min_severity: Optional minimum severity gate ("info"|"warning"|"critical").
-------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    key_hash            TEXT NOT NULL UNIQUE,
    scopes              TEXT NOT NULL DEFAULT '["events.read"]',
    filter_event_types  TEXT,
    filter_min_severity TEXT,
    created_by          TEXT NOT NULL REFERENCES users(id),
    created_at          TIMESTAMPTZ DEFAULT now(),
    last_used_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ
);

-------------------------------------------------
-- OPERATIONAL EVENTS (persisted log)
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
-- FOLDER-LEVEL ESCROW POLICY OVERRIDES
-- Overrides org-level escrow defaults for a specific folder subtree.
-- override_mode: 'replace' (use only these agents), 'merge' (add to org defaults),
--   'none' (disable escrow for this subtree)
-------------------------------------------------
CREATE TABLE folder_escrow_policies (
    id                TEXT    PRIMARY KEY DEFAULT gen_random_uuid()::text,
    folder_id         TEXT    NOT NULL UNIQUE REFERENCES folders(id) ON DELETE CASCADE,
    override_mode     TEXT    NOT NULL DEFAULT 'replace'
        CHECK (override_mode IN ('replace', 'merge', 'none')),
    policy_locked     BOOLEAN NOT NULL DEFAULT FALSE,
    locked_min_tier   INTEGER,
    overrides_allowed BOOLEAN NOT NULL DEFAULT TRUE,
    created_by        TEXT    NOT NULL REFERENCES users(id),
    created_by_tier   INTEGER NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fep_folder ON folder_escrow_policies(folder_id);

CREATE TABLE folder_escrow_policy_agents (
    id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    policy_id     TEXT NOT NULL REFERENCES folder_escrow_policies(id) ON DELETE CASCADE,
    agent_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    agent_role_id TEXT REFERENCES roles(id) ON DELETE CASCADE,
    CHECK (
        (agent_user_id IS NOT NULL AND agent_role_id IS NULL)
        OR  (agent_user_id IS NULL  AND agent_role_id IS NOT NULL)
    )
);

CREATE INDEX idx_fepa_policy ON folder_escrow_policy_agents(policy_id);

-------------------------------------------------
-- SHARING RULES
-- Evaluated at share creation time; first-match-wins in priority order.
-- subject: 'sender' | 'recipient' | 'cross' (relationship between parties)
-------------------------------------------------
CREATE TABLE sharing_rules (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name        TEXT NOT NULL,
    description TEXT,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    priority    INTEGER NOT NULL DEFAULT 100,
    subject     TEXT NOT NULL CHECK (subject IN ('sender', 'recipient', 'cross')),
    applies_to_share_type TEXT CHECK (applies_to_share_type IN ('link', 'user')),
    effect      TEXT NOT NULL DEFAULT 'deny' CHECK (effect IN ('deny', 'allow')),
    is_locked       BOOLEAN NOT NULL DEFAULT FALSE,
    locked_min_tier INTEGER,
    created_by      TEXT NOT NULL REFERENCES users(id),
    created_by_tier INTEGER NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sharing_rules_active_priority ON sharing_rules(is_active, priority);

-------------------------------------------------
-- SHARING RULE CONDITIONS (AND-ed together per rule)
-- attribute_path: '<source>.<attribute_name>'
--   Sources: 'internal' (users columns), 'ldap', 'oidc' (oidc_claims_cache)
-- block_on_missing_attribute: when TRUE, unresolvable attribute → condition matches
--   (fail-closed: deny rules fire, allow rules do not).
-------------------------------------------------
CREATE TABLE sharing_rule_conditions (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    rule_id     TEXT NOT NULL REFERENCES sharing_rules(id) ON DELETE CASCADE,
    attribute_path  TEXT NOT NULL,
    attribute_path2 TEXT,
    operator    TEXT NOT NULL CHECK (operator IN (
        'eq', 'neq', 'contains', 'not_contains', 'starts_with', 'ends_with',
        'in', 'not_in', 'matches_re',
        'cross_eq', 'cross_neq'
    )),
    value       TEXT,
    block_on_missing_attribute BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_src_conditions_rule ON sharing_rule_conditions(rule_id);


-- ===========================================================================
-- SEED DATA
-- ===========================================================================

-------------------------------------------------
-- ROLES: 6-tier admin hierarchy + escrow agent + legacy aliases
-------------------------------------------------
INSERT INTO roles (id, name, description, is_system) VALUES
    ('server_admin',      'Server Admin',      'System settings, disk, logging, integrations; highest authority', 1), -- NOSONAR
    ('org_admin',         'Org Admin',         'Org-wide roles, teams, and org-level policies',                   1), -- NOSONAR
    ('operational_admin', 'Operational Admin', 'User and team lifecycle management, invite generation',           1), -- NOSONAR
    ('team_admin',        'Team Admin',        'Admin authority scoped to a single team',                         1), -- NOSONAR
    ('team_manager',      'Team Manager',      'Member and folder management within a team',                      1), -- NOSONAR
    ('team_member',       'Team Member',       'Upload/download and create folders within a team',                1),
    ('escrow_agent',      'Escrow Agent',      'Recovery access to team key material via admin escrow policy',    1),
    ('role_admin',        'Admin',             'Legacy system administrator role — superseded by server_admin',   1), -- NOSONAR
    ('role_user',         'User',              'Regular user — file storage and sharing',                         1); -- NOSONAR

-------------------------------------------------
-- PERMISSION FLAGS
-------------------------------------------------
INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES
    ('can_view_admin_panel',        'Access the admin panel',                                             'admin',         0), -- NOSONAR
    ('can_manage_system_settings',  'Configure server-level settings (disk, logging, startup)',           'admin',         0), -- NOSONAR
    ('can_manage_org_settings',     'Configure org-level settings (branding, org policies)',              'admin',         0), -- NOSONAR
    ('can_manage_users',            'Create, update, and delete user accounts',                           'admin',         0), -- NOSONAR
    ('can_manage_invites',          'Create and revoke platform-level registration invite links',          'admin',         0), -- NOSONAR
    ('can_manage_teams',            'Create, delete, and configure teams',                                'admin',         0), -- NOSONAR
    ('can_manage_team_members',     'Invite and remove members within a team',                            'admin',         0), -- NOSONAR
    ('can_manage_roles',            'Define roles and grant or revoke role assignments',                   'roles',         0), -- NOSONAR
    ('can_create_roles',            'Create custom roles (permission set capped to creator''s own)',       'roles',         0), -- NOSONAR
    ('can_create_cross_team_roles', 'Create roles that span multiple teams',                              'roles',         0), -- NOSONAR
    ('can_view_disk_usage',         'View disk usage statistics',                                         'observability', 0), -- NOSONAR
    ('can_view_audit_log',          'View the server-wide audit trail',                                   'audit',         0), -- NOSONAR
    ('can_export_audit_log',        'Export the audit trail to CSV or TXT',                               'audit',         0), -- NOSONAR
    ('can_manage_integrations',     'Configure LDAP, SSO, and external identity providers',               'integrations',  0), -- NOSONAR
    ('can_manage_policies',         'Define and enforce org- and team-level policies',                    'policy',        0), -- NOSONAR
    ('can_access_all_files',        'Bypass file ownership checks — grants access to all files',          'files',         1), -- NOSONAR
    ('can_define_policy_fields',    'Register new LDAP/OIDC attribute fields for policy conditions',      'policy',        0), -- NOSONAR
    ('can_act_as_escrow',           'User can be added as a key escrow recovery agent',                   'security',      1), -- NOSONAR
    ('can_manage_user_mfa',         'View and remove MFA credentials for other users (admin)',             'security',      1), -- NOSONAR
    ('can_manage_escrow',           'Manage org-level escrow defaults and folder-level escrow policies',  'security',      1), -- NOSONAR
    ('can_manage_sharing',          'Manage sharing restriction flags and identity-scoped sharing rules', 'security',      0), -- NOSONAR
    ('can_create_link_shares',      'May create anonymous link shares',                                   'sharing',       0), -- NOSONAR
    ('can_create_user_shares',      'May create user-to-user KEM shares',                                 'sharing',       0), -- NOSONAR
    ('can_create_upload_grants',    'May enable upload access on a share',                                'sharing',       0), -- NOSONAR
    ('can_share_folders',           'May create upload-only folder shares',                               'sharing',       0), -- NOSONAR
    ('can_manage_service_accounts', 'Create, rotate, and delete machine-identity service accounts',       'admin',         0), -- NOSONAR
    ('can_copy_files',              'May copy files within copy_boundary policy',                          'files',         0); -- NOSONAR

-------------------------------------------------
-- PERMISSION FLAG GRANTS PER ROLE
-------------------------------------------------

-- server_admin: full access except can_access_all_files
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('server_admin', 'can_view_admin_panel',        '1'),
    ('server_admin', 'can_manage_system_settings',  '1'),
    ('server_admin', 'can_manage_org_settings',     '1'),
    ('server_admin', 'can_manage_users',            '1'),
    ('server_admin', 'can_manage_invites',          '1'),
    ('server_admin', 'can_manage_teams',            '1'),
    ('server_admin', 'can_manage_team_members',     '1'),
    ('server_admin', 'can_manage_roles',            '1'),
    ('server_admin', 'can_create_roles',            '1'),
    ('server_admin', 'can_create_cross_team_roles', '1'),
    ('server_admin', 'can_view_disk_usage',         '1'),
    ('server_admin', 'can_view_audit_log',          '1'),
    ('server_admin', 'can_export_audit_log',        '1'),
    ('server_admin', 'can_manage_integrations',     '1'),
    ('server_admin', 'can_manage_policies',         '1'),
    ('server_admin', 'can_access_all_files',        '0'),
    ('server_admin', 'can_define_policy_fields',    '1'),
    ('server_admin', 'can_manage_user_mfa',         '1'),
    ('server_admin', 'can_manage_escrow',           '1'),
    ('server_admin', 'can_manage_sharing',          '1'),
    ('server_admin', 'can_create_link_shares',      '1'),
    ('server_admin', 'can_create_user_shares',      '1'),
    ('server_admin', 'can_create_upload_grants',    '1'),
    ('server_admin', 'can_share_folders',           '1'),
    ('server_admin', 'can_manage_service_accounts', '1'),
    ('server_admin', 'can_copy_files',              '1');

-- org_admin: org-wide; no system-level or integration settings
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('org_admin', 'can_view_admin_panel',        '1'),
    ('org_admin', 'can_manage_system_settings',  '0'),
    ('org_admin', 'can_manage_org_settings',     '1'),
    ('org_admin', 'can_manage_users',            '1'),
    ('org_admin', 'can_manage_invites',          '1'),
    ('org_admin', 'can_manage_teams',            '1'),
    ('org_admin', 'can_manage_team_members',     '1'),
    ('org_admin', 'can_manage_roles',            '1'),
    ('org_admin', 'can_create_roles',            '1'),
    ('org_admin', 'can_create_cross_team_roles', '1'),
    ('org_admin', 'can_view_disk_usage',         '1'),
    ('org_admin', 'can_view_audit_log',          '1'),
    ('org_admin', 'can_export_audit_log',        '1'),
    ('org_admin', 'can_manage_integrations',     '0'),
    ('org_admin', 'can_manage_policies',         '1'),
    ('org_admin', 'can_access_all_files',        '0'),
    ('org_admin', 'can_define_policy_fields',    '1'),
    ('org_admin', 'can_manage_user_mfa',         '1'),
    ('org_admin', 'can_manage_escrow',           '1'),
    ('org_admin', 'can_manage_sharing',          '1'),
    ('org_admin', 'can_create_link_shares',      '1'),
    ('org_admin', 'can_create_user_shares',      '1'),
    ('org_admin', 'can_create_upload_grants',    '1'),
    ('org_admin', 'can_share_folders',           '1'),
    ('org_admin', 'can_manage_service_accounts', '1'),
    ('org_admin', 'can_copy_files',              '1');

-- operational_admin: user/team lifecycle only
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('operational_admin', 'can_view_admin_panel',        '1'),
    ('operational_admin', 'can_manage_system_settings',  '0'),
    ('operational_admin', 'can_manage_org_settings',     '0'),
    ('operational_admin', 'can_manage_users',            '1'),
    ('operational_admin', 'can_manage_invites',          '1'),
    ('operational_admin', 'can_manage_teams',            '1'),
    ('operational_admin', 'can_manage_team_members',     '1'),
    ('operational_admin', 'can_manage_roles',            '1'),
    ('operational_admin', 'can_create_roles',            '0'),
    ('operational_admin', 'can_create_cross_team_roles', '0'),
    ('operational_admin', 'can_view_disk_usage',         '0'),
    ('operational_admin', 'can_view_audit_log',          '0'),
    ('operational_admin', 'can_export_audit_log',        '0'),
    ('operational_admin', 'can_manage_integrations',     '0'),
    ('operational_admin', 'can_manage_policies',         '0'),
    ('operational_admin', 'can_access_all_files',        '0'),
    ('operational_admin', 'can_define_policy_fields',    '0'),
    ('operational_admin', 'can_manage_user_mfa',         '0'),
    ('operational_admin', 'can_manage_escrow',           '0'),
    ('operational_admin', 'can_manage_sharing',          '0'),
    ('operational_admin', 'can_create_link_shares',      '0'),
    ('operational_admin', 'can_create_user_shares',      '0'),
    ('operational_admin', 'can_create_upload_grants',    '0'),
    ('operational_admin', 'can_share_folders',           '0'),
    ('operational_admin', 'can_manage_service_accounts', '1'),
    ('operational_admin', 'can_copy_files',              '1');

-- team_admin: team-scoped; can create roles and manage within their team
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('team_admin', 'can_view_admin_panel',        '1'),
    ('team_admin', 'can_manage_system_settings',  '0'),
    ('team_admin', 'can_manage_org_settings',     '0'),
    ('team_admin', 'can_manage_users',            '0'),
    ('team_admin', 'can_manage_invites',          '1'),
    ('team_admin', 'can_manage_teams',            '1'),
    ('team_admin', 'can_manage_team_members',     '1'),
    ('team_admin', 'can_manage_roles',            '1'),
    ('team_admin', 'can_create_roles',            '1'),
    ('team_admin', 'can_create_cross_team_roles', '0'),
    ('team_admin', 'can_view_disk_usage',         '0'),
    ('team_admin', 'can_view_audit_log',          '0'),
    ('team_admin', 'can_export_audit_log',        '0'),
    ('team_admin', 'can_manage_integrations',     '0'),
    ('team_admin', 'can_manage_policies',         '0'),
    ('team_admin', 'can_access_all_files',        '0'),
    ('team_admin', 'can_define_policy_fields',    '0'),
    ('team_admin', 'can_manage_user_mfa',         '0'),
    ('team_admin', 'can_manage_escrow',           '0'),
    ('team_admin', 'can_manage_sharing',          '0'),
    ('team_admin', 'can_create_link_shares',      '0'),
    ('team_admin', 'can_create_user_shares',      '0'),
    ('team_admin', 'can_create_upload_grants',    '0'),
    ('team_admin', 'can_share_folders',           '0'),
    ('team_admin', 'can_manage_service_accounts', '0'),
    ('team_admin', 'can_copy_files',              '1');

-- team_manager: member management only
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('team_manager', 'can_view_admin_panel',        '0'),
    ('team_manager', 'can_manage_system_settings',  '0'),
    ('team_manager', 'can_manage_org_settings',     '0'),
    ('team_manager', 'can_manage_users',            '0'),
    ('team_manager', 'can_manage_invites',          '0'),
    ('team_manager', 'can_manage_teams',            '0'),
    ('team_manager', 'can_manage_team_members',     '1'),
    ('team_manager', 'can_manage_roles',            '0'),
    ('team_manager', 'can_create_roles',            '0'),
    ('team_manager', 'can_create_cross_team_roles', '0'),
    ('team_manager', 'can_view_disk_usage',         '0'),
    ('team_manager', 'can_view_audit_log',          '0'),
    ('team_manager', 'can_export_audit_log',        '0'),
    ('team_manager', 'can_manage_integrations',     '0'),
    ('team_manager', 'can_manage_policies',         '0'),
    ('team_manager', 'can_access_all_files',        '0'),
    ('team_manager', 'can_define_policy_fields',    '0'),
    ('team_manager', 'can_manage_user_mfa',         '0'),
    ('team_manager', 'can_manage_escrow',           '0'),
    ('team_manager', 'can_manage_sharing',          '0'),
    ('team_manager', 'can_create_link_shares',      '0'),
    ('team_manager', 'can_create_user_shares',      '0'),
    ('team_manager', 'can_create_upload_grants',    '0'),
    ('team_manager', 'can_share_folders',           '0'),
    ('team_manager', 'can_manage_service_accounts', '0'),
    ('team_manager', 'can_copy_files',              '1');

-- escrow_agent: only the escrow capability flag
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('escrow_agent', 'can_act_as_escrow', '1');

-- role_admin (legacy alias): same grants as server_admin for backward compat
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('role_admin', 'can_view_admin_panel',        '1'),
    ('role_admin', 'can_manage_system_settings',  '1'),
    ('role_admin', 'can_manage_org_settings',     '1'),
    ('role_admin', 'can_manage_users',            '1'),
    ('role_admin', 'can_manage_invites',          '1'),
    ('role_admin', 'can_manage_teams',            '1'),
    ('role_admin', 'can_manage_team_members',     '1'),
    ('role_admin', 'can_manage_roles',            '1'),
    ('role_admin', 'can_create_roles',            '1'),
    ('role_admin', 'can_create_cross_team_roles', '1'),
    ('role_admin', 'can_view_disk_usage',         '1'),
    ('role_admin', 'can_view_audit_log',          '1'),
    ('role_admin', 'can_export_audit_log',        '1'),
    ('role_admin', 'can_manage_integrations',     '1'),
    ('role_admin', 'can_manage_policies',         '1'),
    ('role_admin', 'can_access_all_files',        '0'),
    ('role_admin', 'can_define_policy_fields',    '1'),
    ('role_admin', 'can_manage_user_mfa',         '1'),
    ('role_admin', 'can_manage_escrow',           '1'),
    ('role_admin', 'can_manage_sharing',          '1'),
    ('role_admin', 'can_create_link_shares',      '1'),
    ('role_admin', 'can_create_user_shares',      '1'),
    ('role_admin', 'can_create_upload_grants',    '1'),
    ('role_admin', 'can_share_folders',           '1'),
    ('role_admin', 'can_manage_service_accounts', '1'),
    ('role_admin', 'can_copy_files',              '1');

-- role_user: sharing capabilities; no admin flags
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('role_user', 'can_create_link_shares',   '1'),
    ('role_user', 'can_create_user_shares',   '1'),
    ('role_user', 'can_create_upload_grants', '1'),
    ('role_user', 'can_share_folders',        '1'),
    ('role_user', 'can_copy_files',           '1');

-- team_member and role_user have no other flags granted.

-------------------------------------------------
-- BUILT-IN POLICY FIELD DEFINITIONS (internal source)
-------------------------------------------------
INSERT INTO policy_field_definitions (name, display_label, source, data_type, claim_path) VALUES
    ('totp_enabled',        'TOTP MFA Enabled',               'internal', 'boolean', NULL),
    ('webauthn_enabled',    'WebAuthn Enabled',               'internal', 'boolean', NULL),
    ('mfa_enabled',         'MFA Enabled (TOTP or WebAuthn)', 'internal', 'boolean', NULL),
    ('mfa_reset_required',  'MFA Reset Required',             'internal', 'boolean', NULL),
    ('auth_provider',       'Auth Provider',                  'internal', 'string',  NULL),
    ('auth_method',         'Auth Method',                    'internal', 'string',  NULL),
    ('identity_provider',   'Identity Provider',              'internal', 'string',  NULL),
    ('role',                'Global Role',                    'internal', 'string',  NULL),
    ('is_active',           'Account Active',                 'internal', 'boolean', NULL),
    ('has_recovery_key',    'Recovery Key Enrolled',          'internal', 'boolean', NULL),
    ('has_asymmetric_keys', 'PQ-KEM Keys Generated',          'internal', 'boolean', NULL);

-------------------------------------------------
-- ADMIN SETTINGS SEEDS
-- Additional defaults are injected at startup by seed_admin_settings() in database.py.
-------------------------------------------------
INSERT INTO admin_settings (key, value) VALUES ('mfa_enforcement',             'off')     ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('mfa_oidc_exempt',             '1')       ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('notify_escrow_on_revocation', '0')       ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('audit_retention_days',        '365')     ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_tiering_enabled',     '0')       ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_hot_to_warm_days',    '')        ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_warm_to_cold_days',   '')        ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_warm_volume_id',      '')        ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_cold_volume_id',      '')        ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('storage_auto_warm_on_read',   '0')       ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('server_id',                   '')        ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('op_event_retention_days',     '30')      ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('api_key_expiry_warn_days',    '30')      ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('upload_quota_warn_pct',       '90')      ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('av_scan_endpoint',            '')        ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('av_scan_secret',              '')        ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('av_require_clean',            'false')   ON CONFLICT (key) DO NOTHING; -- NOSONAR
INSERT INTO admin_settings (key, value) VALUES ('av_scan_retry_attempts',      '3')       ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('escrow_default_user_ids',     '[]')      ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('escrow_default_role_ids',     '["escrow_agent"]') ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('escrow_require_coverage',     '0')       ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('regex_match_timeout_ms',      '500')     ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('allow_user_delete_own_account', 'false')  ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('can_delete_owned_shared',       'false')  ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('allow_multi_team_owner',        'false')  ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('first_run_completed',           '0')      ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('trash_enabled',                 'true')   ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('trash_retention_days',          '30')     ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('copy_boundary',                  'any')    ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES ('anon_share_upload_rate_limit',   '20')     ON CONFLICT (key) DO NOTHING; -- requests per 60 s per share_id

-------------------------------------------------
-- DEFAULT LOCAL STORAGE VOLUME
-- Uses the well-known ID 'local-default' so the application can reference it
-- at startup before any admin configuration has been applied.
-------------------------------------------------
INSERT INTO storage_volumes (id, name, provider, tier, is_default, priority)
VALUES ('local-default', 'Local (default)', 'local', 'hot', 1, 0)
ON CONFLICT (id) DO NOTHING;
