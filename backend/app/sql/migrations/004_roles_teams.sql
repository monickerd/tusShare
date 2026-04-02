-- 004_roles_teams.sql — Role-based access control and team collaboration

-------------------------------------------------
-- ROLES
-- System roles (admin, user) are immutable.
-- Team-scoped roles (team_owner, team_supervisor, team_member) are created
-- here alongside the team tables they relate to.
-------------------------------------------------
CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 64),
    description TEXT NOT NULL DEFAULT '',
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO roles (id, name, description, is_system) VALUES
    ('role_admin',       'admin',           'System administrator — management only, no file operations', 1),
    ('role_user',        'user',            'Regular user — file storage and sharing', 1),
    ('team_owner',       'Team Owner',      'Full control: manage members, folders, and delete team', 0),
    ('team_supervisor',  'Team Supervisor', 'Invite and remove members, manage team folders', 0),
    ('team_member',      'Team Member',     'Read/write access to team folders', 0);

-------------------------------------------------
-- USER ↔ ROLE MAPPING
-- NULL values are distinct in PostgreSQL UNIQUE constraints so partial indexes
-- are used to correctly enforce uniqueness for global and scoped roles.
-------------------------------------------------
CREATE TABLE user_roles (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_type  TEXT DEFAULT NULL CHECK(scope_type IS NULL OR scope_type IN ('folder', 'team')),
    scope_id    TEXT DEFAULT NULL,
    granted_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_roles_user  ON user_roles(user_id);
CREATE INDEX idx_user_roles_role  ON user_roles(role_id);
CREATE INDEX idx_user_roles_scope ON user_roles(scope_type, scope_id);

-- Unique: one global role per user
CREATE UNIQUE INDEX idx_user_roles_global_unique
    ON user_roles(user_id, role_id)
    WHERE scope_type IS NULL;

-- Unique: one scoped role per (user, role, resource)
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
