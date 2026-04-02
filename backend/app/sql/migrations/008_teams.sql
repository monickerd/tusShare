-- 008_teams.sql — Teams, per-member key distribution, PRE file keys, team folders.
--
-- PostgreSQL changes from SQLite version:
--   - DEFAULT (lower(hex(randomblob(16)))) → DEFAULT gen_random_uuid()::text
--   - DEFAULT (unixepoch())                → DEFAULT (EXTRACT(EPOCH FROM NOW()))::BIGINT
--   - INSERT OR IGNORE                     → INSERT ... ON CONFLICT DO NOTHING
--   - SQLite trigger syntax                → PostgreSQL PL/pgSQL triggers

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
-- PER-FILE PRE CIPHERTEXT
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
-- TEAM ROLES
-------------------------------------------------
INSERT INTO roles (id, name, description, is_system) VALUES
    ('team_owner',
     'Team Owner',
     'Full control: manage members, folders, and delete team', 0)
    ON CONFLICT DO NOTHING;

INSERT INTO roles (id, name, description, is_system) VALUES
    ('team_supervisor',
     'Team Supervisor',
     'Invite and remove members, manage team folders', 0)
    ON CONFLICT DO NOTHING;

INSERT INTO roles (id, name, description, is_system) VALUES
    ('team_member',
     'Team Member',
     'Read/write access to team folders', 0)
    ON CONFLICT DO NOTHING;

-------------------------------------------------
-- IMMUTABLE ACCESS LOGS (DB-layer enforcement)
--
-- PostgreSQL requires a trigger function + trigger (unlike SQLite's inline syntax).
-------------------------------------------------
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
