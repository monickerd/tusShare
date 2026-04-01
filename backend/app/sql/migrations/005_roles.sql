-- 005_roles.sql — Role-based access control
--
-- Replaces the boolean is_admin column with a flexible roles system.
-- System roles (admin, user) are seeded and immutable.
-- Scoped roles (team_owner, team_supervisor, team_member) can be
-- added later without schema changes — scope_type + scope_id allow
-- roles to be bound to a folder, team, or other resource.

-------------------------------------------------
-- ROLES
-------------------------------------------------
CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE
                    CHECK(length(name) BETWEEN 1 AND 64),
    description TEXT NOT NULL DEFAULT '',
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Seed system roles
INSERT INTO roles (id, name, description, is_system) VALUES
    ('role_admin', 'admin', 'System administrator — management only, no file operations', 1),
    ('role_user',  'user',  'Regular user — file storage and sharing', 1);

-------------------------------------------------
-- USER ↔ ROLE mapping
-------------------------------------------------
CREATE TABLE user_roles (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_type  TEXT DEFAULT NULL
                    CHECK(scope_type IS NULL OR scope_type IN ('folder', 'team')),
    scope_id    TEXT DEFAULT NULL,
    granted_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- A user can only hold a given role once per scope
    UNIQUE(user_id, role_id, scope_type, scope_id)
);

CREATE INDEX idx_user_roles_user     ON user_roles(user_id);
CREATE INDEX idx_user_roles_role     ON user_roles(role_id);
CREATE INDEX idx_user_roles_scope    ON user_roles(scope_type, scope_id);

-------------------------------------------------
-- Migrate existing is_admin data into user_roles
-------------------------------------------------
-- All existing users get the 'user' role (global)
INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by)
    SELECT
        ('ur_user_' || id),
        id,
        'role_user',
        NULL,
        NULL,
        NULL
    FROM users;

-- Existing admins additionally get the 'admin' role (global)
INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by)
    SELECT
        ('ur_admin_' || id),
        id,
        'role_admin',
        NULL,
        NULL,
        NULL
    FROM users
    WHERE is_admin = 1;
