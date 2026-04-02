-- 005_roles.sql — Role-based access control
--
-- System roles (admin, user) are seeded and immutable.
-- Scoped roles (team_owner, team_supervisor, team_member) can be added later
-- without schema changes — scope_type + scope_id bind roles to a resource.
--
-- PostgreSQL note: NULL values are distinct in UNIQUE constraints, so a plain
-- UNIQUE(user_id, role_id, scope_type, scope_id) would allow duplicate global
-- roles (scope_type=NULL, scope_id=NULL). Partial unique indexes are used
-- instead to correctly enforce uniqueness for both global and scoped roles.

-------------------------------------------------
-- ROLES
-------------------------------------------------
CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE
                    CHECK(length(name) BETWEEN 1 AND 64),
    description TEXT NOT NULL DEFAULT '',
    is_system   INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_roles_user  ON user_roles(user_id);
CREATE INDEX idx_user_roles_role  ON user_roles(role_id);
CREATE INDEX idx_user_roles_scope ON user_roles(scope_type, scope_id);

-- Global role unique constraint (scope_type IS NULL, scope_id IS NULL)
CREATE UNIQUE INDEX idx_user_roles_global_unique
    ON user_roles(user_id, role_id)
    WHERE scope_type IS NULL;

-- Scoped role unique constraint
CREATE UNIQUE INDEX idx_user_roles_scoped_unique
    ON user_roles(user_id, role_id, scope_type, scope_id)
    WHERE scope_type IS NOT NULL;

-------------------------------------------------
-- Migrate existing is_admin data into user_roles
-- (No-op on a fresh database; kept for consistency with migration history)
-------------------------------------------------
INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by)
    SELECT ('ur_user_' || id), id, 'role_user', NULL, NULL, NULL
    FROM users
    ON CONFLICT DO NOTHING;

INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by)
    SELECT ('ur_admin_' || id), id, 'role_admin', NULL, NULL, NULL
    FROM users
    WHERE is_admin = 1
    ON CONFLICT DO NOTHING;
