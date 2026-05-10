-- Migration 014 — Permissions v2 (Phase 1 permissions overhaul)
--
-- Run on existing deployments that have schema_v1 applied but do not yet
-- have the Phase 1 tables and constraint extensions.
--
-- Safe to run multiple times (IF NOT EXISTS / IF EXISTS guards throughout).
--
-- ============================================================
-- CLEAN-SLATE POLICY
-- ============================================================
-- The Phase 1 design decision is that existing permissions and user_roles
-- rows are cleared when this migration ships to production.  Admins must
-- reconfigure under the new model.  The cleanup SQL is provided at the
-- bottom of this file but is commented out — an operator must opt in by
-- running it explicitly.
-- ============================================================


-- ------------------------------------------------------------
-- 1. team_folder_role_levels
--    Per-team override: which folder permission level each team role grants.
--    Present in schema_v1 with IF NOT EXISTS, but older live installs may
--    lack the updated_by / updated_at audit columns added in this migration.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS team_folder_role_levels (
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    level      TEXT NOT NULL CHECK(level IN ('admin', 'write', 'read', 'none')),
    updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, role_id)
);

-- Add audit columns if the table already exists without them.
ALTER TABLE team_folder_role_levels
    ADD COLUMN IF NOT EXISTS updated_by TEXT REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE team_folder_role_levels
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();


-- ------------------------------------------------------------
-- 2. admin_scope_grants
--    Individual flag grants scoped to a specific team without a full role
--    assignment.  Loaded alongside scoped role rows at login/refresh.
-- ------------------------------------------------------------
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

CREATE INDEX IF NOT EXISTS idx_admin_scope_grants_user
    ON admin_scope_grants(user_id);

CREATE INDEX IF NOT EXISTS idx_admin_scope_grants_scope
    ON admin_scope_grants(scope_type, scope_id);


-- ------------------------------------------------------------
-- 3. Extend permissions.permission CHECK constraint
--    The original constraint only allowed: read, write, admin.
--    Phase 1 adds: download, delete, rename, manage_permissions, deny.
--
--    PostgreSQL requires dropping and re-adding named constraints.
--    The constraint is unnamed in the original schema (DB assigns an
--    auto-generated name); use a DO block to find and drop it safely.
-- ------------------------------------------------------------
DO $$
DECLARE
    _con TEXT;
BEGIN
    SELECT conname INTO _con
    FROM pg_constraint
    WHERE conrelid = 'permissions'::regclass
      AND contype  = 'c'
      AND pg_get_constraintdef(oid) LIKE '%read%write%admin%'
      AND pg_get_constraintdef(oid) NOT LIKE '%download%'
    LIMIT 1;

    IF _con IS NOT NULL THEN
        EXECUTE format('ALTER TABLE permissions DROP CONSTRAINT %I', _con);
        ALTER TABLE permissions
            ADD CONSTRAINT permissions_permission_check
            CHECK(permission IN (
                'read', 'write', 'admin',
                'download', 'delete', 'rename', 'manage_permissions', 'deny'
            ));
    END IF;
END
$$;


-- ------------------------------------------------------------
-- 4. user_roles scope columns
--    scope_type and scope_id were added to user_roles in this phase.
--    Safe no-ops if already present.
-- ------------------------------------------------------------
ALTER TABLE user_roles
    ADD COLUMN IF NOT EXISTS scope_type TEXT
        CHECK(scope_type IS NULL OR scope_type IN ('folder', 'team'));

ALTER TABLE user_roles
    ADD COLUMN IF NOT EXISTS scope_id TEXT;

-- Partial unique indexes for global vs. scoped rows.
-- CREATE UNIQUE INDEX IF NOT EXISTS requires PG 9.5+ which we already depend on.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'user_roles'
          AND indexname  = 'idx_user_roles_global_unique'
    ) THEN
        CREATE UNIQUE INDEX idx_user_roles_global_unique
            ON user_roles(user_id, role_id)
            WHERE scope_type IS NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'user_roles'
          AND indexname  = 'idx_user_roles_scoped_unique'
    ) THEN
        CREATE UNIQUE INDEX idx_user_roles_scoped_unique
            ON user_roles(user_id, role_id, scope_type, scope_id)
            WHERE scope_type IS NOT NULL;
    END IF;
END
$$;

