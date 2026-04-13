-- 011_e2_team_roles.sql — Phase E2: Custom team-scoped roles
--
-- Adds three tables supporting team-level custom role creation:
--   team_roles             — named roles scoped to a single team
--   team_role_permissions  — move permission flags per team role
--   team_role_assignments  — maps users to team roles within a team
--
-- Global team roles (team_admin/team_manager/team_member) continue to be
-- stored in user_roles with scope_type='team'.  This schema handles only
-- *custom* roles created by team admins via the can_create_roles flag.
--
-- Move flags are team-specific; they do not appear in role_permission_flags.
-- Default move permissions for global team roles are enforced in application
-- logic (team_admin/team_manager: both on; team_member: both off).

-------------------------------------------------
-- CUSTOM TEAM ROLES
-- One row per custom role per team.
-- is_system is always 0 for custom roles; no seeded defaults.
-------------------------------------------------
CREATE TABLE team_roles (
    id          TEXT PRIMARY KEY,
    team_id     TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX idx_team_roles_team ON team_roles(team_id);

-------------------------------------------------
-- MOVE PERMISSION FLAGS PER TEAM ROLE
-- Valid flags:
--   move_own_files_out_of_team    — may move files where owner_id = self
--   move_others_files_out_of_team — may move files owned by another user
-- value: '1' = granted, '0' = denied
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
-- A user may hold multiple custom team roles within the same team.
-- The UNIQUE constraint prevents duplicate assignments.
-------------------------------------------------
CREATE TABLE team_role_assignments (
    id           TEXT PRIMARY KEY,
    team_role_id TEXT NOT NULL REFERENCES team_roles(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id      TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    granted_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    granted_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (team_role_id, user_id)
);

CREATE INDEX idx_team_role_assign_user_team ON team_role_assignments(user_id, team_id);
CREATE INDEX idx_team_role_assign_role      ON team_role_assignments(team_role_id);
