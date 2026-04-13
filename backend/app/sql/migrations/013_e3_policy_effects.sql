-- 013_e3_policy_effects.sql — Phase E3: Policy effect definitions and grant tracking
--
-- Completes the policy engine by adding:
--   policy_effects       — defines what a matching policy grants (effect type + target)
--   policy_team_grants   — per-user tracking for team_member effects (key_wrapped flag)
--   policy_folder_grants — recreated from 012 with effect_id FK + acl_written flag
--
-- Also extends three tables to distinguish policy-sourced rows from manual grants:
--   user_roles     — adds policy_effect_id (NULL = manual; NOT NULL = policy-sourced)
--   user_team_keys — adds policy_effect_id
--   permissions    — recreated: adds policy_effect_id + makes granted_by nullable
--
-- "Apply in order" model
-- ──────────────────────
-- evaluate_user_policies() writes policy rows first (INSERT OR IGNORE with effect_id).
-- Manual admin grants are applied after and also use INSERT OR IGNORE, so where a
-- policy row already exists, the manual grant is silently skipped and the user retains
-- their policy-granted access level.  Where a MANUAL row already exists for a
-- (user, resource) key, the policy INSERT OR IGNORE is skipped — manual wins.
-- Revocation: DELETE FROM ... WHERE user_id = ? AND policy_effect_id IN (...).
-- Manual rows (policy_effect_id IS NULL) are never touched by the revocation path.
--
-- Key-wrapping note (E4 work)
-- ────────────────────────────
-- team_member effects set key_wrapped=0 in policy_team_grants at evaluation time.
-- The actual user_team_keys INSERT requires the client to supply encrypted key
-- material — it cannot be done server-side.  On the user's next login, the client
-- reads pending key_wrapped=0 grants and completes the wrapping.  Until then, the
-- user has the role assignment (user_roles row) but cannot decrypt team content.

-------------------------------------------------
-- POLICY EFFECTS
-- One row per grant an admin configures on a policy.
--
-- effect_type = 'team_member'
--   target_id  = team_id
--   role_level = roles.id (e.g. 'team_member', 'team_manager', 'team_admin')
--   Writes:    user_roles (scope_type='team', scope_id=team_id, role_id=role_level)
--              policy_team_grants (key_wrapped=0 until E4 client wrapping)
--
-- effect_type = 'folder_acl'
--   target_id  = folder_id
--   permission = 'read' | 'write' | 'admin'
--   recursive  = 1 (default) → inherits to subfolders; 0 → exact folder only
--   Writes:    permissions (resource_type='folder', resource_id=target_id)
--              policy_folder_grants (acl_written, key_wrapped)
--              key_wrapped=0 if folder is in a team subtree and user lacks the key
-------------------------------------------------
CREATE TABLE policy_effects (
    id          TEXT    NOT NULL PRIMARY KEY,
    policy_id   TEXT    NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    effect_type TEXT    NOT NULL CHECK(effect_type IN ('team_member', 'folder_acl')),
    target_id   TEXT    NOT NULL,
    role_level  TEXT    REFERENCES roles(id) ON DELETE RESTRICT,  -- team_member only; NULL for folder_acl
    permission  TEXT    CHECK(permission IS NULL OR permission IN ('read', 'write', 'admin')),  -- folder_acl only
    recursive   INTEGER NOT NULL DEFAULT 1,                       -- folder_acl only (ignored for team_member)
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX idx_policy_effects_policy ON policy_effects(policy_id);
CREATE INDEX idx_policy_effects_target ON policy_effects(effect_type, target_id);

-------------------------------------------------
-- POLICY TEAM GRANTS
-- Materialised per-user tracking for team_member effects.
-- key_wrapped=0 → user_team_keys row not yet written; pending E4 client wrapping
-- key_wrapped=1 → user already has the team key (manual or policy-sourced)
-------------------------------------------------
CREATE TABLE policy_team_grants (
    id          TEXT    NOT NULL PRIMARY KEY,
    effect_id   TEXT    NOT NULL REFERENCES policy_effects(id) ON DELETE CASCADE,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_wrapped INTEGER NOT NULL DEFAULT 0,
    granted_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(effect_id, user_id)
);

CREATE INDEX idx_policy_team_grants_user   ON policy_team_grants(user_id);
CREATE INDEX idx_policy_team_grants_effect ON policy_team_grants(effect_id);

-------------------------------------------------
-- POLICY FOLDER GRANTS (replaces migration 012 version)
-- acl_written=1 → permissions row was written by this effect
-- acl_written=0 → manual row already existed; INSERT OR IGNORE was skipped
-- key_wrapped=0 → user_team_keys row not yet written (folder in team subtree)
-- key_wrapped=1 → user has team key, or folder not in any team subtree
-------------------------------------------------
DROP TABLE IF EXISTS policy_folder_grants;

CREATE TABLE policy_folder_grants (
    id          TEXT    NOT NULL PRIMARY KEY,
    effect_id   TEXT    NOT NULL REFERENCES policy_effects(id) ON DELETE CASCADE,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id   TEXT    NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    acl_written INTEGER NOT NULL DEFAULT 0,
    key_wrapped INTEGER NOT NULL DEFAULT 0,
    granted_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(effect_id, user_id, folder_id)
);

CREATE INDEX idx_policy_folder_grants_user   ON policy_folder_grants(user_id);
CREATE INDEX idx_policy_folder_grants_folder ON policy_folder_grants(folder_id);
CREATE INDEX idx_policy_folder_grants_effect ON policy_folder_grants(effect_id);

-------------------------------------------------
-- EXTEND user_roles
-- policy_effect_id: NULL = manually granted; NOT NULL = policy-sourced
-- ON DELETE CASCADE removes associated user_roles rows when the effect is deleted.
-------------------------------------------------
ALTER TABLE user_roles ADD COLUMN policy_effect_id TEXT
    REFERENCES policy_effects(id) ON DELETE CASCADE;

CREATE INDEX idx_user_roles_policy_effect ON user_roles(policy_effect_id);

-------------------------------------------------
-- EXTEND user_team_keys
-- policy_effect_id: NULL = manually granted; NOT NULL = policy-sourced
-------------------------------------------------
ALTER TABLE user_team_keys ADD COLUMN policy_effect_id TEXT
    REFERENCES policy_effects(id) ON DELETE CASCADE;

CREATE INDEX idx_user_team_keys_policy_effect ON user_team_keys(policy_effect_id);

-------------------------------------------------
-- RECREATE permissions
-- Changes from migration 002:
--   • granted_by: NOT NULL → nullable (NULL for policy-sourced rows)
--   • New column: policy_effect_id (nullable FK with cascade delete)
-- The UNIQUE constraint on (resource_type, resource_id, user_id) is preserved.
-- The permissions table has no FK references from other tables, so this is safe.
-------------------------------------------------
CREATE TABLE permissions_new (
    id               TEXT    NOT NULL PRIMARY KEY,
    resource_type    TEXT    NOT NULL CHECK(resource_type IN ('file', 'folder')),
    resource_id      TEXT    NOT NULL,
    user_id          TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission       TEXT    NOT NULL CHECK(permission IN ('read', 'write', 'admin')),
    recursive        INTEGER NOT NULL DEFAULT 0,
    granted_by       TEXT    REFERENCES users(id) ON DELETE SET NULL,  -- NULL for policy-sourced rows
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    policy_effect_id TEXT    REFERENCES policy_effects(id) ON DELETE CASCADE
);

INSERT INTO permissions_new
    SELECT id, resource_type, resource_id, user_id, permission, recursive, granted_by,
           COALESCE(created_at, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')), NULL
    FROM permissions;

DROP TABLE permissions;
ALTER TABLE permissions_new RENAME TO permissions;

CREATE INDEX idx_perm_resource             ON permissions(resource_type, resource_id);
CREATE INDEX idx_perm_user                 ON permissions(user_id);
CREATE UNIQUE INDEX idx_perm_unique        ON permissions(resource_type, resource_id, user_id);
CREATE INDEX idx_permissions_policy_effect ON permissions(policy_effect_id);
