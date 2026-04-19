-- 004_e3_policy_engine.sql — Phase E3: Attribute-based policy engine
--
-- Introduces a flexible attribute-based policy engine that gates folder
-- membership and team access based on user attributes (internal DB fields
-- or external IdP claims via LDAP/OIDC).
--
-- New tables:
--   policy_field_definitions — registry of valid condition fields
--   admin_scope_conditions   — restricts the universe of users an admin can target
--   policies                 — policy records (org- or team-scoped)
--   policy_conditions        — conditions that must all match for a policy to apply
--   policy_effects           — defines what a matching policy grants
--   policy_team_grants       — per-user tracking for team_member effects
--   policy_folder_grants     — materialised grants written by evaluate_user_policies()
--
-- Modified tables:
--   users        — adds policy_last_evaluated_at
--   user_roles   — adds policy_effect_id
--   user_team_keys — adds policy_effect_id
--   permissions  — recreated to add policy_effect_id and make granted_by nullable

-------------------------------------------------
-- POLICY FIELD DEFINITIONS
-- source='internal': fields drawn from local DB (always available; seeded here).
-- source='ldap'/'oidc': requires can_define_policy_fields permission.
-- data_type: 'string' or 'boolean'.
-------------------------------------------------
CREATE TABLE policy_field_definitions (
    name          TEXT    PRIMARY KEY,
    display_label TEXT    NOT NULL,
    source        TEXT    NOT NULL DEFAULT 'ldap'
                          CHECK(source IN ('internal', 'ldap', 'oidc')),
    data_type     TEXT    NOT NULL DEFAULT 'string'
                          CHECK(data_type IN ('string', 'boolean')),
    claim_path    TEXT,
    created_by    TEXT    REFERENCES users(id) ON DELETE SET NULL,
    created_at    TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

INSERT INTO policy_field_definitions (name, display_label, source, data_type, claim_path) VALUES
    ('totp_enabled',      'TOTP MFA Enabled',  'internal', 'boolean', NULL),
    ('auth_provider',     'Auth Provider',     'internal', 'string',  NULL),
    ('identity_provider', 'Identity Provider', 'internal', 'string',  NULL);

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
-- strict=1 forces case-sensitive matching.
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

-- Trigger: when an admin_scope_condition is deleted (ON DELETE SET NULL nulls
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
    permission      TEXT    CHECK(permission IS NULL OR permission IN ('read', 'write', 'admin')),
    recursive       INTEGER NOT NULL DEFAULT 1,
    escrow_override INTEGER,
    created_at      TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX idx_policy_effects_policy ON policy_effects(policy_id);
CREATE INDEX idx_policy_effects_target ON policy_effects(effect_type, target_id);

-------------------------------------------------
-- POLICY TEAM GRANTS
-- Materialised per-user tracking for team_member effects.
-- key_wrapped=0 → user_team_keys row not yet written; pending E4 client wrapping.
-------------------------------------------------
CREATE TABLE policy_team_grants (
    id         TEXT    NOT NULL PRIMARY KEY,
    effect_id  TEXT    NOT NULL REFERENCES policy_effects(id) ON DELETE CASCADE,
    user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_wrapped INTEGER NOT NULL DEFAULT 0,
    granted_at TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
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
-- USERS — policy evaluation debounce timestamp
-------------------------------------------------
ALTER TABLE users ADD COLUMN policy_last_evaluated_at TEXT;

-------------------------------------------------
-- NEW PERMISSION FLAG: can_define_policy_fields
-------------------------------------------------
INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES
    ('can_define_policy_fields',
     'Register new LDAP/OIDC attribute fields for use in policy conditions',
     'policy', 0);

INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('server_admin', 'can_define_policy_fields', '1'),
    ('org_admin',    'can_define_policy_fields', '1'),
    ('role_admin',   'can_define_policy_fields', '1');

-------------------------------------------------
-- EXTEND user_roles
-- policy_effect_id: NULL = manually granted; NOT NULL = policy-sourced.
-------------------------------------------------
ALTER TABLE user_roles ADD COLUMN policy_effect_id TEXT
    REFERENCES policy_effects(id) ON DELETE CASCADE;

CREATE INDEX idx_user_roles_policy_effect ON user_roles(policy_effect_id);

-------------------------------------------------
-- EXTEND user_team_keys
-- policy_effect_id: NULL = manually granted; NOT NULL = policy-sourced.
-------------------------------------------------
ALTER TABLE user_team_keys ADD COLUMN policy_effect_id TEXT
    REFERENCES policy_effects(id) ON DELETE CASCADE;

CREATE INDEX idx_user_team_keys_policy_effect ON user_team_keys(policy_effect_id);

-------------------------------------------------
-- RECREATE permissions
-- Changes from 001_core_schema:
--   • granted_by: NOT NULL → nullable (NULL for policy-sourced rows)
--   • New column: policy_effect_id (nullable FK with cascade delete)
-- No FK references from other tables, so the rename is safe.
-------------------------------------------------
CREATE TABLE permissions_new (
    id               TEXT    NOT NULL PRIMARY KEY,
    resource_type    TEXT    NOT NULL CHECK(resource_type IN ('file', 'folder')),
    resource_id      TEXT    NOT NULL,
    user_id          TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission       TEXT    NOT NULL CHECK(permission IN ('read', 'write', 'admin')),
    recursive        INTEGER NOT NULL DEFAULT 0,
    granted_by       TEXT    REFERENCES users(id) ON DELETE SET NULL,
    created_at       TEXT    NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    policy_effect_id TEXT    REFERENCES policy_effects(id) ON DELETE CASCADE
);

INSERT INTO permissions_new
    SELECT id, resource_type, resource_id, user_id, permission, recursive, granted_by,
           COALESCE(created_at::text, to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')), NULL
    FROM permissions;

DROP TABLE permissions;
ALTER TABLE permissions_new RENAME TO permissions;

CREATE INDEX idx_perm_resource             ON permissions(resource_type, resource_id);
CREATE INDEX idx_perm_user                 ON permissions(user_id);
CREATE UNIQUE INDEX idx_perm_unique        ON permissions(resource_type, resource_id, user_id);
CREATE INDEX idx_permissions_policy_effect ON permissions(policy_effect_id);
