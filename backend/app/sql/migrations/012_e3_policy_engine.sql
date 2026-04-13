-- 012_e3_policy_engine.sql — Phase E3: Policy engine
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
--   policy_folder_grants     — materialised grants written by evaluate_user_policies()
--
-- Modified tables:
--   users                    — adds policy_last_evaluated_at (debounce timestamp)
--   role_permission_flags    — adds can_define_policy_fields flag
--   role_permissions         — seeds new flag for server_admin, org_admin

-------------------------------------------------
-- POLICY FIELD DEFINITIONS
-- Registry of valid condition fields.
-- source='internal': fields drawn from local DB (e.g. totp_enabled).
--   Always available; seeded here; not user-registerable.
-- source='ldap':     LDAP attribute mappings. Only available when an LDAP
--   integration is configured. Requires can_define_policy_fields.
-- source='oidc':     OIDC claim mappings. Only available when an OIDC
--   integration is configured. Requires can_define_policy_fields.
-- claim_path: raw LDAP attribute name or OIDC claim key used for resolution.
--   NULL for source='internal'.
-- data_type: 'string' or 'boolean' — governs operator availability in the UI.
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
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Built-in internal fields (source='internal', not user-editable, no claim_path)
INSERT INTO policy_field_definitions (name, display_label, source, data_type, claim_path) VALUES
    ('totp_enabled',      'TOTP MFA Enabled',  'internal', 'boolean', NULL),
    ('auth_provider',     'Auth Provider',     'internal', 'string',  NULL),
    ('identity_provider', 'Identity Provider', 'internal', 'string',  NULL);

-------------------------------------------------
-- ADMIN SCOPE CONDITIONS
-- Defines which universe of users an admin can target with policies.
-- A user's effective scope = AND of all scope conditions inherited from their
-- account (holder_type='user') and all their assigned roles (holder_type='role').
-- Composing multiple conditions makes scope more restrictive.
-------------------------------------------------
CREATE TABLE admin_scope_conditions (
    id          TEXT NOT NULL PRIMARY KEY,
    holder_type TEXT NOT NULL CHECK(holder_type IN ('user', 'role')),
    holder_id   TEXT NOT NULL,   -- user_id or role name
    field       TEXT NOT NULL REFERENCES policy_field_definitions(name) ON DELETE RESTRICT,
    operator    TEXT NOT NULL,
    value       TEXT NOT NULL
);

CREATE INDEX idx_admin_scope_cond_holder ON admin_scope_conditions(holder_type, holder_id);

-------------------------------------------------
-- POLICIES
-- An org-scoped policy has scope_id=NULL; a team-scoped policy has scope_id=<team_id>.
-------------------------------------------------
CREATE TABLE policies (
    id         TEXT NOT NULL PRIMARY KEY,
    name       TEXT NOT NULL,
    scope_type TEXT NOT NULL DEFAULT 'org' CHECK(scope_type IN ('org', 'team')),
    scope_id   TEXT,           -- team_id for team-scoped; NULL for org-scoped
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX idx_policies_scope ON policies(scope_type, scope_id);

-------------------------------------------------
-- POLICY CONDITIONS
-- All conditions on a policy are ANDed together; all must match.
-- inherited_scope_id links a condition to its originating admin_scope_condition.
--   When non-NULL the row is locked (read-only in the UI; backend rejects edits).
-- scope_detached=1 means the originating scope condition was deleted.
--   UI shows a review banner; policy still evaluates the orphaned condition.
-- strict=1 forces case-sensitive matching (default is case-insensitive).
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

-- Trigger: when an admin_scope_condition is deleted, mark affected policy_conditions
-- as scope_detached=1 (the FK already nulls inherited_scope_id via ON DELETE SET NULL).
CREATE TRIGGER trg_policy_scope_detach
    AFTER UPDATE OF inherited_scope_id ON policy_conditions
    FOR EACH ROW
    WHEN OLD.inherited_scope_id IS NOT NULL AND NEW.inherited_scope_id IS NULL
BEGIN
    UPDATE policy_conditions
    SET scope_detached = 1
    WHERE id = NEW.id;
END;

-------------------------------------------------
-- POLICY FOLDER GRANTS
-- Materialised results written by evaluate_user_policies().
-- key_wrapped=0 means the team key has not yet been wrapped for this user;
-- until it is wrapped, the user cannot access the folder even with a grant.
-- Key wrapping is performed on the user's next password-entry event.
-------------------------------------------------
CREATE TABLE policy_folder_grants (
    id          TEXT    NOT NULL PRIMARY KEY,
    policy_id   TEXT    NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id   TEXT    NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    key_wrapped INTEGER NOT NULL DEFAULT 0,
    granted_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(policy_id, user_id, folder_id)
);

CREATE INDEX idx_policy_folder_grants_user    ON policy_folder_grants(user_id);
CREATE INDEX idx_policy_folder_grants_folder  ON policy_folder_grants(folder_id);
CREATE INDEX idx_policy_folder_grants_policy  ON policy_folder_grants(policy_id);

-------------------------------------------------
-- USERS — add evaluation debounce timestamp
-------------------------------------------------
ALTER TABLE users ADD COLUMN policy_last_evaluated_at TEXT;

-------------------------------------------------
-- NEW PERMISSION FLAG: can_define_policy_fields
-- Only high-tier admins can register LDAP/OIDC attribute names in the field
-- registry; lower tiers can only use existing fields when building conditions.
-------------------------------------------------
INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES
    ('can_define_policy_fields',
     'Register new LDAP/OIDC attribute fields for use in policy conditions',
     'policy', 0);

-- Grant to server_admin and org_admin; all others get '0' (default)
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('server_admin', 'can_define_policy_fields', '1'),
    ('org_admin',    'can_define_policy_fields', '1'),
    ('role_admin',   'can_define_policy_fields', '1');  -- legacy compat
