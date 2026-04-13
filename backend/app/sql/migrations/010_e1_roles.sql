-- 010_e1_roles.sql — Phase E1 prep: modular role/permission framework
--
-- Adds role_permission_flags (flag definitions) and role_permissions (flag
-- values per role) tables.  Removes the legacy 3-tier team roles and inserts
-- the 6-tier default hierarchy.  Seeds all flag defaults per role.
--
-- Migration strategy: new roles added, old ones deleted (clean DB assumed).
-- role_admin is retained as a legacy alias for server_admin during transition.

-------------------------------------------------
-- PERMISSION FLAG DEFINITIONS
-- One row per available flag.
-- is_sensitive=1 flags require extra confirmation in the UI and may only be
-- activated by Server Admin or Org Admin regardless of other permissions.
-------------------------------------------------
CREATE TABLE role_permission_flags (
    flag         TEXT    PRIMARY KEY,
    description  TEXT    NOT NULL DEFAULT '',
    category     TEXT    NOT NULL DEFAULT 'general',
    is_sensitive INTEGER NOT NULL DEFAULT 0
);

-------------------------------------------------
-- PERMISSION FLAG ASSIGNMENTS PER ROLE
-- value is TEXT for future non-binary support (e.g. max durations, counts).
-- Current binary convention: '1' = granted, '0' = denied.
-- When a user holds multiple global roles the max value across roles wins.
-------------------------------------------------
CREATE TABLE role_permissions (
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    flag    TEXT NOT NULL REFERENCES role_permission_flags(flag) ON DELETE CASCADE,
    value   TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (role_id, flag)
);

CREATE INDEX idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_flag ON role_permissions(flag);

-------------------------------------------------
-- REMOVE LEGACY TEAM ROLES
-- Replaced by the 6-tier system below.
-- user_roles rows referencing these cascade-delete automatically.
-------------------------------------------------
DELETE FROM roles WHERE id IN ('team_owner', 'team_supervisor', 'team_member');

-------------------------------------------------
-- 6-TIER DEFAULT ROLE HIERARCHY
-- All seeded as is_system=1 (cannot be deleted, only reconfigured).
-------------------------------------------------
INSERT INTO roles (id, name, description, is_system) VALUES
    ('server_admin',      'Server Admin',      'System settings, disk, logging, integrations; highest authority', 1),
    ('org_admin',         'Org Admin',         'Org-wide roles, teams, and org-level policies',                   1),
    ('operational_admin', 'Operational Admin', 'User and team lifecycle management, invite generation',           1),
    ('team_admin',        'Team Admin',        'Admin authority scoped to a single team',                         1),
    ('team_manager',      'Team Manager',      'Member and folder management within a team',                      1),
    ('team_member',       'Team Member',       'Upload/download and create folders within a team',                1);

-- role_admin predates E1; retained for backward compat during transition to server_admin.
UPDATE roles
SET description = 'Legacy system administrator role — superseded by server_admin (E1)'
WHERE id = 'role_admin';

-------------------------------------------------
-- PERMISSION FLAG DEFINITIONS
-------------------------------------------------
INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES
    ('can_view_admin_panel',        'Access the admin panel',                                             'admin',        0),
    ('can_manage_system_settings',  'Configure server-level settings (disk, logging, startup)',           'admin',        0),
    ('can_manage_org_settings',     'Configure org-level settings (branding, org policies)',              'admin',        0),
    ('can_manage_users',            'Create, update, and delete user accounts',                           'admin',        0),
    ('can_manage_invites',          'Create and revoke platform-level registration invite links',          'admin',        0),
    ('can_manage_teams',            'Create, delete, and configure teams',                                'admin',        0),
    ('can_manage_team_members',     'Invite and remove members within a team',                            'admin',        0),
    ('can_manage_roles',            'Define roles and grant or revoke role assignments',                   'roles',        0),
    ('can_create_roles',            'Create custom roles (permission set capped to creator''s own)',       'roles',        0),
    ('can_create_cross_team_roles', 'Create roles that span multiple teams',                              'roles',        0),
    ('can_view_disk_usage',         'View disk usage statistics',                                         'observability',0),
    ('can_view_audit_log',          'View the server-wide audit trail',                                   'audit',        0),
    ('can_export_audit_log',        'Export the audit trail to CSV or TXT',                               'audit',        0),
    ('can_manage_integrations',     'Configure LDAP, SSO, and external identity providers',               'integrations', 0),
    ('can_manage_policies',         'Define and enforce org- and team-level policies',                    'policy',       0),
    ('can_access_all_files',        'Bypass file ownership checks — grants access to all files on the server', 'files',  1);

-------------------------------------------------
-- DEFAULT FLAG VALUES PER ROLE
-- can_access_all_files is '0' for every role; must be explicitly activated.
-------------------------------------------------

-- server_admin: full access to all flags except can_access_all_files
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
    ('server_admin', 'can_access_all_files',        '0');

-- org_admin: org-wide authority; no system-level or integration settings
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
    ('org_admin', 'can_access_all_files',        '0');

-- operational_admin: user/team lifecycle only; no policy, audit, or observability
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
    ('operational_admin', 'can_access_all_files',        '0');

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
    ('team_admin', 'can_access_all_files',        '0');

-- team_manager: member management only; no admin panel or role creation
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
    ('team_manager', 'can_access_all_files',        '0');

-- role_admin (legacy): same as server_admin for backward compat; can_access_all_files off
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
    ('role_admin', 'can_access_all_files',        '0');

-- team_member and role_user have no flags granted; omitted from role_permissions.
