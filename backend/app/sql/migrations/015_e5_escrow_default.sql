-- 015_e5_escrow_default.sql — E5: org-level escrow defaults + folder-level policy overrides
--
-- Changes:
--   • admin_settings: add is_locked + locked_min_tier columns (shared with sharing rules)
--   • folder_escrow_policies: folder-level escrow policy overrides
--   • folder_escrow_policy_agents: agents (user or role) for each policy
--   • role_permission_flags: can_manage_escrow flag
--   • Grant can_manage_escrow to server_admin and org_admin
--   • Seed org-level escrow admin_settings rows (default user/role IDs + require_coverage)

-- ---------------------------------------------------------------------------
-- admin_settings: lock mechanism (shared by E5 + sharing restrictions)
-- ---------------------------------------------------------------------------
ALTER TABLE admin_settings
    ADD COLUMN IF NOT EXISTS is_locked       BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS locked_min_tier INTEGER;

-- ---------------------------------------------------------------------------
-- Folder-level escrow policy overrides
-- ---------------------------------------------------------------------------
CREATE TABLE folder_escrow_policies (
    id                TEXT    PRIMARY KEY DEFAULT gen_random_uuid()::text,
    folder_id         TEXT    NOT NULL UNIQUE REFERENCES folders(id) ON DELETE CASCADE,
    override_mode     TEXT    NOT NULL DEFAULT 'replace'
        CHECK (override_mode IN ('replace', 'merge', 'none')),
    policy_locked     BOOLEAN NOT NULL DEFAULT FALSE,
    locked_min_tier   INTEGER,
    overrides_allowed BOOLEAN NOT NULL DEFAULT TRUE,
    created_by        TEXT    NOT NULL REFERENCES users(id),
    created_by_tier   INTEGER NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fep_folder ON folder_escrow_policies(folder_id);

CREATE TABLE folder_escrow_policy_agents (
    id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    policy_id     TEXT NOT NULL REFERENCES folder_escrow_policies(id) ON DELETE CASCADE,
    agent_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    agent_role_id TEXT REFERENCES roles(id) ON DELETE CASCADE,
    CHECK (
        (agent_user_id IS NOT NULL AND agent_role_id IS NULL)
        OR  (agent_user_id IS NULL  AND agent_role_id IS NOT NULL)
    )
);

CREATE INDEX idx_fepa_policy ON folder_escrow_policy_agents(policy_id);

-- ---------------------------------------------------------------------------
-- New permission flag: can_manage_escrow
-- ---------------------------------------------------------------------------
INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES
    ('can_manage_escrow', 'Manage org-level escrow defaults and folder-level escrow policies', 'security', 1)
ON CONFLICT (flag) DO NOTHING;

-- Grant to server_admin (tier 1) and org_admin (tier 2)
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('server_admin', 'can_manage_escrow', '1'),
    ('org_admin',    'can_manage_escrow', '1')
ON CONFLICT (role_id, flag) DO UPDATE SET value = EXCLUDED.value;

-- ---------------------------------------------------------------------------
-- Org-level escrow admin_settings seeds
-- ---------------------------------------------------------------------------
INSERT INTO admin_settings (key, value) VALUES
    ('escrow_default_user_ids',  '[]')   ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES
    ('escrow_default_role_ids',  '["escrow_agent"]') ON CONFLICT (key) DO NOTHING;
INSERT INTO admin_settings (key, value) VALUES
    ('escrow_require_coverage',  '0')    ON CONFLICT (key) DO NOTHING;
