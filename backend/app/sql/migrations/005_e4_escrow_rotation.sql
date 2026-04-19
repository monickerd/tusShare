-- 005_e4_escrow_rotation.sql — Phase E4: Pending key grants, admin escrow, ephemeral links
--
-- Adds:
--   • key_confirmed column on user_team_keys (DLEQ post-rotation confirmation)
--   • team_ephemeral_slots table (E4c — one-time invite links)
--   • escrow_agent built-in role + can_act_as_escrow permission flag (E4b)
--
-- Note: escrow_enabled on policies and escrow_override on policy_effects are
-- already included in 004_e3_policy_engine.sql (unified E3/E4 schema).

-------------------------------------------------
-- EXTEND user_team_keys: key_confirmed column
-- Set to 0 on INSERT (including post-rotation wraps).
-- Set to 1 when the member submits a valid Schnorr PoK via
-- POST /teams/{id}/key-confirmation.
-------------------------------------------------
ALTER TABLE user_team_keys ADD COLUMN key_confirmed INTEGER NOT NULL DEFAULT 0;

CREATE INDEX idx_user_team_keys_unconfirmed
    ON user_team_keys(team_id)
    WHERE key_confirmed = 0;

-------------------------------------------------
-- NEW TABLE: team_ephemeral_slots (E4c)
-- One-time-use invite slots for new members who arrive before any existing
-- team member has fulfilled their pending key grant.
--
-- Link format: https://app/#/join/{team_id}/{slot_id}/{k_ephemeral_b64url}
-- k_ephemeral (256-bit AES key) lives ONLY in the URL fragment — never stored.
-- sk_wrapped = AES-GCM(k_ephemeral, sk_team_bytes)
-------------------------------------------------
CREATE TABLE team_ephemeral_slots (
    id         TEXT NOT NULL PRIMARY KEY,
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    sk_wrapped TEXT NOT NULL,
    sk_iv      TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    expires_at TEXT NOT NULL,
    consumed   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_ephemeral_slots_team ON team_ephemeral_slots(team_id);
CREATE INDEX idx_ephemeral_slots_active
    ON team_ephemeral_slots(expires_at)
    WHERE consumed = 0;

-------------------------------------------------
-- NEW ROLE: escrow_agent (E4b)
-------------------------------------------------
INSERT INTO roles (id, name, description, is_system) VALUES
    ('escrow_agent', 'Escrow Agent',
     'Recovery access to team key material via admin escrow policy', 1);

-------------------------------------------------
-- NEW PERMISSION FLAG: can_act_as_escrow (E4b)
-------------------------------------------------
INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES
    ('can_act_as_escrow', 'User can be added as a key escrow recovery agent', 'security', 1);

INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('escrow_agent', 'can_act_as_escrow', '1');
