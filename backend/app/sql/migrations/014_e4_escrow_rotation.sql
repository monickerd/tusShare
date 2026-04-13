-- 014_e4_escrow_rotation.sql — E4: Pending key grants, admin escrow, ephemeral invite links
--
-- Activates the client-side infrastructure prepared in E4 prerequisites by adding:
--   • escrow_enabled column on policies (E4b)
--   • escrow_override column on policy_effects + extend effect_type CHECK (E4b)
--   • key_confirmed column on user_team_keys (DLEQ post-rotation confirmation)
--   • team_ephemeral_slots table (E4c — one-time invite links)
--   • escrow_agent built-in role + can_act_as_escrow permission flag (E4b)
--
-- After this migration, all E4 verification and endpoint logic is unblocked.

-------------------------------------------------
-- EXTEND policies: escrow_enabled flag
-- When set to 1 on a policy, covered teams gain key escrow slots for all
-- users holding the escrow_agent role.
-------------------------------------------------
ALTER TABLE policies ADD COLUMN escrow_enabled INTEGER NOT NULL DEFAULT 0;

-------------------------------------------------
-- EXTEND policy_effects: escrow_override per team
-- escrow_override is only meaningful on effect_type='team_escrow' rows.
--   NULL  — use the policy-level escrow_enabled default
--   1     — force escrow ON for this specific team
--   0     — force escrow OFF for this specific team
-------------------------------------------------
ALTER TABLE policy_effects ADD COLUMN escrow_override INTEGER;

-- Extend the effect_type CHECK constraint to include 'team_escrow'.
-- PostgreSQL lets us drop and re-add named constraints in-place.
ALTER TABLE policy_effects DROP CONSTRAINT IF EXISTS policy_effects_effect_type_check;
ALTER TABLE policy_effects ADD CONSTRAINT policy_effects_effect_type_check
    CHECK(effect_type IN ('team_member', 'folder_acl', 'team_escrow'));

-------------------------------------------------
-- EXTEND user_team_keys: key_confirmed column
-- Set to 0 on INSERT (including post-rotation wraps).
-- Set to 1 when the member submits a valid Schnorr PoK via
-- POST /teams/{id}/key-confirmation, proving they can decrypt their slot.
-------------------------------------------------
ALTER TABLE user_team_keys ADD COLUMN key_confirmed INTEGER NOT NULL DEFAULT 0;

-- Partial index to find unconfirmed slots efficiently.
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
--
-- Security notes (shown in admin UI):
--   • Link contains key material in URL fragment (browser history risk).
--   • Slot DoS: an interceptor who burns the slot first wins; user gets "consumed".
--   • Joining via ephemeral slot triggers immediate key rotation so k_ephemeral
--     is rendered useless even if captured after join.
-------------------------------------------------
CREATE TABLE team_ephemeral_slots (
    id          TEXT NOT NULL PRIMARY KEY,
    team_id     TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    sk_wrapped  TEXT NOT NULL,
    sk_iv       TEXT NOT NULL,
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at  TEXT NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_ephemeral_slots_team ON team_ephemeral_slots(team_id);
CREATE INDEX idx_ephemeral_slots_active
    ON team_ephemeral_slots(expires_at)
    WHERE consumed = 0;

-------------------------------------------------
-- NEW ROLE: escrow_agent (E4b)
-- Built-in org-level role for designated recovery/escrow accounts.
-- is_system=1 means it cannot be deleted from the UI.
-- Escrow agents receive wrapped copies of sk_team for all escrow-enabled teams.
-------------------------------------------------
INSERT INTO roles (id, name, description, is_system) VALUES
    ('escrow_agent', 'Escrow Agent',
     'Recovery access to team key material via admin escrow policy', 1);

-------------------------------------------------
-- NEW PERMISSION FLAG: can_act_as_escrow (E4b)
-- Required to be added as a team escrow key recipient.
-- is_sensitive=1: requires extra confirmation in the admin UI.
-------------------------------------------------
INSERT INTO role_permission_flags (flag, description, category, is_sensitive) VALUES
    ('can_act_as_escrow', 'User can be added as a key escrow recovery agent', 'security', 1);

-- Grant flag to escrow_agent role by default
INSERT INTO role_permissions (role_id, flag, value) VALUES
    ('escrow_agent', 'can_act_as_escrow', '1');
