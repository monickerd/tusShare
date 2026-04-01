-- 008_teams.sql — Teams, per-member key distribution, PRE file keys, team folders.
--
-- Key design decisions:
--
--   Layer 1 (fileKey → team): BLS12-381 Proxy Re-Encryption (AFGH scheme, classical only).
--     - Each team has a PRE keypair: sk_team ∈ Zp, pk_team = sk_team * G2.
--     - file_team_keys stores per-file: (C1 = r*G1 ∈ G1, AES-GCM-encrypted fileKey).
--       Encryption: gt = pairing(C1, pk_team); wrapping_key = HKDF(gt_bytes, "tusShare-teamkey-v1")
--       Decryption by member: gt = pairing(sk_team * C1, G2_base); same HKDF → wrapping_key
--     - PRE rotation: C1_new = rk * C1_old where rk = sk_old * inv(sk_new) mod p.
--       Client-side batch in browser (team owner). C2 (encrypted fileKey) unchanged.
--     - PQ note: No production PQ-PRE library exists for BLS12-381. Known limitation.
--       BLS12-381 has ~128-bit classical security (harder to attack than X25519).
--
--   Layer 2 (sk_team → member): Hybrid X25519 + ML-KEM-768 KEM (same as Phase 5b).
--     - user_team_keys stores sk_team AES-GCM encrypted via hybrid KEM per member.
--     - Rotation: team owner re-wraps new sk_team for remaining members.
--
-- Rotation model: hard-only.
--   Member removed → rotation_pending=1 + user_team_keys row deleted.
--   Team owner downloads current sk_team, generates new keypair, applies PRE to all
--   file_team_keys client-side, re-wraps new sk_team for remaining members, POSTs all
--   updated values. Server atomically commits on success.
--
-- Also adds the DB-layer immutable trigger on access_logs (belt-and-suspenders over
-- the application-layer INSERT-only policy already in place).
--
-- BLS12-381 size reference (base64-encoded):
--   G1 compressed point : 48 bytes  →  64 base64 chars
--   G2 compressed point : 96 bytes  → 128 base64 chars
--   Fr scalar (sk_team) : 32 bytes  →  44 base64 chars  (wrapped via KEM, never raw)
--   ML-KEM-768 ciphertext: 1088 bytes → ~1452 base64 chars

-------------------------------------------------
-- TEAMS
-------------------------------------------------
CREATE TABLE teams (
    id               TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    owner_id         TEXT NOT NULL REFERENCES users(id),
    -- BLS12-381 G2 compressed public key (96 bytes → 128 base64 chars)
    pre_public_key   TEXT NOT NULL,
    -- Set to 1 when a member is removed and re-encryption is pending
    rotation_pending INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at       INTEGER NOT NULL DEFAULT (unixepoch()),
    -- Team names are unique per owner (users can have teams with the same
    -- name as another user's team, but not two teams with the same name themselves)
    UNIQUE(owner_id, name)
);

CREATE INDEX idx_teams_owner ON teams(owner_id);

-------------------------------------------------
-- PER-MEMBER WRAPPED TEAM KEY
-- sk_team encrypted for each member via hybrid X25519 + ML-KEM-768 KEM
-- (same pattern as share_items for user-type shares in Phase 5b)
-------------------------------------------------
CREATE TABLE user_team_keys (
    id                   TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    team_id              TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Sender's ephemeral X25519 public key (32 bytes → ~44 base64)
    ephemeral_x25519_pub TEXT NOT NULL,
    -- ML-KEM-768 ciphertext (1088 bytes → ~1452 base64)
    kem_ciphertext       TEXT NOT NULL,
    -- AES-GCM encrypted sk_team bytes (32 + 16 tag = 48 bytes → 64 base64)
    encrypted_sk         TEXT NOT NULL,
    -- AES-GCM IV for encrypted_sk (12 bytes → 16 base64)
    sk_iv                TEXT NOT NULL,
    created_at           INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(team_id, user_id)
);

CREATE INDEX idx_user_team_keys_team ON user_team_keys(team_id);
CREATE INDEX idx_user_team_keys_user ON user_team_keys(user_id);

-------------------------------------------------
-- PER-FILE PRE CIPHERTEXT
-- Allows any team member to decrypt any team file using sk_team.
-- C1 is updated (in-place) on each key rotation without re-downloading the file.
-------------------------------------------------
CREATE TABLE file_team_keys (
    id                 TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    team_id            TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    file_id            TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    -- BLS12-381 G1 compressed point: r * G1 (48 bytes → 64 base64)
    -- Updated on rotation: C1_new = rk * C1_old (scalar multiply in G1)
    pre_c1             TEXT NOT NULL,
    -- AES-GCM encrypted fileKey bytes under H_HKDF(pairing(C1, pk_team))
    -- C2 is NEVER changed on rotation — only C1 changes.
    encrypted_file_key TEXT NOT NULL,
    key_iv             TEXT NOT NULL,
    created_at         INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(team_id, file_id)
);

CREATE INDEX idx_file_team_keys_team ON file_team_keys(team_id);
CREATE INDEX idx_file_team_keys_file ON file_team_keys(file_id);

-------------------------------------------------
-- TEAM FOLDER MEMBERSHIP
-- Designates which folders are accessible to a team.
-------------------------------------------------
CREATE TABLE team_folders (
    id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    team_id    TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    folder_id  TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    added_by   TEXT NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(team_id, folder_id)
);

CREATE INDEX idx_team_folders_team   ON team_folders(team_id);
CREATE INDEX idx_team_folders_folder ON team_folders(folder_id);

-------------------------------------------------
-- TEAM ROLES
-- Stored as scoped user_roles rows: scope_type='team', scope_id=team_id.
-------------------------------------------------
INSERT OR IGNORE INTO roles (id, name, description, is_system) VALUES
    ('team_owner',
     'Team Owner',
     'Full control: manage members, folders, and delete team', 0),
    ('team_supervisor',
     'Team Supervisor',
     'Invite and remove members, manage team folders', 0),
    ('team_member',
     'Team Member',
     'Read/write access to team folders', 0);

-------------------------------------------------
-- IMMUTABLE ACCESS LOGS (DB-layer enforcement)
--
-- Application layer already uses INSERT-only for access_logs.
-- These triggers add a hard DB barrier so no future code path can accidentally
-- (or maliciously) mutate or purge log rows.
--
-------------------------------------------------
CREATE TRIGGER prevent_access_log_update
    BEFORE UPDATE ON access_logs
BEGIN
    SELECT RAISE(ABORT, 'access_logs is append-only');
END;

CREATE TRIGGER prevent_access_log_delete
    BEFORE DELETE ON access_logs
BEGIN
    SELECT RAISE(ABORT, 'access_logs is append-only');
END;
