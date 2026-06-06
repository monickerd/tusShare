-- Migration 002: Metadata encryption — encrypted file and folder names
--
-- Adds two columns to both `files` and `folders`:
--   name_ct  — AES-256-GCM ciphertext of the original name (12-byte nonce
--               prepended, GCM tag appended), base64-encoded.  NULL for rows
--               that have not yet been through the client-side lazy migration.
--   name_idx — HMAC-SHA-256 of the lowercase-trimmed name under the user's
--               per-user search key, hex-encoded.  Allows the server to do an
--               exact-match lookup without seeing the plaintext name.  NULL
--               until the lazy migration runs.
--
-- Key derivation (client-side only; server never touches these keys):
--   name_key    = HKDF-SHA-256(master_key, salt="tusShare-meta-v1", info="filename-enc")
--   search_key  = HKDF-SHA-256(master_key, salt="tusShare-meta-v1", info="filename-search")
--
-- The existing `original_name` / `sanitized_name` (files) and `name` (folders)
-- columns are kept and remain the authoritative plaintext copies used for
-- server-side access control, uniqueness constraints, and ordering.  Once a row
-- has name_ct set, the client uses that for display; the plaintext columns stay
-- in sync for backward compatibility and admin tooling.
--
-- Safe to run multiple times (all ops use IF NOT EXISTS guards).

-- files
ALTER TABLE files
    ADD COLUMN IF NOT EXISTS name_ct  TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS name_idx TEXT DEFAULT NULL;

-- folders
ALTER TABLE folders
    ADD COLUMN IF NOT EXISTS name_ct  TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS name_idx TEXT DEFAULT NULL;

-- Partial index: lets the server quickly find unmigrated rows for a given owner
-- without a full table scan (used by GET /files/unmigrated-names).
CREATE INDEX IF NOT EXISTS idx_files_unmigrated
    ON files(owner_id) WHERE name_ct IS NULL AND upload_complete = 1 AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_folders_unmigrated
    ON folders(owner_id) WHERE name_ct IS NULL AND deleted_at IS NULL;
