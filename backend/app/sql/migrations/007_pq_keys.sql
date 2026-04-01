-- 007_pq_keys.sql — Per-user hybrid asymmetric keys for PQ-KEM sharing.
--
-- Adds X25519 + ML-KEM-768 public/private key material to the users table.
-- Public keys are stored plaintext (they are public by design).
-- Private keys are AES-256-GCM wrapped with the user's masterKey — the server
-- never sees raw private key material.
--
-- Also adds KEM fields to share_items for user-type (direct) shares, which
-- carry the per-item ephemeral X25519 public key and ML-KEM-768 ciphertext
-- needed by the recipient to re-derive the file key wrapping key.
--
-- Key sizes (base64-encoded):
--   x25519_public_key       : 32 bytes  → ~44 base64 chars
--   mlkem768_public_key     : 1184 bytes → ~1580 base64 chars
--   x25519_private_wrapped  : 32 + 16 (GCM tag) = 48 bytes → ~64 base64 chars
--   mlkem768_private_wrapped: 2400 + 16 = 2416 bytes → ~3224 base64 chars
--   asymmetric_key_iv       : 12 bytes → 16 base64 chars
--   ephemeral_x25519_pub    : 32 bytes → ~44 base64 chars
--   kem_ciphertext          : 1088 bytes → ~1452 base64 chars

ALTER TABLE users ADD COLUMN x25519_public_key       TEXT;
ALTER TABLE users ADD COLUMN mlkem768_public_key      TEXT;
ALTER TABLE users ADD COLUMN x25519_private_wrapped   TEXT;
ALTER TABLE users ADD COLUMN mlkem768_private_wrapped TEXT;
ALTER TABLE users ADD COLUMN asymmetric_key_iv        TEXT;

CREATE INDEX idx_users_has_pq_keys ON users(x25519_public_key) WHERE x25519_public_key IS NOT NULL;

-- KEM fields for user-type share items (NULL for link-type shares)
ALTER TABLE share_items ADD COLUMN ephemeral_x25519_pub TEXT;
ALTER TABLE share_items ADD COLUMN kem_ciphertext       TEXT;
