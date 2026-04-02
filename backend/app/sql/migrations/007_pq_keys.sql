-- 007_pq_keys.sql — Per-user hybrid asymmetric keys for PQ-KEM sharing.
--
-- Adds X25519 + ML-KEM-768 public/private key material to the users table.
-- Also adds KEM fields to share_items for user-type (direct) shares.

ALTER TABLE users ADD COLUMN x25519_public_key       TEXT;
ALTER TABLE users ADD COLUMN mlkem768_public_key      TEXT;
ALTER TABLE users ADD COLUMN x25519_private_wrapped   TEXT;
ALTER TABLE users ADD COLUMN mlkem768_private_wrapped TEXT;
ALTER TABLE users ADD COLUMN asymmetric_key_iv        TEXT;

CREATE INDEX idx_users_has_pq_keys ON users(x25519_public_key) WHERE x25519_public_key IS NOT NULL;

-- KEM fields for user-type share items (NULL for link-type shares)
ALTER TABLE share_items ADD COLUMN ephemeral_x25519_pub TEXT;
ALTER TABLE share_items ADD COLUMN kem_ciphertext       TEXT;
