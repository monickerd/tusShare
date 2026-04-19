-- 012_f5_av_scanning.sql — Phase F5: Virus scanning + download UX overhaul
--
-- Adds:
--   • av_scan_status, av_scanned_at on files (server-side AV verdict tracking)
--   • escrow_ephemeral_pk, escrow_encrypted_key, escrow_key_iv on files
--     (client-encrypted copies of the file key for server-side decryption via
--     ECDH/P-256 escrow key pair when TUSSHARE_ESCROW_PRIVATE_KEY is configured)
--   • admin_settings rows for AV configuration

-------------------------------------------------
-- AV scan status columns
-------------------------------------------------
ALTER TABLE files ADD COLUMN av_scan_status TEXT;
ALTER TABLE files ADD COLUMN av_scanned_at  TEXT;

-------------------------------------------------
-- Escrow-encrypted file key fields
-- Populated by the client only when the server has TUSSHARE_ESCROW_PRIVATE_KEY set.
-- escrow_ephemeral_pk: SPKI-encoded ephemeral P-256 public key (base64) generated
--   by the client for this file's ECDH exchange.
-- escrow_encrypted_key: AES-GCM ciphertext of the raw file key (base64).
-- escrow_key_iv: AES-GCM IV used to encrypt the file key (base64).
-------------------------------------------------
ALTER TABLE files ADD COLUMN escrow_ephemeral_pk   TEXT;
ALTER TABLE files ADD COLUMN escrow_encrypted_key  TEXT;
ALTER TABLE files ADD COLUMN escrow_key_iv         TEXT;

-------------------------------------------------
-- Admin settings for AV
-------------------------------------------------
INSERT INTO admin_settings (key, value) VALUES
    ('av_scan_endpoint',      ''),
    ('av_scan_secret',        ''),
    ('av_require_clean',      'false'),
    ('av_scan_retry_attempts','3')
ON CONFLICT (key) DO NOTHING;
