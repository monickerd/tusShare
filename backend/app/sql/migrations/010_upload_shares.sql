-- 010_upload_shares.sql — Short-link key storage and upload-enabled folder shares
--
-- short_links.share_key: stores the AES share key server-side so root-level
--   slug URLs (/LimaCharlieTango) can redirect to /s/<token>#<key> without
--   the key appearing in the short link itself. The owner acknowledges this
--   is a deliberate security trade-off for verbally shareable links.
--
-- shares.allow_upload: folder shares may allow the recipient to upload files
--   into the target folder during the share's validity window.
--
-- shares.target_folder_id: the folder into which upload-enabled shares
--   accept incoming files. NULL for file-only shares.

ALTER TABLE short_links ADD COLUMN share_key TEXT;

ALTER TABLE shares ADD COLUMN allow_upload INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shares ADD COLUMN target_folder_id TEXT
    REFERENCES folders(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_shares_target_folder ON shares(target_folder_id);
