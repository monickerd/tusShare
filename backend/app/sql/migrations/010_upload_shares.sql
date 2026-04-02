-- 010_upload_shares.sql — Short-link key storage and upload-enabled folder shares

ALTER TABLE short_links ADD COLUMN share_key TEXT;

ALTER TABLE shares ADD COLUMN allow_upload INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shares ADD COLUMN target_folder_id TEXT
    REFERENCES folders(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_shares_target_folder ON shares(target_folder_id);
