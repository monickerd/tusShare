-- 006_sharing_v2.sql — Fix short_links schema: add created_by

ALTER TABLE short_links ADD COLUMN created_by TEXT REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX idx_shortlinks_creator ON short_links(created_by);
