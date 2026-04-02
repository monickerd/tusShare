-- 002_shares.sql — Sharing tables: shares, share_items, short_links

-------------------------------------------------
-- SHARES
-------------------------------------------------
CREATE TABLE shares (
    id              TEXT PRIMARY KEY,
    token           TEXT NOT NULL UNIQUE,
    created_by      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_type      TEXT NOT NULL CHECK(share_type IN ('link', 'user', 'short')),
    target_user_id  TEXT REFERENCES users(id) ON DELETE CASCADE,
    expires_at      TIMESTAMPTZ,
    is_active       INTEGER NOT NULL DEFAULT 1,
    password_hash   TEXT,
    max_downloads   INTEGER,
    download_count  INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_shares_token   ON shares(token);
CREATE INDEX idx_shares_creator ON shares(created_by);
CREATE INDEX idx_shares_target  ON shares(target_user_id);
CREATE INDEX idx_shares_expires ON shares(expires_at);

-------------------------------------------------
-- SHARE ITEMS (M:N between shares and files/folders)
-------------------------------------------------
CREATE TABLE share_items (
    id                  TEXT PRIMARY KEY,
    share_id            TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    resource_type       TEXT NOT NULL CHECK(resource_type IN ('file', 'folder')),
    resource_id         TEXT NOT NULL,
    encrypted_file_key  TEXT,
    key_iv              TEXT,
    UNIQUE(share_id, resource_type, resource_id)
);
CREATE INDEX idx_sitems_share ON share_items(share_id);

-------------------------------------------------
-- SHORT LINKS
-------------------------------------------------
CREATE TABLE short_links (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    share_id    TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_shortlinks_slug    ON short_links(slug);
CREATE INDEX idx_shortlinks_expires ON short_links(expires_at);
