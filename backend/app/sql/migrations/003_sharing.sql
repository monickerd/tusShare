-- 003_sharing.sql — Share links, short links, and invite short links

-------------------------------------------------
-- SHARES
-------------------------------------------------
CREATE TABLE shares (
    id               TEXT PRIMARY KEY,
    token            TEXT NOT NULL UNIQUE,
    created_by       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_type       TEXT NOT NULL CHECK(share_type IN ('link', 'user', 'short')),
    target_user_id   TEXT REFERENCES users(id) ON DELETE CASCADE,
    expires_at       TIMESTAMPTZ,
    is_active        INTEGER NOT NULL DEFAULT 1,
    password_hash    TEXT,
    max_downloads    INTEGER,
    download_count   INTEGER NOT NULL DEFAULT 0,
    allow_upload     INTEGER NOT NULL DEFAULT 0,
    target_folder_id TEXT REFERENCES folders(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_shares_token         ON shares(token);
CREATE INDEX idx_shares_creator       ON shares(created_by);
CREATE INDEX idx_shares_target        ON shares(target_user_id);
CREATE INDEX idx_shares_expires       ON shares(expires_at);
CREATE INDEX idx_shares_target_folder ON shares(target_folder_id);

-------------------------------------------------
-- SHARE ITEMS (files/folders included in a share)
-- KEM fields support PQ-KEM encrypted direct shares (user-type shares only).
-------------------------------------------------
CREATE TABLE share_items (
    id                  TEXT PRIMARY KEY,
    share_id            TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    resource_type       TEXT NOT NULL CHECK(resource_type IN ('file', 'folder')),
    resource_id         TEXT NOT NULL,
    encrypted_file_key  TEXT,
    key_iv              TEXT,
    ephemeral_x25519_pub TEXT,
    kem_ciphertext      TEXT,
    UNIQUE(share_id, resource_type, resource_id)
);

CREATE INDEX idx_sitems_share ON share_items(share_id);

-------------------------------------------------
-- SHORT LINKS (memorable 3-word slugs for link-type shares)
-- share_key is stored server-side so root-level slugs can redirect to
-- /s/<token>#<key> without exposing the key in the slug itself.
-------------------------------------------------
CREATE TABLE short_links (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    share_id    TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    share_key   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_shortlinks_slug    ON short_links(slug);
CREATE INDEX idx_shortlinks_expires ON short_links(expires_at);
CREATE INDEX idx_shortlinks_creator ON short_links(created_by);

-- invite_short_links is defined in 005_admin.sql alongside the invites table
-- it references (FK CASCADE delete when an invite is used or revoked).
