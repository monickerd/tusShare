-- 006_e6_identity_providers.sql — Phase E6: LDAP / OIDC identity providers
--
-- Adds:
--   identity_providers       — one row per configured LDAP or OIDC integration
--   identity_provider_users  — maps internal users to their external IdP identity
--   oidc_states              — short-lived OAuth state nonces (10-min TTL)
--   users.identity_provider_id   — denormalised FK for O(1) MFA-exempt lookup
--   users.oidc_claims_cache      — JSON blob of last-login OIDC claims
--   users.oidc_refresh_token_enc — AES-GCM encrypted refresh token (live_refetch mode)
--
-- Security notes:
--   config_enc stores the entire provider config (including secrets such as
--   bind_password and client_secret) as a single AES-256-GCM ciphertext blob
--   so credentials are never visible in plaintext DB dumps.  The key is derived
--   from TUSSHARE_IDP_ENCRYPTION_KEY or via HKDF from TUSSHARE_JWT_SECRET.
--
--   oidc_refresh_token_enc uses the same encryption envelope.
--   claim_path was added to policy_field_definitions in 004_e3_policy_engine.sql.

-------------------------------------------------
-- IDENTITY PROVIDERS
--   provider_type : 'ldap' or 'oidc'
--   claim_mode    : OIDC only — 'at_login' (cached) or 'live_refetch' (always current)
--                   NULL for LDAP (always live; no caching concept)
--   config_enc    : AES-GCM encrypted JSON blob (shape varies by provider_type)
--                   LDAP: { server_uri, bind_dn, bind_password, base_dn,
--                           user_filter, tls, username_attr }
--                   OIDC: { issuer_url, client_id, client_secret, scopes, redirect_uri }
-------------------------------------------------
CREATE TABLE identity_providers (
    id            TEXT    PRIMARY KEY,
    provider_type TEXT    NOT NULL CHECK(provider_type IN ('ldap', 'oidc')),
    name          TEXT    NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    claim_mode    TEXT    CHECK(claim_mode IN ('at_login', 'live_refetch')),
    config_enc    TEXT    NOT NULL,
    created_at    BIGINT  NOT NULL,
    updated_at    BIGINT  NOT NULL
);

CREATE UNIQUE INDEX idx_idp_name ON identity_providers(name);
CREATE INDEX idx_idp_active ON identity_providers(is_active);

-------------------------------------------------
-- IDENTITY PROVIDER USERS
-- Maps a tusShare user to their external identity at a given provider.
-- external_id: OIDC sub claim, or the value of username_attr for LDAP.
-- A user can exist in at most one provider (UNIQUE on user_id alone via
-- the users.identity_provider_id FK, but the junction table keeps the
-- external_id for identity resolution when the username changes).
-------------------------------------------------
CREATE TABLE identity_provider_users (
    id          TEXT NOT NULL PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    UNIQUE (provider_id, user_id),
    UNIQUE (provider_id, external_id)
);

CREATE INDEX idx_idp_users_user     ON identity_provider_users(user_id);
CREATE INDEX idx_idp_users_provider ON identity_provider_users(provider_id);

-------------------------------------------------
-- OIDC STATE NONCES
-- One row per in-flight OIDC authorization request.
-- id        = the state parameter (cryptographically random, 32 bytes URL-safe)
-- redirect_to = optional app path to send the user after successful auth
-- Rows are deleted on use; background sweep removes any that expire unused.
-------------------------------------------------
CREATE TABLE oidc_states (
    id          TEXT    PRIMARY KEY,
    provider_id TEXT    NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    redirect_to TEXT,
    created_at  BIGINT  NOT NULL,
    expires_at  BIGINT  NOT NULL
);

CREATE INDEX idx_oidc_states_expires    ON oidc_states(expires_at);
CREATE INDEX idx_oidc_states_provider   ON oidc_states(provider_id);

-------------------------------------------------
-- EXTEND USERS TABLE
-- identity_provider_id : FK to the provider that authenticated this user.
--   NULL = local OPAQUE account.
--   Set once on first IdP login (or provisioning) and never changed.
--   Used for fast O(1) MFA-exemption and policy-field evaluation without
--   joining identity_provider_users on every request.
-- oidc_claims_cache : JSON blob of raw claims from the last OIDC login.
--   Populated in both at_login and live_refetch modes (fallback in live mode).
-- oidc_refresh_token_enc : AES-GCM encrypted OIDC refresh token.
--   Only populated in live_refetch mode; NULL otherwise.
-------------------------------------------------
ALTER TABLE users ADD COLUMN identity_provider_id    TEXT REFERENCES identity_providers(id);
ALTER TABLE users ADD COLUMN oidc_claims_cache       TEXT;
ALTER TABLE users ADD COLUMN oidc_refresh_token_enc  TEXT;

CREATE INDEX idx_users_idp ON users(identity_provider_id)
    WHERE identity_provider_id IS NOT NULL;

-------------------------------------------------
-- Expand auth_method CHECK to include IdP methods
-- The inline CHECK in 001 auto-named itself users_auth_method_check.
-------------------------------------------------
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_auth_method_check;
ALTER TABLE users ADD CONSTRAINT users_auth_method_check
    CHECK(auth_method IN ('opaque', 'ldap', 'oidc'));
