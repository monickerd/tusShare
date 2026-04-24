-- 014_t4_oidc_nonce.sql — T4 security review: OIDC nonce binding
--
-- Adds a nonce column to oidc_states so the server can verify the ID token's
-- nonce claim, preventing replay of ID tokens across separate authorization flows.
--
-- The nonce is generated at begin_oidc_flow time, stored here, passed to the IdP
-- in the authorization URL, and validated against the id_token's nonce claim during
-- handle_oidc_callback.  Existing rows (if any) get a NULL nonce and are treated
-- as pre-nonce-era flows; the validation path handles NULL gracefully.

ALTER TABLE oidc_states ADD COLUMN nonce TEXT;
