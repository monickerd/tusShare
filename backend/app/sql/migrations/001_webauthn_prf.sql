-- Migration 001: WebAuthn PRF key binding
--
-- Adds four columns to `users` for the optional PRF-bound master-key wrap,
-- one column to `webauthn_challenges` for storing the per-enrollment PRF salt,
-- and extends the purpose CHECK constraint to include 'prf'.
--
-- Safe to run multiple times (all ops use IF NOT EXISTS / DO-NOTHING guards).

-- users: PRF binding columns
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS prf_credential_id         TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS prf_wrapped_master_key    TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS prf_wrapped_master_key_iv TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS prf_salt                  TEXT DEFAULT NULL;

-- webauthn_challenges: PRF salt column
ALTER TABLE webauthn_challenges
    ADD COLUMN IF NOT EXISTS prf_salt TEXT DEFAULT NULL;

-- Extend the purpose CHECK constraint to include 'prf'.
-- PostgreSQL auto-names inline column constraints as <table>_<col>_check.
DO $$ BEGIN
    ALTER TABLE webauthn_challenges
        DROP CONSTRAINT webauthn_challenges_purpose_check;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

ALTER TABLE webauthn_challenges
    ADD CONSTRAINT webauthn_challenges_purpose_check
    CHECK(purpose IN ('registration', 'authentication', 'step_up', 'unlock', 'prf'));
