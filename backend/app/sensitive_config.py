"""Sensitive function configuration — in-memory loader with integrity check.

The sensitive_config PostgreSQL schema is created automatically on first
startup when TUSSHARE_SUPERUSER_URL is set.  After that it is locked:
  - The schema owner role has NOLOGIN — no one can authenticate as it.
  - BEFORE UPDATE/DELETE triggers raise exceptions on any mutation attempt.
  - The app DB role has SELECT only.

At startup, this module:
  1. If the schema is absent and TUSSHARE_SUPERUSER_URL is configured,
     bootstraps the schema automatically (first-run self-setup).
  2. Loads all rows from sensitive_config.sensitive_functions.
  3. Computes a SHA-256 of the sorted rows.
  4. Compares to DATA_DIR/.sensitive_config.hash (written at bootstrap time).
  5. On mismatch, raises RuntimeError and refuses to start.
  6. Stores the config in a frozen module-level dict for O(1) runtime checks.

All runtime callers use is_sensitive() and get_challenge_type() — they never
touch the database.
"""

import asyncpg
import hashlib
import json
import logging
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Module-level frozen state — set once in load(), never mutated after that.
_config: dict[str, dict[str, Any]] = {}
_loaded = False

_HASH_FILENAME = ".sensitive_config.hash"

# ---------------------------------------------------------------------------
# Default sensitive function seeds
# ---------------------------------------------------------------------------

# is_sensitive=True — require step-up authentication
_SENSITIVE_DEFAULTS = [
    ("admin.settings.crypto.*",    "password", "All crypto-related server settings"),
    ("admin.settings.security.*",  "password", "Security policy settings"),
    ("policy.escrow.enable",       "password", "Enable admin key escrow"),
    ("policy.escrow.disable",      "password", "Disable admin key escrow"),
    ("policy.sharing.*",           "password", "Any sharing policy change"),
    ("admin.audit.export",         "password", "Export the audit trail"),
    ("admin.audit.configure",      "password", "Change audit retention or settings"),
    ("admin.user.freeze",          "password", "Freeze a user account"),
    ("admin.user.delete",          "password", "Delete a user account"),
    ("integration.ldap.configure", "password", "Configure LDAP / identity provider"),
]

# is_sensitive=False — common operations (step-up can be enabled later by
# dropping the schema and restarting with an edited seed list)
_NON_SENSITIVE_DEFAULTS = [
    ("admin.invite.create",  "password", "Create a registration invite (routine)"),
    ("team.key.rotate",      "password", "Rotate team encryption keys (routine)"),
]


# ---------------------------------------------------------------------------
# Hash utility
# ---------------------------------------------------------------------------

def _hash_rows(rows: list[dict]) -> str:
    """Deterministic SHA-256 of the config rows (sorted by function_key)."""
    canonical = [
        {
            "function_key": r["function_key"],
            "is_sensitive": bool(r["is_sensitive"]),
            "challenge_type": r["challenge_type"],
        }
        for r in sorted(rows, key=lambda r: r["function_key"])
    ]
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# ---------------------------------------------------------------------------
# First-run bootstrap (runs once when schema is absent)
# ---------------------------------------------------------------------------

async def _bootstrap(superuser_url: str, app_role: str, data_dir: Path) -> None:
    """Create the immutable sensitive_config schema using superuser credentials.

    Called automatically by load() on first startup when the schema is absent.
    Uses a dedicated asyncpg connection (not the app pool) because it requires
    CREATEROLE privileges that the app role deliberately does not have.
    """
    logger.info("sensitive_config schema absent — running first-run bootstrap")

    try:
        conn = await asyncpg.connect(superuser_url)
    except Exception as exc:
        raise RuntimeError(
            f"sensitive_config bootstrap failed: could not connect with "
            f"TUSSHARE_SUPERUSER_URL: {exc}"
        ) from exc

    owner_role = "sensitive_config_owner"

    try:
        # Guard: abort if schema already exists (race condition on concurrent startup)
        exists = await conn.fetchval(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name = 'sensitive_config'"
        )
        if exists:
            logger.info("sensitive_config schema appeared during bootstrap — skipping creation")
            return

        owner_password = secrets.token_urlsafe(64)

        logger.info("Bootstrap: creating role %s", owner_role)
        # CREATE ROLE does not support bind parameters for the PASSWORD clause —
        # PostgreSQL DDL rejects $1 syntax here. owner_password is always
        # secrets.token_urlsafe(64) which produces only [A-Za-z0-9_-] so
        # direct interpolation is safe.
        await conn.execute(
            f"CREATE ROLE {owner_role} WITH LOGIN PASSWORD '{owner_password}'"
        )

        logger.info("Bootstrap: creating schema sensitive_config")
        await conn.execute(f"CREATE SCHEMA sensitive_config AUTHORIZATION {owner_role}")

        logger.info("Bootstrap: creating sensitive_functions table")
        await conn.execute(f"SET ROLE {owner_role}")
        await conn.execute("""
            CREATE TABLE sensitive_config.sensitive_functions (
                function_key   TEXT        PRIMARY KEY,
                is_sensitive   BOOLEAN     NOT NULL DEFAULT FALSE,
                challenge_type TEXT        NOT NULL DEFAULT 'password',
                description    TEXT,
                created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)

        await conn.execute("""
            CREATE OR REPLACE FUNCTION sensitive_config._prevent_mutation()
            RETURNS TRIGGER LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION
                    'sensitive_config is immutable. '
                    'To change it, DROP SCHEMA sensitive_config CASCADE, '
                    'delete DATA_DIR/.sensitive_config.hash, and restart.';
            END;
            $$
        """)
        await conn.execute("""
            CREATE TRIGGER prevent_update
                BEFORE UPDATE ON sensitive_config.sensitive_functions
                FOR EACH ROW EXECUTE FUNCTION sensitive_config._prevent_mutation()
        """)
        await conn.execute("""
            CREATE TRIGGER prevent_delete
                BEFORE DELETE ON sensitive_config.sensitive_functions
                FOR EACH ROW EXECUTE FUNCTION sensitive_config._prevent_mutation()
        """)

        logger.info("Bootstrap: seeding default entries")
        all_rows = []
        for key, challenge, desc in _SENSITIVE_DEFAULTS:
            await conn.execute(
                "INSERT INTO sensitive_config.sensitive_functions "
                "(function_key, is_sensitive, challenge_type, description) "
                "VALUES ($1, TRUE, $2, $3)",
                key, challenge, desc,
            )
            all_rows.append({"function_key": key, "is_sensitive": True, "challenge_type": challenge})

        for key, challenge, desc in _NON_SENSITIVE_DEFAULTS:
            await conn.execute(
                "INSERT INTO sensitive_config.sensitive_functions "
                "(function_key, is_sensitive, challenge_type, description) "
                "VALUES ($1, FALSE, $2, $3)",
                key, challenge, desc,
            )
            all_rows.append({"function_key": key, "is_sensitive": False, "challenge_type": challenge})

        await conn.execute("RESET ROLE")

        logger.info("Bootstrap: granting SELECT on sensitive_config to %s", app_role)
        await conn.execute(f"GRANT USAGE ON SCHEMA sensitive_config TO {app_role}")
        await conn.execute(
            f"GRANT SELECT ON ALL TABLES IN SCHEMA sensitive_config TO {app_role}"
        )

        logger.info("Bootstrap: locking %s (NOLOGIN)", owner_role)
        await conn.execute(f"ALTER ROLE {owner_role} NOLOGIN")

        config_hash = _hash_rows(all_rows)
        hash_path = data_dir / _HASH_FILENAME
        data_dir.mkdir(parents=True, exist_ok=True)
        hash_path.write_text(config_hash)

        logger.info(
            "Bootstrap complete. sensitive_config schema sealed. Hash: %s", config_hash
        )

    except Exception as exc:
        # Best-effort rollback on failure
        try:
            await conn.execute("RESET ROLE")
            await conn.execute("DROP SCHEMA IF EXISTS sensitive_config CASCADE")
            await conn.execute("DROP ROLE IF EXISTS sensitive_config_owner")
        except Exception:
            pass
        raise RuntimeError(f"sensitive_config bootstrap failed: {exc}") from exc
    finally:
        await conn.close()


# ---------------------------------------------------------------------------
# Startup loader
# ---------------------------------------------------------------------------

async def load(db, data_dir: Path, superuser_url: str = "") -> None:
    """Load sensitive config from DB, verify integrity, freeze into memory.

    On first startup (schema absent):
      - If superuser_url is provided: bootstraps the schema automatically.
      - Otherwise: raises RuntimeError with instructions.

    On subsequent startups:
      - Loads rows, verifies SHA-256 against DATA_DIR/.sensitive_config.hash.
      - Raises RuntimeError on hash mismatch (possible tampering).
    """
    global _config, _loaded

    cursor = await db.execute(
        "SELECT schema_name FROM information_schema.schemata "
        "WHERE schema_name = 'sensitive_config'"
    )
    schema_exists = await cursor.fetchone() is not None

    if not schema_exists:
        if not superuser_url:
            raise RuntimeError(
                "sensitive_config schema not found and TUSSHARE_SUPERUSER_URL is not set. "
                "Set TUSSHARE_SUPERUSER_URL to a PostgreSQL superuser connection string "
                "and restart — the schema will be created automatically on first run."
            )
        parsed = urlparse(superuser_url)
        app_parsed = urlparse(db.dsn if hasattr(db, "dsn") else "")
        # Derive app role from the live connection if possible, else fall back
        # to parsing it from the app DATABASE_URL setting.
        from app.config import settings
        app_role = urlparse(settings.DATABASE_URL).username or "tusshare"
        await _bootstrap(superuser_url, app_role, data_dir)

    # Load all rows
    cursor = await db.execute(
        "SELECT function_key, is_sensitive, challenge_type "
        "FROM sensitive_config.sensitive_functions "
        "ORDER BY function_key"
    )
    rows = [dict(row) for row in await cursor.fetchall()]

    # Verify against the hash file written at bootstrap time
    hash_path = data_dir / _HASH_FILENAME
    if not hash_path.exists():
        raise RuntimeError(
            f"Sensitive config hash file not found at {hash_path}. "
            "If the schema was created outside of the auto-bootstrap, "
            "re-run the bootstrap by dropping the schema and restarting."
        )

    stored_hash = hash_path.read_text().strip()
    computed_hash = _hash_rows(rows)

    if computed_hash != stored_hash:
        logger.critical(
            "SENSITIVE CONFIG INTEGRITY CHECK FAILED — possible tampering. "
            "Stored hash: %s  Computed: %s",
            stored_hash, computed_hash,
        )
        raise RuntimeError(
            "Sensitive config integrity check FAILED — "
            "sensitive_config.sensitive_functions does not match the stored hash. "
            "If this change was intentional, DROP SCHEMA sensitive_config CASCADE, "
            "delete DATA_DIR/.sensitive_config.hash, and restart."
        )

    _config = {
        row["function_key"]: {
            "is_sensitive": bool(row["is_sensitive"]),
            "challenge_type": row["challenge_type"],
        }
        for row in rows
    }
    _loaded = True

    sensitive_count = sum(1 for v in _config.values() if v["is_sensitive"])
    logger.info(
        "Sensitive config loaded: %d entries (%d sensitive, %d not sensitive)",
        len(_config),
        sensitive_count,
        len(_config) - sensitive_count,
    )


# ---------------------------------------------------------------------------
# Runtime accessors
# ---------------------------------------------------------------------------

def is_sensitive(function_key: str) -> bool:
    """Return True if the function key is marked sensitive.

    Supports wildcard suffix matching via dot notation:
      'admin.settings.*' matches 'admin.settings.crypto.update',
      'admin.settings.security.toggle', etc.

    Resolution order: exact match, then most-specific wildcard, then less
    specific, then default (False = not sensitive).
    """
    if not _loaded:
        raise RuntimeError("sensitive_config.load() has not been called")

    entry = _config.get(function_key)
    if entry is not None:
        return entry["is_sensitive"]

    parts = function_key.split(".")
    for i in range(len(parts) - 1, 0, -1):
        wildcard = ".".join(parts[:i]) + ".*"
        entry = _config.get(wildcard)
        if entry is not None:
            return entry["is_sensitive"]

    return False


def get_challenge_type(function_key: str) -> str:
    """Return the challenge type for a function key.

    Falls back to 'password' if the key is not found.
    """
    if not _loaded:
        raise RuntimeError("sensitive_config.load() has not been called")

    entry = _config.get(function_key)
    if entry is not None:
        return entry["challenge_type"]

    parts = function_key.split(".")
    for i in range(len(parts) - 1, 0, -1):
        wildcard = ".".join(parts[:i]) + ".*"
        entry = _config.get(wildcard)
        if entry is not None:
            return entry["challenge_type"]

    return "password"
