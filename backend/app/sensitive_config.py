"""Sensitive function configuration — in-memory loader with integrity check.

The sensitive_config PostgreSQL schema is created automatically on first
startup when TUSSHARE_SUPERUSER_URL is set.  After that it is locked:
  - BEFORE UPDATE/DELETE triggers raise exceptions on any mutation attempt.
  - The app DB role has SELECT only.

At startup, this module:
  1. If the schema is absent and TUSSHARE_SUPERUSER_URL is configured,
     bootstraps the schema automatically (first-run self-setup).
  2. Loads all rows from sensitive_config.sensitive_functions and
     sensitive_config.config_values.
  3. Computes a SHA-256 over the combined sorted rows.
  4. Compares to DATA_DIR/.sensitive_config.hash (written at bootstrap time).
  5. On mismatch, raises RuntimeError and refuses to start.
  6. Stores the config in frozen module-level dicts for O(1) runtime access.

Runtime callers use:
  is_sensitive(key)       — step-up auth gate
  get_challenge_type(key) — which verifier to use
  get_config_value(key)   — arbitrary config blobs (e.g. OPAQUE server setup)
"""

import asyncio
import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import asyncpg

logger = logging.getLogger(__name__)

# Module-level frozen state — set once in load(), never mutated after that.
_config: dict[str, dict[str, Any]] = {}
_config_values: dict[str, str] = {}
_loaded = False

_HASH_FILENAME = ".sensitive_config.hash"
_ERR_NOT_LOADED = "sensitive_config.load() has not been called"

# Sensitive config key for the OPAQUE server setup blob (base64-encoded bytes).
OPAQUE_SERVER_SETUP_KEY = "opaque.server_setup"

# ---------------------------------------------------------------------------
# Default sensitive function seeds
# ---------------------------------------------------------------------------

# is_sensitive=True — require step-up authentication
_SENSITIVE_DEFAULTS = [
    ("admin.settings.crypto.*", "password", "All crypto-related server settings"),
    ("admin.settings.security.*", "password", "Security policy settings"),
    ("policy.escrow.enable", "password", "Enable admin key escrow"),
    ("policy.escrow.disable", "password", "Disable admin key escrow"),
    ("policy.sharing.*", "password", "Any sharing policy change"),
    ("admin.audit.export", "password", "Export the audit trail"),
    ("admin.audit.configure", "password", "Change audit retention or settings"),
    ("admin.user.freeze", "password", "Freeze a user account"),
    ("admin.user.delete", "password", "Delete a user account"),
    ("integration.ldap.configure", "password", "Configure LDAP / identity provider"),
    ("admin.storage.configure", "password", "Add, edit, or delete storage volumes and credentials"),
    ("admin.notifications.configure", "password", "Add, edit, or delete notification channels and channel secrets"),
    ("admin.api_keys.manage", "password", "Create or revoke API keys for pull event consumers"),
    ("auth.mfa.admin_remove", "password", "Admin removes MFA credential(s) from a user account"),
    ("auth.mfa.admin_reset", "password", "Admin forces MFA re-enrollment for a user"),
    ("admin.service_accounts.*", "password", "Create, delete, or rotate service account keys"),
    ("user.change_password", "password", "Change own account password (OPAQUE re-registration)"),
]

# is_sensitive=False — common operations (step-up can be enabled later by
# dropping the schema and restarting with an edited seed list)
_NON_SENSITIVE_DEFAULTS = [
    ("admin.invite.create", "password", "Create a registration invite (routine)"),
    ("team.key.rotate", "password", "Rotate team encryption keys (routine)"),
]


# ---------------------------------------------------------------------------
# Hash utility
# ---------------------------------------------------------------------------


def _hash_rows(func_rows: list[dict], value_rows: list[dict]) -> str:
    """Deterministic SHA-256 over both config tables (sorted by key).

    Covers sensitive_functions rows AND config_values rows so that tampering
    with either table (including the OPAQUE server setup) is detected.
    """
    canonical_funcs = [
        {
            "function_key": r["function_key"],
            "is_sensitive": bool(r["is_sensitive"]),
            "challenge_type": r["challenge_type"],
        }
        for r in sorted(func_rows, key=lambda r: r["function_key"])
    ]
    canonical_values = [
        {"config_key": r["config_key"], "config_value": r["config_value"]}
        for r in sorted(value_rows, key=lambda r: r["config_key"])
    ]
    payload = {
        "functions": canonical_funcs,
        "values": canonical_values,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---------------------------------------------------------------------------
# First-run bootstrap (runs once when schema is absent)
# ---------------------------------------------------------------------------


async def _bootstrap(superuser_url: str, app_role: str, data_dir: Path) -> None:
    """Create the immutable sensitive_config schema using superuser credentials.

    Called automatically by load() on first startup when the schema is absent.
    Uses a dedicated asyncpg connection (not the app pool) because the app role
    has SELECT-only on this schema and cannot create it.

    Creates two tables:
      sensitive_functions — step-up auth configuration (function key → sensitivity)
      config_values       — arbitrary config blobs (OPAQUE server setup, etc.)

    Both tables are protected by BEFORE UPDATE/DELETE triggers that block all
    mutations.  A SHA-256 hash of all rows is written to DATA_DIR at bootstrap
    time and verified on every subsequent startup.
    """
    logger.info("sensitive_config schema absent — running first-run bootstrap")

    try:
        conn = await asyncpg.connect(superuser_url)
    except Exception as exc:
        raise RuntimeError(
            f"sensitive_config bootstrap failed: could not connect with TUSSHARE_SUPERUSER_URL: {exc}"
        ) from exc

    try:
        # Guard: abort if schema appeared between the check in load() and now
        exists = await conn.fetchval(
            "SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'sensitive_config'"
        )
        if exists:
            logger.info("sensitive_config schema appeared during bootstrap — skipping creation")
            return

        logger.info("Bootstrap: creating schema sensitive_config")
        await conn.execute("CREATE SCHEMA sensitive_config")

        # --- sensitive_functions table ---
        logger.info("Bootstrap: creating sensitive_functions table")
        await conn.execute("""
            CREATE TABLE sensitive_config.sensitive_functions (
                function_key   TEXT        PRIMARY KEY,
                is_sensitive   BOOLEAN     NOT NULL DEFAULT FALSE,
                challenge_type TEXT        NOT NULL DEFAULT 'password',
                description    TEXT,
                created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)

        # --- config_values table ---
        logger.info("Bootstrap: creating config_values table")
        await conn.execute("""
            CREATE TABLE sensitive_config.config_values (
                config_key    TEXT        PRIMARY KEY,
                config_value  TEXT        NOT NULL,
                description   TEXT,
                created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)

        # --- Immutability trigger (shared by both tables) ---
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
        for table in ("sensitive_functions", "config_values"):
            await conn.execute(f"""
                CREATE TRIGGER prevent_update
                    BEFORE UPDATE ON sensitive_config.{table}
                    FOR EACH ROW EXECUTE FUNCTION sensitive_config._prevent_mutation()
            """)
            await conn.execute(f"""
                CREATE TRIGGER prevent_delete
                    BEFORE DELETE ON sensitive_config.{table}
                    FOR EACH ROW EXECUTE FUNCTION sensitive_config._prevent_mutation()
            """)

        # --- Seed sensitive_functions ---
        logger.info("Bootstrap: seeding sensitive_functions")
        func_rows = []
        for key, challenge, desc in _SENSITIVE_DEFAULTS:
            await conn.execute(
                "INSERT INTO sensitive_config.sensitive_functions "
                "(function_key, is_sensitive, challenge_type, description) "
                "VALUES ($1, TRUE, $2, $3)",
                key,
                challenge,
                desc,
            )
            func_rows.append({"function_key": key, "is_sensitive": True, "challenge_type": challenge})

        for key, challenge, desc in _NON_SENSITIVE_DEFAULTS:
            await conn.execute(
                "INSERT INTO sensitive_config.sensitive_functions "
                "(function_key, is_sensitive, challenge_type, description) "
                "VALUES ($1, FALSE, $2, $3)",
                key,
                challenge,
                desc,
            )
            func_rows.append({"function_key": key, "is_sensitive": False, "challenge_type": challenge})

        # --- Seed config_values: OPAQUE server setup ---
        logger.info("Bootstrap: generating OPAQUE server setup")
        try:
            import tusshare_opaque

            setup_bytes = await asyncio.to_thread(tusshare_opaque.generate_server_setup)
            setup_b64 = base64.b64encode(setup_bytes).decode()
        except ImportError:
            raise RuntimeError(
                "tusshare_opaque module not found — the PyO3 wheel must be "
                "installed before bootstrapping sensitive_config. "
                "Rebuild the Docker image to include the maturin build stage."
            )

        value_rows = []
        await conn.execute(
            "INSERT INTO sensitive_config.config_values (config_key, config_value, description) VALUES ($1, $2, $3)",
            OPAQUE_SERVER_SETUP_KEY,
            setup_b64,
            "OPAQUE aPAKE server setup blob (ServerSetup<TusShareCipherSuite>, base64). "
            "Contains OPRF seed + server keypair. Treat like a CA private key — "
            "if leaked an attacker can run offline dictionary attacks against all "
            "stored registration records.",
        )
        value_rows.append({"config_key": OPAQUE_SERVER_SETUP_KEY, "config_value": setup_b64})
        logger.info("Bootstrap: OPAQUE server setup generated and stored")

        # --- Permissions ---
        logger.info("Bootstrap: granting SELECT on sensitive_config to %s", app_role)
        await conn.execute(f"GRANT USAGE ON SCHEMA sensitive_config TO {app_role}")
        await conn.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA sensitive_config TO {app_role}")
        await conn.execute("REVOKE ALL ON SCHEMA sensitive_config FROM PUBLIC")

        # --- Write integrity hash ---
        config_hash = _hash_rows(func_rows, value_rows)
        hash_path = data_dir / _HASH_FILENAME
        data_dir.mkdir(parents=True, exist_ok=True)
        hash_path.write_text(config_hash)

        logger.info("Bootstrap complete. sensitive_config schema sealed. Hash: %s", config_hash)

    except Exception as exc:
        try:
            await conn.execute("DROP SCHEMA IF EXISTS sensitive_config CASCADE")
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
      - Loads rows from both tables, verifies SHA-256 against
        DATA_DIR/.sensitive_config.hash.
      - Raises RuntimeError on hash mismatch (possible tampering).
    """
    global _config, _config_values, _loaded

    cursor = await db.execute(
        "SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'sensitive_config'"
    )
    schema_exists = await cursor.fetchone() is not None

    if not schema_exists:
        if not superuser_url:
            raise RuntimeError(
                "sensitive_config schema not found and TUSSHARE_SUPERUSER_URL is not set. "
                "Set TUSSHARE_SUPERUSER_URL to a PostgreSQL superuser connection string "
                "and restart — the schema will be created automatically on first run."
            )
        from app.config import settings

        app_role = urlparse(settings.DATABASE_URL).username or "tusshare"
        await _bootstrap(superuser_url, app_role, data_dir)

    # Load sensitive_functions
    cursor = await db.execute(
        "SELECT function_key, is_sensitive, challenge_type "
        "FROM sensitive_config.sensitive_functions "
        "ORDER BY function_key"
    )
    func_rows = [dict(row) for row in await cursor.fetchall()]

    # Load config_values
    cursor = await db.execute("SELECT config_key, config_value FROM sensitive_config.config_values ORDER BY config_key")
    value_rows = [dict(row) for row in await cursor.fetchall()]

    # Verify combined hash
    hash_path = data_dir / _HASH_FILENAME
    if not hash_path.exists():
        raise RuntimeError(
            f"Sensitive config hash file not found at {hash_path}. "
            "If the schema was created outside of the auto-bootstrap, "
            "re-run the bootstrap by dropping the schema and restarting."
        )

    stored_hash = hash_path.read_text().strip()
    computed_hash = _hash_rows(func_rows, value_rows)

    if computed_hash != stored_hash:
        logger.critical(
            "SENSITIVE CONFIG INTEGRITY CHECK FAILED — possible tampering. Stored hash: %s  Computed: %s",
            stored_hash,
            computed_hash,
        )
        raise RuntimeError(
            "Sensitive config integrity check FAILED — "
            "sensitive_config tables do not match the stored hash. "
            "If this change was intentional, DROP SCHEMA sensitive_config CASCADE, "
            "delete DATA_DIR/.sensitive_config.hash, and restart."
        )

    _config = {
        row["function_key"]: {
            "is_sensitive": bool(row["is_sensitive"]),
            "challenge_type": row["challenge_type"],
        }
        for row in func_rows
    }
    _config_values = {row["config_key"]: row["config_value"] for row in value_rows}
    _loaded = True

    sensitive_count = sum(1 for v in _config.values() if v["is_sensitive"])
    logger.info(
        "Sensitive config loaded: %d function entries (%d sensitive), %d config values",
        len(_config),
        sensitive_count,
        len(_config_values),
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
        raise RuntimeError(_ERR_NOT_LOADED)

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
        raise RuntimeError(_ERR_NOT_LOADED)

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


def get_config_value(key: str) -> str | None:
    """Return a config value by key, or None if not present.

    Values are stored as text (binary blobs are base64-encoded by convention).
    Raises RuntimeError if called before load().
    """
    if not _loaded:
        raise RuntimeError(_ERR_NOT_LOADED)
    return _config_values.get(key)


def get_opaque_server_setup() -> bytes:
    """Return the OPAQUE ServerSetup blob as raw bytes.

    Decodes the base64 value stored under OPAQUE_SERVER_SETUP_KEY.
    Raises RuntimeError if the key is missing (schema not bootstrapped correctly).
    """
    raw = get_config_value(OPAQUE_SERVER_SETUP_KEY)
    if raw is None:
        raise RuntimeError(
            "OPAQUE server setup not found in sensitive_config. "
            "Drop the sensitive_config schema and restart to re-bootstrap."
        )
    return base64.b64decode(raw)
