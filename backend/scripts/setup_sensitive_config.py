#!/usr/bin/env python3
"""Manual bootstrap for the sensitive_config immutable PostgreSQL schema.

Under normal operation the server bootstraps this automatically on first
startup when TUSSHARE_SUPERUSER_URL is set.  This script is provided as
a fallback for environments where running the server for bootstrapping is
not practical.

Creates the schema in the app database:
  - Schema owned by the connecting superuser.
  - The app DB role receives SELECT-only on all tables in the schema.
  - BEFORE UPDATE / BEFORE DELETE triggers block all mutations via the app role.
  - The app loads rows into a frozen in-memory dict at startup and validates
    them against a SHA-256 hash file written here.

RUN ONCE before first server start.  Re-running on an already-configured
instance will abort with an error — that is intentional.

Required environment variables:
  TUSSHARE_DATABASE_URL        App connection string.
                               The username embedded here is the app role that
                               will receive SELECT on sensitive_config tables.
                               e.g. postgresql://tusshare:pass@postgres:5432/tusshare
  TUSSHARE_SUPERUSER_URL       Postgres superuser connection string.
                               Needs CREATE SCHEMA privilege on the app database.
                               e.g. postgresql://postgres:pass@postgres:5432/tusshare
  TUSSHARE_DATA_DIR            Directory where the hash file will be written.
                               Must match DATA_DIR used by the app at runtime.
                               Default: /data
"""

import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import asyncpg


# ---------------------------------------------------------------------------
# Default sensitive function seeds (must match sensitive_config.py)
# ---------------------------------------------------------------------------

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

_NON_SENSITIVE_DEFAULTS = [
    ("admin.invite.create",  "password", "Create a registration invite (routine)"),
    ("team.key.rotate",      "password", "Rotate team encryption keys (routine)"),
]


# ---------------------------------------------------------------------------
# Hash utility (must match app/sensitive_config.py exactly)
# ---------------------------------------------------------------------------

def _hash_rows(rows: list[dict]) -> str:
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
# Setup
# ---------------------------------------------------------------------------

async def main() -> None:
    database_url  = os.environ.get("TUSSHARE_DATABASE_URL", "")
    superuser_url = os.environ.get("TUSSHARE_SUPERUSER_URL", "")
    data_dir      = Path(os.environ.get("TUSSHARE_DATA_DIR", "/data"))

    if not database_url:
        sys.exit("ERROR: TUSSHARE_DATABASE_URL is not set")
    if not superuser_url:
        sys.exit("ERROR: TUSSHARE_SUPERUSER_URL is not set")

    app_role = urlparse(database_url).username
    if not app_role:
        sys.exit("ERROR: Could not parse app role from TUSSHARE_DATABASE_URL")

    print(f"[setup] App role:        {app_role}")
    print(f"[setup] Hash directory:  {data_dir}")

    try:
        conn = await asyncpg.connect(superuser_url)
    except Exception as exc:
        sys.exit(f"ERROR: Could not connect with TUSSHARE_SUPERUSER_URL: {exc}")

    try:
        exists = await conn.fetchval(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name = 'sensitive_config'"
        )
        if exists:
            sys.exit(
                "ERROR: sensitive_config schema already exists. "
                "To rebuild from scratch, DROP SCHEMA sensitive_config CASCADE, "
                "delete DATA_DIR/.sensitive_config.hash, and re-run this script."
            )

        print("[setup] Creating schema sensitive_config ...")
        await conn.execute("CREATE SCHEMA sensitive_config")

        print("[setup] Creating sensitive_functions table ...")
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

        print("[setup] Seeding default entries ...")
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

        print(f"[setup] Granting SELECT on sensitive_config to {app_role} ...")
        await conn.execute(f"GRANT USAGE ON SCHEMA sensitive_config TO {app_role}")
        await conn.execute(
            f"GRANT SELECT ON ALL TABLES IN SCHEMA sensitive_config TO {app_role}"
        )
        await conn.execute("REVOKE ALL ON SCHEMA sensitive_config FROM PUBLIC")

        config_hash = _hash_rows(all_rows)
        hash_path = data_dir / ".sensitive_config.hash"
        data_dir.mkdir(parents=True, exist_ok=True)
        hash_path.write_text(config_hash)
        print(f"[setup] Hash written to {hash_path}")
        print(f"[setup] Hash: {config_hash}")

        print()
        print("[setup] Done. sensitive_config schema is sealed.")
        print(f"[setup] {len(_SENSITIVE_DEFAULTS)} functions marked sensitive by default.")
        print(f"[setup] {len(_NON_SENSITIVE_DEFAULTS)} functions present but NOT sensitive by default.")

    except SystemExit:
        raise
    except Exception as exc:
        try:
            await conn.execute("DROP SCHEMA IF EXISTS sensitive_config CASCADE")
        except Exception:
            pass
        sys.exit(f"ERROR during setup: {exc}")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
