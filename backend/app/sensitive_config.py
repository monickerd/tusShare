"""Sensitive function configuration — in-memory loader with integrity check.

The sensitive_config PostgreSQL schema is seeded once by
scripts/setup_sensitive_config.py, then locked:
  - The schema owner role has NOLOGIN — no one can authenticate as it.
  - BEFORE UPDATE/DELETE triggers raise exceptions on any mutation attempt.
  - The app DB role has SELECT only.

At startup, this module:
  1. Loads all rows from sensitive_config.sensitive_functions.
  2. Computes a SHA-256 of the sorted rows.
  3. Compares to DATA_DIR/.sensitive_config.hash (written at setup time).
  4. On mismatch, raises RuntimeError and refuses to start.
  5. Stores the config in a frozen module-level dict for O(1) runtime checks.

All runtime callers use is_sensitive() and get_challenge_type() — they never
touch the database.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Module-level frozen state — set once in load(), never mutated after that.
_config: dict[str, dict[str, Any]] = {}
_loaded = False

_HASH_FILENAME = ".sensitive_config.hash"


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


async def load(db, data_dir: Path) -> None:
    """Load sensitive config from DB, verify integrity, freeze into memory.

    Called once from the app lifespan (main.py).  Raises RuntimeError on:
      - Schema not found: setup script has not been run.
      - Hash file missing: setup script has not been run.
      - Hash mismatch: the sensitive_config table was modified outside the
        setup script — this is a critical security event.
    """
    global _config, _loaded

    # Verify the schema exists (tells us setup was run)
    cursor = await db.execute(
        "SELECT schema_name FROM information_schema.schemata "
        "WHERE schema_name = 'sensitive_config'"
    )
    if await cursor.fetchone() is None:
        raise RuntimeError(
            "sensitive_config schema not found. "
            "Run 'python scripts/setup_sensitive_config.py' before starting the server."
        )

    # Load all rows
    cursor = await db.execute(
        "SELECT function_key, is_sensitive, challenge_type "
        "FROM sensitive_config.sensitive_functions "
        "ORDER BY function_key"
    )
    rows = [dict(row) for row in await cursor.fetchall()]

    # Verify against the hash file written at setup time
    hash_path = data_dir / _HASH_FILENAME
    if not hash_path.exists():
        raise RuntimeError(
            f"Sensitive config hash file not found at {hash_path}. "
            "Run 'python scripts/setup_sensitive_config.py' before starting the server."
        )

    stored_hash = hash_path.read_text().strip()
    computed_hash = _hash_rows(rows)

    if computed_hash != stored_hash:
        logger.critical(
            "SENSITIVE CONFIG INTEGRITY CHECK FAILED. "
            "The sensitive_config table does not match the stored hash. "
            "Possible tampering detected. Server will not start."
        )
        raise RuntimeError(
            "Sensitive config integrity check FAILED — "
            "sensitive_config.sensitive_functions has been modified outside the setup script. "
            "If this change was intentional, re-run 'python scripts/setup_sensitive_config.py'."
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
