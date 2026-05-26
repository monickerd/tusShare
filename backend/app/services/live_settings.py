"""In-process live settings cache.

Loaded from admin_settings at startup, updated in-place after admin writes.
All accessors are synchronous so they can be called from non-async code (e.g. jwt.py).

Multi-worker note: workers hold independent in-process caches. Changes written by
one worker take effect immediately in that worker; other workers stay on the
previous value until restart or a future Redis pub/sub bust. Rate limits and TTLs
tolerate this window of staleness.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_cache: dict[str, str] = {}


def get(key: str, default: str | None = None) -> str | None:
    return _cache.get(key, default)


def get_int(key: str, default: int = 0) -> int:
    val = _cache.get(key)
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def get_bool(key: str, default: bool = False) -> bool:
    val = _cache.get(key)
    if val is None:
        return default
    return val.lower() in ("true", "1", "yes")


async def load(db) -> None:
    """Populate cache from admin_settings. Called once at startup after init_db()."""
    cursor = await db.execute("SELECT key, value FROM admin_settings")
    rows = await cursor.fetchall()
    _cache.clear()
    for row in rows:
        if row["value"] is not None:
            _cache[row["key"]] = str(row["value"])
    logger.debug("live_settings: loaded %d entries from admin_settings", len(_cache))


def update(key: str, value: str) -> None:
    """Update a single key after a DB write."""
    _cache[key] = value


def update_many(pairs: dict[str, str]) -> None:
    """Update multiple keys after a batch DB write."""
    _cache.update(pairs)
