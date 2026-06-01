"""In-process live settings cache.

Loaded from admin_settings at startup, updated in-place after admin writes.
All accessors are synchronous so they can be called from non-async code (e.g. jwt.py).

Multi-worker mode (TUSSHARE_REDIS_URL set): each call to update/update_many publishes
a 'live_settings:invalidate' message so other workers reload from DB.
run_settings_invalidation_listener() must be started as a background task in main.py.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

_REDIS_CHANNEL = "live_settings:invalidate"

_cache: dict[str, str] = {}
_bg_tasks: set = set()


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
    """Update a single key after a DB write and notify other workers via Redis."""
    _cache[key] = value
    _schedule_invalidation()


def update_many(pairs: dict[str, str]) -> None:
    """Update multiple keys after a batch DB write and notify other workers via Redis."""
    _cache.update(pairs)
    _schedule_invalidation()


def _schedule_invalidation() -> None:
    """Schedule a Redis pub/sub invalidation message (fire-and-forget)."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            t = loop.create_task(_publish_invalidation())
            _bg_tasks.add(t)
            t.add_done_callback(_bg_tasks.discard)
    except RuntimeError:
        pass  # no running loop (e.g., tests or CLI context)


async def _publish_invalidation() -> None:
    from app.redis_client import get_redis

    r = get_redis()
    if r is None:
        return
    try:
        await r.publish(_REDIS_CHANNEL, "reload")
    except Exception as exc:
        logger.debug("live_settings: Redis invalidation publish failed: %s", exc)


async def run_settings_invalidation_listener(db_factory) -> None:
    """Background task: subscribe to Redis and reload the cache when another worker
    writes a settings change.  No-op when Redis is not configured."""
    from app.redis_client import get_redis

    r = get_redis()
    if r is None:
        return

    pubsub = r.pubsub()
    await pubsub.subscribe(_REDIS_CHANNEL)
    logger.info("live_settings: Redis invalidation listener active")
    try:
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            try:
                async with db_factory() as db:
                    await load(db)
                logger.debug("live_settings: reloaded from DB (Redis invalidation)")
            except Exception:
                logger.exception("live_settings: reload failed after Redis invalidation")
    except asyncio.CancelledError:
        await pubsub.unsubscribe(_REDIS_CHANNEL)
        try:
            await pubsub.aclose()
        except Exception:
            pass
        raise
    except Exception:
        logger.exception("live_settings: invalidation listener crashed")
        raise
