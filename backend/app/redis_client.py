"""Optional Redis connection pool.

Used for multi-worker rate limiting, SSE fan-out, and upload-eviction offsets.
When TUSSHARE_REDIS_URL is not set every function returns None / no-ops and the
app falls back to single-process in-memory state.
"""

import logging

from app.config import settings

logger = logging.getLogger(__name__)

_pool = None


def _init() -> None:
    """Initialise the connection pool once on first use."""
    global _pool
    if _pool is not None or not settings.REDIS_URL:
        return
    try:
        import redis.asyncio as redis  # type: ignore[import]

        _pool = redis.ConnectionPool.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            max_connections=20,
        )
        logger.info("Redis connection pool created: %s", settings.REDIS_URL)
    except ImportError:
        logger.warning(
            "TUSSHARE_REDIS_URL is set but the 'redis' package is not installed. "
            "Install it with: pip install 'redis[asyncio]>=5.0'"
        )
    except Exception:
        logger.exception("Failed to create Redis connection pool")


def get_redis():
    """Return a Redis client or None if Redis is not configured."""
    if not settings.REDIS_URL:
        return None
    if _pool is None:
        _init()
    if _pool is None:
        return None
    try:
        import redis.asyncio as redis  # type: ignore[import]

        return redis.Redis(connection_pool=_pool)
    except Exception:
        return None


async def close() -> None:
    """Drain and close the connection pool on shutdown."""
    global _pool
    if _pool is not None:
        try:
            await _pool.aclose()
        except Exception:
            pass
        _pool = None
