"""Bandwidth enforcement — per-user and global byte rate limiting.

Tracks bytes transferred in a 60-second sliding window.

Per-user limit: users.bandwidth_limit (bytes/second; 0 or NULL = no limit).
Global limit:   admin_settings.global_bandwidth_limit (bytes/second; 0 = no limit).

The effective per-window limit = limit_bps * WINDOW_SECONDS.
A transfer that would push the current window total over the limit is rejected
with HTTP 429 before any data is read or written.

Multi-worker mode (TUSSHARE_REDIS_URL set): uses Redis sorted sets so the window
is shared across all app instances.  Falls back to in-process memory when Redis
is unavailable or not configured.
"""

import asyncio
import logging
import time
import uuid
from collections import defaultdict

from fastapi import HTTPException

from app.config import settings
from app.services import live_settings

# Lua script: atomic sliding-window bandwidth check-and-record.
# Member format: "{bytes}:{uuid}" — bytes encoded in the member so we can SUM them.
# KEYS[1] = bw key; ARGV[1] = now (float), ARGV[2] = window (int),
# ARGV[3] = limit (int bytes), ARGV[4] = bytes_to_add (int), ARGV[5] = unique id.
# Returns: 1 = allowed, 0 = denied.
_REDIS_BW_SCRIPT = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local win    = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local nbytes = tonumber(ARGV[4])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - win)
local members = redis.call('ZRANGE', key, 0, -1)
local total = 0
for _, m in ipairs(members) do
    local b = tonumber(string.match(m, '^(%d+):'))
    if b then total = total + b end
end
if total + nbytes > limit then return 0 end
redis.call('ZADD', key, now, ARGV[4] .. ':' .. ARGV[5])
redis.call('EXPIRE', key, win + 1)
return 1
"""

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60

# (timestamp, bytes) pairs per tracking key
_windows: dict[str, list[tuple[float, int]]] = defaultdict(list)
_lock = asyncio.Lock()


async def check_bandwidth(db, user_id: str, bytes_count: int, user_bw_limit: int | None = None) -> None:
    """Check per-user and global bandwidth limits before a transfer.

    Raises HTTP 429 if either limit would be exceeded.
    Records bytes in the sliding window on success.

    Both checks are evaluated before recording anything — a request that
    would exceed the global limit is rejected even if the per-user check
    would have passed, and vice versa.

    Args:
        db:            active database connection (unused when user_bw_limit provided)
        user_id:       authenticated user performing the transfer
        bytes_count:   bytes about to be transferred (chunk or range size)
        user_bw_limit: pre-fetched per-user bandwidth_limit (bytes/sec); None = no limit
    """
    user_bw_bps: int = user_bw_limit or 0

    # Global limit comes from the in-process live_settings cache — no DB round-trip.
    global_bw_bps: int = live_settings.get_int("global_bandwidth_limit", settings.GLOBAL_BANDWIDTH_LIMIT)

    user_window_limit = user_bw_bps * WINDOW_SECONDS
    global_window_limit = global_bw_bps * WINDOW_SECONDS

    # Build the list of (redis_key, in_memory_key, limit, error_detail) for active limits.
    checks: list[tuple[str, int, str]] = []
    if user_window_limit > 0:
        checks.append((f"bw:{user_id}", user_window_limit, "Bandwidth limit exceeded"))
    if global_window_limit > 0:
        checks.append(("bw:global", global_window_limit, "Server bandwidth limit exceeded"))

    if not checks:
        return  # No limits active — fast path

    from app.redis_client import get_redis

    r = get_redis()
    if r is not None:
        # Redis path: atomic Lua script, shared across all workers.
        now = time.time()
        uid = str(uuid.uuid4())
        for redis_key, limit, detail in checks:
            try:
                result = await r.eval(
                    _REDIS_BW_SCRIPT, 1,
                    redis_key, now, WINDOW_SECONDS, limit, bytes_count, uid,
                )
                if not result:
                    logger.warning(
                        "Bandwidth limit exceeded (Redis): key=%s requested=%d limit=%d",
                        redis_key, bytes_count, limit,
                    )
                    raise HTTPException(
                        status_code=429,
                        detail=detail,
                        headers={"Retry-After": str(WINDOW_SECONDS)},
                    )
            except HTTPException:
                raise
            except Exception as exc:
                logger.warning("Redis bandwidth eval failed (%s); falling back to local", exc)
                break  # fall through to in-process check below
        else:
            return  # all Redis checks passed

    # In-process fallback (single-worker mode or Redis unavailable).
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS

    async with _lock:
        pruned: dict[str, list[tuple[float, int]]] = {}
        for key, limit, detail in checks:
            pruned[key] = [(t, b) for t, b in _windows[key] if t > cutoff]
            current = sum(b for _, b in pruned[key])
            if current + bytes_count > limit:
                logger.warning(
                    "Bandwidth limit exceeded: key=%s current=%d requested=%d limit=%d",
                    key, current, bytes_count, limit,
                )
                raise HTTPException(
                    status_code=429,
                    detail=detail,
                    headers={"Retry-After": str(WINDOW_SECONDS)},
                )

        for key, _limit, _detail in checks:
            _windows[key] = pruned[key]
            _windows[key].append((now, bytes_count))


async def cleanup(max_age: float = 3600.0) -> None:
    """Purge keys with no activity in the last max_age seconds.

    Called from run_rate_limit_cleanup in rate_limit.py so both trackers
    share the same periodic cleanup task.
    """
    now = time.monotonic()
    async with _lock:
        stale = [k for k, v in _windows.items() if not v or v[-1][0] < now - max_age]
        for k in stale:
            del _windows[k]
        if stale:
            logger.debug("Bandwidth tracker cleanup: removed %d stale keys", len(stale))
