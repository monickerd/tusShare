"""Bandwidth enforcement — per-user and global byte rate limiting.

Tracks bytes transferred in a 60-second sliding window.

Per-user limit: users.bandwidth_limit (bytes/second; 0 or NULL = no limit).
Global limit:   admin_settings.global_bandwidth_limit (bytes/second; 0 = no limit).

The effective per-window limit = limit_bps * WINDOW_SECONDS.
A transfer that would push the current window total over the limit is rejected
with HTTP 429 before any data is read or written.

In-memory only — resets on restart (same trade-off as rate limiting).
"""

import asyncio
import logging
import time
from collections import defaultdict

from fastapi import HTTPException

from app.config import settings

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60

# (timestamp, bytes) pairs per tracking key
_windows: dict[str, list[tuple[float, int]]] = defaultdict(list)
_lock = asyncio.Lock()


async def check_bandwidth(db, user_id: str, bytes_count: int) -> None:
    """Check per-user and global bandwidth limits before a transfer.

    Raises HTTP 429 if either limit would be exceeded.
    Records bytes in the sliding window on success.

    Both checks are evaluated before recording anything — a request that
    would exceed the global limit is rejected even if the per-user check
    would have passed, and vice versa.

    Args:
        db:          active database connection
        user_id:     authenticated user performing the transfer
        bytes_count: bytes about to be transferred (chunk or range size)
    """
    # Read per-user bandwidth limit
    cursor = await db.execute(
        "SELECT bandwidth_limit FROM users WHERE id = ?", (user_id,)
    )
    row = await cursor.fetchone()
    user_bw_bps: int = (row["bandwidth_limit"] or 0) if row else 0

    # Read global bandwidth limit
    cursor = await db.execute(
        "SELECT value FROM admin_settings WHERE key = 'global_bandwidth_limit'"
    )
    row = await cursor.fetchone()
    global_bw_bps: int = int(row["value"]) if row else settings.GLOBAL_BANDWIDTH_LIMIT

    user_window_limit   = user_bw_bps   * WINDOW_SECONDS
    global_window_limit = global_bw_bps * WINDOW_SECONDS

    # Build the list of (key, limit, error_detail) pairs that are actually active
    checks: list[tuple[str, int, str]] = []
    if user_window_limit > 0:
        checks.append((f"bw:{user_id}", user_window_limit, "Bandwidth limit exceeded"))
    if global_window_limit > 0:
        checks.append(("bw:global", global_window_limit, "Server bandwidth limit exceeded"))

    if not checks:
        return  # No limits active — fast path

    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS

    async with _lock:
        # Prune expired entries and check all limits before recording anything.
        # Pruning happens first so the current-bytes calculation is accurate.
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

        # All checks passed — commit pruned windows and record new event
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
        stale = [
            k for k, v in _windows.items()
            if not v or v[-1][0] < now - max_age
        ]
        for k in stale:
            del _windows[k]
        if stale:
            logger.debug("Bandwidth tracker cleanup: removed %d stale keys", len(stale))
