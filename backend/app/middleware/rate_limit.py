"""In-memory sliding window rate limiter.

Tracks request counts per key (IP or user ID) within sliding windows.
Returns 429 Too Many Requests when limits are exceeded.

Note: In-memory only — resets on restart. Acceptable for small user pools.
"""

import asyncio
import logging
import time
from collections import defaultdict

from fastapi import Depends, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.conf.middleware import (
    RATE_LIMIT_CLEANUP_MAX_AGE,
    RATE_LIMIT_LOGIN_WINDOW,
    RATE_LIMIT_MANAGEMENT_WINDOW,
)
from app.config import settings

logger = logging.getLogger(__name__)


class _SlidingWindowCounter:
    """Tracks request timestamps per key within a sliding window.

    All mutations are protected by an asyncio.Lock to prevent race conditions
    between concurrent requests (read-modify-write on the timestamps list).
    """

    def __init__(self):
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds

        async with self._lock:
            timestamps = self._requests[key]
            self._requests[key] = [t for t in timestamps if t > cutoff]

            if len(self._requests[key]) >= max_requests:
                return False

            self._requests[key].append(now)
            return True

    async def cleanup(self, max_age: float = RATE_LIMIT_CLEANUP_MAX_AGE) -> None:
        now = time.monotonic()
        async with self._lock:
            stale_keys = [
                k for k, v in self._requests.items()
                if not v or v[-1] < now - max_age
            ]
            for k in stale_keys:
                del self._requests[k]
            if stale_keys:
                logger.debug("Rate limiter cleanup: removed %d stale keys", len(stale_keys))


_counter = _SlidingWindowCounter()


class _ErrorRateTracker:
    """Tracks per-IP error counts for brute-force and scanning detection.

    When an IP accumulates >= threshold non-429 4xx/5xx responses within
    the error window, it enters 'escalated' mode and is throttled to
    ESCALATED_MAX requests per ESCALATED_WINDOW seconds for
    ESCALATED_DURATION seconds.
    """

    def __init__(self):
        self._errors: dict[str, list[float]] = defaultdict(list)
        self._escalated_until: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def record_error(self, ip: str) -> bool:
        """Record an error for the given IP.

        Returns True if this error pushed the IP into escalated mode for
        the first time (so the caller can log the escalation event).
        """
        threshold = settings.RATE_LIMIT_ERROR_THRESHOLD
        if threshold <= 0:
            return False  # escalation disabled

        now = time.monotonic()
        cutoff = now - settings.RATE_LIMIT_ERROR_WINDOW

        async with self._lock:
            self._errors[ip] = [t for t in self._errors[ip] if t > cutoff]
            self._errors[ip].append(now)

            already_escalated = (
                ip in self._escalated_until and self._escalated_until[ip] > now
            )
            if not already_escalated and len(self._errors[ip]) >= threshold:
                self._escalated_until[ip] = now + settings.RATE_LIMIT_ESCALATED_DURATION
                return True
        return False

    async def is_escalated(self, ip: str) -> bool:
        """Return True if the IP is currently in escalated throttle mode."""
        if settings.RATE_LIMIT_ERROR_THRESHOLD <= 0:
            return False
        now = time.monotonic()
        async with self._lock:
            return ip in self._escalated_until and self._escalated_until[ip] > now

    async def cleanup(self, max_age: float) -> None:
        now = time.monotonic()
        async with self._lock:
            stale_errors = [k for k, v in self._errors.items() if not v or v[-1] < now - max_age]
            for k in stale_errors:
                del self._errors[k]
            expired_esc = [k for k, v in self._escalated_until.items() if v < now]
            for k in expired_esc:
                del self._escalated_until[k]


_error_tracker = _ErrorRateTracker()


async def run_rate_limit_cleanup(interval: float = RATE_LIMIT_CLEANUP_MAX_AGE) -> None:
    """Periodic cleanup task — call from app lifespan. Runs until cancelled."""
    from app.middleware.bandwidth import cleanup as _bandwidth_cleanup
    while True:
        await asyncio.sleep(interval)
        await _counter.cleanup()
        await _error_tracker.cleanup(RATE_LIMIT_CLEANUP_MAX_AGE)
        await _bandwidth_cleanup()


def _get_client_ip(request: Request) -> str:
    trusted_header = settings.TRUSTED_IP_HEADER
    if trusted_header:
        forwarded = request.headers.get(trusted_header, "")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
            if ip:
                return ip
    return request.client.host if request.client else "unknown"


# Route-specific rate limit rules: (path_prefix, methods, max_requests, window_seconds)
_ROUTE_LIMITS = [
    ("/api/v1/auth/login",      {"POST"},         settings.RATE_LIMIT_LOGIN, RATE_LIMIT_LOGIN_WINDOW),
    ("/api/v1/auth/me/password", {"POST", "PUT"},  settings.RATE_LIMIT_LOGIN, RATE_LIMIT_LOGIN_WINDOW),
    # Registration via invite — same limit as login to prevent invite brute-force
    ("/api/v1/auth/register",   {"POST"},         settings.RATE_LIMIT_LOGIN, RATE_LIMIT_LOGIN_WINDOW),
    # OPAQUE login and registration — same limits as above
    ("/api/v1/auth/opaque/login/",    {"POST"}, settings.RATE_LIMIT_LOGIN, RATE_LIMIT_LOGIN_WINDOW),
    ("/api/v1/auth/opaque/register/", {"POST"}, settings.RATE_LIMIT_LOGIN, RATE_LIMIT_LOGIN_WINDOW),
    ("/api/v1/auth/opaque/step-up/",  {"POST"}, settings.RATE_LIMIT_LOGIN, RATE_LIMIT_LOGIN_WINDOW),
    ("/api/v1/auth/opaque/migrate/",  {"POST"}, settings.RATE_LIMIT_LOGIN, RATE_LIMIT_LOGIN_WINDOW),
    ("/api/v1/auth/opaque/recover/",  {"POST"}, settings.RATE_LIMIT_LOGIN, RATE_LIMIT_LOGIN_WINDOW),
    # Invite validation — tighter window to slow token enumeration
    ("/api/v1/auth/invite/",    {"GET"},          20,                        60),
    # Public share/short-link resolution — keyed by IP to slow token enumeration
    ("/s/",                     {"GET"},          60,                        60),
    ("/l/",                     {"GET"},          60,                        60),
]


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = _get_client_ip(request)
        path = request.url.path

        # Escalated throttle check: IPs that recently exceeded the error threshold
        # are throttled to ESCALATED_MAX requests per ESCALATED_WINDOW seconds.
        if await _error_tracker.is_escalated(client_ip):
            if not await _counter.is_allowed(
                f"esc:{client_ip}",
                settings.RATE_LIMIT_ESCALATED_MAX,
                settings.RATE_LIMIT_ESCALATED_WINDOW,
            ):
                logger.warning(
                    "Escalated rate limit enforced: ip=%s on %s %s",
                    client_ip, request.method, path,
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": "Too many requests. Please try again later.",
                        }
                    },
                    headers={"Retry-After": str(settings.RATE_LIMIT_ESCALATED_WINDOW)},
                )

        # Route-specific limits
        for prefix, methods, max_req, window in _ROUTE_LIMITS:
            if path.startswith(prefix) and request.method in methods:
                key = f"rate:{prefix}:{client_ip}"
                if not await _counter.is_allowed(key, max_req, window):
                    logger.warning(
                        "Rate limited: %s on %s (ip=%s)", request.method, path, client_ip
                    )
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": {
                                "code": "RATE_LIMITED",
                                "message": "Too many requests. Please try again later.",
                            }
                        },
                        headers={"Retry-After": str(window)},
                    )

        response = await call_next(request)

        # Track error responses to detect brute-force / scanning.
        # Exclude 429s (our own rate-limit responses) to avoid positive feedback loops.
        if response.status_code >= 400 and response.status_code != 429:
            escalated = await _error_tracker.record_error(client_ip)
            if escalated:
                logger.warning(
                    "IP escalated to aggressive rate limiting: ip=%s "
                    "(>= %d errors in %ds window)",
                    client_ip,
                    settings.RATE_LIMIT_ERROR_THRESHOLD,
                    settings.RATE_LIMIT_ERROR_WINDOW,
                )

        return response


async def check_management_rate_limit(
    user: AuthenticatedUser = Depends(require_user_role),
) -> None:
    """FastAPI dependency: rate-limit non-file management actions per authenticated user.

    Applied at the router level to folder CRUD, share CRUD, and similar endpoints.
    FastAPI de-duplicates the inner require_user_role dependency within a single request,
    so authentication is not performed twice.
    """
    allowed = await _counter.is_allowed(
        f"mgmt:{user.id}",
        settings.RATE_LIMIT_MANAGEMENT,
        RATE_LIMIT_MANAGEMENT_WINDOW,
    )
    if not allowed:
        logger.warning("Management rate limited: user=%s", user.id)
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(RATE_LIMIT_MANAGEMENT_WINDOW)},
        )
