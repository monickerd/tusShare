"""API key authentication for machine/external access.

Usage
-----
As a FastAPI dependency (scope baked in, not injectable via query param):

    @router.get("/audit/logs/stream")
    async def stream(_key=Depends(make_api_key_dep("audit_read"))):
        ...

    # Accept any of several scopes (backward-compatible endpoints):
    @router.get("/op-events/log")
    async def log(_key=Depends(make_api_key_dep("ops_read", "events.read"))):
        ...

For dual-auth (JWT or API key) routes, call check_api_key() directly:

    from app.auth.api_key import check_api_key
    await check_api_key(request.headers.get("x-api-key", ""), "audit_read",
                        client_ip=request.client.host)
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import Header, HTTPException, Request

from app.database import db_session
from app.util.crypto import sha256_hex
from app.util.ip_restrict import is_allowed as ip_is_allowed

logger = logging.getLogger(__name__)

_PREFIX = "tss_"

# Pending last_used_at timestamps — flushed in bulk by run_last_used_flush.
_last_used_pending: dict[str, datetime] = {}


async def _update_last_used(key_id: str) -> None:
    _last_used_pending[key_id] = datetime.now(timezone.utc)


async def run_last_used_flush(db_factory, interval: float = 60.0) -> None:
    """Periodic flush: write coalesced last_used_at values to the DB in one transaction."""
    global _last_used_pending
    while True:
        await asyncio.sleep(interval)
        if not _last_used_pending:
            continue
        pending = _last_used_pending
        _last_used_pending = {}
        try:
            async with db_factory() as db:
                for key_id, ts in pending.items():
                    await db.execute(
                        "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                        (ts.isoformat(), key_id),
                    )
                await db.commit()
        except Exception:
            logger.debug("api_key: failed to flush last_used_at for %d key(s)", len(pending))


async def _check_key(
    raw_key: str,
    accepted_scopes: tuple[str, ...],
    *,
    client_ip: str | None = None,
) -> dict:
    """Core validation: look up raw key hash, check expiry, scope, enabled flag, and IP."""
    if not raw_key.startswith(_PREFIX) or len(raw_key) < 20:
        raise HTTPException(status_code=401, detail="Invalid API key")

    key_hash = sha256_hex(raw_key)
    now_iso = datetime.now(timezone.utc).isoformat()

    async with db_session() as db:
        cursor = await db.execute(
            "SELECT id, scopes, expires_at, event_filter, filter_min_severity, allowed_ips, enabled "
            "FROM api_keys "
            "WHERE key_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
            (key_hash, now_iso),
        )
        row = await cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")

    if not row["enabled"]:
        raise HTTPException(status_code=401, detail="API key is disabled")

    key_scopes = set(json.loads(row["scopes"] or "[]"))
    if not key_scopes.intersection(accepted_scopes):
        needed = ", ".join(sorted(accepted_scopes))
        raise HTTPException(status_code=403, detail=f"API key requires one of: {needed}")

    if not ip_is_allowed(client_ip, row["allowed_ips"]):
        logger.warning("api_key: request from disallowed IP %s for key %s", client_ip, row["id"])
        raise HTTPException(status_code=403, detail="Request source IP is not in this key's allowlist")

    await _update_last_used(row["id"])
    return dict(row)


async def check_api_key(
    raw_key: str,
    *accepted_scopes: str,
    client_ip: str | None = None,
) -> dict:
    """Validate a raw API key directly (for dual-auth routes that call this imperatively).

    Raises HTTPException on failure. Returns the API key DB row on success.
    """
    return await _check_key(raw_key, tuple(accepted_scopes), client_ip=client_ip)


def make_api_key_dep(*accepted_scopes: str):
    """Return a FastAPI dependency that validates X-API-Key against the given scopes."""
    _scopes = tuple(accepted_scopes)

    async def _dep(x_api_key: str = Header(...), request: Request = None) -> dict:
        client_ip = request.client.host if request and request.client else None
        return await _check_key(x_api_key, _scopes, client_ip=client_ip)

    return _dep


# Default op-events dependency — accepts the legacy events.read scope and the new ops_read.
require_api_key = make_api_key_dep("ops_read", "events.read")
