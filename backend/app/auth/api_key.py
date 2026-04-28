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
    await check_api_key(request.headers.get("x-api-key", ""), "audit_read")
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone

from fastapi import Header, HTTPException

from app.database import db_session

logger = logging.getLogger(__name__)

_PREFIX = "tss_"


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def _update_last_used(key_id: str) -> None:
    try:
        async with db_session() as db:
            await db.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), key_id),
            )
            await db.commit()
    except Exception:
        logger.debug("api_key: failed to update last_used_at for %s", key_id)


async def _check_key(raw_key: str, accepted_scopes: tuple[str, ...]) -> dict:
    """Core validation: look up raw key hash, check expiry, verify scope membership."""
    if not raw_key.startswith(_PREFIX) or len(raw_key) < 20:
        raise HTTPException(status_code=401, detail="Invalid API key")

    key_hash = _hash_key(raw_key)
    now_iso  = datetime.now(timezone.utc).isoformat()

    async with db_session() as db:
        cursor = await db.execute(
            "SELECT id, scopes, expires_at, filter_event_types, filter_min_severity "
            "FROM api_keys "
            "WHERE key_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
            (key_hash, now_iso),
        )
        row = await cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")

    key_scopes = set(json.loads(row["scopes"] or "[]"))
    if not key_scopes.intersection(accepted_scopes):
        needed = ", ".join(sorted(accepted_scopes))
        raise HTTPException(status_code=403, detail=f"API key requires one of: {needed}")

    asyncio.create_task(_update_last_used(row["id"]))
    return dict(row)


async def check_api_key(raw_key: str, *accepted_scopes: str) -> dict:
    """Validate a raw API key directly (for dual-auth routes that call this imperatively).

    Raises HTTPException on failure. Returns the API key DB row on success.
    """
    return await _check_key(raw_key, tuple(accepted_scopes))


def make_api_key_dep(*accepted_scopes: str):
    """Return a FastAPI dependency that validates X-API-Key against the given scopes.

    Scopes are baked into the closure — they cannot be overridden via query params.
    Pass multiple scopes to accept any one of them (useful for backward-compatible
    endpoints that need to honour both an old and a new scope name).
    """
    _scopes = tuple(accepted_scopes)

    async def _dep(x_api_key: str = Header(...)) -> dict:
        return await _check_key(x_api_key, _scopes)

    return _dep


# Default op-events dependency — accepts the legacy events.read scope and the new ops_read.
require_api_key = make_api_key_dep("ops_read", "events.read")
