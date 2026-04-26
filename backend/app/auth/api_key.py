"""API key authentication dependency for the pull events endpoint.

Usage:
    @router.get("/events/stream")
    async def stream(_key=Depends(require_api_key)):
        ...
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


async def require_api_key(
    scope: str = "events.read",
    x_api_key: str = Header(...),
) -> dict:
    """FastAPI dependency. Validates X-API-Key header and required scope."""
    if not x_api_key.startswith(_PREFIX) or len(x_api_key) < 20:
        raise HTTPException(status_code=401, detail="Invalid API key")

    key_hash = _hash_key(x_api_key)
    now_iso  = datetime.now(timezone.utc).isoformat()

    async with db_session() as db:
        cursor = await db.execute(
            "SELECT id, scopes, expires_at FROM api_keys "
            "WHERE key_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
            (key_hash, now_iso),
        )
        row = await cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")

    scopes = json.loads(row["scopes"] or "[]")
    if scope not in scopes:
        raise HTTPException(status_code=403, detail=f"API key does not have scope: {scope}")

    asyncio.create_task(_update_last_used(row["id"]))
    return dict(row)
