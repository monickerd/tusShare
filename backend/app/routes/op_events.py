"""Operational events pull endpoints.

GET /api/v1/op-events/stream  — SSE stream authenticated by X-API-Key
GET /api/v1/op-events/log     — JSON log polling with cursor pagination

Both endpoints require an API key with the "events.read" scope.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from app.auth.api_key import require_api_key
from app.database import Database, get_db
from app.services import op_bus
from app.services.notification_emitter import _matches_filter

logger = logging.getLogger(__name__)
router = APIRouter()

_KEEPALIVE_INTERVAL = 25  # seconds


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------


@router.get("/stream")
async def op_events_stream(
    _key: Annotated[dict, Depends(require_api_key)],
    types: Annotated[str | None, Query(description="Comma-separated prefix filter")] = None,
):
    """Stream operational events as Server-Sent Events."""
    type_filters = [t.strip() for t in types.split(",")] if types else []

    async def event_generator():
        q = op_bus.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=_KEEPALIVE_INTERVAL)
                    if not type_filters or _matches_filter(event.event_type, type_filters):
                        yield f"data: {event.model_dump_json()}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            op_bus.unsubscribe(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Log poll (cursor-paginated)
# ---------------------------------------------------------------------------


def _encode_cursor(created_at: str, event_id: str) -> str:
    raw = f"{created_at}:{event_id}"
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()


def _decode_cursor(cursor: str) -> tuple[str, str]:
    padded = cursor + "=" * (-len(cursor) % 4)
    raw = base64.urlsafe_b64decode(padded).decode()
    parts = raw.split(":", 1)
    if len(parts) != 2:
        raise ValueError("invalid cursor")
    return parts[0], parts[1]


@router.get("/log")
async def op_events_log(
    _key: Annotated[dict, Depends(require_api_key)],
    db: Annotated[Database, Depends(get_db)],
    since: Annotated[str | None, Query(description="ISO datetime lower bound")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    types: Annotated[str | None, Query(description="Comma-separated prefix filter")] = None,
    cursor: Annotated[str | None, Query(description="Opaque pagination cursor")] = None,
):
    """Return a page of operational events from the persisted log."""
    type_filters = [t.strip() for t in types.split(",")] if types else []

    params: list = []
    where_clauses: list[str] = []

    if cursor:
        try:
            cur_ts, cur_id = _decode_cursor(cursor)
            where_clauses.append("(created_at, id) < (?, ?)")
            params.extend([cur_ts, cur_id])
        except Exception:
            pass
    elif since:
        where_clauses.append("created_at >= ?")
        params.append(since)

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    sql = (
        f"SELECT id, event_id, event_type, severity, source, data_json, server_id, created_at "
        f"FROM operational_events {where_sql} "
        f"ORDER BY created_at DESC, id DESC "
        f"LIMIT ?"
    )
    params.append(limit + 1)

    rows = await (await db.execute(sql, params)).fetchall()
    has_next = len(rows) > limit
    rows = rows[:limit]

    events = []
    for r in rows:
        try:
            data = json.loads(r["data_json"])
        except Exception:
            data = {}
        events.append(
            {
                "event_id": r["event_id"],
                "event_type": r["event_type"],
                "severity": r["severity"],
                "source": r["source"],
                "data": data,
                "server_id": r["server_id"],
                "created_at": r["created_at"],
            }
        )

    # Apply type prefix filter in Python (avoids complex SQL)
    if type_filters:
        events = [e for e in events if _matches_filter(e["event_type"], type_filters)]

    next_cursor = None
    if has_next and rows:
        last = rows[-1]
        next_cursor = _encode_cursor(last["created_at"], last["id"])

    return {"events": events, "has_next": has_next, "next_cursor": next_cursor}
