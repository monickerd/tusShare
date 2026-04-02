"""Server-Sent Events endpoint for real-time folder change notifications.

Clients connect with:
  GET /api/v1/events?folder_id=<uuid>   — watch a specific folder
  GET /api/v1/events                     — watch the current user's root view

The server pushes a {"type": "change"} event whenever the watched folder's
contents are mutated (file uploaded, deleted, renamed; subfolder created,
deleted, or renamed). Clients should reload the folder listing on receipt.

A heartbeat comment (": heartbeat") is sent every 25 seconds to keep the
connection alive through proxies and detect broken connections quickly.
"""
import asyncio
import json
import logging

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from app.auth.dependencies import require_user_role
from app.auth.interface import AuthenticatedUser
from app.database import get_db
from app.services import sse_broker
from app.validation.sanitizers import validate_uuid

logger = logging.getLogger(__name__)
router = APIRouter()

_HEARTBEAT_INTERVAL = 25  # seconds


@router.get("/events")
async def folder_events(
    folder_id: str | None = None,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Stream folder change events as Server-Sent Events."""
    if folder_id is not None:
        try:
            folder_id = validate_uuid(folder_id)
        except ValueError:
            folder_id = None

    topic = folder_id if folder_id else f"root:{user.id}"

    async def event_stream():
        q = sse_broker.subscribe(topic)
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=_HEARTBEAT_INTERVAL)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            sse_broker.unsubscribe(topic, q)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx proxy buffering for SSE
        },
    )
