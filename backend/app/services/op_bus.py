"""Operational event bus.

Architecture mirrors event_bus.py. Extra features:
  - State-transition deduplication gate for stateful event types
  - Persistence to operational_events table
  - Background cleanup (hourly) and API key expiry check (daily)
  - server_id resolution from admin_settings with 60-second cache

Public API:
  emit(event)          — sync, non-blocking
  subscribe()          — returns asyncio.Queue[OperationalEvent]
  unsubscribe(q)
  init(db_factory)
  async start()        — starts drainer, returns Task
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone

from app.schemas.op_event import OperationalEvent
from app.util.db import get_admin_setting

_bg_tasks: set = set()

logger = logging.getLogger(__name__)

_SUBSCRIBER_MAXSIZE = 2000

_write_queue: asyncio.Queue[OperationalEvent] = asyncio.Queue()
_subscribers: list[asyncio.Queue[OperationalEvent]] = []
_db_session_factory = None

# ---------------------------------------------------------------------------
# Event type constants
# ---------------------------------------------------------------------------

_EVT_API_KEY_EXPIRING = "system.api_key.expiring_soon"
_EVT_API_KEY_EXPIRED = "system.api_key.expired"

# ---------------------------------------------------------------------------
# State-transition deduplication gate
# ---------------------------------------------------------------------------

_STATEFUL_TYPES: frozenset[str] = frozenset(
    {
        "storage.volume.capacity_warning",
        "storage.volume.capacity_ok",
        "upload.quota.warning",
        "upload.quota.ok",
        _EVT_API_KEY_EXPIRING,
        _EVT_API_KEY_EXPIRED,
    }
)

_PROBLEM_EVENTS: frozenset[str] = frozenset(
    {
        "storage.volume.capacity_warning",
        "upload.quota.warning",
        _EVT_API_KEY_EXPIRING,
        _EVT_API_KEY_EXPIRED,
    }
)

# state_key → "problem" | "ok"  (in-memory, single-process)
_state: dict[str, str] = {}


def _state_key(event: OperationalEvent) -> str:
    d = event.data
    resource = d.get("volume_id") or d.get("user_id") or d.get("key_id") or event.source
    return f"{event.source}::{resource}"


def _should_pass_gate(event: OperationalEvent) -> bool:
    """Return True if the event should proceed through the bus."""
    if event.event_type not in _STATEFUL_TYPES:
        return True
    sk = _state_key(event)
    is_problem = event.event_type in _PROBLEM_EVENTS
    last = _state.get(sk)
    if is_problem and last == "problem":
        return False
    if not is_problem and last != "problem":
        return False
    _state[sk] = "problem" if is_problem else "ok"
    return True


# ---------------------------------------------------------------------------
# server_id cache
# ---------------------------------------------------------------------------

_server_id_cache: str | None = None
_server_id_fetched_at: float = 0.0
_SERVER_ID_TTL = 60.0


async def _get_server_id_cached(db) -> str | None:
    global _server_id_cache, _server_id_fetched_at
    if time.monotonic() - _server_id_fetched_at < _SERVER_ID_TTL:
        return _server_id_cache
    cursor = await db.execute("SELECT value FROM admin_settings WHERE key = 'server_id'")
    row = await cursor.fetchone()
    val = row["value"] if row else None
    _server_id_cache = val if val else socket.gethostname()
    _server_id_fetched_at = time.monotonic()
    return _server_id_cache


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def emit(event: OperationalEvent) -> None:
    """Enqueue an operational event. Synchronous, non-blocking."""
    _write_queue.put_nowait(event)


def subscribe() -> asyncio.Queue[OperationalEvent]:
    q: asyncio.Queue[OperationalEvent] = asyncio.Queue(maxsize=_SUBSCRIBER_MAXSIZE)
    _subscribers.append(q)
    return q


def unsubscribe(q: asyncio.Queue[OperationalEvent]) -> None:
    try:
        _subscribers.remove(q)
    except ValueError:
        pass


def init(db_session_factory) -> None:
    global _db_session_factory
    _db_session_factory = db_session_factory


def start() -> asyncio.Task:
    task = asyncio.create_task(_drain_loop(), name="op_bus_drainer")
    return task


# ---------------------------------------------------------------------------
# Internal — drainer
# ---------------------------------------------------------------------------


async def _flush_remaining() -> None:
    while not _write_queue.empty():
        try:
            event = _write_queue.get_nowait()
            if _should_pass_gate(event):
                await _persist(event)
                _fanout(event)
        except asyncio.QueueEmpty:
            break
        except Exception:
            logger.exception("op_bus: error flushing on shutdown")


def _tick_background_tasks(now: float, last_cleanup: float, last_key_check: float) -> tuple[float, float]:
    if now - last_cleanup > 3600:
        _t = asyncio.create_task(_cleanup_old_events())
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)
        last_cleanup = now
    if now - last_key_check > 86400:
        _t = asyncio.create_task(_check_api_key_expiry())
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)
        last_key_check = now
    return last_cleanup, last_key_check


async def _drain_loop() -> None:
    last_cleanup = time.monotonic()
    last_key_check = time.monotonic()

    while True:
        try:
            event = await _write_queue.get()
            if _should_pass_gate(event):
                await _persist(event)
                _fanout(event)

            last_cleanup, last_key_check = _tick_background_tasks(time.monotonic(), last_cleanup, last_key_check)

        except asyncio.CancelledError:
            await _flush_remaining()
            raise
        except Exception:
            logger.exception("op_bus: unhandled error in drain loop")


async def _persist(event: OperationalEvent) -> None:
    if _db_session_factory is None:
        return
    try:
        async with _db_session_factory() as db:
            server_id = await _get_server_id_cached(db)
            ts = event.timestamp.astimezone(timezone.utc).isoformat()
            await db.execute(
                "INSERT INTO operational_events "
                "(id, event_id, event_type, severity, source, data_json, server_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    event.event_id,
                    event.event_type,
                    event.severity,
                    event.source,
                    json.dumps(event.data, separators=(",", ":")),
                    server_id,
                    ts,
                ),
            )
            await db.commit()
    except Exception:
        logger.exception("op_bus: failed to persist event %s", event.event_type)


def _fanout(event: OperationalEvent) -> None:
    dead: list[asyncio.Queue] = []
    for q in _subscribers:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            logger.debug("op_bus: subscriber queue full — dropping slow consumer")
            dead.append(q)
    for q in dead:
        unsubscribe(q)


# ---------------------------------------------------------------------------
# Background jobs
# ---------------------------------------------------------------------------


async def _cleanup_old_events() -> None:
    if _db_session_factory is None:
        return
    try:
        async with _db_session_factory() as db:
            days = await get_admin_setting(db, "op_event_retention_days", default=30, dtype=int)
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            await db.execute("DELETE FROM operational_events WHERE created_at < ?", (cutoff,))
            await db.commit()
            logger.debug("op_bus: cleaned up events older than %d days", days)
    except Exception:
        logger.exception("op_bus: error in cleanup task")


async def _check_api_key_expiry() -> None:
    if _db_session_factory is None:
        return
    try:
        async with _db_session_factory() as db:
            warn_days = await get_admin_setting(db, "api_key_expiry_warn_days", default=30, dtype=int)
            now = datetime.now(timezone.utc)
            warn_cutoff = (now + timedelta(days=warn_days)).isoformat()

            cursor = await db.execute(
                "SELECT id, name, expires_at FROM api_keys WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (warn_cutoff,),
            )
            rows = await cursor.fetchall()
            for row in rows:
                exp = datetime.fromisoformat(row["expires_at"])
                if exp <= now:
                    emit(
                        OperationalEvent(
                            event_type=_EVT_API_KEY_EXPIRED,
                            severity="error",
                            source="system",
                            data={
                                "key_id": row["id"],
                                "key_name": row["name"],
                                "expires_at": row["expires_at"],
                            },
                        )
                    )
                else:
                    emit(
                        OperationalEvent(
                            event_type=_EVT_API_KEY_EXPIRING,
                            severity="warning",
                            source="system",
                            data={
                                "key_id": row["id"],
                                "key_name": row["name"],
                                "expires_at": row["expires_at"],
                                "days_remaining": (exp - now).days,
                            },
                        )
                    )
    except Exception:
        logger.exception("op_bus: error in api_key expiry check")
