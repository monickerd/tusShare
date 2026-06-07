"""Internal security event bus.

Architecture
------------
emit(SecurityEvent)  ← synchronous, non-blocking, safe to call anywhere
        │
asyncio.Queue  (write queue, unbounded — emitters never block)
        │
background drainer task  (one task, owns its own DB connection)
   ├── persists event to security_events table
   └── fans out to subscriber queues (bounded, slow consumers are dropped)
              ├── SSE audit stream    subscribe()/unsubscribe()
              ├── syslog dispatcher  subscribe()/unsubscribe()
              └── webhook dispatcher subscribe()/unsubscribe()

SIEM output paths are coroutines that call subscribe() at startup and
``await q.get()`` in a loop. No changes to this module are required
to add new output paths.

Single-process only — replace with a Redis-backed implementation for
multi-worker deployments (same as sse_broker).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import timezone

from app.config import settings
from app.schemas.security_event import SecurityEvent
from app.services import audit_key as _audit_key

logger = logging.getLogger(__name__)

# Subscriber queue capacity — events are dropped for a slow consumer rather
# than letting it grow without bound and OOM the process.
_SUBSCRIBER_MAXSIZE = 2000

# Maximum number of persist-flagged events batched into a single INSERT+COMMIT.
_PERSIST_BATCH_MAX = 100

# Module-level queue: emitters put (event, should_persist) tuples here.
# should_persist=False is used when the caller already wrote the DB row inline
# and only wants fan-out to SSE/syslog/webhook subscribers.
_write_queue: asyncio.Queue[tuple[SecurityEvent, bool]] = asyncio.Queue()

# Live subscriber queues — each is a bounded asyncio.Queue.
_subscribers: list[asyncio.Queue[SecurityEvent]] = []

# Set once during lifespan startup.
_db_session_factory = None
_drainer_task: asyncio.Task | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def emit(event: SecurityEvent) -> None:
    """Enqueue a security event for persistence and fan-out.

    Synchronous and non-blocking — safe to call from any route handler or
    background task without await. The drainer task persists and fans out
    asynchronously.
    """
    _write_queue.put_nowait((event, True))


def emit_fanout_only(event: SecurityEvent) -> None:
    """Enqueue a security event for fan-out only — skip the DB persist step.

    Use this when the caller has already written the row to security_events
    inline (e.g. log_security_event) and only needs SIEM subscriber delivery
    (SSE stream, syslog, webhook) without creating a duplicate DB row.
    """
    _write_queue.put_nowait((event, False))


def subscribe() -> asyncio.Queue[SecurityEvent]:
    """Register a live consumer. Returns a bounded queue to read from.

    The caller is responsible for calling unsubscribe() when done, e.g.
    in a finally block, to avoid accumulating stale subscriber references.
    """
    q: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=_SUBSCRIBER_MAXSIZE)
    _subscribers.append(q)
    return q


def unsubscribe(q: asyncio.Queue[SecurityEvent]) -> None:
    """Remove a subscriber queue. Safe to call even if already removed."""
    try:
        _subscribers.remove(q)
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Lifecycle — called from main.py lifespan
# ---------------------------------------------------------------------------


def init(db_session_factory) -> None:
    """Store the DB session factory. Called once before start()."""
    global _db_session_factory
    _db_session_factory = db_session_factory


def start() -> asyncio.Task:
    """Start the background drainer task. Returns the task for cancellation."""
    global _drainer_task
    _clear_capture()
    _drainer_task = asyncio.create_task(_drain_loop(), name="event_bus_drainer")
    return _drainer_task


# ---------------------------------------------------------------------------
# Internal — drainer + persistence
# ---------------------------------------------------------------------------


async def _flush_remaining_events() -> None:
    while not _write_queue.empty():
        try:
            event, should_persist = _write_queue.get_nowait()
            if should_persist:
                await _persist(event)
            _fanout(event)
        except asyncio.QueueEmpty:
            break
        except Exception:
            logger.exception("Event bus: error flushing event on shutdown")


async def _drain_loop() -> None:
    """Drain the write queue: persist events in batches then fan out to subscribers."""
    while True:
        try:
            # Block on the first event, then greedily drain the rest without blocking.
            event, should_persist = await _write_queue.get()
            batch_persist: list[SecurityEvent] = []
            if should_persist:
                batch_persist.append(event)
            _fanout(event)

            while len(batch_persist) < _PERSIST_BATCH_MAX:
                try:
                    ev2, sp2 = _write_queue.get_nowait()
                    if sp2:
                        batch_persist.append(ev2)
                    _fanout(ev2)
                except asyncio.QueueEmpty:
                    break

            if len(batch_persist) == 1:
                await _persist(batch_persist[0])
            elif batch_persist:
                await _persist_batch(batch_persist)
        except asyncio.CancelledError:
            await _flush_remaining_events()
            raise
        except Exception:
            logger.exception("Event bus: unhandled error in drain loop")


def _build_persist_params(event: SecurityEvent, event_id: str) -> tuple:
    """Build INSERT params for security_events, encrypting sensitive fields.

    If K_audit is available the social-graph fields are bundled into detail_enc
    (AES-256-GCM) and stored as NULL in their plaintext columns.  Readers that
    need the fields must decrypt detail_enc.  The four routing columns
    (event_type, severity, outcome, timestamp) are always plaintext.
    """
    ts = event.timestamp.astimezone(timezone.utc).isoformat()

    k = _audit_key.get_k_audit()
    if k is not None:
        sensitive = {
            "actor_username": event.actor.username,
            "ip_address":     event.actor.ip or "",
            "target_id":      event.target.id   if event.target else None,
            "target_name":    event.target.name if event.target else None,
            "admin_actor_id": event.admin_actor_id,
            "detail":         event.detail or {},
        }
        detail_enc = _audit_key.encrypt_detail(sensitive)
        actor_username = None
        ip_address     = None
        target_id      = event.target.id   if event.target else None  # kept for filtering
        target_name    = None
        admin_actor_id = None
        detail_json    = None
    else:
        detail_enc     = None
        actor_username = event.actor.username
        ip_address     = event.actor.ip or ""
        target_id      = event.target.id   if event.target else None
        target_name    = event.target.name if event.target else None
        admin_actor_id = event.admin_actor_id
        detail_json    = json.dumps(event.detail) if event.detail else None

    return (
        event_id,
        event.actor.user_id,
        actor_username,
        event.actor.auth_method,
        ip_address,
        None,  # user_agent — not available at bus level
        event.event_type,
        event.severity,
        event.outcome,
        event.actor.session_id,
        event.target.type if event.target else None,
        target_id,
        target_name,
        admin_actor_id,
        detail_json,
        ts,
        detail_enc,
    )


async def _persist(event: SecurityEvent) -> None:
    """Write the event to the security_events table."""
    if _db_session_factory is None:
        logger.warning("Event bus: db_session_factory not set — event not persisted")
        return
    try:
        async with _db_session_factory() as db:
            params = _build_persist_params(event, str(uuid.uuid4()))
            await db.execute(
                """
                INSERT INTO security_events
                    (id, user_id, actor_username, actor_auth_method, ip_address, user_agent,
                     event_type, severity, outcome, actor_session_id,
                     target_type, target_id, target_name,
                     admin_actor_id, detail, timestamp, detail_enc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                params,
            )
            await db.commit()
    except Exception:
        logger.exception("Event bus: failed to persist event %s", event.event_type)


async def _persist_batch(events: list[SecurityEvent]) -> None:
    """Write multiple security events in a single INSERT+COMMIT."""
    if _db_session_factory is None:
        logger.warning("Event bus: db_session_factory not set — %d events not persisted", len(events))
        return
    try:
        async with _db_session_factory() as db:
            for event in events:
                params = _build_persist_params(event, str(uuid.uuid4()))
                await db.execute(
                    """
                    INSERT INTO security_events
                        (id, user_id, actor_username, actor_auth_method, ip_address, user_agent,
                         event_type, severity, outcome, actor_session_id,
                         target_type, target_id, target_name,
                         admin_actor_id, detail, timestamp, detail_enc)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    params,
                )
            await db.commit()
    except Exception:
        logger.exception("Event bus: failed to persist batch of %d events", len(events))


def _fanout(event: SecurityEvent) -> None:
    """Push event to all live subscriber queues. Drop slow consumers."""
    dead: list[asyncio.Queue] = []
    for q in _subscribers:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            logger.debug("Event bus: subscriber queue full — dropping slow consumer")
            dead.append(q)
    for q in dead:
        unsubscribe(q)
    _write_capture(event)


def _write_capture(event: SecurityEvent) -> None:
    """Append event as a JSON line to SIEM_CAPTURE_FILE. No-op if not configured."""
    path = settings.SIEM_CAPTURE_FILE
    if not path:
        return
    try:
        line = json.dumps(event.model_dump(mode="json"))
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        logger.exception("Event bus: failed to write SIEM capture file")


def _clear_capture() -> None:
    """Truncate the capture file at startup. No-op if SIEM_CAPTURE_FILE not set."""
    path = settings.SIEM_CAPTURE_FILE
    if not path:
        return
    try:
        open(path, "w").close()  # noqa: WPS515
    except Exception:
        logger.exception("Event bus: failed to clear SIEM capture file")
