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
from contextlib import asynccontextmanager
from datetime import timezone

from app.schemas.security_event import SecurityEvent

logger = logging.getLogger(__name__)

# Subscriber queue capacity — events are dropped for a slow consumer rather
# than letting it grow without bound and OOM the process.
_SUBSCRIBER_MAXSIZE = 2000

# Module-level queue: emitters put events here; the drainer task reads them.
_write_queue: asyncio.Queue[SecurityEvent] = asyncio.Queue()

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
    _write_queue.put_nowait(event)


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


async def start() -> asyncio.Task:
    """Start the background drainer task. Returns the task for cancellation."""
    global _drainer_task
    _drainer_task = asyncio.create_task(_drain_loop(), name="event_bus_drainer")
    return _drainer_task


# ---------------------------------------------------------------------------
# Internal — drainer + persistence
# ---------------------------------------------------------------------------

async def _drain_loop() -> None:
    """Drain the write queue: persist each event then fan out to subscribers."""
    while True:
        try:
            event = await _write_queue.get()
            await _persist(event)
            _fanout(event)
        except asyncio.CancelledError:
            # Flush remaining events before exiting so nothing is silently lost.
            while not _write_queue.empty():
                try:
                    event = _write_queue.get_nowait()
                    await _persist(event)
                    _fanout(event)
                except asyncio.QueueEmpty:
                    break
                except Exception:
                    logger.exception("Event bus: error flushing event on shutdown")
            return
        except Exception:
            logger.exception("Event bus: unhandled error in drain loop")


async def _persist(event: SecurityEvent) -> None:
    """Write the event to the security_events table."""
    if _db_session_factory is None:
        logger.warning("Event bus: db_session_factory not set — event not persisted")
        return
    try:
        async with _db_session_factory() as db:
            ts = event.timestamp.astimezone(timezone.utc).isoformat()
            detail_json = json.dumps(event.detail) if event.detail else None
            await db.execute(
                """
                INSERT INTO security_events
                    (id, user_id, actor_username, ip_address, user_agent, event_type,
                     severity, outcome, actor_session_id,
                     target_type, target_id, target_name,
                     admin_actor_id, detail, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    event.actor.user_id,
                    event.actor.username,
                    event.actor.ip or "",
                    None,                           # user_agent — not available at bus level
                    event.event_type,
                    event.severity,
                    event.outcome,
                    event.actor.session_id,
                    event.target.type if event.target else None,
                    event.target.id if event.target else None,
                    event.target.name if event.target else None,
                    event.admin_actor_id,
                    detail_json,
                    ts,
                ),
            )
            await db.commit()
    except Exception:
        logger.exception("Event bus: failed to persist event %s", event.event_type)


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
