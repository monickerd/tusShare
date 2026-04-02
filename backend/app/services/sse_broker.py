"""In-memory SSE pub/sub broker.

Topics are strings:
  - A folder UUID       → all clients currently viewing that folder
  - "root:<user_id>"   → a user's root file view

Single-process only. For multi-worker deployments this would need to be
replaced with a Redis Pub/Sub backed implementation.
"""
import asyncio
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# topic → set of asyncio.Queue instances (one per connected SSE client)
_listeners: dict[str, set[asyncio.Queue]] = defaultdict(set)


def subscribe(topic: str) -> asyncio.Queue:
    """Register a new listener for *topic*. Returns the queue to read from."""
    q: asyncio.Queue = asyncio.Queue(maxsize=32)
    _listeners[topic].add(q)
    return q


def unsubscribe(topic: str, q: asyncio.Queue) -> None:
    """Remove *q* from *topic*. Safe to call even if already absent."""
    _listeners[topic].discard(q)
    if not _listeners[topic]:
        _listeners.pop(topic, None)


def publish(topic: str, event: dict) -> None:
    """Push *event* to every listener on *topic*. Non-blocking.

    Queues that are full (slow / stalled clients) are silently dropped and
    removed so they don't accumulate indefinitely.
    """
    if topic not in _listeners:
        return
    dead: set[asyncio.Queue] = set()
    for q in _listeners[topic]:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            logger.debug("SSE queue full on topic %s — dropping slow client", topic)
            dead.add(q)
    for q in dead:
        _listeners[topic].discard(q)
    if not _listeners[topic]:
        _listeners.pop(topic, None)
