"""SSE pub/sub broker.

Single-worker mode (no Redis configured): in-process asyncio.Queue fanout.
Multi-worker mode (TUSSHARE_REDIS_URL set): publish via Redis Pub/Sub;
  a background listener task fans messages out to per-client local queues.

Topics are strings:
  - A folder UUID       → clients viewing that folder
  - "root:<user_id>"   → a user's root file view
"""

import asyncio
import json
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

_CHANNEL_PREFIX = "sse:"

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


def _fanout_local(topic: str, event: dict) -> None:
    """Push *event* to every local listener queue on *topic*."""
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


async def _redis_publish(topic: str, event: dict) -> None:
    from app.redis_client import get_redis
    r = get_redis()
    if r is None:
        _fanout_local(topic, event)
        return
    try:
        await r.publish(f"{_CHANNEL_PREFIX}{topic}", json.dumps(event))
    except Exception as exc:
        logger.warning("Redis SSE publish failed (%s); falling back to local fanout", exc)
        _fanout_local(topic, event)


def publish(topic: str, event: dict) -> None:
    """Push *event* to listeners.

    When Redis is configured, publishes to the Redis Pub/Sub channel so all
    workers receive the message.  Falls back to local fanout on Redis failure
    or when Redis is not configured.
    """
    from app.redis_client import get_redis
    if get_redis() is not None:
        asyncio.create_task(_redis_publish(topic, event))
    else:
        _fanout_local(topic, event)


async def run_redis_listener() -> None:
    """Background task: subscribe to all SSE channels and fan out to local queues.

    Only runs when TUSSHARE_REDIS_URL is set.  Cancelled cleanly on shutdown.
    """
    from app.redis_client import get_redis
    r = get_redis()
    if r is None:
        return

    pubsub = r.pubsub()
    await pubsub.psubscribe(f"{_CHANNEL_PREFIX}*")
    logger.info("Redis SSE listener active on pattern %s*", _CHANNEL_PREFIX)
    try:
        async for message in pubsub.listen():
            if message.get("type") not in ("pmessage", "message"):
                continue
            channel = message.get("channel", "")
            if not channel.startswith(_CHANNEL_PREFIX):
                continue
            topic = channel[len(_CHANNEL_PREFIX):]
            try:
                event = json.loads(message["data"])
            except Exception:
                continue
            _fanout_local(topic, event)
    except asyncio.CancelledError:
        logger.info("Redis SSE listener cancelled")
        await pubsub.punsubscribe()
        try:
            await pubsub.aclose()
        except Exception:
            pass
        raise
    except Exception as exc:
        logger.error("Redis SSE listener crashed: %s", exc)
        raise
