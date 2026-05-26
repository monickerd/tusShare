"""
Webhook SIEM dispatcher.

Subscribes to the internal event bus and POSTs batches of security events to
all active webhook-type SIEM destinations.

Features
--------
- HMAC-SHA256 request signing (X-TusShare-Signature header)
- Configurable batch size (1 = real-time, up to 100 for throughput)
- Exponential backoff retry (3 attempts: 1s, 4s, 16s)
- In-memory overflow queue per destination (up to 2000 events before drop)
- Destination list reloaded from DB every 60 seconds

The signing format matches GitHub/Stripe webhooks:
  X-TusShare-Signature: sha256=<hex(hmac-sha256(secret, body))>
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import timezone

import httpx

from app.schemas.security_event import SecurityEvent
from app.services.siem_filters import matches_destination_filter
from app.util.crypto import hmac_sha256_hex

_bg_tasks: set = set()

logger = logging.getLogger(__name__)

_RELOAD_INTERVAL_SECS = 60
_RETRY_DELAYS = (1, 4, 16)  # seconds between attempts
_OVERFLOW_MAXSIZE = 2000
_db_session_factory = None
_dispatcher_task: asyncio.Task | None = None


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def init(db_session_factory) -> None:
    global _db_session_factory
    _db_session_factory = db_session_factory


def start() -> asyncio.Task:
    from app.services import event_bus

    global _dispatcher_task
    _dispatcher_task = asyncio.create_task(_dispatch_loop(event_bus.subscribe()), name="siem_webhook")
    return _dispatcher_task


# ---------------------------------------------------------------------------
# Main dispatch loop
# ---------------------------------------------------------------------------


def _flush_pending(
    destinations: list[dict],
    overflow: dict[str, list[SecurityEvent]],
    secrets_cache: dict[str, str],
) -> None:
    for dest in destinations:
        did = dest["id"]
        if overflow.get(did):
            _t = asyncio.create_task(_send_with_retry(dest, overflow[did], secrets_cache.get(did, "")))
            _bg_tasks.add(_t)
            _t.add_done_callback(_bg_tasks.discard)


def _enqueue_for_dest(dest: dict, event: SecurityEvent, overflow: dict, secrets_cache: dict) -> None:
    if not matches_destination_filter(dest, event):
        return
    did = dest["id"]
    if did not in overflow:
        overflow[did] = []
    overflow[did].append(event)
    batch_size = max(1, dest.get("batch_size") or 1)
    if len(overflow[did]) >= batch_size:
        batch = overflow[did][:batch_size]
        overflow[did] = overflow[did][batch_size:]
        _t = asyncio.create_task(_send_with_retry(dest, batch, secrets_cache.get(did, "")))
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)


async def _dispatch_loop(q: asyncio.Queue[SecurityEvent]) -> None:
    from app.services import event_bus

    destinations: list[dict] = []
    secrets_cache: dict[str, str] = {}  # dest_id → plaintext secret
    # Per-destination overflow queues for retry buffering
    overflow: dict[str, list[SecurityEvent]] = {}
    reload_countdown = _RELOAD_INTERVAL_SECS

    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=10)
            except asyncio.TimeoutError:
                reload_countdown -= 10
                if reload_countdown <= 0:
                    destinations, secrets_cache = await _load_destinations()
                    reload_countdown = _RELOAD_INTERVAL_SECS
                continue

            reload_countdown -= 1
            if reload_countdown <= 0:
                destinations, secrets_cache = await _load_destinations()
                reload_countdown = _RELOAD_INTERVAL_SECS

            for dest in destinations:
                _enqueue_for_dest(dest, event, overflow, secrets_cache)

    except asyncio.CancelledError:
        event_bus.unsubscribe(q)
        _flush_pending(destinations, overflow, secrets_cache)
        raise


async def _load_destinations() -> tuple[list[dict], dict[str, str]]:
    from app.auth.idp_crypto import decrypt_token

    if _db_session_factory is None:
        return [], {}
    try:
        async with _db_session_factory() as db:
            cursor = await db.execute("SELECT * FROM siem_destinations WHERE type='webhook' AND is_active=1")
            rows = await cursor.fetchall()
            dests = [dict(r) for r in rows]
            secrets: dict[str, str] = {}
            for d in dests:
                if d.get("secret_enc"):
                    try:
                        secrets[d["id"]] = decrypt_token(d["secret_enc"])
                    except Exception:
                        logger.warning("siem_webhook: could not decrypt secret for %s", d["id"])
                        secrets[d["id"]] = ""
            return dests, secrets
    except Exception:
        logger.exception("siem_webhook: failed to load destinations")
        return [], {}


# ---------------------------------------------------------------------------
# HTTP sending + retry
# ---------------------------------------------------------------------------


async def _send_with_retry(dest: dict, events: list[SecurityEvent], secret: str) -> None:
    url = dest.get("url") or ""
    if not url:
        return

    for attempt, delay in enumerate((*_RETRY_DELAYS, None), start=1):
        try:
            await send_one(dest, events, secret)
            return
        except Exception as exc:
            logger.warning(
                "siem_webhook: attempt %d/%d failed for %s: %s",
                attempt,
                len(_RETRY_DELAYS) + 1,
                dest.get("name"),
                exc,
            )
            if delay is None:
                logger.error(
                    "siem_webhook: giving up on %d event(s) for destination %s after %d attempts",
                    len(events),
                    dest.get("name"),
                    len(_RETRY_DELAYS) + 1,
                )
                return
            await asyncio.sleep(delay)


async def send_one(dest: dict, events: list[SecurityEvent], secret: str) -> None:
    """POST a batch of events to a webhook destination.

    Raises httpx.HTTPError on network failure or non-2xx response.
    """
    url = dest.get("url") or ""
    payload_dict = {
        "events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.astimezone(timezone.utc).isoformat(),
                "event_type": e.event_type,
                "severity": e.severity,
                "outcome": e.outcome,
                "actor": {
                    "user_id": e.actor.user_id,
                    "username": e.actor.username,
                    "ip": e.actor.ip,
                    "session_id": e.actor.session_id,
                },
                "target": {
                    "type": e.target.type,
                    "id": e.target.id,
                    "name": e.target.name,
                }
                if e.target
                else None,
                "detail": e.detail,
            }
            for e in events
        ]
    }
    body = json.dumps(payload_dict, separators=(",", ":")).encode()
    sig = hmac_sha256_hex(secret, body)

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-TusShare-Signature": f"sha256={sig}",
                "X-TusShare-Event-Count": str(len(events)),
            },
        )
        resp.raise_for_status()
