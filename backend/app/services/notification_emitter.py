"""Notification emitter — supervisor + per-channel delivery loops.

Subscribes to op_bus (always) and optionally to event_bus (when ≥1 active
channel has a "security:" prefix filter). Reloads channel configs every 60 s.

Public API:
  init(db_factory)
  async start()            — returns supervisor Task
  async reload(db)         — force immediate config reload
  async catch_up(id, db)  — deliver current warning states to a new channel
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.schemas.op_event import OperationalEvent
from app.services import op_bus

logger = logging.getLogger(__name__)

_db_session_factory = None
_reload_event: asyncio.Event | None = None

# Populated by supervisor; keyed by channel_id → asyncio.Queue
_channel_queues: dict[str, asyncio.Queue] = {}

_RETRY_DELAYS = (5, 20, 60)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init(db_factory) -> None:
    global _db_session_factory
    _db_session_factory = db_factory


async def start() -> asyncio.Task:
    global _reload_event
    _reload_event = asyncio.Event()
    task = asyncio.create_task(_supervisor_loop(), name="notif_emitter_supervisor")
    return task


async def reload(db) -> None:
    """Force the supervisor to reload channel configs immediately."""
    if _reload_event is not None:
        _reload_event.set()


async def catch_up(channel_id: str, db) -> None:
    """Deliver current warning states to a newly created channel."""
    catch_up_events: list[OperationalEvent] = []

    # 1. Storage volumes
    try:
        from app.storage.manager import get_manager
        cursor = await db.execute(
            "SELECT key, value FROM admin_settings WHERE key IN (?, ?)",
            ("storage_warn_pct", "storage_warn_bytes_remaining"),
        )
        rows = await cursor.fetchall()
        sm = {r["key"]: r["value"] for r in rows}
        warn_pct   = float(sm["storage_warn_pct"])         if sm.get("storage_warn_pct")            else 90.0
        warn_bytes = int(sm["storage_warn_bytes_remaining"]) if sm.get("storage_warn_bytes_remaining") else 1 * 1024 ** 3

        mgr = get_manager()
        usage = await mgr.get_usage_summary(warn_pct=warn_pct, warn_bytes_remaining=warn_bytes)
        for vol in usage.get("volumes", []):
            if vol.get("warning"):
                e = OperationalEvent(
                    event_type="storage.volume.capacity_warning",
                    severity="warning", source="storage",
                    data={**vol, "catch_up": True},
                )
                catch_up_events.append(e)
                op_bus._state[f"storage::{vol.get('id', vol.get('name', ''))}"] = "problem"
    except Exception:
        logger.exception("notif: catch-up storage usage check failed")

    # 2. User quotas
    try:
        cursor = await db.execute(
            "SELECT value FROM admin_settings WHERE key = 'upload_quota_warn_pct'"
        )
        row = await cursor.fetchone()
        warn_pct_upload = int(row["value"]) if row and row["value"] else 90

        cursor = await db.execute(
            "SELECT id, disk_used, disk_quota FROM users "
            "WHERE disk_quota IS NOT NULL AND disk_used * 100.0 / disk_quota >= ?",
            (warn_pct_upload,),
        )
        for row in await cursor.fetchall():
            e = OperationalEvent(
                event_type="upload.quota.warning", severity="warning", source="upload",
                data={
                    "user_id":     row["id"],
                    "used_bytes":  row["disk_used"],
                    "quota_bytes": row["disk_quota"],
                    "used_pct":    round(row["disk_used"] / row["disk_quota"] * 100, 1),
                    "catch_up":    True,
                },
            )
            catch_up_events.append(e)
            op_bus._state[f"upload::{row['id']}"] = "problem"
    except Exception:
        logger.exception("notif: catch-up quota check failed")

    # 3. API key expiry
    try:
        cursor = await db.execute(
            "SELECT value FROM admin_settings WHERE key = 'api_key_expiry_warn_days'"
        )
        row = await cursor.fetchone()
        warn_days = int(row["value"]) if row and row["value"] else 30
        warn_cutoff = (datetime.now(timezone.utc) + timedelta(days=warn_days)).isoformat()

        cursor = await db.execute(
            "SELECT id, name, expires_at FROM api_keys "
            "WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (warn_cutoff,),
        )
        for row in await cursor.fetchall():
            e = OperationalEvent(
                event_type="system.api_key.expiring_soon", severity="warning", source="system",
                data={
                    "key_id":    row["id"],
                    "key_name":  row["name"],
                    "expires_at": row["expires_at"],
                    "catch_up":  True,
                },
            )
            catch_up_events.append(e)
            op_bus._state[f"system::{row['id']}"] = "problem"
    except Exception:
        logger.exception("notif: catch-up api_key expiry check failed")

    if not catch_up_events:
        return

    channel_q = _channel_queues.get(channel_id)
    if channel_q:
        for e in catch_up_events:
            try:
                channel_q.put_nowait(e)
            except asyncio.QueueFull:
                logger.warning("notif: catch-up queue full for channel %s", channel_id)


# ---------------------------------------------------------------------------
# Filter helpers
# ---------------------------------------------------------------------------

def _matches_filter(event_type: str, filters: list[str]) -> bool:
    """Dot-segment prefix match for operational events. [] = accept all."""
    if not filters:
        return True
    for f in filters:
        if f.startswith("security:"):
            continue
        if event_type == f or event_type.startswith(f + "."):
            return True
    return False


def _matches_security_filter(event_type: str, filters: list[str]) -> bool:
    for f in filters:
        if not f.startswith("security:"):
            continue
        prefix = f[len("security:"):]
        if event_type == prefix or event_type.startswith(prefix + "."):
            return True
    return False


def _security_to_op(sec_event) -> dict:
    return {
        "event_id":   sec_event.event_id,
        "timestamp":  sec_event.timestamp.astimezone(timezone.utc).isoformat(),
        "version":    "1",
        "event_type": sec_event.event_type,
        "severity":   sec_event.severity,
        "source":     "security",
        "data": {
            "actor": {
                "user_id":  sec_event.actor.user_id,
                "username": sec_event.actor.username,
                "ip":       sec_event.actor.ip,
            },
            "target": (
                {
                    "type": sec_event.target.type,
                    "id":   sec_event.target.id,
                    "name": sec_event.target.name,
                }
                if sec_event.target else None
            ),
            "outcome": sec_event.outcome,
            "detail":  sec_event.detail,
        },
        "server_id": None,
    }


def _event_to_dict(event: OperationalEvent) -> dict:
    return {
        "event_id":   event.event_id,
        "timestamp":  event.timestamp.astimezone(timezone.utc).isoformat(),
        "version":    event.version,
        "event_type": event.event_type,
        "severity":   event.severity,
        "source":     event.source,
        "data":       event.data,
        "server_id":  event.server_id,
    }


# ---------------------------------------------------------------------------
# Supervisor loop
# ---------------------------------------------------------------------------

async def _load_channels() -> list[dict]:
    if _db_session_factory is None:
        return []
    try:
        async with _db_session_factory() as db:
            cursor = await db.execute(
                "SELECT id, name, endpoint_url, secret_enc, event_filter, "
                "       batch_size, batch_interval_s, enabled "
                "FROM notification_channels"
            )
            return await cursor.fetchall()
    except Exception:
        logger.exception("notif: failed to load channels")
        return []


async def _supervisor_loop() -> None:
    channel_tasks:  dict[str, asyncio.Task] = {}
    channel_queues_local: dict[str, asyncio.Queue] = {}
    sec_sub_q: asyncio.Queue | None = None

    while True:
        channels = await _load_channels()

        needs_sec = any(
            any(f.startswith("security:") for f in json.loads(ch["event_filter"] or "[]"))
            for ch in channels
            if ch["enabled"]
        )

        if needs_sec and sec_sub_q is None:
            from app.services import event_bus
            sec_sub_q = event_bus.subscribe()
            asyncio.create_task(
                _forward_security_events(sec_sub_q, channel_queues_local),
                name="notif_sec_forwarder",
            )
        elif not needs_sec and sec_sub_q is not None:
            from app.services import event_bus
            event_bus.unsubscribe(sec_sub_q)
            sec_sub_q = None

        active_ids = {ch["id"] for ch in channels if ch["enabled"]}

        for ch_id in list(channel_tasks):
            if ch_id not in active_ids:
                channel_tasks[ch_id].cancel()
                del channel_tasks[ch_id]
                q = channel_queues_local.pop(ch_id, None)
                if q is not None:
                    op_bus.unsubscribe(q)
                _channel_queues.pop(ch_id, None)

        for ch in channels:
            if not ch["enabled"]:
                continue
            if ch["id"] not in channel_tasks:
                q = op_bus.subscribe()
                channel_queues_local[ch["id"]] = q
                _channel_queues[ch["id"]] = q
                t = asyncio.create_task(
                    _channel_loop(dict(ch), q),
                    name=f"notif_ch_{ch['id'][:8]}",
                )
                channel_tasks[ch["id"]] = t

        # Wait 60 s, but wake early on a forced reload
        try:
            await asyncio.wait_for(_reload_event.wait(), timeout=60.0)
            _reload_event.clear()
        except asyncio.TimeoutError:
            pass


async def _forward_security_events(
    sec_q: asyncio.Queue,
    chan_queues: dict[str, asyncio.Queue],
) -> None:
    try:
        while True:
            sec_event = await sec_q.get()
            event_dict = _security_to_op(sec_event)
            for ch_id, q in list(chan_queues.items()):
                # Only forward if the channel has matching security: filter
                channels = await _load_channels()
                ch_map = {c["id"]: c for c in channels}
                ch = ch_map.get(ch_id)
                if ch and _matches_security_filter(
                    sec_event.event_type,
                    json.loads(ch["event_filter"] or "[]"),
                ):
                    try:
                        q.put_nowait(event_dict)
                    except asyncio.QueueFull:
                        logger.debug("notif: security forwarder queue full for ch %s", ch_id)
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.exception("notif: security forwarder crashed")


# ---------------------------------------------------------------------------
# Per-channel delivery loop
# ---------------------------------------------------------------------------

async def _channel_loop(channel: dict, q: asyncio.Queue) -> None:
    batch_size = channel.get("batch_size")
    interval_s = channel.get("batch_interval_s")
    filters    = json.loads(channel.get("event_filter") or "[]")
    accumulated: list = []
    last_flush = time.monotonic()

    try:
        while True:
            if interval_s:
                elapsed = time.monotonic() - last_flush
                timeout = max(0.5, interval_s - elapsed)
            else:
                timeout = 30.0

            try:
                item = await asyncio.wait_for(q.get(), timeout=timeout)
                # item may be OperationalEvent (from op_bus) or dict (from security forwarder)
                if isinstance(item, OperationalEvent):
                    if _matches_filter(item.event_type, filters):
                        accumulated.append(_event_to_dict(item))
                else:
                    # Already a dict (security event reshaped)
                    accumulated.append(item)
            except asyncio.TimeoutError:
                pass

            now = time.monotonic()
            count_trigger = batch_size and len(accumulated) >= batch_size
            timer_trigger = interval_s and (now - last_flush) >= interval_s and accumulated
            if count_trigger or timer_trigger:
                asyncio.create_task(_send_with_retry(channel, list(accumulated)))
                accumulated.clear()
                last_flush = now
    except asyncio.CancelledError:
        if accumulated:
            asyncio.create_task(_send_with_retry(channel, list(accumulated)))
        op_bus.unsubscribe(q)


# ---------------------------------------------------------------------------
# HTTP delivery
# ---------------------------------------------------------------------------

async def _send_with_retry(channel: dict, events: list[dict]) -> None:
    for attempt, delay in enumerate((*_RETRY_DELAYS, None), start=1):
        try:
            await _send_one(channel, events)
            return
        except Exception as exc:
            logger.warning(
                "notif: attempt %d/%d failed for channel %s: %s",
                attempt, len(_RETRY_DELAYS) + 1, channel.get("name"), exc,
            )
            if delay is None:
                logger.error(
                    "notif: giving up on %d event(s) for channel %s",
                    len(events), channel.get("name"),
                )
                return
            await asyncio.sleep(delay)


async def _send_one(channel: dict, events: list[dict]) -> None:
    from app.services.notification_crypto import decrypt_channel_secret

    url    = channel["endpoint_url"]
    secret = ""
    if channel.get("secret_enc"):
        try:
            secret = decrypt_channel_secret(channel["secret_enc"])
        except Exception:
            logger.warning("notif: could not decrypt secret for channel %s", channel["id"])

    body = json.dumps({"events": events}, separators=(",", ":")).encode()
    sig  = _sign(secret, body) if secret else ""

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "X-TusShare-Notification-Count": str(len(events)),
    }
    if sig:
        headers["X-TusShare-Notification-Signature"] = f"sha256={sig}"

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, content=body, headers=headers)
        resp.raise_for_status()


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
