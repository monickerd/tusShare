"""
Syslog SIEM dispatcher.

Subscribes to the internal event bus and forwards every security event to all
active syslog-type SIEM destinations.

Supported output formats:
  - RFC 5424 -- structured syslog with STRUCTURED-DATA block
  - CEF       -- ArcSight Common Event Format
  - LEEF      -- IBM QRadar Log Event Extended Format

Transport: UDP (default), TCP, or TLS (wraps TCP with ssl.SSLContext).

The dispatcher reloads its destination list from the DB every 60 seconds so
admin changes take effect without a restart.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import timezone

from app.schemas.security_event import SecurityEvent
from app.services.siem_filters import matches_destination_filter

logger = logging.getLogger(__name__)

_RELOAD_INTERVAL_SECS = 60
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
    _dispatcher_task = asyncio.create_task(_dispatch_loop(event_bus.subscribe()), name="siem_syslog")
    return _dispatcher_task


# ---------------------------------------------------------------------------
# Main dispatch loop
# ---------------------------------------------------------------------------


async def _dispatch_to_destinations(destinations: list[dict], event: SecurityEvent) -> None:
    for dest in destinations:
        if not matches_destination_filter(dest, event):
            continue
        try:
            await send_one(dest, event)
        except Exception:
            logger.exception("Syslog dispatch error for destination %s", dest.get("id"))


async def _dispatch_loop(q: asyncio.Queue[SecurityEvent]) -> None:
    from app.services import event_bus

    destinations: list[dict] = []
    reload_countdown = _RELOAD_INTERVAL_SECS

    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=10)
            except asyncio.TimeoutError:
                reload_countdown -= 10
                if reload_countdown <= 0:
                    destinations = await _load_destinations()
                    reload_countdown = _RELOAD_INTERVAL_SECS
                continue

            reload_countdown -= 1
            if reload_countdown <= 0:
                destinations = await _load_destinations()
                reload_countdown = _RELOAD_INTERVAL_SECS

            await _dispatch_to_destinations(destinations, event)

    except asyncio.CancelledError:
        event_bus.unsubscribe(q)
        raise


async def _load_destinations() -> list[dict]:
    if _db_session_factory is None:
        return []
    try:
        async with _db_session_factory() as db:
            cursor = await db.execute("SELECT * FROM siem_destinations WHERE type='syslog' AND is_active=1")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
    except Exception:
        logger.exception("siem_syslog: failed to load destinations")
        return []


# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------

_SEVERITY_TO_SYSLOG = {"info": 6, "warning": 4, "critical": 2}  # syslog severity numbers


def _syslog_pri(facility: int, severity: str) -> int:
    sev = _SEVERITY_TO_SYSLOG.get(severity, 6)
    return facility * 8 + sev


def _format_rfc5424(dest: dict, event: SecurityEvent) -> bytes:
    """RFC 5424 structured syslog message.

    user_agent is intentionally omitted from all three syslog formats (RFC 5424,
    CEF, LEEF). Events arriving via the bus carry user_agent=None, and including
    it would require sanitising control characters to prevent syslog injection.
    """
    pri = _syslog_pri(dest.get("facility", 16), event.severity)
    ts = event.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    hostname = "-"
    app_name = "tusShare"
    msgid = event.event_type.replace(".", "_")
    structured = (
        f'[tusShare@0 event_type="{event.event_type}" '
        f'severity="{event.severity}" '
        f'outcome="{event.outcome or ""}" '
        f'actor_user_id="{event.actor.user_id or ""}" '
        f'actor_username="{event.actor.username or ""}" '
        f'actor_ip="{event.actor.ip or ""}"]'
    )
    msg = f"<{pri}>1 {ts} {hostname} {app_name} - {msgid} {structured}"
    return msg.encode("utf-8")


def _format_cef(dest: dict, event: SecurityEvent) -> bytes:
    """ArcSight CEF format."""
    pri = _syslog_pri(dest.get("facility", 16), event.severity)
    sev_map = {"info": 3, "warning": 6, "critical": 9}
    cef_sev = sev_map.get(event.severity, 3)
    ext_parts = [
        f"rt={int(event.timestamp.timestamp() * 1000)}",
        f"suser={event.actor.username or ''}",
        f"src={event.actor.ip or ''}",
        f"outcome={event.outcome or ''}",
    ]
    if event.target:
        ext_parts.append(f"fname={event.target.name or ''}")
    extension = " ".join(ext_parts)
    msg = f"<{pri}>CEF:0|tusShare|tusShare|1.0|{event.event_type}|{event.event_type}|{cef_sev}|{extension}"
    return msg.encode("utf-8")


def _format_leef(dest: dict, event: SecurityEvent) -> bytes:
    """IBM QRadar LEEF 1.0 format."""
    pri = _syslog_pri(dest.get("facility", 16), event.severity)
    attrs = "\t".join(
        [
            f"devTime={event.timestamp.astimezone(timezone.utc).isoformat()}",
            f"usrName={event.actor.username or ''}",
            f"src={event.actor.ip or ''}",
            f"cat={event.event_type}",
            f"sev={event.severity}",
            f"outcome={event.outcome or ''}",
        ]
    )
    msg = f"<{pri}>LEEF:1.0|tusShare|tusShare|1.0|{event.event_type}|{attrs}"
    return msg.encode("utf-8")


def _format_event(dest: dict, event: SecurityEvent) -> bytes:
    fmt = dest.get("syslog_format") or "rfc5424"
    if fmt == "cef":
        return _format_cef(dest, event)
    if fmt == "leef":
        return _format_leef(dest, event)
    return _format_rfc5424(dest, event)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


async def send_one(dest: dict, event: SecurityEvent) -> None:
    """Format and send a single event to a syslog destination (blocking I/O in thread pool)."""
    payload = _format_event(dest, event)
    protocol = (dest.get("protocol") or "udp").lower()
    host = dest.get("host") or ""
    port = int(dest.get("port") or 514)

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _send_sync, protocol, host, port, payload)


def _send_sync(protocol: str, host: str, port: int, payload: bytes) -> None:
    if protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload + b"\n", (host, port))
    elif protocol == "tls":
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                ssock.sendall(payload + b"\n")
    else:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(payload + b"\n")
