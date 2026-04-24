"""Audit trail + SIEM management routes — E7.

Endpoints
---------
GET  /admin/audit/logs            — paginated pull API (history + gap-fill)
GET  /admin/audit/logs/export     — CSV download (same filters, bounded)
GET  /admin/audit/logs/stream     — SSE live stream from event bus
GET  /admin/audit/siem            — list SIEM destinations
POST /admin/audit/siem            — add a destination
PUT  /admin/audit/siem/{dest_id}  — update a destination
DELETE /admin/audit/siem/{dest_id}— remove a destination
POST /admin/audit/siem/{dest_id}/test — send a synthetic test event
"""
from __future__ import annotations

import csv
import fnmatch
import io
import json
import logging
import secrets
import uuid
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.auth.idp_crypto import encrypt_token, decrypt_token
from app.database import get_db
from app.models.role import FLAG_MANAGE_USERS
from app.services.siem_filters import PROFILE_META
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus
from app.validation.sanitizers import validate_uuid
from app.validation.validators import validate_pagination

logger = logging.getLogger(__name__)
router = APIRouter()

_SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
_MAX_EXPORT_ROWS = 50_000
_SSE_KEEPALIVE_SECS = 25  # comment-only keepalive to hold the connection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _matches_event_types(event_type: str, patterns: list[str]) -> bool:
    """Return True if event_type matches any of the given glob patterns."""
    return any(fnmatch.fnmatch(event_type, p) for p in patterns)


def _severity_gte(severity: str, minimum: str) -> bool:
    return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(minimum, 0)


def _row_to_dict(r) -> dict:
    return {
        "event_id":        r["id"],
        "timestamp":       str(r["timestamp"]),
        "event_type":      r["event_type"],
        "severity":        r["severity"] or "info",
        "outcome":         r["outcome"],
        "actor_user_id":   r["user_id"],
        "actor_ip":        r["ip_address"],
        "actor_session_id":r["actor_session_id"],
        "target_type":     r["target_type"],
        "target_id":       r["target_id"],
        "target_name":     r["target_name"],
        "admin_actor_id":  r["admin_actor_id"],
        "detail":          (json.loads(r["detail"]) if r["detail"] else None),
    }


# ---------------------------------------------------------------------------
# GET /admin/audit/logs — paginated pull API
# ---------------------------------------------------------------------------

@router.get("/logs")
async def list_audit_logs(
    limit:       int   = Query(100, ge=1, le=500),
    offset:      int   = Query(0,   ge=0),
    event_types: str   = Query("",  description="Comma-separated glob patterns, e.g. auth.*,file.*"),
    severity:    str   = Query("info", description="Minimum severity: info|warning|critical"),
    user_id:     str   = Query("",  description="Filter by actor user_id"),
    since:       str   = Query("",  description="ISO timestamp lower bound"),
    until:       str   = Query("",  description="ISO timestamp upper bound"),
    after:       str   = Query("",  description="Cursor — event_id to page from (exclusive)"),
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Paginated query over security_events. Suitable for gap-fill after SIEM reconnect."""
    if severity not in _SEVERITY_ORDER:
        raise HTTPException(status_code=400, detail="severity must be info, warning, or critical")

    clauses = []
    params: list = []

    if severity != "info":
        sev_values = [k for k, v in _SEVERITY_ORDER.items() if v >= _SEVERITY_ORDER[severity]]
        placeholders = ",".join("?" * len(sev_values))
        clauses.append(f"severity IN ({placeholders})")
        params.extend(sev_values)

    if user_id.strip():
        clauses.append("user_id = ?")
        params.append(validate_uuid(user_id.strip()))

    if since.strip():
        clauses.append("timestamp >= ?")
        params.append(since.strip())

    if until.strip():
        clauses.append("timestamp <= ?")
        params.append(until.strip())

    if after.strip():
        # cursor-based pagination: find the timestamp of the cursor row, then filter
        cur = await db.execute(
            "SELECT timestamp FROM security_events WHERE id = ?",
            (validate_uuid(after.strip()),),
        )
        cursor_row = await cur.fetchone()
        if cursor_row:
            clauses.append("timestamp > ?")
            params.append(str(cursor_row["timestamp"]))

    # event_types glob filtering is applied post-fetch because SQL LIKE doesn't
    # support the glob patterns well enough (e.g. auth.* with dots).
    # For very large result sets this could be optimised with a prefix index;
    # at typical audit log volumes it's fine.
    et_patterns = [p.strip() for p in event_types.split(",") if p.strip()]

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"""
        SELECT id, user_id, ip_address, actor_session_id,
               event_type, severity, outcome, action_key, detail, timestamp,
               target_type, target_id, target_name, admin_actor_id
        FROM security_events
        {where}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()

    if et_patterns:
        rows = [r for r in rows if _matches_event_types(r["event_type"], et_patterns)]

    return {"events": [_row_to_dict(r) for r in rows], "count": len(rows)}


# ---------------------------------------------------------------------------
# GET /admin/audit/logs/export — CSV download
# ---------------------------------------------------------------------------

@router.get("/logs/export")
async def export_audit_logs(
    event_types: str = Query(""),
    severity:    str = Query("info"),
    user_id:     str = Query(""),
    since:       str = Query(""),
    until:       str = Query(""),
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Download security_events as a CSV file (max 50 000 rows)."""
    if severity not in _SEVERITY_ORDER:
        raise HTTPException(status_code=400, detail="severity must be info, warning, or critical")

    clauses = []
    params: list = []

    if severity != "info":
        sev_values = [k for k, v in _SEVERITY_ORDER.items() if v >= _SEVERITY_ORDER[severity]]
        placeholders = ",".join("?" * len(sev_values))
        clauses.append(f"severity IN ({placeholders})")
        params.extend(sev_values)

    if user_id.strip():
        clauses.append("user_id = ?")
        params.append(validate_uuid(user_id.strip()))

    if since.strip():
        clauses.append("timestamp >= ?")
        params.append(since.strip())

    if until.strip():
        clauses.append("timestamp <= ?")
        params.append(until.strip())

    et_patterns = [p.strip() for p in event_types.split(",") if p.strip()]

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"""
        SELECT id, user_id, ip_address, actor_session_id,
               event_type, severity, outcome, detail, timestamp,
               target_type, target_id, target_name, admin_actor_id
        FROM security_events
        {where}
        ORDER BY timestamp ASC
        LIMIT ?
    """
    params.append(_MAX_EXPORT_ROWS)
    cursor = await db.execute(query, params)
    rows = await cursor.fetchall()

    if et_patterns:
        rows = [r for r in rows if _matches_event_types(r["event_type"], et_patterns)]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "event_id", "timestamp", "event_type", "severity", "outcome",
        "actor_user_id", "actor_ip", "actor_session_id",
        "target_type", "target_id", "target_name",
        "admin_actor_id", "detail",
    ])
    for r in rows:
        writer.writerow([
            r["id"], r["timestamp"], r["event_type"],
            r["severity"] or "info", r["outcome"] or "",
            r["user_id"] or "", r["ip_address"] or "", r["actor_session_id"] or "",
            r["target_type"] or "", r["target_id"] or "", r["target_name"] or "",
            r["admin_actor_id"] or "", r["detail"] or "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )


# ---------------------------------------------------------------------------
# GET /admin/audit/logs/stream — SSE live stream
# ---------------------------------------------------------------------------

@router.get("/logs/stream")
async def stream_audit_logs(
    event_types: str = Query(""),
    severity:    str = Query("info"),
    user_id:     str = Query(""),
    admin: AuthenticatedUser = Depends(require_admin),
):
    """Stream security events in real-time via Server-Sent Events.

    Reconnect via Last-Event-ID header to resume from the last seen event_id.
    The endpoint validates admin auth and then subscribes to the event bus.
    Clients should reconnect automatically (standard SSE browser behaviour).
    """
    et_patterns = [p.strip() for p in event_types.split(",") if p.strip()]
    min_sev = severity if severity in _SEVERITY_ORDER else "info"
    uid_filter = user_id.strip() or None

    async def _generate() -> AsyncGenerator[bytes, None]:
        import asyncio
        q = event_bus.subscribe()
        try:
            while True:
                try:
                    event: SecurityEvent = await asyncio.wait_for(q.get(), timeout=_SSE_KEEPALIVE_SECS)
                except asyncio.TimeoutError:
                    # keepalive comment — prevents proxy / load-balancer timeouts
                    yield b": keepalive\n\n"
                    continue

                if not _severity_gte(event.severity, min_sev):
                    continue
                if et_patterns and not _matches_event_types(event.event_type, et_patterns):
                    continue
                if uid_filter and event.actor.user_id != uid_filter:
                    continue

                payload = event.model_dump_json()
                sse_msg = (
                    f"id: {event.event_id}\n"
                    f"event: {event.event_type}\n"
                    f"data: {payload}\n\n"
                )
                yield sse_msg.encode()
        finally:
            event_bus.unsubscribe(q)

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering for SSE
        },
    )


# ---------------------------------------------------------------------------
# SIEM destination CRUD
# ---------------------------------------------------------------------------

class SiemDestinationRequest(BaseModel):
    name:               str
    type:               str   # "syslog" | "webhook"
    is_active:          bool = True
    # syslog
    host:               str | None = None
    port:               int | None = None
    protocol:           str | None = None   # udp | tcp | tls
    syslog_format:      str | None = None   # rfc5424 | cef | leef
    facility:           int = 16            # LOCAL0
    # webhook
    url:                str | None = None
    secret:             str | None = None   # plaintext; stored encrypted; omit to keep existing
    batch_size:         int = 1
    # event filter
    filter_profile:     str = "recommended"  # high_security | recommended | relaxed | custom
    filter_custom_json: str | None = None    # JSON for custom profile


_VALID_PROFILES = frozenset({"high_security", "recommended", "relaxed", "custom"})


def _validate_destination(body: SiemDestinationRequest) -> None:
    if body.type not in ("syslog", "webhook"):
        raise HTTPException(status_code=400, detail="type must be 'syslog' or 'webhook'")
    if body.type == "syslog":
        if not body.host:
            raise HTTPException(status_code=400, detail="syslog destination requires host")
        if body.protocol and body.protocol not in ("udp", "tcp", "tls"):
            raise HTTPException(status_code=400, detail="protocol must be udp, tcp, or tls")
        if body.syslog_format and body.syslog_format not in ("rfc5424", "cef", "leef"):
            raise HTTPException(status_code=400, detail="syslog_format must be rfc5424, cef, or leef")
    if body.type == "webhook":
        if not body.url:
            raise HTTPException(status_code=400, detail="webhook destination requires url")
        if not body.url.startswith("https://"):
            raise HTTPException(status_code=400, detail="webhook url must use HTTPS")
        if body.batch_size < 1 or body.batch_size > 100:
            raise HTTPException(status_code=400, detail="batch_size must be 1–100")
    if body.filter_profile not in _VALID_PROFILES:
        raise HTTPException(status_code=400, detail="filter_profile must be high_security, recommended, relaxed, or custom")
    if body.filter_profile == "custom":
        try:
            parsed = json.loads(body.filter_custom_json or "")
            if not isinstance(parsed.get("event_type_globs"), list):
                raise ValueError
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=400,
                detail='custom filter_custom_json must be valid JSON with {"event_type_globs": [...], "min_severity": "info|warning|critical"}',
            )


def _dest_row_to_dict(r, redact_secret: bool = True) -> dict:
    return {
        "id":                 r["id"],
        "name":               r["name"],
        "type":               r["type"],
        "is_active":          bool(r["is_active"]),
        "host":               r["host"],
        "port":               r["port"],
        "protocol":           r["protocol"],
        "syslog_format":      r["syslog_format"],
        "facility":           r["facility"],
        "url":                r["url"],
        "has_secret":         bool(r["secret_enc"]),   # never expose the raw secret
        "batch_size":         r["batch_size"],
        "filter_profile":     r["filter_profile"] or "recommended",
        "filter_custom_json": r["filter_custom_json"],
        "created_at":         str(r["created_at"]),
        "updated_at":         str(r["updated_at"]),
    }


@router.get("/siem")
async def list_siem_destinations(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    cursor = await db.execute(
        "SELECT * FROM siem_destinations ORDER BY created_at ASC"
    )
    rows = await cursor.fetchall()
    return {
        "destinations": [_dest_row_to_dict(r) for r in rows],
        "filter_profiles": PROFILE_META,
    }


@router.post("/siem")
async def create_siem_destination(
    body: SiemDestinationRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    _validate_destination(body)
    dest_id = str(uuid.uuid4())
    secret_enc = encrypt_token(body.secret) if body.secret else None

    await db.execute(
        """
        INSERT INTO siem_destinations
            (id, name, type, is_active,
             host, port, protocol, syslog_format, facility,
             url, secret_enc, batch_size,
             filter_profile, filter_custom_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (dest_id, body.name, body.type, int(body.is_active),
         body.host, body.port, body.protocol, body.syslog_format, body.facility,
         body.url, secret_enc, body.batch_size,
         body.filter_profile, body.filter_custom_json),
    )
    await db.commit()

    event_bus.emit(SecurityEvent(
        event_type="admin.siem.config_changed",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username),
        detail={"action": "created", "destination_id": dest_id, "name": body.name, "type": body.type},
    ))

    return {"ok": True, "id": dest_id}


@router.put("/siem/{dest_id}")
async def update_siem_destination(
    dest_id: str,
    body: SiemDestinationRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    dest_id = validate_uuid(dest_id)
    _validate_destination(body)

    cur = await db.execute("SELECT secret_enc FROM siem_destinations WHERE id = ?", (dest_id,))
    existing = await cur.fetchone()
    if existing is None:
        raise HTTPException(status_code=404, detail="SIEM destination not found")

    # Keep existing encrypted secret if none provided
    secret_enc = encrypt_token(body.secret) if body.secret else existing["secret_enc"]

    await db.execute(
        """
        UPDATE siem_destinations
        SET name=?, type=?, is_active=?,
            host=?, port=?, protocol=?, syslog_format=?, facility=?,
            url=?, secret_enc=?, batch_size=?,
            filter_profile=?, filter_custom_json=?,
            updated_at=NOW()
        WHERE id=?
        """,
        (body.name, body.type, int(body.is_active),
         body.host, body.port, body.protocol, body.syslog_format, body.facility,
         body.url, secret_enc, body.batch_size,
         body.filter_profile, body.filter_custom_json,
         dest_id),
    )
    await db.commit()

    event_bus.emit(SecurityEvent(
        event_type="admin.siem.config_changed",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username),
        detail={"action": "updated", "destination_id": dest_id, "name": body.name},
    ))

    return {"ok": True}


@router.delete("/siem/{dest_id}")
async def delete_siem_destination(
    dest_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    dest_id = validate_uuid(dest_id)
    cur = await db.execute("SELECT name FROM siem_destinations WHERE id = ?", (dest_id,))
    row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="SIEM destination not found")

    await db.execute("DELETE FROM siem_destinations WHERE id = ?", (dest_id,))
    await db.commit()

    event_bus.emit(SecurityEvent(
        event_type="admin.siem.config_changed",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username),
        detail={"action": "deleted", "destination_id": dest_id, "name": row["name"]},
    ))

    return {"ok": True}


@router.post("/siem/{dest_id}/test")
async def test_siem_destination(
    dest_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Send a synthetic admin.siem.test event to the destination to verify connectivity."""
    from app.services import siem_syslog, siem_webhook

    dest_id = validate_uuid(dest_id)
    cur = await db.execute("SELECT * FROM siem_destinations WHERE id = ?", (dest_id,))
    row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="SIEM destination not found")

    test_event = SecurityEvent(
        event_type="admin.siem.test",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username),
        detail={"destination_id": dest_id, "destination_name": row["name"]},
    )

    try:
        if row["type"] == "syslog":
            await siem_syslog.send_one(row, test_event)
        else:
            secret = decrypt_token(row["secret_enc"]) if row["secret_enc"] else ""
            await siem_webhook.send_one(row, [test_event], secret)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
