"""Audit trail and SIEM management routes.

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

import asyncio
import csv
import fnmatch
import io
import json
import logging
import uuid
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.auth.api_key import check_api_key, make_api_key_dep
from app.auth.dependencies import get_optional_user, require_admin
from app.auth.idp_crypto import decrypt_token, encrypt_token
from app.auth.interface import AuthenticatedUser
from app.database import Database, get_db
from app.middleware.rate_limit import _get_client_ip
from app.models.role import FLAG_ADMIN_PANEL_VIEW
from app.schemas.security_event import EventActor, SecurityEvent
from app.services import audit_key as _audit_key
from app.services import event_bus
from app.services.siem_filters import PROFILE_META
from app.validation.sanitizers import validate_uuid

_EVT_SIEM_CONFIG_CHANGED = "admin.siem.config_changed"
_ERR_SIEM_NOT_FOUND = "SIEM destination not found"

logger = logging.getLogger(__name__)
router = APIRouter()

_SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
_MAX_EXPORT_ROWS = 50_000
_SSE_KEEPALIVE_SECS = 25  # comment-only keepalive to hold the connection

# FastAPI dependency for API-key-only callers that need the raw key row (e.g. rotate).
_require_audit_key = make_api_key_dep("audit_read")


# ---------------------------------------------------------------------------
# Dual-auth dependency (admin JWT OR audit_read API key)
# ---------------------------------------------------------------------------


async def _require_audit_read(
    request: Request,
    optional_user: Annotated[AuthenticatedUser | None, Depends(get_optional_user)],
) -> dict | None:
    """Accept either an admin JWT or an audit_read API key.

    Returns the API key DB row when authenticated via API key (callers use
    filter_event_types / filter_min_severity from it), or None for JWT auth.
    Browser admin UI uses the JWT path; machine consumers use the API key path.
    """
    x_api_key = request.headers.get("x-api-key")
    if x_api_key:
        return await check_api_key(x_api_key, "audit_read")
    if optional_user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not optional_user.has_flag(FLAG_ADMIN_PANEL_VIEW):
        raise HTTPException(status_code=403, detail="Admin access required")
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _matches_event_types(event_type: str, patterns: list[str]) -> bool:
    """Return True if event_type matches any of the given glob patterns."""
    return any(fnmatch.fnmatch(event_type, p) for p in patterns)


def _severity_gte(severity: str, minimum: str) -> bool:
    return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(minimum, 0)


def _event_passes_filters(
    event: "SecurityEvent",
    min_sev: str,
    key_min_sev: str,
    et_patterns: list[str],
    key_et_patterns: list[str],
    uid_filter: str | None,
) -> bool:
    if not _severity_gte(event.severity, min_sev):
        return False
    if not _severity_gte(event.severity, key_min_sev):
        return False
    if et_patterns and not _matches_event_types(event.event_type, et_patterns):
        return False
    if key_et_patterns and not _matches_event_types(event.event_type, key_et_patterns):
        return False
    if uid_filter and event.actor.user_id != uid_filter:
        return False
    return True


def _apply_key_filters(rows: list, key_row: dict | None) -> list:
    """Apply per-key event-type and severity filters from the API key's own config.

    Only active when auth is via API key (key_row is not None) and the key has
    filter_event_types or filter_min_severity set.  These constraints are
    additive — they narrow results on top of any query-param filters.
    """
    if not key_row:
        return rows
    et_raw = key_row.get("filter_event_types")
    sev = key_row.get("filter_min_severity")
    if et_raw:
        patterns = [p.strip() for p in et_raw.split(",") if p.strip()]
        if patterns:
            rows = [r for r in rows if _matches_event_types(r["event_type"], patterns)]
    if sev:
        rows = [r for r in rows if _severity_gte(r.get("severity") or "info", sev)]
    return rows


async def _build_audit_filter(
    db,
    severity: str,
    user_id: str = "",
    since: str = "",
    until: str = "",
    after: str = "",
    event_types: str = "",
) -> tuple[list, list, list]:
    """Build (clauses, params, et_patterns) for security_events WHERE clauses.

    Returns SQL clause fragments, their positional params, and the list of
    glob patterns extracted from *event_types*.  The *after* cursor requires
    a DB lookup and is only used by the paginated list endpoint.
    """
    clauses: list = []
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
        cur = await db.execute(
            "SELECT timestamp FROM security_events WHERE id = ?",
            (validate_uuid(after.strip()),),
        )
        cursor_row = await cur.fetchone()
        if cursor_row:
            clauses.append("timestamp > ?")
            params.append(str(cursor_row["timestamp"]))

    et_patterns = [p.strip() for p in event_types.split(",") if p.strip()]
    return clauses, params, et_patterns


def _row_to_dict(r) -> dict:
    # Decrypt detail_enc (present on rows written after audit encryption was enabled).
    # Falls back to plaintext detail column for older rows.
    detail_enc = r["detail_enc"] if "detail_enc" in r.keys() else None
    if detail_enc:
        decrypted = _audit_key.decrypt_detail(detail_enc) or {}
        actor_username = decrypted.get("actor_username") or r["actor_username"]
        actor_ip       = decrypted.get("ip_address")     or r["ip_address"]
        target_id      = decrypted.get("target_id")      or r["target_id"]
        target_name    = decrypted.get("target_name")    or r["target_name"]
        admin_actor_id = decrypted.get("admin_actor_id") or r["admin_actor_id"]
        detail_val     = decrypted.get("detail")
    else:
        actor_username = r["actor_username"]
        actor_ip       = r["ip_address"]
        target_id      = r["target_id"]
        target_name    = r["target_name"]
        admin_actor_id = r["admin_actor_id"]
        detail_val     = json.loads(r["detail"]) if r["detail"] else None

    return {
        "event_id":        r["id"],
        "timestamp":       str(r["timestamp"]),
        "event_type":      r["event_type"],
        "severity":        r["severity"] or "info",
        "outcome":         r["outcome"],
        "action_key":      r["action_key"],
        "actor_user_id":   r["user_id"],
        "actor_username":  actor_username,
        "actor_ip":        actor_ip,
        "actor_session_id": r["actor_session_id"],
        "user_agent":      r["user_agent"],
        "target_type":     r["target_type"],
        "target_id":       target_id,
        "target_name":     target_name,
        "admin_actor_id":  admin_actor_id,
        "detail":          detail_val,
    }


async def _fill_missing_usernames(db, events: list[dict]) -> list[dict]:
    """Backfill actor_username for events where it is NULL but user_id is present.

    security_events is append-only so old rows cannot be updated; instead we
    look the username up live from the users table and merge it into the response.
    """
    missing = {e["actor_user_id"] for e in events if not e["actor_username"] and e["actor_user_id"]}
    if not missing:
        return events
    placeholders = ",".join("?" * len(missing))
    cur = await db.execute(
        f"SELECT id, username FROM users WHERE id IN ({placeholders})",
        list(missing),
    )
    urows = await cur.fetchall()
    umap = {r["id"]: r["username"] for r in urows}
    return [{**e, "actor_username": e["actor_username"] or umap.get(e["actor_user_id"])} for e in events]


# ---------------------------------------------------------------------------
# GET /admin/audit/logs — paginated pull API
# ---------------------------------------------------------------------------


@router.get("/logs", responses={400: {"description": "Bad Request"}})
async def list_audit_logs(
    _auth: Annotated[None, Depends(_require_audit_read)],
    db: Annotated[Database, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    event_types: Annotated[str, Query(description="Comma-separated glob patterns, e.g. auth.*,file.*")] = "",
    severity: Annotated[str, Query(description="Minimum severity: info|warning|critical")] = "info",
    user_id: Annotated[str, Query(description="Filter by actor user_id")] = "",
    since: Annotated[str, Query(description="ISO timestamp lower bound")] = "",
    until: Annotated[str, Query(description="ISO timestamp upper bound")] = "",
    after: Annotated[str, Query(description="Cursor — event_id to page from (exclusive)")] = "",
):
    """Paginated query over security_events. Suitable for gap-fill after SIEM reconnect."""
    if severity not in _SEVERITY_ORDER:
        raise HTTPException(status_code=400, detail="severity must be info, warning, or critical")

    # event_types glob filtering is applied post-fetch because SQL LIKE doesn't
    # support the glob patterns well enough (e.g. auth.* with dots).
    clauses, params, et_patterns = await _build_audit_filter(
        db,
        severity,
        user_id=user_id,
        since=since,
        until=until,
        after=after,
        event_types=event_types,
    )

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"""
        SELECT id, user_id, actor_username, ip_address, actor_session_id,
               user_agent, event_type, severity, outcome, action_key, detail, timestamp,
               target_type, target_id, target_name, admin_actor_id, detail_enc
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

    rows = _apply_key_filters(rows, _auth)
    events = await _fill_missing_usernames(db, [_row_to_dict(r) for r in rows])
    return {"events": events, "count": len(events)}


# ---------------------------------------------------------------------------
# GET /admin/audit/logs/export — CSV download
# ---------------------------------------------------------------------------


@router.get("/logs/export", responses={400: {"description": "Bad Request"}})
async def export_audit_logs(
    _auth: Annotated[None, Depends(_require_audit_read)],
    db: Annotated[Database, Depends(get_db)],
    event_types: Annotated[str, Query()] = "",
    severity: Annotated[str, Query()] = "info",
    user_id: Annotated[str, Query()] = "",
    since: Annotated[str, Query()] = "",
    until: Annotated[str, Query()] = "",
):
    """Download security_events as a CSV file (max 50 000 rows)."""
    if severity not in _SEVERITY_ORDER:
        raise HTTPException(status_code=400, detail="severity must be info, warning, or critical")

    clauses, params, et_patterns = await _build_audit_filter(
        db,
        severity,
        user_id=user_id,
        since=since,
        until=until,
        event_types=event_types,
    )

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    query = f"""
        SELECT id, user_id, actor_username, ip_address, actor_session_id,
               user_agent, event_type, severity, outcome, action_key, detail, timestamp,
               target_type, target_id, target_name, admin_actor_id, detail_enc
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

    rows = _apply_key_filters(rows, _auth)

    # Convert to dicts (decrypts detail_enc) then resolve missing usernames.
    event_dicts = await _fill_missing_usernames(db, [_row_to_dict(r) for r in rows])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "event_id",
            "timestamp",
            "event_type",
            "severity",
            "outcome",
            "actor_user_id",
            "actor_username",
            "actor_ip",
            "actor_session_id",
            "target_type",
            "target_id",
            "target_name",
            "admin_actor_id",
            "detail",
        ]
    )
    for e in event_dicts:
        writer.writerow([
            e["event_id"], e["timestamp"], e["event_type"], e["severity"] or "info",
            e["outcome"] or "", e["actor_user_id"] or "", e["actor_username"] or "",
            e["actor_ip"] or "", e["actor_session_id"] or "",
            e["target_type"] or "", e["target_id"] or "", e["target_name"] or "",
            e["admin_actor_id"] or "",
            json.dumps(e["detail"], separators=(",", ":")) if e["detail"] else "",
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


@router.get("/logs/stream", responses={400: {"description": "Bad Request"}})
async def stream_audit_logs(
    _key: Annotated[dict, Depends(_require_audit_key)],
    event_types: Annotated[str, Query()] = "",
    severity: Annotated[str, Query()] = "info",
    user_id: Annotated[str, Query()] = "",
):
    """Stream security events in real-time via Server-Sent Events.

    Machine/SIEM consumer endpoint — requires an audit_read API key.
    Browser admin UI uses the pull API (/logs) with auto-refresh instead.
    API key callers get their per-key event-type and severity filters applied
    on top of the query-param filters.
    """
    et_patterns = [p.strip() for p in event_types.split(",") if p.strip()]
    min_sev = severity if severity in _SEVERITY_ORDER else "info"
    uid_filter = user_id.strip() or None

    # Per-key filter constraints from the API key's own configuration.
    key_et_raw = _key.get("filter_event_types") or ""
    key_et_patterns = [p.strip() for p in key_et_raw.split(",") if p.strip()]
    key_min_sev = _key.get("filter_min_severity") or "info"

    async def _generate() -> AsyncGenerator[bytes, None]:
        q = event_bus.subscribe()
        try:
            while True:
                try:
                    event: SecurityEvent = await asyncio.wait_for(q.get(), timeout=_SSE_KEEPALIVE_SECS)
                except asyncio.TimeoutError:
                    # keepalive comment — prevents proxy / load-balancer timeouts
                    yield b": keepalive\n\n"
                    continue

                if not _event_passes_filters(event, min_sev, key_min_sev, et_patterns, key_et_patterns, uid_filter):
                    continue

                payload = event.model_dump_json()
                sse_msg = f"id: {event.event_id}\nevent: {event.event_type}\ndata: {payload}\n\n"
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
    name: str
    type: str  # "syslog" | "webhook"
    is_active: bool = True
    # syslog
    host: str | None = None
    port: int | None = None
    protocol: str | None = None  # udp | tcp | tls
    syslog_format: str | None = None  # rfc5424 | cef | leef
    facility: int = 16  # LOCAL0
    # webhook
    url: str | None = None
    secret: str | None = None  # plaintext; stored encrypted; omit to keep existing
    batch_size: int = 1
    # event filter
    filter_profile: str = "recommended"  # high_security | recommended | relaxed | custom
    filter_custom_json: str | None = None  # JSON for custom profile


_VALID_PROFILES = frozenset({"high_security", "recommended", "relaxed", "custom"})


def _validate_syslog(body: SiemDestinationRequest) -> None:
    if not body.host:
        raise HTTPException(status_code=400, detail="syslog destination requires host")
    if body.protocol and body.protocol not in ("udp", "tcp", "tls"):
        raise HTTPException(status_code=400, detail="protocol must be udp, tcp, or tls")
    if body.syslog_format and body.syslog_format not in ("rfc5424", "cef", "leef"):
        raise HTTPException(status_code=400, detail="syslog_format must be rfc5424, cef, or leef")


def _validate_webhook(body: SiemDestinationRequest) -> None:
    if not body.url:
        raise HTTPException(status_code=400, detail="webhook destination requires url")
    if not body.url.startswith("https://"):
        raise HTTPException(status_code=400, detail="webhook url must use HTTPS")
    if body.batch_size < 1 or body.batch_size > 100:
        raise HTTPException(status_code=400, detail="batch_size must be 1–100")


def _validate_filter_profile(body: SiemDestinationRequest) -> None:
    if body.filter_profile not in _VALID_PROFILES:
        raise HTTPException(
            status_code=400, detail="filter_profile must be high_security, recommended, relaxed, or custom"
        )
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


def _validate_destination(body: SiemDestinationRequest) -> None:
    if body.type not in ("syslog", "webhook"):
        raise HTTPException(status_code=400, detail="type must be 'syslog' or 'webhook'")
    if body.type == "syslog":
        _validate_syslog(body)
    if body.type == "webhook":
        _validate_webhook(body)
    _validate_filter_profile(body)


def _dest_row_to_dict(r) -> dict:
    return {
        "id": r["id"],
        "name": r["name"],
        "type": r["type"],
        "is_active": bool(r["is_active"]),
        "host": r["host"],
        "port": r["port"],
        "protocol": r["protocol"],
        "syslog_format": r["syslog_format"],
        "facility": r["facility"],
        "url": r["url"],
        "has_secret": bool(r["secret_enc"]),  # never expose the raw secret
        "batch_size": r["batch_size"],
        "filter_profile": r["filter_profile"] or "recommended",
        "filter_custom_json": r["filter_custom_json"],
        "created_at": str(r["created_at"]),
        "updated_at": str(r["updated_at"]),
    }


@router.get("/siem")
async def list_siem_destinations(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    cursor = await db.execute("SELECT * FROM siem_destinations ORDER BY created_at ASC")
    rows = await cursor.fetchall()
    return {
        "destinations": [_dest_row_to_dict(r) for r in rows],
        "filter_profiles": PROFILE_META,
    }


@router.post("/siem", responses={400: {"description": "Bad Request"}})
async def create_siem_destination(
    request: Request,
    body: SiemDestinationRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
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
        (
            dest_id,
            body.name,
            body.type,
            int(body.is_active),
            body.host,
            body.port,
            body.protocol,
            body.syslog_format,
            body.facility,
            body.url,
            secret_enc,
            body.batch_size,
            body.filter_profile,
            body.filter_custom_json,
        ),
    )
    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type=_EVT_SIEM_CONFIG_CHANGED,
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
            detail={"action": "created", "destination_id": dest_id, "name": body.name, "type": body.type},
        )
    )

    return {"ok": True, "id": dest_id}


@router.put("/siem/{dest_id}", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}})
async def update_siem_destination(
    request: Request,
    dest_id: str,
    body: SiemDestinationRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    dest_id = validate_uuid(dest_id)
    _validate_destination(body)

    cur = await db.execute("SELECT secret_enc FROM siem_destinations WHERE id = ?", (dest_id,))
    existing = await cur.fetchone()
    if existing is None:
        raise HTTPException(status_code=404, detail=_ERR_SIEM_NOT_FOUND)

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
        (
            body.name,
            body.type,
            int(body.is_active),
            body.host,
            body.port,
            body.protocol,
            body.syslog_format,
            body.facility,
            body.url,
            secret_enc,
            body.batch_size,
            body.filter_profile,
            body.filter_custom_json,
            dest_id,
        ),
    )
    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type=_EVT_SIEM_CONFIG_CHANGED,
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
            detail={"action": "updated", "destination_id": dest_id, "name": body.name},
        )
    )

    return {"ok": True}


@router.delete("/siem/{dest_id}", responses={404: {"description": "Not Found"}})
async def delete_siem_destination(
    request: Request,
    dest_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    dest_id = validate_uuid(dest_id)
    cur = await db.execute("SELECT name FROM siem_destinations WHERE id = ?", (dest_id,))
    row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_SIEM_NOT_FOUND)

    await db.execute("DELETE FROM siem_destinations WHERE id = ?", (dest_id,))
    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type=_EVT_SIEM_CONFIG_CHANGED,
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
            detail={"action": "deleted", "destination_id": dest_id, "name": row["name"]},
        )
    )

    return {"ok": True}


@router.post("/siem/{dest_id}/test", responses={404: {"description": "Not Found"}})
async def test_siem_destination(
    request: Request,
    dest_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Send a synthetic admin.siem.test event to the destination to verify connectivity."""
    from app.services import siem_syslog, siem_webhook

    dest_id = validate_uuid(dest_id)
    cur = await db.execute("SELECT * FROM siem_destinations WHERE id = ?", (dest_id,))
    row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_SIEM_NOT_FOUND)

    test_event = SecurityEvent(
        event_type="admin.siem.test",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
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


# ---------------------------------------------------------------------------
# audit_key_grants — per-user K_audit access for audit_log_view holders
# ---------------------------------------------------------------------------


@router.get("/key-grants", responses={403: {"description": "Forbidden"}})
async def list_audit_key_grants(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """List users who have been granted access to K_audit (audit_key_grants rows)."""
    cursor = await db.execute(
        "SELECT akg.id, akg.user_id, u.username, akg.created_at "
        "FROM audit_key_grants akg "
        "JOIN users u ON u.id = akg.user_id "
        "ORDER BY u.username",
    )
    rows = await cursor.fetchall()
    return {
        "grants": [
            {"id": r["id"], "user_id": r["user_id"], "username": r["username"], "created_at": str(r["created_at"])}
            for r in rows
        ]
    }


@router.post(
    "/key-grants/{user_id}",
    status_code=201,
    responses={400: {"description": "User lacks X25519 public key"}, 404: {"description": "Not Found"}, 409: {"description": "Already granted"}},
)
async def grant_audit_key_access(
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Wrap K_audit under the target user's X25519 public key and store in audit_key_grants."""
    from app.database import DuplicateError
    from app.services.audit_key import wrap_k_audit_for_user

    user_id = validate_uuid(user_id)
    cursor = await db.execute(
        "SELECT id, username, x25519_public_key FROM users WHERE id = ? AND is_active = 1", (user_id,),
    )
    target = await cursor.fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found or inactive")
    if not target["x25519_public_key"]:
        raise HTTPException(status_code=400, detail="User does not have an X25519 public key stored — they must log in once first")

    try:
        wrapped = wrap_k_audit_for_user(target["x25519_public_key"])
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    grant_id = str(uuid.uuid4())
    try:
        await db.execute(
            "INSERT INTO audit_key_grants (id, user_id, ephemeral_x25519_pub, kem_ciphertext, encrypted_k_audit, sk_iv) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (grant_id, user_id, wrapped["ephemeral_x25519_pub"], wrapped["kem_ciphertext"], wrapped["encrypted_k_audit"], wrapped["sk_iv"]),
        )
        await db.commit()
    except DuplicateError:
        raise HTTPException(status_code=409, detail="User already has an audit key grant")

    return {"id": grant_id, "user_id": user_id, "username": target["username"]}


@router.delete("/key-grants/{user_id}", status_code=204)
async def revoke_audit_key_access(
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Revoke K_audit access for a user (delete their audit_key_grants row)."""
    user_id = validate_uuid(user_id)
    cursor = await db.execute("SELECT id FROM audit_key_grants WHERE user_id = ?", (user_id,))
    if not await cursor.fetchone():
        raise HTTPException(status_code=404, detail="Audit key grant not found for this user")
    await db.execute("DELETE FROM audit_key_grants WHERE user_id = ?", (user_id,))
    await db.commit()


@router.get("/key-grants/my-wrapped-key", responses={404: {"description": "No grant for caller"}})
async def get_my_wrapped_audit_key(
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return the caller's wrapped K_audit entry for client-side decryption of detail_enc."""
    cursor = await db.execute(
        "SELECT ephemeral_x25519_pub, kem_ciphertext, encrypted_k_audit, sk_iv "
        "FROM audit_key_grants WHERE user_id = ?",
        (user.id,),
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="No audit key grant for your account — ask an admin to grant access")
    return {
        "ephemeral_x25519_pub": row["ephemeral_x25519_pub"],
        "kem_ciphertext":       row["kem_ciphertext"],
        "encrypted_k_audit":   row["encrypted_k_audit"],
        "sk_iv":                row["sk_iv"],
    }
