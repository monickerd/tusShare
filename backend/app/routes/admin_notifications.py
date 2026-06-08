"""Admin routes for notification channels and API keys.

Endpoints
─────────
GET    /admin/notifications/channels
POST   /admin/notifications/channels              [step-up: admin.notifications.configure]
GET    /admin/notifications/channels/{id}
PUT    /admin/notifications/channels/{id}         [step-up]
DELETE /admin/notifications/channels/{id}         [step-up]
POST   /admin/notifications/channels/{id}/test
GET    /admin/notifications/events
GET    /admin/notifications/settings
PUT    /admin/notifications/settings              [step-up]
GET    /admin/api-keys
POST   /admin/api-keys                            [step-up: admin.api_keys.manage]
PUT    /admin/api-keys/{id}                       [step-up]
DELETE /admin/api-keys/{id}                       [step-up]
POST   /admin/api-keys/{id}/rotate               [step-up]
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.database import Database, get_db
from app.middleware.stepup import require_step_up
from app.services.notification_crypto import encrypt_channel_secret
from app.util.ip_restrict import validate_list as validate_ip_list
from app.util.ssrf import validate_endpoint_url
from app.validation.sanitizers import validate_uuid

_ERR_CHANNEL_NOT_FOUND = "Channel not found"
_ERR_KEY_NOT_FOUND = "API key not found"

logger = logging.getLogger(__name__)
router = APIRouter()  # mounted at /api/v1/admin/notifications
api_keys_router = APIRouter()  # mounted at /api/v1/admin

_STEPUP_NOTIF = "admin.notifications.configure"
_STEPUP_KEYS = "admin.api_keys.manage"
_REDACTED = "••••••••"
_FILTER_RE = re.compile(r"^[a-z][a-z0-9._:*-]{0,127}$")


# ---------------------------------------------------------------------------
# Scope derivation — inferred from event_filter rather than explicit scopes UI.
# ---------------------------------------------------------------------------


def _derive_scopes(event_filter: list[str]) -> list[str]:
    """Derive API key scopes from the event filter list.

    security: prefixes → audit_read; operational prefixes → ops_read.
    Empty filter (all events) → both scopes.
    """
    if not event_filter:
        return ["audit_read", "ops_read"]
    scopes: set[str] = set()
    for f in event_filter:
        if f.startswith("security:"):
            scopes.add("audit_read")
        else:
            scopes.add("ops_read")
    return sorted(scopes)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


def _validate_filter_entry(f: str) -> bool:
    return bool(_FILTER_RE.match(f))


def _validate_allowed_ips(v: list[str]) -> list[str]:
    try:
        return validate_ip_list(v)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


class ChannelCreateModel(BaseModel):
    name: str
    endpoint_url: str
    secret: str | None = None
    event_filter: list[str] = []
    filter_min_severity: str | None = None
    batch_size: int | None = None
    batch_interval_s: int | None = None
    enabled: bool = True
    expires_at: str | None = None
    allowed_ips: list[str] = []

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("name must be 1–128 characters")
        return v

    @field_validator("event_filter")
    @classmethod
    def _filters(cls, v: list[str]) -> list[str]:
        for f in v:
            if not _validate_filter_entry(f):
                raise ValueError(f"Invalid filter prefix: {f!r}")
        return v

    @field_validator("filter_min_severity")
    @classmethod
    def _severity(cls, v: str | None) -> str | None:
        if v is not None and v not in ("info", "warning", "critical"):
            raise ValueError("filter_min_severity must be info, warning, or critical")
        return v

    @field_validator("batch_size")
    @classmethod
    def _batch_size(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("batch_size must be >= 1")
        return v

    @field_validator("batch_interval_s")
    @classmethod
    def _interval(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("batch_interval_s must be >= 1")
        return v

    @field_validator("allowed_ips")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        return _validate_allowed_ips(v)


class NotifSettingsModel(BaseModel):
    server_id: str | None = None
    op_event_retention_days: int = 30
    api_key_expiry_warn_days: int = 30
    upload_quota_warn_pct: int = 90

    @field_validator("op_event_retention_days")
    @classmethod
    def _ret(cls, v: int) -> int:
        if not 1 <= v <= 3650:
            raise ValueError("op_event_retention_days must be 1–3650")
        return v

    @field_validator("api_key_expiry_warn_days")
    @classmethod
    def _expiry(cls, v: int) -> int:
        if not 1 <= v <= 365:
            raise ValueError("api_key_expiry_warn_days must be 1–365")
        return v

    @field_validator("upload_quota_warn_pct")
    @classmethod
    def _quota(cls, v: int) -> int:
        if not 1 <= v <= 100:
            raise ValueError("upload_quota_warn_pct must be 1–100")
        return v


class ApiKeyCreateModel(BaseModel):
    name: str
    event_filter: list[str] = []
    expires_at: str | None = None
    allowed_ips: list[str] = []
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("name must be 1–128 characters")
        return v

    @field_validator("event_filter")
    @classmethod
    def _filters(cls, v: list[str]) -> list[str]:
        for f in v:
            if not _validate_filter_entry(f):
                raise ValueError(f"Invalid filter prefix: {f!r}")
        return v

    @field_validator("allowed_ips")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        return _validate_allowed_ips(v)


class ApiKeyUpdateModel(BaseModel):
    name: str | None = None
    event_filter: list[str] | None = None
    expires_at: str | None = None
    allowed_ips: list[str] | None = None
    enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            if not v or len(v) > 128:
                raise ValueError("name must be 1–128 characters")
        return v

    @field_validator("event_filter")
    @classmethod
    def _filters(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            for f in v:
                if not _validate_filter_entry(f):
                    raise ValueError(f"Invalid filter prefix: {f!r}")
        return v

    @field_validator("allowed_ips")
    @classmethod
    def _ips(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            return _validate_allowed_ips(v)
        return v


# ---------------------------------------------------------------------------
# Notification channel CRUD
# ---------------------------------------------------------------------------


@router.get("/channels")
async def list_channels(
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    cursor = await db.execute(
        "SELECT id, name, endpoint_url, event_filter, filter_min_severity, "
        "       batch_size, batch_interval_s, enabled, expires_at, allowed_ips, created_at "
        "FROM notification_channels ORDER BY created_at ASC"
    )
    rows = await cursor.fetchall()
    return {"channels": [dict(r) for r in rows]}


@router.post("/channels", status_code=201)
async def create_channel(
    body: ChannelCreateModel,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP_NOTIF))],
):
    await validate_endpoint_url(body.endpoint_url)
    secret_enc = encrypt_channel_secret(body.secret) if body.secret else None
    ch_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    await db.execute(
        "INSERT INTO notification_channels "
        "(id, name, endpoint_url, secret_enc, event_filter, filter_min_severity, "
        " batch_size, batch_interval_s, enabled, expires_at, allowed_ips, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ch_id,
            body.name,
            body.endpoint_url,
            secret_enc,
            json.dumps(body.event_filter),
            body.filter_min_severity,
            body.batch_size,
            body.batch_interval_s,
            1 if body.enabled else 0,
            body.expires_at,
            json.dumps(body.allowed_ips) if body.allowed_ips else None,
            now,
        ),
    )
    await db.commit()

    from app.services import notification_emitter

    notification_emitter.reload(db)
    await asyncio.sleep(0.1)
    await notification_emitter.catch_up(ch_id, db)

    return {"id": ch_id, "name": body.name}


@router.get("/channels/{channel_id}", responses={404: {"description": "Not Found"}})
async def get_channel(
    channel_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    channel_id = validate_uuid(channel_id)
    cursor = await db.execute(
        "SELECT id, name, endpoint_url, secret_enc, event_filter, filter_min_severity, "
        "       batch_size, batch_interval_s, enabled, expires_at, allowed_ips, created_at "
        "FROM notification_channels WHERE id = ?",
        (channel_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_CHANNEL_NOT_FOUND)
    d = dict(row)
    if d.get("secret_enc"):
        d["secret_enc"] = _REDACTED
    return d


@router.put("/channels/{channel_id}", responses={404: {"description": "Not Found"}})
async def update_channel(
    channel_id: str,
    body: ChannelCreateModel,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP_NOTIF))],
):
    channel_id = validate_uuid(channel_id)
    cursor = await db.execute("SELECT id, secret_enc FROM notification_channels WHERE id = ?", (channel_id,))
    existing = await cursor.fetchone()
    if existing is None:
        raise HTTPException(status_code=404, detail=_ERR_CHANNEL_NOT_FOUND)

    await validate_endpoint_url(body.endpoint_url)

    if body.secret == _REDACTED or body.secret is None:
        secret_enc = existing["secret_enc"]
    else:
        secret_enc = encrypt_channel_secret(body.secret) if body.secret else None

    await db.execute(
        "UPDATE notification_channels SET name=?, endpoint_url=?, secret_enc=?, "
        "event_filter=?, filter_min_severity=?, batch_size=?, batch_interval_s=?, "
        "enabled=?, expires_at=?, allowed_ips=? WHERE id=?",
        (
            body.name,
            body.endpoint_url,
            secret_enc,
            json.dumps(body.event_filter),
            body.filter_min_severity,
            body.batch_size,
            body.batch_interval_s,
            1 if body.enabled else 0,
            body.expires_at,
            json.dumps(body.allowed_ips) if body.allowed_ips else None,
            channel_id,
        ),
    )
    await db.commit()

    from app.services import notification_emitter

    notification_emitter.reload(db)
    return {"ok": True}


@router.delete("/channels/{channel_id}", responses={404: {"description": "Not Found"}})
async def delete_channel(
    channel_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP_NOTIF))],
):
    channel_id = validate_uuid(channel_id)
    cursor = await db.execute("SELECT id FROM notification_channels WHERE id = ?", (channel_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail=_ERR_CHANNEL_NOT_FOUND)

    await db.execute("DELETE FROM notification_channels WHERE id = ?", (channel_id,))
    await db.commit()

    from app.services import notification_emitter

    notification_emitter.reload(db)
    return {"ok": True}


@router.post("/channels/{channel_id}/test", responses={404: {"description": "Not Found"}})
async def test_channel(
    channel_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    channel_id = validate_uuid(channel_id)
    cursor = await db.execute(
        "SELECT id, name, endpoint_url, secret_enc, event_filter, filter_min_severity, "
        "       batch_size, batch_interval_s, enabled "
        "FROM notification_channels WHERE id = ?",
        (channel_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_CHANNEL_NOT_FOUND)

    from app.schemas.op_event import OperationalEvent
    from app.services.notification_emitter import _event_to_dict, _send_one

    test_event = OperationalEvent(
        event_type="system.startup",
        severity="info",
        source="system",
        data={"test": True},
    )
    try:
        await _send_one(dict(row), [_event_to_dict(test_event)])
        return {"ok": True, "status_code": 200}
    except Exception as exc:
        logger.warning("notif test failed for channel %s: %s", channel_id, exc)
        return {"ok": False, "error": "Delivery failed — check endpoint and server logs"}


# ---------------------------------------------------------------------------
# Events log
# ---------------------------------------------------------------------------


@router.get("/events")
async def list_op_events(
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    limit: int = 50,
    since: str | None = None,
    types: str | None = None,
):
    type_filters = [t.strip() for t in types.split(",")] if types else []
    params: list = []
    where_clauses: list[str] = []

    if since:
        where_clauses.append("created_at >= ?")
        params.append(since)

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    sql = (
        f"SELECT id, event_id, event_type, severity, source, data_json, server_id, created_at "
        f"FROM operational_events {where_sql} "
        f"ORDER BY created_at DESC LIMIT ?"
    )
    params.append(min(limit, 1000))

    rows = await (await db.execute(sql, params)).fetchall()
    events = []
    for r in rows:
        try:
            data = json.loads(r["data_json"])
        except Exception:
            data = {}
        events.append(
            {
                "event_id": r["event_id"],
                "event_type": r["event_type"],
                "severity": r["severity"],
                "source": r["source"],
                "data": data,
                "server_id": r["server_id"],
                "created_at": r["created_at"],
            }
        )

    if type_filters:
        from app.services.notification_emitter import _matches_filter

        events = [e for e in events if _matches_filter(e["event_type"], type_filters)]

    return {"events": events, "total": len(events)}


# ---------------------------------------------------------------------------
# Notification settings
# ---------------------------------------------------------------------------


@router.get("/settings")
async def get_notif_settings(
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    keys = ["server_id", "op_event_retention_days", "api_key_expiry_warn_days", "upload_quota_warn_pct"]
    cursor = await db.execute(
        f"SELECT key, value FROM admin_settings WHERE key IN ({','.join('?' * len(keys))})",
        keys,
    )
    rows = await cursor.fetchall()
    result = {r["key"]: r["value"] for r in rows}
    return {
        "server_id": result.get("server_id", ""),
        "op_event_retention_days": int(result.get("op_event_retention_days", 30)),
        "api_key_expiry_warn_days": int(result.get("api_key_expiry_warn_days", 30)),
        "upload_quota_warn_pct": int(result.get("upload_quota_warn_pct", 90)),
    }


@router.put("/settings", responses={404: {"description": "Not Found"}})
async def update_notif_settings(
    body: NotifSettingsModel,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP_NOTIF))],
):
    pairs = [
        ("server_id", body.server_id or ""),
        ("op_event_retention_days", str(body.op_event_retention_days)),
        ("api_key_expiry_warn_days", str(body.api_key_expiry_warn_days)),
        ("upload_quota_warn_pct", str(body.upload_quota_warn_pct)),
    ]
    for key, value in pairs:
        await db.execute(
            "INSERT INTO admin_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (key, value),
        )
    await db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# API key CRUD (separate sub-path: /admin/api-keys)
# ---------------------------------------------------------------------------


@api_keys_router.get("/api-keys")
async def list_api_keys(
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    cursor = await db.execute(
        "SELECT id, name, scopes, event_filter, filter_min_severity, "
        "       allowed_ips, enabled, created_at, last_used_at, expires_at "
        "FROM api_keys ORDER BY created_at ASC"
    )
    rows = await cursor.fetchall()
    return {"keys": [dict(r) for r in rows]}


@api_keys_router.post("/api-keys", status_code=201)
async def create_api_key(
    body: ApiKeyCreateModel,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP_KEYS))],
):
    raw = "tss_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    key_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    scopes = _derive_scopes(body.event_filter)

    await db.execute(
        "INSERT INTO api_keys "
        "(id, name, key_hash, scopes, event_filter, allowed_ips, enabled, "
        " created_by, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            key_id,
            body.name,
            key_hash,
            json.dumps(scopes),
            json.dumps(body.event_filter),
            json.dumps(body.allowed_ips) if body.allowed_ips else None,
            body.enabled,
            user.id,
            now,
            body.expires_at,
        ),
    )
    await db.commit()

    return {
        "id": key_id,
        "name": body.name,
        "key": raw,
        "scopes": scopes,
        "event_filter": body.event_filter,
        "allowed_ips": body.allowed_ips,
        "enabled": body.enabled,
        "created_at": now,
        "expires_at": body.expires_at,
    }


@api_keys_router.put("/api-keys/{key_id}", responses={404: {"description": "API key not found"}})
async def update_api_key(
    key_id: str,
    body: ApiKeyUpdateModel,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP_KEYS))],
):
    """Update API key metadata. The key value itself is unchanged; use /rotate for that."""
    key_id = validate_uuid(key_id)
    cursor = await db.execute("SELECT id FROM api_keys WHERE id = ?", (key_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail=_ERR_KEY_NOT_FOUND)

    updates: list[str] = []
    params: list = []

    if body.name is not None:
        updates.append("name = ?")
        params.append(body.name)
    if body.event_filter is not None:
        updates.append("scopes = ?")
        params.append(json.dumps(_derive_scopes(body.event_filter)))
        updates.append("event_filter = ?")
        params.append(json.dumps(body.event_filter))
    if body.expires_at is not None:
        updates.append("expires_at = ?")
        params.append(body.expires_at or None)
    if body.allowed_ips is not None:
        updates.append("allowed_ips = ?")
        params.append(json.dumps(body.allowed_ips) if body.allowed_ips else None)
    if body.enabled is not None:
        updates.append("enabled = ?")
        params.append(body.enabled)

    if not updates:
        return {"ok": True}

    params.append(key_id)
    await db.execute(f"UPDATE api_keys SET {', '.join(updates)} WHERE id = ?", params)
    await db.commit()
    return {"ok": True}


@api_keys_router.post(
    "/api-keys/{key_id}/rotate", status_code=200, responses={404: {"description": "API key not found"}}
)
async def rotate_api_key(
    key_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP_KEYS))],
):
    """Issue a new raw key for an existing API key entry (old key is immediately invalidated)."""
    key_id = validate_uuid(key_id)
    cursor = await db.execute(
        "SELECT id, name, scopes, event_filter, expires_at FROM api_keys WHERE id = ?",
        (key_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_KEY_NOT_FOUND)

    raw = "tss_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()

    await db.execute(
        "UPDATE api_keys SET key_hash = ?, last_used_at = NULL WHERE id = ?",
        (key_hash, key_id),
    )
    await db.commit()

    return {
        "id": key_id,
        "name": row["name"],
        "key": raw,
        "scopes": json.loads(row["scopes"] or "[]"),
        "event_filter": json.loads(row["event_filter"] or "[]") if row["event_filter"] else [],
        "expires_at": row["expires_at"],
    }


@api_keys_router.delete("/api-keys/{key_id}", responses={404: {"description": "API key not found"}})
async def delete_api_key(
    key_id: str,
    user: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP_KEYS))],
):
    key_id = validate_uuid(key_id)
    cursor = await db.execute("SELECT id FROM api_keys WHERE id = ?", (key_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail=_ERR_KEY_NOT_FOUND)

    await db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    await db.commit()
    return {"ok": True}
