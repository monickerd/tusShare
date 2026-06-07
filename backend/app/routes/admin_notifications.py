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
DELETE /admin/api-keys/{id}                       [step-up]
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
from app.util.ssrf import validate_endpoint_url
from app.validation.sanitizers import validate_uuid

_ERR_CHANNEL_NOT_FOUND = "Channel not found"

logger = logging.getLogger(__name__)
router = APIRouter()  # mounted at /api/v1/admin/notifications
api_keys_router = APIRouter()  # mounted at /api/v1/admin

_STEPUP_NOTIF = "admin.notifications.configure"
_STEPUP_KEYS = "admin.api_keys.manage"
_REDACTED = "••••••••"
_FILTER_RE = re.compile(r"^[a-z][a-z0-9._:*-]{0,127}$")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ChannelCreateModel(BaseModel):
    name: str
    endpoint_url: str
    secret: str | None = None
    event_filter: list[str] = []
    filter_min_severity: str | None = None
    batch_size: int | None = None
    batch_interval_s: int | None = None
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
            if not _FILTER_RE.match(f):
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


_VALID_SCOPES = frozenset({"events.read", "ops_read", "audit_read", "notification_write"})


class ApiKeyCreateModel(BaseModel):
    name: str
    scopes: list[str] = ["events.read"]
    expires_at: str | None = None  # ISO datetime string or None
    filter_event_types: str | None = None  # comma-separated glob patterns, e.g. "auth.*,admin.*"
    filter_min_severity: str | None = None  # info | warning | critical

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("name must be 1–128 characters")
        return v

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, v: list[str]) -> list[str]:
        unknown = set(v) - _VALID_SCOPES
        if unknown:
            raise ValueError(
                f"Unknown scope(s): {', '.join(sorted(unknown))}. Valid: {', '.join(sorted(_VALID_SCOPES))}"
            )
        if not v:
            raise ValueError("At least one scope is required")
        return v

    @field_validator("filter_min_severity")
    @classmethod
    def _severity(cls, v: str | None) -> str | None:
        if v is not None and v not in ("info", "warning", "critical"):
            raise ValueError("filter_min_severity must be info, warning, or critical")
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
        "       batch_size, batch_interval_s, enabled, created_at "
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
        " batch_size, batch_interval_s, enabled, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            now,
        ),
    )
    await db.commit()

    from app.services import notification_emitter

    notification_emitter.reload(db)
    await asyncio.sleep(0.1)  # brief yield so supervisor picks up new channel
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
        "       batch_size, batch_interval_s, enabled, created_at "
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
        # Keep existing secret
        secret_enc = existing["secret_enc"]
    else:
        secret_enc = encrypt_channel_secret(body.secret) if body.secret else None

    await db.execute(
        "UPDATE notification_channels SET name=?, endpoint_url=?, secret_enc=?, "
        "event_filter=?, filter_min_severity=?, batch_size=?, batch_interval_s=?, enabled=? WHERE id=?",
        (
            body.name,
            body.endpoint_url,
            secret_enc,
            json.dumps(body.event_filter),
            body.filter_min_severity,
            body.batch_size,
            body.batch_interval_s,
            1 if body.enabled else 0,
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
# Events log (admin view — no API key required, admin session sufficient)
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
        "SELECT id, name, scopes, created_at, last_used_at, expires_at FROM api_keys ORDER BY created_at ASC"
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

    await db.execute(
        "INSERT INTO api_keys "
        "(id, name, key_hash, scopes, filter_event_types, filter_min_severity, "
        " created_by, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            key_id,
            body.name,
            key_hash,
            json.dumps(body.scopes),
            body.filter_event_types,
            body.filter_min_severity,
            user.id,
            now,
            body.expires_at,
        ),
    )
    await db.commit()

    return {
        "id": key_id,
        "name": body.name,
        "key": raw,  # shown only once
        "scopes": body.scopes,
        "filter_event_types": body.filter_event_types,
        "filter_min_severity": body.filter_min_severity,
        "created_at": now,
        "expires_at": body.expires_at,
    }


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
        "SELECT id, name, scopes, filter_event_types, filter_min_severity, expires_at FROM api_keys WHERE id = ?",
        (key_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="API key not found")

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
        "key": raw,  # shown only once
        "scopes": json.loads(row["scopes"] or "[]"),
        "filter_event_types": row["filter_event_types"],
        "filter_min_severity": row["filter_min_severity"],
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
        raise HTTPException(status_code=404, detail="API key not found")

    await db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    await db.commit()
    return {"ok": True}
