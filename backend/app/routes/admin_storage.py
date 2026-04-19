"""Admin routes for storage volume management (F3).

Endpoints
─────────
GET    /admin/storage/volumes              — list all volumes (no credentials)
POST   /admin/storage/volumes              — create a new volume  [step-up]
GET    /admin/storage/volumes/{id}         — get one volume (credentials redacted)
PUT    /admin/storage/volumes/{id}         — update volume config  [step-up]
DELETE /admin/storage/volumes/{id}         — delete volume  [step-up]
POST   /admin/storage/volumes/{id}/test    — test connectivity
POST   /admin/storage/volumes/{id}/default — set as default volume  [step-up]
GET    /admin/storage/usage                — disk usage across all volumes
GET    /admin/storage/tiers                — tiering policy settings
PUT    /admin/storage/tiers                — update tiering policy  [step-up]

All mutation endpoints require the admin.storage.configure step-up key because
they expose or modify provider credentials (access keys, bucket names).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import urllib.parse
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.config import settings
from app.database import get_db
from app.middleware.stepup import require_step_up
from app.storage.crypto import decrypt_volume_config, encrypt_volume_config
import app.storage.manager as storage
from app.validation.sanitizers import validate_uuid

logger = logging.getLogger(__name__)

router = APIRouter()

_STEPUP = "admin.storage.configure"
_REDACTED = "••••••••"
_SECRET_FIELDS = {"access_key_id", "secret_access_key", "bind_password", "client_secret"}

_VALID_PROVIDERS = {"local", "s3", "b2"}
_VALID_TIERS = {"hot", "warm", "cold"}

# Networks that must never be targets of server-side outbound connections.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata (169.254.169.254)
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT shared space
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]


async def _validate_endpoint_url(url: str) -> None:
    """Reject endpoint URLs that point to private/internal networks (SSRF prevention).

    Enforces HTTPS in non-debug mode and resolves the hostname to check for
    RFC 1918, link-local (including the AWS/GCP metadata IP), and loopback ranges.
    Raises HTTPException(422) on any violation.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise HTTPException(status_code=422, detail="endpoint_url is not a valid URL")

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=422, detail="endpoint_url must use http or https scheme")
    if parsed.scheme == "http" and not settings.DEBUG:
        raise HTTPException(
            status_code=422,
            detail="endpoint_url must use https in production (set DEBUG=true to allow plain http)",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=422, detail="endpoint_url must include a hostname")

    try:
        addr_infos = await asyncio.to_thread(socket.getaddrinfo, hostname, None)
    except socket.gaierror:
        raise HTTPException(
            status_code=422, detail="Cannot resolve the hostname in endpoint_url"
        )

    for _, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for net in _BLOCKED_NETWORKS:
            try:
                if ip in net:
                    raise HTTPException(
                        status_code=422,
                        detail=(
                            "endpoint_url resolves to a private or reserved address. "
                            "Direct access to internal networks is not permitted."
                        ),
                    )
            except TypeError:
                pass  # IPv4 address checked against IPv6 network (or vice-versa) — skip


def _redact_config(cfg: dict) -> dict:
    return {k: (_REDACTED if k in _SECRET_FIELDS else v) for k, v in cfg.items()}


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class VolumeCreateModel(BaseModel):
    name: str
    provider: str
    tier: str = "hot"
    config: dict = {}

    @field_validator("name")
    @classmethod
    def val_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be empty")
        if len(v) > 128:
            raise ValueError("name too long")
        return v

    @field_validator("provider")
    @classmethod
    def val_provider(cls, v: str) -> str:
        if v not in _VALID_PROVIDERS:
            raise ValueError(f"provider must be one of: {', '.join(_VALID_PROVIDERS)}")
        return v

    @field_validator("tier")
    @classmethod
    def val_tier(cls, v: str) -> str:
        if v not in _VALID_TIERS:
            raise ValueError(f"tier must be one of: {', '.join(_VALID_TIERS)}")
        return v


class TieringPolicyModel(BaseModel):
    enabled: bool = False
    hot_to_warm_days: int | None = None
    warm_to_cold_days: int | None = None
    warm_volume_id: str | None = None
    cold_volume_id: str | None = None
    auto_warm_on_read: bool = False
    warn_pct: float | None = 90.0
    warn_bytes_remaining: int | None = 1 * 1024 ** 3

    @field_validator("warn_pct")
    @classmethod
    def val_warn_pct(cls, v: float | None) -> float | None:
        if v is not None and not (0 <= v <= 100):
            raise ValueError("warn_pct must be between 0 and 100")
        return v

    @field_validator("warn_bytes_remaining")
    @classmethod
    def val_warn_bytes(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError("warn_bytes_remaining must be non-negative")
        return v


# ---------------------------------------------------------------------------
# Volume CRUD
# ---------------------------------------------------------------------------

@router.get("/volumes")
async def list_volumes(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    cursor = await db.execute(
        "SELECT id, name, provider, tier, is_default, priority, created_at "
        "FROM storage_volumes ORDER BY priority ASC, created_at ASC"
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


@router.post("/volumes", dependencies=[Depends(require_step_up(_STEPUP))])
async def create_volume(
    body: VolumeCreateModel,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    if body.provider in ("s3", "b2") and body.config.get("endpoint_url"):
        await _validate_endpoint_url(body.config["endpoint_url"])

    vol_id = str(uuid.uuid4())
    config_enc = encrypt_volume_config(body.config) if body.config else None

    try:
        await db.execute(
            "INSERT INTO storage_volumes (id, name, provider, config_enc, tier, is_default, priority) "
            "VALUES (?, ?, ?, ?, ?, 0, 0)",
            (vol_id, body.name, body.provider, config_enc, body.tier),
        )
        await db.commit()
    except Exception as exc:
        if "UNIQUE" in str(exc).upper():
            raise HTTPException(status_code=409, detail="A volume with that name already exists")
        raise

    await storage.get_manager().load_volumes(db)
    return {"id": vol_id, "message": "Volume created"}


@router.get("/volumes/{volume_id}")
async def get_volume(
    volume_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    volume_id = validate_uuid(volume_id)
    cursor = await db.execute(
        "SELECT id, name, provider, config_enc, tier, is_default, priority, created_at "
        "FROM storage_volumes WHERE id = ?",
        (volume_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Volume not found")

    result = dict(row)
    if result.get("config_enc"):
        try:
            cfg = decrypt_volume_config(result["config_enc"])
            result["config"] = _redact_config(cfg)
        except Exception:
            result["config"] = {}
    else:
        result["config"] = {}
    del result["config_enc"]
    return result


@router.put("/volumes/{volume_id}", dependencies=[Depends(require_step_up(_STEPUP))])
async def update_volume(
    volume_id: str,
    body: VolumeCreateModel,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    volume_id = validate_uuid(volume_id)

    cursor = await db.execute("SELECT config_enc FROM storage_volumes WHERE id = ?", (volume_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Volume not found")

    # If the client sent redacted values, keep the existing encrypted config for those fields
    existing_config: dict = {}
    if row["config_enc"]:
        try:
            existing_config = decrypt_volume_config(row["config_enc"])
        except Exception:
            pass

    merged = dict(existing_config)
    for k, v in body.config.items():
        if v != _REDACTED:
            merged[k] = v

    if body.provider in ("s3", "b2") and merged.get("endpoint_url"):
        await _validate_endpoint_url(merged["endpoint_url"])

    config_enc = encrypt_volume_config(merged) if merged else None

    await db.execute(
        "UPDATE storage_volumes SET name = ?, provider = ?, config_enc = ?, tier = ? WHERE id = ?",
        (body.name, body.provider, config_enc, body.tier, volume_id),
    )
    await db.commit()
    await storage.get_manager().load_volumes(db)
    return {"message": "Volume updated"}


@router.delete("/volumes/{volume_id}", dependencies=[Depends(require_step_up(_STEPUP))])
async def delete_volume(
    volume_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    volume_id = validate_uuid(volume_id)

    cursor = await db.execute(
        "SELECT is_default FROM storage_volumes WHERE id = ?", (volume_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Volume not found")
    if row["is_default"]:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete the default volume. Set another volume as default first.",
        )

    # Reject if any files still live on this volume
    cursor = await db.execute(
        "SELECT COUNT(*) FROM file_storage_locations WHERE volume_id = ?", (volume_id,)
    )
    count_row = await cursor.fetchone()
    if count_row[0] > 0:
        raise HTTPException(
            status_code=409,
            detail=f"Volume still holds {count_row[0]} file location(s). Migrate or delete them first.",
        )

    await db.execute("DELETE FROM storage_volumes WHERE id = ?", (volume_id,))
    await db.commit()
    await storage.get_manager().load_volumes(db)
    return {"message": "Volume deleted"}


@router.post("/volumes/{volume_id}/default", dependencies=[Depends(require_step_up(_STEPUP))])
async def set_default_volume(
    volume_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    volume_id = validate_uuid(volume_id)

    cursor = await db.execute("SELECT id FROM storage_volumes WHERE id = ?", (volume_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="Volume not found")

    await db.execute("BEGIN")
    try:
        await db.execute("UPDATE storage_volumes SET is_default = 0")
        await db.execute("UPDATE storage_volumes SET is_default = 1 WHERE id = ?", (volume_id,))
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    await storage.get_manager().load_volumes(db)
    return {"message": "Default volume updated"}


@router.post("/volumes/{volume_id}/test")
async def test_volume(
    volume_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    volume_id = validate_uuid(volume_id)
    mgr = storage.get_manager()

    if volume_id not in mgr._providers:
        raise HTTPException(status_code=404, detail="Volume not loaded or not found")

    provider = mgr._providers[volume_id]
    try:
        used, total = await provider.get_usage()
        return {"ok": True, "used_bytes": used, "total_bytes": total}
    except Exception as exc:
        logger.warning("Volume connectivity test failed for %s: %s", volume_id, exc)
        return {"ok": False, "error": "Connection failed — check credentials and endpoint configuration"}


# ---------------------------------------------------------------------------
# Usage summary
# ---------------------------------------------------------------------------

@router.get("/usage")
async def get_storage_usage(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    cursor = await db.execute(
        "SELECT key, value FROM admin_settings WHERE key IN (?, ?)",
        ("storage_warn_pct", "storage_warn_bytes_remaining"),
    )
    rows = await cursor.fetchall()
    sm = {r["key"]: r["value"] for r in rows}

    raw_pct = sm.get("storage_warn_pct", "")
    raw_bytes = sm.get("storage_warn_bytes_remaining", "")
    warn_pct = float(raw_pct) if raw_pct not in (None, "", "null") else None
    warn_bytes = int(raw_bytes) if raw_bytes not in (None, "", "null") else None

    return await storage.get_manager().get_usage_summary(
        warn_pct=warn_pct,
        warn_bytes_remaining=warn_bytes,
    )


# ---------------------------------------------------------------------------
# Tiering policy
# ---------------------------------------------------------------------------

@router.get("/tiers")
async def get_tiering_policy(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    keys = [
        "storage_tiering_enabled",
        "storage_hot_to_warm_days",
        "storage_warm_to_cold_days",
        "storage_warm_volume_id",
        "storage_cold_volume_id",
        "storage_auto_warm_on_read",
        "storage_warn_pct",
        "storage_warn_bytes_remaining",
    ]
    cursor = await db.execute(
        f"SELECT key, value FROM admin_settings WHERE key IN ({','.join('?' * len(keys))})",
        keys,
    )
    rows = await cursor.fetchall()
    sm = {row["key"]: row["value"] for row in rows}

    raw_pct = sm.get("storage_warn_pct", "90")
    raw_bytes = sm.get("storage_warn_bytes_remaining", str(1 * 1024 ** 3))
    return {
        "enabled": sm.get("storage_tiering_enabled", "0") == "1",
        "hot_to_warm_days": int(sm["storage_hot_to_warm_days"])
            if sm.get("storage_hot_to_warm_days") else None,
        "warm_to_cold_days": int(sm["storage_warm_to_cold_days"])
            if sm.get("storage_warm_to_cold_days") else None,
        "warm_volume_id": sm.get("storage_warm_volume_id") or None,
        "cold_volume_id": sm.get("storage_cold_volume_id") or None,
        "auto_warm_on_read": sm.get("storage_auto_warm_on_read", "0") == "1",
        "warn_pct": float(raw_pct) if raw_pct not in (None, "", "null") else None,
        "warn_bytes_remaining": int(raw_bytes) if raw_bytes not in (None, "", "null") else None,
    }


@router.post("/tiering/trigger")
async def trigger_tiering_pass(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Run a tiering pass immediately without waiting for the scheduled interval.

    Useful for manual operations and testing.  Emits capacity events via op_bus
    after the pass completes, identical to the scheduled background task.
    """
    mgr = storage.get_manager()
    await mgr._run_tiering_pass(db)
    await mgr._emit_volume_states(db)
    return {"ok": True}


@router.put("/tiers", dependencies=[Depends(require_step_up(_STEPUP))])
async def update_tiering_policy(
    body: TieringPolicyModel,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    updates = {
        "storage_tiering_enabled":      "1" if body.enabled else "0",
        "storage_hot_to_warm_days":     str(body.hot_to_warm_days) if body.hot_to_warm_days else "",
        "storage_warm_to_cold_days":    str(body.warm_to_cold_days) if body.warm_to_cold_days else "",
        "storage_warm_volume_id":       body.warm_volume_id or "",
        "storage_cold_volume_id":       body.cold_volume_id or "",
        "storage_auto_warm_on_read":    "1" if body.auto_warm_on_read else "0",
        "storage_warn_pct":             str(body.warn_pct) if body.warn_pct is not None else "null",
        "storage_warn_bytes_remaining": str(body.warn_bytes_remaining) if body.warn_bytes_remaining is not None else "null",
    }
    for key, value in updates.items():
        await db.execute(
            "INSERT INTO admin_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (key, value),
        )
    await db.commit()
    return {"message": "Tiering policy updated"}
