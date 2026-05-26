"""Service account admin routes.

Endpoints
---------
GET    /admin/service-accounts              list all
POST   /admin/service-accounts              create + issue key  [step-up]
GET    /admin/service-accounts/{id}         detail + role list
PATCH  /admin/service-accounts/{id}         update name/description/active/expires_at  [step-up]
DELETE /admin/service-accounts/{id}         delete account + key  [step-up]
POST   /admin/service-accounts/{id}/rotate-key  replace key, return new one  [step-up]

All mutations require FLAG_SERVICE_ACCOUNTS_MANAGE.  Step-up action key:
  admin.service_accounts.*
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.database import Database, get_db
from app.middleware.stepup import require_step_up
from app.models.role import FLAG_SERVICE_ACCOUNTS_MANAGE
from app.routes._access import require_flag
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus
from app.validation.sanitizers import validate_uuid

_ERR_PERM_SERVICE_ACCOUNTS = "Service account management permission required"
_ERR_SERVICE_ACCOUNT_NOT_FOUND = "Service account not found"

logger = logging.getLogger(__name__)
router = APIRouter()

_STEPUP = "admin.service_accounts.*"
_KEY_PREFIX = "sa_"
_KEY_ENTROPY_BYTES = 24  # 24 bytes → 32 url-safe base64 chars


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------


def _generate_raw_key() -> str:
    return _KEY_PREFIX + base64.urlsafe_b64encode(secrets.token_bytes(_KEY_ENTROPY_BYTES)).rstrip(b"=").decode()


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _key_prefix_display(raw: str) -> str:
    return raw[:12]


# ---------------------------------------------------------------------------
# Permission guard
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


def _validate_expires_at(v: Optional[str]) -> Optional[str]:
    """Accept None/empty (no expiry), or a future ISO-8601 timestamp."""
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        raise ValueError("expires_at must be a valid ISO-8601 timestamp")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if dt <= datetime.now(timezone.utc):
        raise ValueError("expires_at must be a future date")
    return v


class CreateServiceAccountRequest(BaseModel):
    username: str
    description: Optional[str] = None
    expires_at: Optional[str] = None  # ISO-8601 or None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError("username must be 1–64 characters")
        return v

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, v: Optional[str]) -> Optional[str]:
        return _validate_expires_at(v)


class UpdateServiceAccountRequest(BaseModel):
    username: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    expires_at: Optional[str] = None  # ISO-8601, empty string = clear

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError("username must be 1–64 characters")
        return v

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, v: Optional[str]) -> Optional[str]:
        return _validate_expires_at(v)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _sa_row_to_dict(row, key_row=None) -> dict:
    d = {
        "id": row["id"],
        "username": row["username"],
        "description": row["description"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
    }
    if key_row is not None:
        d["key_prefix"] = key_row["key_prefix"]
        d["key_created_at"] = key_row["created_at"]
        d["key_expires_at"] = key_row["expires_at"]
        d["last_used_at"] = key_row["last_used_at"]
    return d


# ---------------------------------------------------------------------------
# GET /service-accounts
# ---------------------------------------------------------------------------


@router.get("/service-accounts")
async def list_service_accounts(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    require_flag(admin, FLAG_SERVICE_ACCOUNTS_MANAGE, _ERR_PERM_SERVICE_ACCOUNTS)

    cursor = await db.execute(
        """
        SELECT u.id, u.username, u.description, u.is_active, u.created_at,
               sak.key_prefix, sak.created_at AS key_created_at,
               sak.expires_at, sak.last_used_at
        FROM   users u
        LEFT JOIN service_account_keys sak ON sak.service_account_id = u.id
        WHERE  u.auth_method = 'service'
        ORDER  BY u.created_at DESC
        """
    )
    rows = await cursor.fetchall()
    return {
        "service_accounts": [
            {
                "id": r["id"],
                "username": r["username"],
                "description": r["description"],
                "is_active": bool(r["is_active"]),
                "created_at": r["created_at"],
                "key_prefix": r["key_prefix"],
                "key_created_at": r["key_created_at"],
                "key_expires_at": r["expires_at"],
                "last_used_at": r["last_used_at"],
            }
            for r in rows
        ]
    }


# ---------------------------------------------------------------------------
# POST /service-accounts  [step-up]
# ---------------------------------------------------------------------------


@router.post("/service-accounts", responses={409: {"description": "Conflict"}})
async def create_service_account(
    body: CreateServiceAccountRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP))],
):
    require_flag(admin, FLAG_SERVICE_ACCOUNTS_MANAGE, _ERR_PERM_SERVICE_ACCOUNTS)

    sa_id = str(uuid.uuid4())
    raw_key = _generate_raw_key()
    key_hash = _hash_key(raw_key)
    key_prefix = _key_prefix_display(raw_key)
    key_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Insert users row — no OPAQUE record, no KEK, no MFA.
    # Policy hooks are intentionally NOT called here (service accounts are
    # policy-exempt by design; auth_method='service' guard in evaluate_user_policies).
    try:
        await db.execute(
            """
            INSERT INTO users
                (id, username, auth_method, is_admin, is_active, description, created_at, updated_at)
            VALUES (?, ?, 'service', 0, 1, ?, ?, ?)
            """,
            (sa_id, body.username, body.description, now, now),
        )
    except Exception as exc:
        if "UNIQUE" in str(exc).upper() or "unique" in str(exc):
            raise HTTPException(status_code=409, detail="Username already taken")
        raise

    await db.execute(
        """
        INSERT INTO service_account_keys
            (id, service_account_id, key_hash, key_prefix, created_by, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (key_id, sa_id, key_hash, key_prefix, admin.id, now, body.expires_at),
    )
    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type="admin.service_account.created",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username),
            target=EventTarget(object_id=sa_id, type="service_account"),
            detail={"username": body.username},
        )
    )
    logger.info(
        "Service account '%s' created by %s", body.username, admin.username
    )  # NOSONAR — server-side audit log; values are Pydantic-validated

    return {
        "id": sa_id,
        "username": body.username,
        "key": raw_key,  # shown exactly once
    }


# ---------------------------------------------------------------------------
# GET /service-accounts/{id}
# ---------------------------------------------------------------------------


@router.get("/service-accounts/{sa_id}", responses={404: {"description": "Not Found"}})
async def get_service_account(
    sa_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    require_flag(admin, FLAG_SERVICE_ACCOUNTS_MANAGE, _ERR_PERM_SERVICE_ACCOUNTS)
    sa_id = validate_uuid(sa_id)

    cursor = await db.execute(
        """
        SELECT u.id, u.username, u.description, u.is_active, u.created_at,
               sak.id AS key_id, sak.key_prefix, sak.created_at AS key_created_at,
               sak.expires_at, sak.last_used_at
        FROM   users u
        LEFT JOIN service_account_keys sak ON sak.service_account_id = u.id
        WHERE  u.id = ? AND u.auth_method = 'service'
        """,
        (sa_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_SERVICE_ACCOUNT_NOT_FOUND)

    # Load role assignments
    rc = await db.execute(
        "SELECT role_id, scope_type, scope_id FROM user_roles WHERE user_id = ?",
        (sa_id,),
    )
    roles = [
        {"role_id": r["role_id"], "scope_type": r["scope_type"], "scope_id": r["scope_id"]} for r in await rc.fetchall()
    ]

    return {
        "id": row["id"],
        "username": row["username"],
        "description": row["description"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "key_prefix": row["key_prefix"],
        "key_created_at": row["key_created_at"],
        "key_expires_at": row["expires_at"],
        "last_used_at": row["last_used_at"],
        "roles": roles,
    }


# ---------------------------------------------------------------------------
# PATCH /service-accounts/{id}  [step-up]
# ---------------------------------------------------------------------------


@router.patch("/service-accounts/{sa_id}", responses={404: {"description": "Not Found"}})
async def update_service_account(
    sa_id: str,
    body: UpdateServiceAccountRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP))],
):
    require_flag(admin, FLAG_SERVICE_ACCOUNTS_MANAGE, _ERR_PERM_SERVICE_ACCOUNTS)
    sa_id = validate_uuid(sa_id)

    cursor = await db.execute(
        "SELECT id, username, is_active FROM users WHERE id = ? AND auth_method = 'service'",
        (sa_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_SERVICE_ACCOUNT_NOT_FOUND)

    now = datetime.now(timezone.utc).isoformat()
    updates: list[str] = ["updated_at = ?"]
    params: list = [now]

    if body.username is not None:
        updates.append("username = ?")
        params.append(body.username)
    if body.description is not None:
        updates.append("description = ?")
        params.append(body.description)
    if body.is_active is not None:
        updates.append("is_active = ?")
        params.append(1 if body.is_active else 0)

    params.append(sa_id)
    await db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)

    # expires_at lives on the key row
    if body.expires_at is not None:
        expires = body.expires_at if body.expires_at else None
        await db.execute(
            "UPDATE service_account_keys SET expires_at = ? WHERE service_account_id = ?",
            (expires, sa_id),
        )

    await db.commit()

    changed = body.dict(exclude_none=True)
    severity = "warning" if body.is_active is False else "info"
    event_type = "admin.service_account.deactivated" if body.is_active is False else "admin.service_account.updated"

    event_bus.emit(
        SecurityEvent(
            event_type=event_type,
            severity=severity,
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username),
            target=EventTarget(object_id=sa_id, type="service_account"),
            detail={"username": row["username"], "changes": list(changed.keys())},
        )
    )

    return {"id": sa_id, "updated": True}


# ---------------------------------------------------------------------------
# DELETE /service-accounts/{id}  [step-up]
# ---------------------------------------------------------------------------


@router.delete("/service-accounts/{sa_id}", responses={404: {"description": "Not Found"}})
async def delete_service_account(
    sa_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP))],
):
    require_flag(admin, FLAG_SERVICE_ACCOUNTS_MANAGE, _ERR_PERM_SERVICE_ACCOUNTS)
    sa_id = validate_uuid(sa_id)

    cursor = await db.execute(
        "SELECT id, username FROM users WHERE id = ? AND auth_method = 'service'",
        (sa_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_SERVICE_ACCOUNT_NOT_FOUND)

    # CASCADE on service_account_keys handles key deletion
    await db.execute("DELETE FROM users WHERE id = ?", (sa_id,))
    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type="admin.service_account.deleted",
            severity="warning",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username),
            target=EventTarget(object_id=sa_id, type="service_account"),
            detail={"username": row["username"]},
        )
    )
    logger.warning("Service account '%s' deleted by %s", row["username"], admin.username)

    return {"deleted": True}


# ---------------------------------------------------------------------------
# POST /service-accounts/{id}/rotate-key  [step-up]
# ---------------------------------------------------------------------------


@router.post("/service-accounts/{sa_id}/rotate-key", responses={404: {"description": "Not Found"}})
async def rotate_service_account_key(
    sa_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    _stepup: Annotated[None, Depends(require_step_up(_STEPUP))],
):
    require_flag(admin, FLAG_SERVICE_ACCOUNTS_MANAGE, _ERR_PERM_SERVICE_ACCOUNTS)
    sa_id = validate_uuid(sa_id)

    cursor = await db.execute(
        "SELECT id, username FROM users WHERE id = ? AND auth_method = 'service'",
        (sa_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_SERVICE_ACCOUNT_NOT_FOUND)

    raw_key = _generate_raw_key()
    key_hash = _hash_key(raw_key)
    key_prefix = _key_prefix_display(raw_key)
    key_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Delete the old key row (CASCADE would also handle account deletion but
    # here we're replacing, not deleting the account)
    await db.execute(
        "DELETE FROM service_account_keys WHERE service_account_id = ?",
        (sa_id,),
    )
    await db.execute(
        """
        INSERT INTO service_account_keys
            (id, service_account_id, key_hash, key_prefix, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (key_id, sa_id, key_hash, key_prefix, admin.id, now),
    )
    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type="admin.service_account.key_rotated",
            severity="warning",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username),
            target=EventTarget(object_id=sa_id, type="service_account"),
            detail={"username": row["username"]},
        )
    )
    logger.warning("Service account '%s' key rotated by %s", row["username"], admin.username)

    return {
        "id": sa_id,
        "key": raw_key,  # shown exactly once
    }
