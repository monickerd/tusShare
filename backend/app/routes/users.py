"""Admin user management routes.

Two separate creation flows:
  POST /users       — create a regular user (file storage account)
  POST /admins      — create an admin-only account (management, no file operations)

This separation ensures admin accounts never accidentally gain user privileges
and regular user creation cannot escalate to admin.
"""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.models.role import FLAG_MANAGE_USERS, FLAG_MANAGE_ROLES
from app.database import db_session, get_db
from app.models.role import ADMIN_ROLE_IDS, ROLE_ADMIN, ROLE_USER, ROLE_TIER, admin_best_tier, grant_role, revoke_role
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus
import app.storage.manager as storage
from app.models.user import User
from app.validation.sanitizers import sanitize_username, validate_base64, validate_uuid
from app.validation.validators import validate_pagination

router = APIRouter()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request models — separate schemas for users vs admins
# ---------------------------------------------------------------------------

class CreateUserRequest(BaseModel):
    """Regular user — has E2E encryption, quotas, file operations."""
    username: str
    disk_quota: int | None = None
    bandwidth_limit: int | None = None
    max_file_size: int | None = None
    wrapped_master_key: str | None = None
    wrapped_master_key_iv: str | None = None
    recovery_key_wrapped: str | None = None
    recovery_key_iv: str | None = None
    recovery_key_hash: str | None = None
    # Asymmetric PQ keys (Phase 5b — optional, set on first login if not provided)
    x25519_public_key: str | None = None
    mlkem768_public_key: str | None = None
    x25519_private_wrapped: str | None = None
    mlkem768_private_wrapped: str | None = None
    asymmetric_key_iv: str | None = None

    @field_validator(
        "wrapped_master_key", "wrapped_master_key_iv",
        "recovery_key_wrapped", "recovery_key_iv",
        "x25519_public_key", "mlkem768_public_key",
        "x25519_private_wrapped", "mlkem768_private_wrapped",
        "asymmetric_key_iv",
    )
    @classmethod
    def validate_blobs(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v)
        return v

    @field_validator("recovery_key_hash")
    @classmethod
    def validate_hash(cls, v: str | None) -> str | None:
        if v is not None:
            if not v or len(v) > 128 or not all(c in "0123456789abcdef" for c in v):
                raise ValueError("Invalid recovery key hash (expected hex)")
        return v


class CreateAdminRequest(BaseModel):
    """Admin-only account — management operations only, no file storage."""
    username: str


class UpdateUserRequest(BaseModel):
    """Mutable user settings. Role changes use dedicated grant/revoke endpoints."""
    is_active: bool | None = None
    disk_quota: int | None = None
    bandwidth_limit: int | None = None
    max_file_size: int | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_users(
    page: int = 1,
    limit: int = 20,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """List all users with pagination."""
    if not admin.has_flag(FLAG_MANAGE_USERS):
        raise HTTPException(status_code=403, detail="can_manage_users permission required")
    pagination = validate_pagination(page, limit)
    cursor = await db.execute(
        "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (pagination.limit, pagination.offset),
    )
    rows = await cursor.fetchall()

    count_cursor = await db.execute("SELECT COUNT(*) FROM users")
    total = (await count_cursor.fetchone())[0]

    def _user_dict(r) -> dict:
        return {
            "id":                       r["id"],
            "username":                 r["username"],
            "is_admin":                 bool(r["is_admin"]),
            "is_active":                bool(r["is_active"]),
            "auth_method":              r["auth_method"],
            "identity_provider_id":     r["identity_provider_id"],
            "wrapped_master_key":       r["wrapped_master_key"],
            "max_file_size":            r["max_file_size"],
            "disk_quota":               r["disk_quota"],
            "bandwidth_limit":          r["bandwidth_limit"],
            "disk_used":                r["disk_used"],
            "created_at":               str(r["created_at"]) if r["created_at"] else None,
        }

    return {
        "users": [_user_dict(r) for r in rows],
        "total": total,
        "page": pagination.page,
        "limit": pagination.limit,
    }


@router.post("")
async def create_user(
    body: CreateUserRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Create a regular user — use the invite flow instead.

    Direct password-based user creation is not compatible with OPAQUE
    authentication.  Generate an invite via POST /api/v1/admin/invites and
    have the user register via /api/v1/auth/opaque/register/start+finish.
    """
    raise HTTPException(
        status_code=410,
        detail=(
            "Direct user creation is not supported with OPAQUE authentication. "
            "Use POST /api/v1/admin/invites to generate an invite link, "
            "then have the user register via the OPAQUE registration flow."
        ),
    )


@router.post("/admins")
async def create_admin(
    body: CreateAdminRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Create an admin-only account — use the invite+role-grant flow instead.

    Direct password-based admin creation is not compatible with OPAQUE
    authentication.  Generate an invite via POST /api/v1/admin/invites,
    have the user register, then grant the admin role via
    POST /api/v1/admin/users/{id}/roles/role_admin.
    """
    raise HTTPException(
        status_code=410,
        detail=(
            "Direct admin creation is not supported with OPAQUE authentication. "
            "Use POST /api/v1/admin/invites to generate an invite link, "
            "have the user register via OPAQUE, then grant the admin role via "
            "POST /api/v1/admin/users/{user_id}/roles/role_admin."
        ),
    )


@router.get("/{user_id}")
async def get_user(
    user_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Get a single user's details including roles."""
    user_id = validate_uuid(user_id)
    cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Load roles
    role_cursor = await db.execute(
        "SELECT role_id FROM user_roles WHERE user_id = ? AND scope_type IS NULL",
        (user_id,),
    )
    roles = [r["role_id"] for r in await role_cursor.fetchall()]

    user_dict = {
        "id":              row["id"],
        "username":        row["username"],
        "is_admin":        bool(row["is_admin"]),
        "is_active":       bool(row["is_active"]),
        "max_file_size":   row["max_file_size"],
        "disk_quota":      row["disk_quota"],
        "bandwidth_limit": row["bandwidth_limit"],
        "disk_used":       row["disk_used"],
        "created_at":      str(row["created_at"]) if row["created_at"] else None,
    }
    user_dict["roles"] = sorted(roles)
    return {"user": user_dict}


@router.put("/{user_id}")
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Update a user's settings (quotas, active status)."""
    if not admin.has_flag(FLAG_MANAGE_USERS):
        raise HTTPException(status_code=403, detail="can_manage_users permission required")
    user_id = validate_uuid(user_id)

    # Prevent admin from deactivating themselves
    if user_id == admin.id and body.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    updates = []
    params = []
    for field, column in [
        ("is_active", "is_active"),
        ("disk_quota", "disk_quota"),
        ("bandwidth_limit", "bandwidth_limit"),
        ("max_file_size", "max_file_size"),
    ]:
        value = getattr(body, field)
        if value is not None:
            updates.append(f"{column} = ?")
            params.append(int(value) if isinstance(value, bool) else value)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates.append("updated_at = NOW()")
    params.append(user_id)

    result = await db.execute(
        f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
        params,
    )
    await db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")

    if body.is_active is not None:
        event_bus.emit(SecurityEvent(
            event_type="admin.user.deactivated" if not body.is_active else "admin.user.activated",
            severity="warning" if not body.is_active else "info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username),
            target=EventTarget(type="user", id=user_id),
        ))

    if body.is_active is False:
        # Immediately revoke all active sessions — defence-in-depth on top of the
        # is_active gate in get_user_by_id (which already blocks new requests).
        await db.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
            (user_id,),
        )
        # Remove team key material so access is blocked even if the account is
        # later re-activated without a deliberate re-invitation to each team.
        await db.execute(
            "DELETE FROM user_team_keys WHERE user_id = ?",
            (user_id,),
        )
        # Immediately expire all link/user shares created by this account so
        # recipients can no longer download via those links.
        await db.execute(
            "UPDATE shares SET expires_at = NOW() "
            "WHERE created_by = ? AND (expires_at IS NULL OR expires_at > NOW())",
            (user_id,),
        )
        await db.commit()

    return {"message": "User updated"}


@router.get("/{user_id}/roles")
async def list_user_roles(
    user_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """List all role assignments for a user (global + scoped)."""
    user_id = validate_uuid(user_id)

    cursor = await db.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="User not found")

    cursor = await db.execute(
        "SELECT ur.id, ur.role_id, ur.scope_type, ur.scope_id, ur.granted_by, "
        "       r.name AS role_name, r.is_system "
        "FROM user_roles ur "
        "JOIN roles r ON r.id = ur.role_id "
        "WHERE ur.user_id = ? "
        "ORDER BY ur.scope_type NULLS FIRST, ur.role_id",
        (user_id,),
    )
    rows = await cursor.fetchall()
    return {
        "user_id": user_id,
        "roles": [
            {
                "assignment_id": r["id"],
                "role_id":       r["role_id"],
                "role_name":     r["role_name"],
                "is_system":     bool(r["is_system"]),
                "scope_type":    r["scope_type"],
                "scope_id":      r["scope_id"],
                "granted_by":    r["granted_by"],
            }
            for r in rows
        ],
    }


@router.post("/{user_id}/roles/{role_id}")
async def add_role_to_user(
    user_id: str,
    role_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Grant a global role to a user.

    Requires can_manage_roles.  For roles in the fixed tier hierarchy, the
    granted role's tier must be >= the granting admin's own best tier so that
    a lower-tier admin cannot promote anyone to a higher tier than themselves.
    Custom (non-tiered) roles have no tier restriction.
    """
    if not admin.has_flag(FLAG_MANAGE_ROLES):
        raise HTTPException(status_code=403, detail="can_manage_roles permission required")

    user_id = validate_uuid(user_id)

    # Tier escalation guard for system roles
    granted_tier = ROLE_TIER.get(role_id)
    if granted_tier is not None:
        my_tier = admin_best_tier(admin.roles)
        if granted_tier < my_tier:
            raise HTTPException(
                status_code=403,
                detail="Cannot grant a role with higher authority than your own tier",
            )

    # Verify role exists
    cursor = await db.execute("SELECT id FROM roles WHERE id = ?", (role_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="Role not found")

    # Verify user exists
    cursor = await db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    target_row = await cursor.fetchone()
    if target_row is None:
        raise HTTPException(status_code=404, detail="User not found")

    await grant_role(db, user_id, role_id, granted_by=admin.id)

    # Keep legacy is_admin column in sync until it is retired.
    if role_id in ADMIN_ROLE_IDS:
        await db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))

    await db.commit()

    event_bus.emit(SecurityEvent(
        event_type="admin.role.granted",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username),
        target=EventTarget(type="user", id=user_id, name=target_row["username"]),
        detail={"role_id": role_id},
    ))

    return {"message": f"Role {role_id} granted to user {user_id}"}


@router.delete("/{user_id}/roles/{role_id}")
async def remove_role_from_user(
    user_id: str,
    role_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Revoke a global role from a user.

    Requires can_manage_roles.  The same tier cap as grant applies: you cannot
    revoke a role with higher authority than your own tier.
    """
    if not admin.has_flag(FLAG_MANAGE_ROLES):
        raise HTTPException(status_code=403, detail="can_manage_roles permission required")

    user_id = validate_uuid(user_id)

    # Cannot remove your own admin role
    if user_id == admin.id and role_id in ADMIN_ROLE_IDS:
        raise HTTPException(status_code=400, detail="Cannot remove your own admin role")

    # Tier cap: cannot strip a role with higher authority than your own
    revoked_tier = ROLE_TIER.get(role_id)
    if revoked_tier is not None:
        my_tier = admin_best_tier(admin.roles)
        if revoked_tier < my_tier:
            raise HTTPException(
                status_code=403,
                detail="Cannot revoke a role with higher authority than your own tier",
            )

    # Fetch target username for the audit event before deletion
    cursor = await db.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    target_row = await cursor.fetchone()

    removed = await revoke_role(db, user_id, role_id)
    if not removed:
        raise HTTPException(status_code=404, detail="User does not have this role")

    # Keep legacy is_admin column in sync until it is retired.
    # After revoke, clear is_admin only if the user no longer holds any admin role.
    if role_id in ADMIN_ROLE_IDS:
        cursor = await db.execute(
            "SELECT 1 FROM user_roles WHERE user_id = ? AND role_id IN ({}) AND scope_type IS NULL LIMIT 1".format(
                ",".join("?" * len(ADMIN_ROLE_IDS))
            ),
            (user_id, *ADMIN_ROLE_IDS),
        )
        if await cursor.fetchone() is None:
            await db.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))

    await db.commit()

    event_bus.emit(SecurityEvent(
        event_type="admin.role.revoked",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username),
        target=EventTarget(type="user", id=user_id, name=target_row["username"] if target_row else None),
        detail={"role_id": role_id},
    ))

    return {"message": f"Role {role_id} revoked from user {user_id}"}


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Delete a user and all their data.

    Collects file storage keys before deleting (CASCADE removes DB rows),
    then cleans up blobs from disk in a background thread.
    """
    if not admin.has_flag(FLAG_MANAGE_USERS):
        raise HTTPException(status_code=403, detail="can_manage_users permission required")

    user_id = validate_uuid(user_id)

    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    # Fetch username before deletion for the audit event
    cursor = await db.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    target_row = await cursor.fetchone()

    # Collect file id+key pairs before CASCADE deletes the file rows
    cursor = await db.execute(
        "SELECT id, storage_key FROM files WHERE owner_id = ?", (user_id,)
    )
    file_rows = await cursor.fetchall()

    result = await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    await db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")

    event_bus.emit(SecurityEvent(
        event_type="admin.user.deleted",
        severity="critical",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username),
        target=EventTarget(type="user", id=user_id, name=target_row["username"] if target_row else None),
    ))

    # Best-effort blob cleanup via storage manager (handles all volumes)
    rows_snapshot = list(file_rows)
    uid_snapshot = user_id

    async def _cleanup_blobs():
        mgr = storage.get_manager()
        cleaned = 0
        async with db_session() as _db:
            for row in rows_snapshot:
                try:
                    await mgr.delete_blob(_db, row["id"], row["storage_key"])
                    cleaned += 1
                except Exception as exc:
                    logger.warning("Failed to delete blob %s: %s", row["storage_key"], exc)
        if cleaned:
            logger.info("Cleaned up %d file blobs for deleted user %s", cleaned, uid_snapshot)

    asyncio.create_task(_cleanup_blobs())

    return {"message": "User deleted"}
