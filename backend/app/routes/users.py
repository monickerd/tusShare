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
from app.config import settings
from app.database import get_db
from app.models.role import ROLE_ADMIN, ROLE_USER, grant_role, revoke_role
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
    pagination = validate_pagination(page, limit)
    cursor = await db.execute(
        "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (pagination.limit, pagination.offset),
    )
    rows = await cursor.fetchall()

    count_cursor = await db.execute("SELECT COUNT(*) FROM users")
    total = (await count_cursor.fetchone())[0]

    return {
        "users": [User.from_row(r).to_public_dict() for r in rows],
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

    user_dict = User.from_row(row).to_public_dict()
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

    return {"message": "User updated"}


@router.post("/{user_id}/roles/{role_id}")
async def add_role_to_user(
    user_id: str,
    role_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Grant a global role to a user."""
    user_id = validate_uuid(user_id)

    # Verify role exists
    cursor = await db.execute("SELECT id FROM roles WHERE id = ?", (role_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="Role not found")

    # Verify user exists
    cursor = await db.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="User not found")

    await grant_role(db, user_id, role_id, granted_by=admin.id)

    # Keep is_admin column in sync
    if role_id == ROLE_ADMIN:
        await db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))

    await db.commit()
    return {"message": f"Role {role_id} granted to user {user_id}"}


@router.delete("/{user_id}/roles/{role_id}")
async def remove_role_from_user(
    user_id: str,
    role_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Revoke a global role from a user."""
    user_id = validate_uuid(user_id)

    # Cannot remove your own admin role
    if user_id == admin.id and role_id == ROLE_ADMIN:
        raise HTTPException(status_code=400, detail="Cannot remove your own admin role")

    removed = await revoke_role(db, user_id, role_id)
    if not removed:
        raise HTTPException(status_code=404, detail="User does not have this role")

    # Keep is_admin column in sync
    if role_id == ROLE_ADMIN:
        await db.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))

    await db.commit()
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
    user_id = validate_uuid(user_id)

    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    # Collect blob keys before CASCADE deletes the file rows
    cursor = await db.execute(
        "SELECT storage_key FROM files WHERE owner_id = ?", (user_id,)
    )
    blob_keys = [row["storage_key"] for row in await cursor.fetchall()]

    result = await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    await db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found")

    # Best-effort blob cleanup in background thread
    if blob_keys:
        def _cleanup_blobs():
            cleaned = 0
            for key in blob_keys:
                path = settings.FILES_DIR / key
                try:
                    path.unlink(missing_ok=True)
                    cleaned += 1
                except OSError as exc:
                    logger.warning("Failed to delete blob %s: %s", key, exc)
            if cleaned:
                logger.info("Cleaned up %d file blobs for deleted user %s", cleaned, user_id)

        await asyncio.to_thread(_cleanup_blobs)

    return {"message": "User deleted"}
