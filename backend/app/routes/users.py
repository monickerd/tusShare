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
from app.auth.local import LocalAuthProvider
from app.conf.auth import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH
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

class _UsernamePasswordBase(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < PASSWORD_MIN_LENGTH or len(v) > PASSWORD_MAX_LENGTH:
            raise ValueError(f"Password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters")
        return v


class CreateUserRequest(_UsernamePasswordBase):
    """Regular user — has E2E encryption, quotas, file operations."""
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


class CreateAdminRequest(_UsernamePasswordBase):
    """Admin-only account — management operations only, no file storage."""
    pass


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
    """Create a regular user with the 'user' role."""
    provider = LocalAuthProvider(db)
    try:
        user = await provider.create_user(
            username=body.username,
            password=body.password,
            role=ROLE_USER,
            wrapped_master_key=body.wrapped_master_key,
            wrapped_master_key_iv=body.wrapped_master_key_iv,
            recovery_key_wrapped=body.recovery_key_wrapped,
            recovery_key_iv=body.recovery_key_iv,
            recovery_key_hash=body.recovery_key_hash,
            x25519_public_key=body.x25519_public_key,
            mlkem768_public_key=body.mlkem768_public_key,
            x25519_private_wrapped=body.x25519_private_wrapped,
            mlkem768_private_wrapped=body.mlkem768_private_wrapped,
            asymmetric_key_iv=body.asymmetric_key_iv,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    # Set optional quotas/limits
    updates = []
    params = []
    if body.disk_quota is not None:
        updates.append("disk_quota = ?")
        params.append(body.disk_quota)
    if body.bandwidth_limit is not None:
        updates.append("bandwidth_limit = ?")
        params.append(body.bandwidth_limit)
    if body.max_file_size is not None:
        updates.append("max_file_size = ?")
        params.append(body.max_file_size)

    if updates:
        params.append(user.id)
        await db.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
            params,
        )
        await db.commit()

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "is_admin": user.is_admin,
            "roles": sorted(user.roles),
        }
    }


@router.post("/admins")
async def create_admin(
    body: CreateAdminRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Create an admin-only account (no file storage, no encryption blobs)."""
    provider = LocalAuthProvider(db)
    try:
        user = await provider.create_user(
            username=body.username,
            password=body.password,
            role=ROLE_ADMIN,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "is_admin": user.is_admin,
            "roles": sorted(user.roles),
        }
    }


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

    updates.append("updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')")
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
