"""Admin role and permission management routes.

Provides CRUD for role definitions and their permission flag assignments.
All write operations enforce the modular permission framework:
  - can_manage_roles  → create, edit, delete roles; update their flags; assign/revoke roles
  - can_create_roles  → create new custom roles (subject to inheritance cap)
  - Sensitive flags (can_access_all_files) → only server_admin or org_admin may activate

Inheritance cap (hard invariant): a newly created role's permission set must be
a strict subset of the creator's own effective permissions.  Enforced here at
creation time; cannot be bypassed regardless of tier.

Lock model: when is_locked=TRUE on a role_permissions row, only admins with
role_tier <= locked_min_tier may modify that flag's value or lock state.
An admin may not lock a flag at a tier lower (higher privilege) than their own.
"""

import re as _re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.dependencies import get_current_user, require_admin
from app.auth.interface import AuthenticatedUser
from app.database import get_db
from app.models.role import (
    FLAG_CREATE_ROLES,
    FLAG_MANAGE_ROLES,
    ROLE_ORG_ADMIN,
    ROLE_SERVER_ADMIN,
    SENSITIVE_FLAGS,
    admin_best_tier,
)
from app.routes._access import require_flag

router = APIRouter()

# Roles that are allowed to activate sensitive flags
_SENSITIVE_FLAG_ROLE_IDS = frozenset({ROLE_SERVER_ADMIN, ROLE_ORG_ADMIN, "role_admin"})

# Hard limit on role_id / name length
_MAX_ROLE_ID_LEN   = 64
_MAX_ROLE_NAME_LEN = 80
_MAX_ROLE_DESC_LEN = 255

# Allowed characters in a custom role ID (slug-style)
_ROLE_ID_RE = _re.compile(r'^[a-z0-9_]{1,64}$')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _load_role(db, role_id: str):
    """Fetch a role row or raise 404."""
    cursor = await db.execute("SELECT * FROM roles WHERE id = ?", (role_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return row


async def _load_role_permissions(db, role_id: str) -> dict:
    """Return {flag: {value, is_locked, locked_min_tier}} for all flags on a role."""
    cursor = await db.execute(
        "SELECT flag, value, is_locked, locked_min_tier FROM role_permissions WHERE role_id = ?",
        (role_id,),
    )
    return {
        r["flag"]: {
            "value":           r["value"],
            "is_locked":       bool(r["is_locked"]),
            "locked_min_tier": r["locked_min_tier"],
        }
        for r in await cursor.fetchall()
    }


async def _load_all_flags(db) -> list[dict]:
    """Return all flag definitions ordered by category then flag name."""
    cursor = await db.execute(
        "SELECT flag, description, category, is_sensitive "
        "FROM role_permission_flags ORDER BY category, flag"
    )
    return [
        {
            "flag":         r["flag"],
            "description":  r["description"],
            "category":     r["category"],
            "is_sensitive": bool(r["is_sensitive"]),
        }
        for r in await cursor.fetchall()
    ]


def _role_to_dict(row, permissions: dict[str, str]) -> dict:
    return {
        "id":          row["id"],
        "name":        row["name"],
        "description": row["description"],
        "is_system":   bool(row["is_system"]),
        "permissions": permissions,
    }




def _check_sensitive_flag_authority(user: AuthenticatedUser):
    """Raise 403 if the user is not server_admin, org_admin, or role_admin (legacy)."""
    if not (user.roles & _SENSITIVE_FLAG_ROLE_IDS):
        raise HTTPException(
            status_code=403,
            detail="Only Server Admin or Org Admin may modify sensitive permission flags",
        )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateRoleRequest(BaseModel):
    id:          str
    name:        str
    description: str = ""
    permissions: dict[str, str] = {}   # {flag: '0'/'1'}


class UpdateRoleRequest(BaseModel):
    name:        str | None = None
    description: str | None = None


class FlagUpdate(BaseModel):
    value:           str
    is_locked:       bool = False
    locked_min_tier: int | None = None


class UpdatePermissionsRequest(BaseModel):
    permissions: dict[str, FlagUpdate]  # {flag: {value, is_locked, locked_min_tier}}


# ---------------------------------------------------------------------------
# GET /roles — list all roles with their permission flags
# ---------------------------------------------------------------------------

@router.get("")
async def list_roles(
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """List all roles (system and custom) with their permission flag values.

    Also returns the full flag registry so the UI can render toggles without
    a second round-trip.
    """
    require_flag(admin, FLAG_MANAGE_ROLES, "can_manage_roles required")
    cursor = await db.execute(
        "SELECT * FROM roles ORDER BY is_system DESC, id"
    )
    role_rows = await cursor.fetchall()

    # Bulk-load permissions for all roles in one query
    cursor = await db.execute(
        "SELECT role_id, flag, value, is_locked, locked_min_tier FROM role_permissions"
    )
    perm_rows = await cursor.fetchall()
    perms_by_role: dict[str, dict] = {}
    for r in perm_rows:
        perms_by_role.setdefault(r["role_id"], {})[r["flag"]] = {
            "value":           r["value"],
            "is_locked":       bool(r["is_locked"]),
            "locked_min_tier": r["locked_min_tier"],
        }

    roles = [
        _role_to_dict(row, perms_by_role.get(row["id"], {}))
        for row in role_rows
    ]

    flags = await _load_all_flags(db)
    return {"roles": roles, "flags": flags, "admin_tier": admin_best_tier(admin.roles)}


# ---------------------------------------------------------------------------
# POST /roles — create a custom role
# ---------------------------------------------------------------------------

@router.post("")
async def create_role(
    body: CreateRoleRequest,
    admin: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Create a custom role.

    Requires can_create_roles.  Enforces the inheritance cap: the new role's
    permission set must be a strict subset of the creator's effective permissions.
    Sensitive flags cannot be activated unless the creator holds server_admin or org_admin.
    """
    require_flag(admin, FLAG_CREATE_ROLES, "can_create_roles required")

    # Validate role ID
    if not _ROLE_ID_RE.match(body.id):
        raise HTTPException(
            status_code=400,
            detail="Role ID must be 1–64 lowercase alphanumeric characters or underscores",
        )

    # Validate name / description length
    if len(body.name) < 1 or len(body.name) > _MAX_ROLE_NAME_LEN:
        raise HTTPException(status_code=400, detail=f"Role name must be 1–{_MAX_ROLE_NAME_LEN} characters")
    if len(body.description) > _MAX_ROLE_DESC_LEN:
        raise HTTPException(status_code=400, detail=f"Description must be ≤{_MAX_ROLE_DESC_LEN} characters")

    # Verify all specified flags exist
    all_flags_cursor = await db.execute(
        "SELECT flag FROM role_permission_flags"
    )
    known_flags = {r["flag"] for r in await all_flags_cursor.fetchall()}

    for flag in body.permissions:
        if flag not in known_flags:
            raise HTTPException(status_code=400, detail=f"Unknown flag: {flag}")
        val = body.permissions[flag]
        if val not in ("0", "1"):
            raise HTTPException(status_code=400, detail=f"Flag value must be '0' or '1', got: {val!r}")

    # Inheritance cap: new role may not grant flags the creator does not have
    for flag, val in body.permissions.items():
        if val == "1" and not admin.has_flag(flag):
            raise HTTPException(
                status_code=403,
                detail=f"Cannot grant flag '{flag}': you do not hold this permission yourself",
            )

    # Sensitive flag check (can_access_all_files etc.)
    for flag in SENSITIVE_FLAGS:
        if body.permissions.get(flag, "0") == "1":
            _check_sensitive_flag_authority(admin)

    # Insert role
    try:
        await db.execute(
            "INSERT INTO roles (id, name, description, is_system) VALUES (?, ?, ?, 0)",
            (body.id, body.name, body.description),
        )
    except Exception:
        raise HTTPException(status_code=409, detail="A role with that ID already exists")

    # Insert permission flags
    for flag, val in body.permissions.items():
        await db.execute(
            "INSERT INTO role_permissions (role_id, flag, value) VALUES (?, ?, ?)",
            (body.id, flag, val),
        )

    await db.commit()
    return {"message": "Role created", "role_id": body.id}


# ---------------------------------------------------------------------------
# GET /roles/{role_id}
# ---------------------------------------------------------------------------

@router.get("/{role_id}")
async def get_role(
    role_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Get a single role with its permission flags."""
    row = await _load_role(db, role_id)
    permissions = await _load_role_permissions(db, role_id)
    flags = await _load_all_flags(db)
    return {"role": _role_to_dict(row, permissions), "flags": flags, "admin_tier": admin_best_tier(admin.roles)}


# ---------------------------------------------------------------------------
# PATCH /roles/{role_id} — update name / description
# ---------------------------------------------------------------------------

@router.patch("/{role_id}")
async def update_role(
    role_id: str,
    body: UpdateRoleRequest,
    admin: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Update a role's name and/or description. System roles can be renamed."""
    require_flag(admin, FLAG_MANAGE_ROLES, "can_manage_roles required")

    row = await _load_role(db, role_id)

    updates = []
    params = []
    if body.name is not None:
        if len(body.name) < 1 or len(body.name) > _MAX_ROLE_NAME_LEN:
            raise HTTPException(status_code=400, detail=f"Name must be 1–{_MAX_ROLE_NAME_LEN} characters")
        updates.append("name = ?")
        params.append(body.name)
    if body.description is not None:
        if len(body.description) > _MAX_ROLE_DESC_LEN:
            raise HTTPException(status_code=400, detail=f"Description must be ≤{_MAX_ROLE_DESC_LEN} characters")
        updates.append("description = ?")
        params.append(body.description)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    params.append(role_id)
    await db.execute(f"UPDATE roles SET {', '.join(updates)} WHERE id = ?", params)
    await db.commit()
    return {"message": "Role updated"}


# ---------------------------------------------------------------------------
# DELETE /roles/{role_id}
# ---------------------------------------------------------------------------

@router.delete("/{role_id}")
async def delete_role(
    role_id: str,
    admin: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Delete a custom role. System roles (is_system=1) cannot be deleted."""
    require_flag(admin, FLAG_MANAGE_ROLES, "can_manage_roles required")

    row = await _load_role(db, role_id)
    if row["is_system"]:
        raise HTTPException(status_code=400, detail="System roles cannot be deleted")

    # CASCADE on role_permissions and user_roles removes child rows automatically
    await db.execute("DELETE FROM roles WHERE id = ?", (role_id,))
    await db.commit()
    return {"message": "Role deleted"}


# ---------------------------------------------------------------------------
# PUT /roles/{role_id}/permissions — replace all flag values for a role
# ---------------------------------------------------------------------------

@router.put("/{role_id}/permissions")
async def update_role_permissions(
    role_id: str,
    body: UpdatePermissionsRequest,
    admin: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Set permission flag values and lock state for a role.

    Requires can_manage_roles.  Sensitive flags require server_admin or org_admin.
    The inheritance cap does NOT apply here (an admin with can_manage_roles can
    grant flags they don't personally hold, subject to the sensitive-flag gate).
    This mirrors how an org admin can delegate permissions to lower tiers.

    Lock enforcement: if a flag is currently locked, only admins at the required
    tier may modify its value or lock state.  An admin may not lock a flag at a
    tier lower (higher privilege) than their own.
    """
    require_flag(admin, FLAG_MANAGE_ROLES, "can_manage_roles required")
    my_tier = admin_best_tier(admin.roles)

    await _load_role(db, role_id)  # 404 if missing

    # Verify all flag names are valid
    all_flags_cursor = await db.execute("SELECT flag FROM role_permission_flags")
    known_flags = {r["flag"] for r in await all_flags_cursor.fetchall()}

    for flag, fu in body.permissions.items():
        if flag not in known_flags:
            raise HTTPException(status_code=400, detail=f"Unknown flag: {flag}")
        if fu.value not in ("0", "1"):
            raise HTTPException(status_code=400, detail=f"Flag value must be '0' or '1', got: {fu.value!r}")

    # Load existing lock state for all flags being touched
    if body.permissions:
        placeholders = ",".join("?" * len(body.permissions))
        cursor = await db.execute(
            f"SELECT flag, is_locked, locked_min_tier FROM role_permissions "
            f"WHERE role_id = ? AND flag IN ({placeholders})",
            (role_id, *body.permissions.keys()),
        )
        existing_locks = {r["flag"]: r for r in await cursor.fetchall()}
    else:
        existing_locks = {}

    # Lock enforcement: blocked if flag is locked and caller lacks the required tier
    for flag in body.permissions:
        row = existing_locks.get(flag)
        if row and row["is_locked"] and row["locked_min_tier"] is not None:
            if my_tier > row["locked_min_tier"]:
                raise HTTPException(
                    status_code=403,
                    detail=f"Flag '{flag}' is locked — requires role tier ≤ {row['locked_min_tier']}",
                )

    # Prevent locking a flag at a tier the caller does not hold
    for flag, fu in body.permissions.items():
        if fu.is_locked and fu.locked_min_tier is not None and fu.locked_min_tier < my_tier:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot lock '{flag}' at tier {fu.locked_min_tier} — your best tier is {my_tier}",
            )

    # Sensitive flag gate
    for flag in SENSITIVE_FLAGS:
        fu = body.permissions.get(flag)
        if fu is not None and fu.value == "1":
            _check_sensitive_flag_authority(admin)

    # Upsert each flag with value and lock state
    for flag, fu in body.permissions.items():
        await db.execute(
            "INSERT INTO role_permissions (role_id, flag, value, is_locked, locked_min_tier) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (role_id, flag) DO UPDATE SET "
            "value = excluded.value, is_locked = excluded.is_locked, locked_min_tier = excluded.locked_min_tier",
            (role_id, flag, fu.value, fu.is_locked, fu.locked_min_tier),
        )

    await db.commit()
    return {"message": "Permissions updated"}
