"""Custom team-scoped role management routes.

Mounted at /api/v1/teams (alongside existing teams router), providing
sub-routes under /{team_id}/custom-roles.

Access control:
  - View roles / assignments : team member OR can_manage_roles (global)
  - Create role              : team_admin for this team OR can_create_roles (global)
                               Cross-team creation requires can_create_cross_team_roles
  - Manage roles (edit/delete/permissions/assign) : team_admin OR can_manage_roles

Inheritance cap (hard invariant on creation):
  - If creator lacks can_manage_roles, their effective move flags for this team
    cap what they can grant to the new role.
  - Users with can_manage_roles bypass the cap (they're managing on behalf of others).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.auth.interface import AuthenticatedUser
from app.database import Database, get_db
from app.models.role import FLAG_CREATE_ROLES, FLAG_CREATE_CROSS_TEAM_ROLES, FLAG_MANAGE_ROLES
from app.models.team import get_team, get_team_member_role
from app.models.team_role import (
    MAX_TEAM_ROLE_DESC_LEN,
    MAX_TEAM_ROLE_NAME_LEN,
    TEAM_FLAG_META,
    TEAM_ROLE_FLAGS,
    TeamRole,
    get_user_team_move_flags,
)
from app.conf.teams import TEAM_ROLE_OWNER
from app.validation.sanitizers import validate_uuid
from typing import Annotated

router = APIRouter()


# ---------------------------------------------------------------------------
# Shared access-control helpers
# ---------------------------------------------------------------------------

async def _require_team(db, team_id: str):
    """Return team row or raise 404."""
    team = await get_team(db, team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")  # NOSONAR — helper; 404 documented in callers
    return team


async def _get_member_role(db, team_id: str, user_id: str) -> str | None:
    return await get_team_member_role(db, team_id, user_id)


def _is_team_admin(member_role: str | None) -> bool:
    return member_role == TEAM_ROLE_OWNER


def _check_can_view(user: AuthenticatedUser, member_role: str | None):
    """Viewable by any team member or global role managers."""
    if member_role is None and not user.has_flag(FLAG_MANAGE_ROLES):
        raise HTTPException(status_code=403, detail="Team membership or can_manage_roles required")  # NOSONAR — helper; 403 documented in callers


def _check_can_manage(user: AuthenticatedUser, member_role: str | None):
    """Editable/deletable by team_admin for this team or global can_manage_roles."""
    if user.has_flag(FLAG_MANAGE_ROLES):
        return
    if not _is_team_admin(member_role):
        raise HTTPException(status_code=403, detail="Team Admin or can_manage_roles required")  # NOSONAR — helper; 403 documented in callers


def _check_can_create(user: AuthenticatedUser, member_role: str | None):
    """
    Can create a role in this team if:
      - user has can_create_roles (global) AND (is team member OR has can_create_cross_team_roles)
      - OR user is team_admin for this team (their team_admin global role carries can_create_roles)
    """
    if _is_team_admin(member_role):
        return  # team_admin for this team: implicitly authorised
    if not user.has_flag(FLAG_CREATE_ROLES):
        raise HTTPException(status_code=403, detail="can_create_roles required")
    if member_role is None:
        # Not a member of this team — needs cross-team authority
        if not user.has_flag(FLAG_CREATE_CROSS_TEAM_ROLES):
            raise HTTPException(
                status_code=403,
                detail="can_create_cross_team_roles required to create roles in a team you do not belong to",
            )


async def _load_team_role(db, team_id: str, role_id: str):
    """Fetch a team role row or raise 404. Also verifies it belongs to the team."""
    cursor = await db.execute(
        "SELECT * FROM team_roles WHERE id = ? AND team_id = ?", (role_id, team_id)
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Team role not found")  # NOSONAR — helper; 404 documented in callers
    return row


async def _load_role_permissions(db, team_role_id: str) -> dict[str, str]:
    cursor = await db.execute(
        "SELECT flag, value FROM team_role_permissions WHERE team_role_id = ?",
        (team_role_id,),
    )
    return {r["flag"]: r["value"] for r in await cursor.fetchall()}


def _row_to_dict(row, permissions: dict[str, str]) -> dict:
    return {
        "id":          row["id"],
        "team_id":     row["team_id"],
        "name":        row["name"],
        "description": row["description"],
        "created_by":  row["created_by"],
        "created_at":  row["created_at"],
        "permissions": permissions,
    }


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateTeamRoleRequest(BaseModel):
    name:        str
    description: str = ""
    permissions: dict[str, str] = {}   # {flag: '0'/'1'}


class UpdateTeamRoleRequest(BaseModel):
    name:        str | None = None
    description: str | None = None


class UpdateTeamRolePermissionsRequest(BaseModel):
    permissions: dict[str, str]   # {flag: '0'/'1'}


class AssignRoleRequest(BaseModel):
    user_id: str

    def validate_ids(self) -> "AssignRoleRequest":
        self.user_id = validate_uuid(self.user_id)
        return self


# ---------------------------------------------------------------------------
# GET /{team_id}/custom-roles
# ---------------------------------------------------------------------------

@router.get("/{team_id}/custom-roles")
async def list_team_roles(
    team_id: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all custom roles for a team with their permission flags."""
    team_id = validate_uuid(team_id)
    await _require_team(db, team_id)
    member_role = await _get_member_role(db, team_id, user.id)
    _check_can_view(user, member_role)

    cursor = await db.execute(
        "SELECT * FROM team_roles WHERE team_id = ? ORDER BY name",
        (team_id,),
    )
    role_rows = await cursor.fetchall()

    # Bulk-load permissions for all roles in one query
    cursor = await db.execute(
        "SELECT team_role_id, flag, value FROM team_role_permissions "
        "WHERE team_role_id IN (SELECT id FROM team_roles WHERE team_id = ?)",
        (team_id,),
    )
    perms_by_role: dict[str, dict[str, str]] = {}
    for r in await cursor.fetchall():
        perms_by_role.setdefault(r["team_role_id"], {})[r["flag"]] = r["value"]

    roles = [
        _row_to_dict(row, perms_by_role.get(row["id"], {}))
        for row in role_rows
    ]

    return {"roles": roles, "flags": TEAM_FLAG_META}


# ---------------------------------------------------------------------------
# POST /{team_id}/custom-roles
# ---------------------------------------------------------------------------

def _validate_permission_flags(permissions: dict) -> None:
    """Raise 400 if any flag name or value is invalid."""
    for flag, val in permissions.items():
        if flag not in TEAM_ROLE_FLAGS:
            raise HTTPException(status_code=400, detail=f"Unknown team role flag: {flag!r}")
        if val not in ("0", "1"):
            raise HTTPException(
                status_code=400, detail=f"Flag value must be '0' or '1', got: {val!r}"
            )


@router.post("/{team_id}/custom-roles", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}})
async def create_team_role(
    team_id: str,
    body: CreateTeamRoleRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Create a custom role for a team.

    Requires team_admin for this team OR can_create_roles (+ cross-team flag if
    not a member).  Enforces an inheritance cap: without can_manage_roles, the
    new role's move flags may not exceed the creator's own effective move flags
    in this team.
    """
    team_id = validate_uuid(team_id)
    await _require_team(db, team_id)
    member_role = await _get_member_role(db, team_id, user.id)
    _check_can_create(user, member_role)

    # Validate name / description
    if len(body.name) < 1 or len(body.name) > MAX_TEAM_ROLE_NAME_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Role name must be 1–{MAX_TEAM_ROLE_NAME_LEN} characters",
        )
    if len(body.description) > MAX_TEAM_ROLE_DESC_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Description must be ≤{MAX_TEAM_ROLE_DESC_LEN} characters",
        )

    _validate_permission_flags(body.permissions)

    # Inheritance cap: if creator lacks can_manage_roles, cap flags to their own
    if not user.has_flag(FLAG_MANAGE_ROLES):
        creator_flags = await get_user_team_move_flags(db, user.id, team_id)
        for flag, val in body.permissions.items():
            if val == "1" and not creator_flags.get(flag, False):
                raise HTTPException(
                    status_code=403,
                    detail=f"Cannot grant flag '{flag}': you do not hold this permission in this team",
                )

    role_id = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO team_roles (id, team_id, name, description, created_by) "
        "VALUES (?, ?, ?, ?, ?)",
        (role_id, team_id, body.name, body.description, user.id),
    )

    for flag, val in body.permissions.items():
        await db.execute(
            "INSERT INTO team_role_permissions (team_role_id, flag, value) VALUES (?, ?, ?)",
            (role_id, flag, val),
        )

    await db.commit()
    return {"message": "Team role created", "role_id": role_id}


# ---------------------------------------------------------------------------
# GET /{team_id}/custom-roles/{role_id}
# ---------------------------------------------------------------------------

@router.get("/{team_id}/custom-roles/{role_id}")
async def get_team_role(
    team_id: str,
    role_id: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Get a single custom team role with its permission flags."""
    team_id = validate_uuid(team_id)
    role_id = validate_uuid(role_id)
    await _require_team(db, team_id)
    member_role = await _get_member_role(db, team_id, user.id)
    _check_can_view(user, member_role)

    row = await _load_team_role(db, team_id, role_id)
    permissions = await _load_role_permissions(db, role_id)
    return {"role": _row_to_dict(row, permissions), "flags": TEAM_FLAG_META}


# ---------------------------------------------------------------------------
# PATCH /{team_id}/custom-roles/{role_id}
# ---------------------------------------------------------------------------

@router.patch("/{team_id}/custom-roles/{role_id}", responses={400: {"description": "Bad Request"}})
async def update_team_role(
    team_id: str,
    role_id: str,
    body: UpdateTeamRoleRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Update a custom team role's name and/or description."""
    team_id = validate_uuid(team_id)
    role_id = validate_uuid(role_id)
    await _require_team(db, team_id)
    member_role = await _get_member_role(db, team_id, user.id)
    _check_can_manage(user, member_role)

    await _load_team_role(db, team_id, role_id)  # 404 guard

    updates = []
    params = []
    if body.name is not None:
        if len(body.name) < 1 or len(body.name) > MAX_TEAM_ROLE_NAME_LEN:
            raise HTTPException(
                status_code=400,
                detail=f"Name must be 1–{MAX_TEAM_ROLE_NAME_LEN} characters",
            )
        updates.append("name = ?")
        params.append(body.name)
    if body.description is not None:
        if len(body.description) > MAX_TEAM_ROLE_DESC_LEN:
            raise HTTPException(
                status_code=400,
                detail=f"Description must be ≤{MAX_TEAM_ROLE_DESC_LEN} characters",
            )
        updates.append("description = ?")
        params.append(body.description)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    params.append(role_id)
    await db.execute(f"UPDATE team_roles SET {', '.join(updates)} WHERE id = ?", params)
    await db.commit()
    return {"message": "Team role updated"}


# ---------------------------------------------------------------------------
# DELETE /{team_id}/custom-roles/{role_id}
# ---------------------------------------------------------------------------

@router.delete("/{team_id}/custom-roles/{role_id}")
async def delete_team_role(
    team_id: str,
    role_id: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Delete a custom team role. Cascades to permissions and assignments."""
    team_id = validate_uuid(team_id)
    role_id = validate_uuid(role_id)
    await _require_team(db, team_id)
    member_role = await _get_member_role(db, team_id, user.id)
    _check_can_manage(user, member_role)

    await _load_team_role(db, team_id, role_id)  # 404 guard

    await db.execute("DELETE FROM team_roles WHERE id = ?", (role_id,))
    await db.commit()
    return {"message": "Team role deleted"}


# ---------------------------------------------------------------------------
# PUT /{team_id}/custom-roles/{role_id}/permissions
# ---------------------------------------------------------------------------

@router.put("/{team_id}/custom-roles/{role_id}/permissions", responses={400: {"description": "Bad Request"}})
async def update_team_role_permissions(
    team_id: str,
    role_id: str,
    body: UpdateTeamRolePermissionsRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Set permission flag values for a custom team role.

    Requires team_admin or can_manage_roles.  No inheritance cap here —
    a team admin managing roles can set any flags for their team's custom roles.
    """
    team_id = validate_uuid(team_id)
    role_id = validate_uuid(role_id)
    await _require_team(db, team_id)
    member_role = await _get_member_role(db, team_id, user.id)
    _check_can_manage(user, member_role)

    await _load_team_role(db, team_id, role_id)  # 404 guard

    for flag, val in body.permissions.items():
        if flag not in TEAM_ROLE_FLAGS:
            raise HTTPException(status_code=400, detail=f"Unknown team role flag: {flag!r}")
        if val not in ("0", "1"):
            raise HTTPException(
                status_code=400, detail=f"Flag value must be '0' or '1', got: {val!r}"
            )

    for flag, val in body.permissions.items():
        await db.execute(
            "INSERT INTO team_role_permissions (team_role_id, flag, value) VALUES (?, ?, ?) "
            "ON CONFLICT (team_role_id, flag) DO UPDATE SET value = excluded.value",
            (role_id, flag, val),
        )

    await db.commit()
    return {"message": "Team role permissions updated"}


# ---------------------------------------------------------------------------
# GET /{team_id}/custom-roles/{role_id}/assignments
# ---------------------------------------------------------------------------

@router.get("/{team_id}/custom-roles/{role_id}/assignments")
async def list_role_assignments(
    team_id: str,
    role_id: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all users assigned to a custom team role."""
    team_id = validate_uuid(team_id)
    role_id = validate_uuid(role_id)
    await _require_team(db, team_id)
    member_role = await _get_member_role(db, team_id, user.id)
    _check_can_view(user, member_role)

    await _load_team_role(db, team_id, role_id)  # 404 guard

    cursor = await db.execute(
        "SELECT tra.id, tra.user_id, u.username, tra.granted_by, tra.granted_at "
        "FROM team_role_assignments tra "
        "JOIN users u ON u.id = tra.user_id "
        "WHERE tra.team_role_id = ? "
        "ORDER BY u.username",
        (role_id,),
    )
    assignments = [
        {
            "id":         r["id"],
            "user_id":    r["user_id"],
            "username":   r["username"],
            "granted_by": r["granted_by"],
            "granted_at": r["granted_at"],
        }
        for r in await cursor.fetchall()
    ]
    return {"assignments": assignments}


# ---------------------------------------------------------------------------
# POST /{team_id}/custom-roles/{role_id}/assignments
# ---------------------------------------------------------------------------

@router.post("/{team_id}/custom-roles/{role_id}/assignments", responses={400: {"description": "Bad Request"}, 409: {"description": "Conflict"}})
async def assign_team_role(
    team_id: str,
    role_id: str,
    body: AssignRoleRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Assign a user to a custom team role. The target user must be a team member."""
    team_id = validate_uuid(team_id)
    role_id = validate_uuid(role_id)
    target_user_id = validate_uuid(body.user_id)

    await _require_team(db, team_id)
    member_role = await _get_member_role(db, team_id, user.id)
    _check_can_manage(user, member_role)

    await _load_team_role(db, team_id, role_id)  # 404 guard

    # Target user must already be a member of this team
    target_member_role = await _get_member_role(db, team_id, target_user_id)
    if target_member_role is None:
        raise HTTPException(
            status_code=400,
            detail="Target user is not a member of this team",
        )

    assignment_id = str(uuid.uuid4())
    try:
        await db.execute(
            "INSERT INTO team_role_assignments "
            "(id, team_role_id, user_id, team_id, granted_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (assignment_id, role_id, target_user_id, team_id, user.id),
        )
        await db.commit()
    except Exception:
        raise HTTPException(status_code=409, detail="User already assigned to this role")

    return {"message": "Role assigned", "assignment_id": assignment_id}


# ---------------------------------------------------------------------------
# DELETE /{team_id}/custom-roles/{role_id}/assignments/{user_id}
# ---------------------------------------------------------------------------

@router.delete("/{team_id}/custom-roles/{role_id}/assignments/{target_user_id}", responses={404: {"description": "Not Found"}})
async def revoke_team_role(
    team_id: str,
    role_id: str,
    target_user_id: str,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Remove a user from a custom team role."""
    team_id = validate_uuid(team_id)
    role_id = validate_uuid(role_id)
    target_user_id = validate_uuid(target_user_id)

    await _require_team(db, team_id)
    member_role = await _get_member_role(db, team_id, user.id)
    _check_can_manage(user, member_role)

    await _load_team_role(db, team_id, role_id)  # 404 guard

    result = await db.execute(
        "DELETE FROM team_role_assignments "
        "WHERE team_role_id = ? AND user_id = ? RETURNING id",
        (role_id, target_user_id),
    )
    deleted = await result.fetchone()
    if deleted is None:
        raise HTTPException(status_code=404, detail="Assignment not found")

    await db.commit()
    return {"message": "Role assignment revoked"}
