"""Admin endpoints for viewing and managing all teams."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.conf.teams import TEAM_ROLE_OWNER, VALID_TEAM_ROLES
from app.database import Database, get_db
from app.models.team_role import TEAM_FLAG_META
from app.middleware.rate_limit import _get_client_ip
from app.models.policy import get_blocking_policies
from app.models.role import FLAG_TEAMS_MANAGE, FLAG_TEAMS_MEMBERS_MANAGE
from app.routes.admin_scope import require_team_scope, scope_team_ids
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus
from app.services.trash import get_trash_settings
from app.validation.sanitizers import validate_uuid

router = APIRouter()

_ERR_INVALID_TEAM_ID = "Invalid team ID"
_ERR_TEAM_NOT_FOUND = "Team not found"


def _require_team_admin(admin: AuthenticatedUser) -> None:
    if not admin.has_flag(FLAG_TEAMS_MANAGE):
        raise HTTPException(status_code=403, detail="teams_manage permission required")  # NOSONAR


@router.get("/teams")
async def list_all_teams(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    _require_team_admin(admin)
    allowed = scope_team_ids(admin, FLAG_TEAMS_MANAGE)

    if allowed is None:
        # Org-wide admin: return all teams.
        cursor = await db.execute(
            """
            SELECT t.id, t.name, t.description, t.rotation_pending,
                   to_char(to_timestamp(t.created_at), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
                   t.scheduled_delete_at,
                   u.id AS owner_id, u.username AS owner_username,
                   COUNT(DISTINCT utk.user_id) AS member_count
            FROM teams t
            JOIN users u ON t.owner_id = u.id
            LEFT JOIN user_team_keys utk ON utk.team_id = t.id
            GROUP BY t.id, t.name, t.description, t.rotation_pending, t.created_at,
                     t.scheduled_delete_at, u.id, u.username
            ORDER BY t.created_at DESC
            """
        )
    elif allowed:
        # Scoped admin: return only their teams via an IN clause.
        placeholders = ",".join("?" * len(allowed))
        cursor = await db.execute(
            f"""
            SELECT t.id, t.name, t.description, t.rotation_pending,
                   to_char(to_timestamp(t.created_at), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
                   t.scheduled_delete_at,
                   u.id AS owner_id, u.username AS owner_username,
                   COUNT(DISTINCT utk.user_id) AS member_count
            FROM teams t
            JOIN users u ON t.owner_id = u.id
            LEFT JOIN user_team_keys utk ON utk.team_id = t.id
            WHERE t.id IN ({placeholders})
            GROUP BY t.id, t.name, t.description, t.rotation_pending, t.created_at,
                     t.scheduled_delete_at, u.id, u.username
            ORDER BY t.created_at DESC
            """,
            tuple(allowed),
        )
    else:
        # Scoped admin with no teams in scope.
        return {"teams": []}

    rows = await cursor.fetchall()
    return {
        "teams": [
            {
                "id": r["id"],
                "name": r["name"],
                "description": r["description"],
                "rotation_pending": bool(r["rotation_pending"]),
                "created_at": r["created_at"],
                "scheduled_delete_at": str(r["scheduled_delete_at"]) if r["scheduled_delete_at"] else None,
                "owner_id": r["owner_id"],
                "owner_username": r["owner_username"],
                "member_count": r["member_count"],
            }
            for r in rows
        ]
    }


@router.get("/teams/{team_id}", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}})
async def get_team_detail(
    team_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute(
        """
        SELECT t.id, t.name, t.description, t.rotation_pending,
               to_char(to_timestamp(t.created_at), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
               u.id AS owner_id, u.username AS owner_username
        FROM teams t
        JOIN users u ON t.owner_id = u.id
        WHERE t.id = ?
        """,
        (team_id,),
    )
    team_row = await cursor.fetchone()
    if team_row is None:
        raise HTTPException(status_code=404, detail=_ERR_TEAM_NOT_FOUND)

    cursor2 = await db.execute(
        """
        SELECT u.id, u.username, u.is_active,
               COALESCE(utk.key_confirmed, 0) AS key_confirmed,
               CASE WHEN utk.id IS NULL THEN 1 ELSE 0 END AS key_delivery_pending,
               to_char(ur.created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS joined_at,
               ur.role_id, r.name AS role_name
        FROM user_roles ur
        JOIN users u ON ur.user_id = u.id
        LEFT JOIN user_team_keys utk ON utk.team_id = ur.scope_id AND utk.user_id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        WHERE ur.scope_type = 'team' AND ur.scope_id = ?
        ORDER BY ur.created_at
        """,
        (team_id,),
    )
    members = [
        {
            "id": m["id"],
            "username": m["username"],
            "is_active": bool(m["is_active"]),
            "key_confirmed": bool(m["key_confirmed"]),
            "key_delivery_pending": bool(m["key_delivery_pending"]),
            "joined_at": m["joined_at"],
            "role_id": m["role_id"],
            "role_name": m["role_name"],
        }
        for m in await cursor2.fetchall()
    ]

    return {
        "team": {
            "id": team_row["id"],
            "name": team_row["name"],
            "description": team_row["description"],
            "rotation_pending": bool(team_row["rotation_pending"]),
            "created_at": team_row["created_at"],
            "owner_id": team_row["owner_id"],
            "owner_username": team_row["owner_username"],
        },
        "members": members,
    }


@router.delete("/teams/{team_id}", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}, 409: {"description": "Conflict"}})
async def admin_delete_team(
    team_id: str,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT id, name, scheduled_delete_at FROM teams WHERE id = ?", (team_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_TEAM_NOT_FOUND)

    if row["scheduled_delete_at"] is not None:
        raise HTTPException(status_code=409, detail="Team is already scheduled for deletion")

    trash_enabled, retention_days = await get_trash_settings(db)

    if trash_enabled:
        await db.execute(
            "UPDATE teams SET scheduled_delete_at = NOW() + (? || ' days')::INTERVAL, "
            "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
            (str(retention_days), team_id),
        )
        event_bus.emit(
            SecurityEvent(
                event_type="admin.team.delete_scheduled",
                severity="warning",
                outcome="success",
                actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
                target=EventTarget(type="team", id=team_id, name=row["name"]),
                detail={"retention_days": retention_days},
            )
        )
        return {"deleted": False, "scheduled": True, "name": row["name"]}

    await db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    event_bus.emit(
        SecurityEvent(
            event_type="admin.team.deleted",
            severity="warning",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
            target=EventTarget(type="team", id=team_id, name=row["name"]),
        )
    )
    return {"deleted": True, "name": row["name"]}


@router.post(
    "/teams/{team_id}/recover",
    responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}, 409: {"description": "Conflict"}},
)
async def recover_team(
    team_id: str,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Cancel a pending team soft-delete and restore member access."""
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT id, name, scheduled_delete_at FROM teams WHERE id = ?", (team_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_TEAM_NOT_FOUND)
    if row["scheduled_delete_at"] is None:
        raise HTTPException(status_code=409, detail="Team is not scheduled for deletion")

    await db.execute(
        "UPDATE teams SET scheduled_delete_at = NULL, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
        (team_id,),
    )
    event_bus.emit(
        SecurityEvent(
            event_type="admin.team.delete_cancelled",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
            target=EventTarget(type="team", id=team_id, name=row["name"]),
        )
    )
    return {"message": "Team deletion cancelled", "name": row["name"]}


class AdminAddMemberRequest(BaseModel):
    username: str
    role: str = "team_member"

    @field_validator("role")
    @classmethod
    def _validate_role(cls, v: str) -> str:
        if v not in VALID_TEAM_ROLES:
            raise ValueError(f"role must be one of: {', '.join(sorted(VALID_TEAM_ROLES))}")
        return v


@router.post(
    "/teams/{team_id}/members",
    status_code=201,
    responses={
        400: {"description": "Bad Request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        409: {"description": "Conflict"},
    },
)
async def admin_add_team_member(
    team_id: str,
    body: AdminAddMemberRequest,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Admin: add a user to a team without key material.

    The member receives no encrypted team key — the team is marked for rotation
    so the owner/supervisor can deliver keys during the next rotation cycle.
    Assigning the owner role also updates teams.owner_id (useful for recovery
    when the original owner was deleted or deactivated).
    """
    if not admin.has_flag(FLAG_TEAMS_MANAGE):
        raise HTTPException(status_code=403, detail="teams_manage permission required")
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT id, name, owner_id FROM teams WHERE id = ?", (team_id,))
    team_row = await cursor.fetchone()
    if team_row is None:
        raise HTTPException(status_code=404, detail=_ERR_TEAM_NOT_FOUND)

    cursor = await db.execute(
        "SELECT id, username FROM users WHERE LOWER(username) = LOWER(?) AND is_active = 1",
        (body.username,),
    )
    target = await cursor.fetchone()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found or inactive")

    target_id = target["id"]

    cursor = await db.execute(
        "SELECT id FROM user_roles WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (target_id, team_id),
    )
    if await cursor.fetchone() is not None:
        raise HTTPException(status_code=409, detail="User is already a member of this team")

    ur_id = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO user_roles (id, user_id, role_id, scope_type, scope_id, granted_by) "
        "VALUES (?, ?, ?, 'team', ?, ?)",
        (ur_id, target_id, body.role, team_id, admin.id),
    )

    # If assigning owner, update teams.owner_id so FK and display stay consistent
    if body.role == TEAM_ROLE_OWNER:
        await db.execute(
            "UPDATE teams SET owner_id = ?, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
            (target_id, team_id),
        )
    else:
        await db.execute(
            "UPDATE teams SET rotation_pending = 1, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
            (team_id,),
        )

    await db.commit()
    event_bus.emit(
        SecurityEvent(
            event_type="admin.team.member_added",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
            target=EventTarget(type="team", id=team_id, name=team_row["name"]),
            detail={"target_user_id": target_id, "target_username": target["username"], "role": body.role},
        )
    )
    return {"user_id": target_id, "username": target["username"], "role": body.role}


@router.delete(
    "/teams/{team_id}/members/{user_id}",
    status_code=204,
    responses={
        400: {"description": "Bad Request"},
        404: {"description": "Not Found"},
        409: {"description": "Conflict"},
        422: {"description": "Unprocessable Entity"},
    },
)
async def admin_remove_team_member(
    team_id: str,
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Admin: forcibly remove a user from a team.

    Deletes the member's key entry and role assignment, sets rotation_pending=1.
    The team owner must subsequently rotate keys to fully revoke the member's access.
    Cannot remove the team owner.
    """
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    if not validate_uuid(user_id):
        raise HTTPException(status_code=400, detail="Invalid user ID")
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT id, owner_id FROM teams WHERE id = ?", (team_id,))
    team_row = await cursor.fetchone()
    if team_row is None:
        raise HTTPException(status_code=404, detail=_ERR_TEAM_NOT_FOUND)
    if team_row["owner_id"] == user_id:
        raise HTTPException(status_code=422, detail="Cannot remove the team owner")

    cursor = await db.execute(
        "SELECT id FROM user_roles WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (user_id, team_id),
    )
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="User is not a member of this team")

    blocks = await get_blocking_policies(db, user_id, team_id)
    if blocks:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "This membership is enforced by a policy. Create a policy exemption for this user before removing them.",
                "blocked_by": blocks,
            },
        )

    await db.execute(
        "DELETE FROM user_roles WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (user_id, team_id),
    )
    await db.execute(
        "DELETE FROM user_team_keys WHERE team_id = ? AND user_id = ?",
        (team_id, user_id),
    )
    await db.execute(
        "UPDATE teams SET rotation_pending = 1, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = ?",
        (team_id,),
    )
    await db.commit()


@router.get(
    "/teams/{team_id}/folder-role-levels",
    responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}},
)
async def get_team_folder_role_levels(
    team_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return the folder permission levels configured for each team role.

    Missing rows use the system defaults (owner=admin, supervisor=write, member=write).
    """
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT id FROM teams WHERE id = ?", (team_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail=_ERR_TEAM_NOT_FOUND)

    cursor = await db.execute(
        "SELECT role_id, level FROM team_folder_role_levels WHERE team_id = ?",
        (team_id,),
    )
    overrides = {row["role_id"]: row["level"] for row in await cursor.fetchall()}

    from app.conf.teams import TEAM_ROLE_HIERARCHY
    from app.routes._access import _TEAM_ROLE_DEFAULTS

    levels = {}
    for role_id in TEAM_ROLE_HIERARCHY:
        levels[role_id] = overrides.get(role_id, _TEAM_ROLE_DEFAULTS.get(role_id, "write"))

    return {"team_id": team_id, "levels": levels}


@router.put(
    "/teams/{team_id}/folder-role-levels",
    responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}},
)
async def set_team_folder_role_levels(
    team_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    body: dict,
):
    """Update folder permission level for one or more team roles.

    Body: {"levels": {"team_admin": "admin", "team_manager": "write", "team_member": "read"}}
    Valid levels: admin, write, read, none
    """
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT id FROM teams WHERE id = ?", (team_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail=_ERR_TEAM_NOT_FOUND)

    levels: dict = body.get("levels", {})
    if not isinstance(levels, dict):
        raise HTTPException(status_code=400, detail="levels must be an object")

    from app.conf.teams import VALID_TEAM_ROLES

    valid_levels = {"admin", "write", "read", "none"}

    for role_id, level in levels.items():
        if role_id not in VALID_TEAM_ROLES:
            raise HTTPException(status_code=400, detail=f"Unknown team role: {role_id}")
        if level not in valid_levels:
            raise HTTPException(status_code=400, detail=f"Invalid level '{level}' for role {role_id}")
        await db.execute(
            """
            INSERT INTO team_folder_role_levels (team_id, role_id, level, updated_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (team_id, role_id) DO UPDATE SET level = EXCLUDED.level, updated_by = EXCLUDED.updated_by,
                updated_at = NOW()
            """,
            (team_id, role_id, level, admin.id),
        )

    await db.commit()
    return {"updated": list(levels.keys())}


# ---------------------------------------------------------------------------
# Admin: custom team-role management
# ---------------------------------------------------------------------------


@router.get(
    "/teams/{team_id}/custom-roles",
    responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}},
)
async def admin_list_custom_roles(
    team_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all custom roles for a team with permissions and current assignments."""
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT id FROM teams WHERE id = ?", (team_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail=_ERR_TEAM_NOT_FOUND)

    cursor = await db.execute(
        "SELECT id, name, description FROM team_roles WHERE team_id = ? ORDER BY name",
        (team_id,),
    )
    role_rows = await cursor.fetchall()

    if not role_rows:
        return {"roles": [], "flags": TEAM_FLAG_META}

    role_ids = [r["id"] for r in role_rows]
    placeholders = ",".join("?" * len(role_ids))

    perm_cursor = await db.execute(
        f"SELECT team_role_id, flag, value FROM team_role_permissions WHERE team_role_id IN ({placeholders})",
        role_ids,
    )
    perms_by_role: dict[str, dict] = {}
    for r in await perm_cursor.fetchall():
        perms_by_role.setdefault(r["team_role_id"], {})[r["flag"]] = r["value"]

    assign_cursor = await db.execute(
        f"SELECT tra.team_role_id, tra.user_id, u.username "
        f"FROM team_role_assignments tra "
        f"JOIN users u ON u.id = tra.user_id "
        f"WHERE tra.team_role_id IN ({placeholders}) "
        f"ORDER BY u.username",
        role_ids,
    )
    assigns_by_role: dict[str, list] = {}
    for r in await assign_cursor.fetchall():
        assigns_by_role.setdefault(r["team_role_id"], []).append(
            {"user_id": r["user_id"], "username": r["username"]}
        )

    roles = [
        {
            "id": r["id"],
            "name": r["name"],
            "description": r["description"],
            "permissions": perms_by_role.get(r["id"], {}),
            "assignments": assigns_by_role.get(r["id"], []),
        }
        for r in role_rows
    ]
    return {"roles": roles, "flags": TEAM_FLAG_META}


class AdminAssignCustomRoleRequest(BaseModel):
    user_id: str


@router.post(
    "/teams/{team_id}/custom-roles/{role_id}/assignments",
    status_code=201,
    responses={
        400: {"description": "Bad Request"},
        404: {"description": "Not Found"},
        409: {"description": "Conflict"},
    },
)
async def admin_assign_custom_role(
    team_id: str,
    role_id: str,
    body: AdminAssignCustomRoleRequest,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Assign a team member to a custom role."""
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    if not validate_uuid(role_id):
        raise HTTPException(status_code=400, detail="Invalid role ID")
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT name FROM team_roles WHERE id = ? AND team_id = ?", (role_id, team_id))
    role_row = await cursor.fetchone()
    if role_row is None:
        raise HTTPException(status_code=404, detail="Custom role not found")

    target_id = validate_uuid(body.user_id)
    cursor = await db.execute(
        "SELECT id FROM user_roles WHERE user_id = ? AND scope_type = 'team' AND scope_id = ?",
        (target_id, team_id),
    )
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=400, detail="Target user is not a member of this team")

    assignment_id = str(uuid.uuid4())
    try:
        await db.execute(
            "INSERT INTO team_role_assignments (id, team_role_id, user_id, team_id, granted_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (assignment_id, role_id, target_id, team_id, admin.id),
        )
        await db.commit()
    except Exception:
        raise HTTPException(status_code=409, detail="User already assigned to this role")

    event_bus.emit(
        SecurityEvent(
            event_type="admin.team_role.assigned",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
            target=EventTarget(type="team", id=team_id),
            detail={"role_id": role_id, "role_name": role_row["name"], "target_user_id": target_id},
        )
    )
    return {"assignment_id": assignment_id}


@router.delete(
    "/teams/{team_id}/custom-roles/{role_id}/assignments/{target_user_id}",
    responses={
        400: {"description": "Bad Request"},
        404: {"description": "Not Found"},
    },
)
async def admin_revoke_custom_role(
    team_id: str,
    role_id: str,
    target_user_id: str,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Revoke a custom role assignment from a team member."""
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    if not validate_uuid(role_id):
        raise HTTPException(status_code=400, detail="Invalid role ID")
    target_user_id = validate_uuid(target_user_id)
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT name FROM team_roles WHERE id = ? AND team_id = ?", (role_id, team_id))
    role_row = await cursor.fetchone()
    if role_row is None:
        raise HTTPException(status_code=404, detail="Custom role not found")

    result = await db.execute(
        "DELETE FROM team_role_assignments WHERE team_role_id = ? AND user_id = ? RETURNING id",
        (role_id, target_user_id),
    )
    if await result.fetchone() is None:
        raise HTTPException(status_code=404, detail="Assignment not found")

    await db.commit()
    event_bus.emit(
        SecurityEvent(
            event_type="admin.team_role.revoked",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
            target=EventTarget(type="team", id=team_id),
            detail={"role_id": role_id, "role_name": role_row["name"], "target_user_id": target_user_id},
        )
    )
    return {"message": "Assignment revoked"}
