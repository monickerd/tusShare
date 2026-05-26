"""Admin endpoints for viewing and managing all teams."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.database import Database, get_db
from app.models.policy import get_blocking_policies
from app.models.role import FLAG_TEAMS_MANAGE
from app.routes.admin_scope import require_team_scope, scope_team_ids
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
                   u.id AS owner_id, u.username AS owner_username,
                   COUNT(DISTINCT utk.user_id) AS member_count
            FROM teams t
            JOIN users u ON t.owner_id = u.id
            LEFT JOIN user_team_keys utk ON utk.team_id = t.id
            GROUP BY t.id, t.name, t.description, t.rotation_pending, t.created_at,
                     u.id, u.username
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
                   u.id AS owner_id, u.username AS owner_username,
                   COUNT(DISTINCT utk.user_id) AS member_count
            FROM teams t
            JOIN users u ON t.owner_id = u.id
            LEFT JOIN user_team_keys utk ON utk.team_id = t.id
            WHERE t.id IN ({placeholders})
            GROUP BY t.id, t.name, t.description, t.rotation_pending, t.created_at,
                     u.id, u.username
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
               utk.key_confirmed,
               to_char(to_timestamp(utk.created_at), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS joined_at,
               r.id AS role_id, r.name AS role_name
        FROM user_team_keys utk
        JOIN users u ON utk.user_id = u.id
        LEFT JOIN user_roles ur ON ur.user_id = u.id
                                AND ur.scope_type = 'team'
                                AND ur.scope_id = ?
        LEFT JOIN roles r ON ur.role_id = r.id
        WHERE utk.team_id = ?
        ORDER BY utk.created_at
        """,
        (team_id, team_id),
    )
    members = [
        {
            "id": m["id"],
            "username": m["username"],
            "is_active": bool(m["is_active"]),
            "key_confirmed": bool(m["key_confirmed"]),
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


@router.delete("/teams/{team_id}", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}})
async def admin_delete_team(
    team_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail=_ERR_INVALID_TEAM_ID)
    require_team_scope(admin, team_id, FLAG_TEAMS_MANAGE)

    cursor = await db.execute("SELECT id, name FROM teams WHERE id = ?", (team_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_TEAM_NOT_FOUND)

    await db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    return {"deleted": True, "name": row["name"]}


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
        "SELECT user_id FROM user_team_keys WHERE team_id = ? AND user_id = ?",
        (team_id, user_id),
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
