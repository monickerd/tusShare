"""Admin endpoints for viewing and managing all teams."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.database import Database, get_db
from app.validation.sanitizers import validate_uuid

router = APIRouter()


def _require_team_admin(admin: AuthenticatedUser) -> None:
    if not admin.has_flag("can_manage_teams"):
        raise HTTPException(status_code=403, detail="Requires can_manage_teams permission")


@router.get("/teams")
async def list_all_teams(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    _require_team_admin(admin)
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
    rows = await cursor.fetchall()
    return {
        "teams": [
            {
                "id":               r["id"],
                "name":             r["name"],
                "description":      r["description"],
                "rotation_pending": bool(r["rotation_pending"]),
                "created_at":       r["created_at"],
                "owner_id":         r["owner_id"],
                "owner_username":   r["owner_username"],
                "member_count":     r["member_count"],
            }
            for r in rows
        ]
    }


@router.get("/teams/{team_id}")
async def get_team_detail(
    team_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail="Invalid team ID")

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
        raise HTTPException(status_code=404, detail="Team not found")

    # Members via user_team_keys joined with user_roles for role display
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
            "id":            m["id"],
            "username":      m["username"],
            "is_active":     bool(m["is_active"]),
            "key_confirmed": bool(m["key_confirmed"]),
            "joined_at":     m["joined_at"],
            "role_id":       m["role_id"],
            "role_name":     m["role_name"],
        }
        for m in await cursor2.fetchall()
    ]

    return {
        "team": {
            "id":               team_row["id"],
            "name":             team_row["name"],
            "description":      team_row["description"],
            "rotation_pending": bool(team_row["rotation_pending"]),
            "created_at":       team_row["created_at"],
            "owner_id":         team_row["owner_id"],
            "owner_username":   team_row["owner_username"],
        },
        "members": members,
    }


@router.delete("/teams/{team_id}")
async def admin_delete_team(
    team_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    _require_team_admin(admin)
    if not validate_uuid(team_id):
        raise HTTPException(status_code=400, detail="Invalid team ID")

    cursor = await db.execute("SELECT id, name FROM teams WHERE id = ?", (team_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Team not found")

    await db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    return {"deleted": True, "name": row["name"]}
