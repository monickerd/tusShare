"""
Emergency revocation routes.

POST /admin/users/{user_id}/emergency-revoke
    Atomically suspend an account and apply all containment actions defined in
    the S1 threat model: token family revocation, share revocation, transfer
    lock, team key rotation trigger, team admin privilege strip.

GET  /admin/users/{user_id}/transfer-locks
    List files currently locked as a result of a revocation for this user.

DELETE /admin/files/{file_id}/transfer-lock
    Admin explicitly clears a transfer lock on a single file.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.database import get_db
from app.models.role import FLAG_MANAGE_USERS
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus, sse_broker
from app.middleware.rate_limit import _get_client_ip
from app.validation.sanitizers import validate_uuid
from app.validation.validators import validate_pagination

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class EmergencyRevokeRequest(BaseModel):
    reason: str
    scope: Literal["owned_only", "all_access"] = "owned_only"
    # When True, push a rotation_requested SSE event to enrolled escrow agents
    # so they can complete team key rotation without manual intervention.
    # Only takes effect when the admin_settings key notify_escrow_on_revocation='1'.
    notify_escrow: bool = False


# ---------------------------------------------------------------------------
# POST /admin/users/{user_id}/emergency-revoke
# ---------------------------------------------------------------------------

@router.post("/users/{user_id}/emergency-revoke")
async def emergency_revoke(
    request: Request,
    user_id: str,
    body: EmergencyRevokeRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Perform an emergency account revocation.

    Actions taken (all logged immutably):
      1. Deactivate account — blocks all subsequent authenticated requests instantly
         (auth dependency does a DB user lookup on every request).
      2. Revoke entire token family — marks every refresh token for this user as
         revoked so no new access tokens can be issued.
      3. Revoke all shares owned by the user.
      4. Apply transfer lock to files (scope: owned_only or all_access).
      5. Mark all teams the user was a member of as rotation_pending=1 and
         strip team-scoped admin roles.
      6. Optionally notify escrow agents via SSE so they can complete key rotation
         without a team member needing to manually trigger it.
      7. Emit admin.emergency_revocation at severity=critical to the event bus.
    """
    user_id = validate_uuid(user_id)

    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot self-revoke")

    if not admin.has_flag(FLAG_MANAGE_USERS):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Verify target user exists
    cursor = await db.execute(
        "SELECT id, username, is_active FROM users WHERE id = ?",
        (user_id,),
    )
    target = await cursor.fetchone()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    now = datetime.now(timezone.utc).isoformat()
    result: dict = {
        "user_id": user_id,
        "username": target["username"],
        "was_active": bool(target["is_active"]),
        "tokens_revoked": 0,
        "shares_revoked": 0,
        "files_locked": 0,
        "teams_flagged": 0,
        "team_admin_roles_stripped": 0,
        "escrow_agents_notified": 0,
    }

    # ------------------------------------------------------------------
    # 1. Deactivate user — immediately blocks all auth on next request
    # ------------------------------------------------------------------
    await db.execute(
        "UPDATE users SET is_active = 0, updated_at = NOW() WHERE id = ?",
        (user_id,),
    )

    # ------------------------------------------------------------------
    # 2. Revoke entire token family
    # ------------------------------------------------------------------
    rev_cursor = await db.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0 RETURNING id",
        (user_id,),
    )
    result["tokens_revoked"] = len(await rev_cursor.fetchall())

    # ------------------------------------------------------------------
    # 3. Revoke all shares owned by user
    # ------------------------------------------------------------------
    share_cursor = await db.execute(
        "UPDATE shares SET is_active = 0 WHERE created_by = ? AND is_active = 1 RETURNING id",
        (user_id,),
    )
    result["shares_revoked"] = len(await share_cursor.fetchall())

    # ------------------------------------------------------------------
    # 4. Transfer lock — scope determines which files are locked
    # ------------------------------------------------------------------
    if body.scope == "owned_only":
        lock_cursor = await db.execute(
            "UPDATE files SET transfer_locked_at = ?, transfer_locked_by = ? "
            "WHERE owner_id = ? AND transfer_locked_at IS NULL RETURNING id",
            (now, admin.id, user_id),
        )
    else:
        # all_access: lock files the user owned OR had team-based access to
        lock_cursor = await db.execute(
            """
            UPDATE files SET transfer_locked_at = ?, transfer_locked_by = ?
            WHERE transfer_locked_at IS NULL
              AND (
                owner_id = ?
                OR id IN (
                    SELECT ftk.file_id
                    FROM file_team_keys ftk
                    JOIN user_team_keys utk ON utk.team_id = ftk.team_id
                    WHERE utk.user_id = ?
                )
              )
            RETURNING id
            """,
            (now, admin.id, user_id, user_id),
        )
    result["files_locked"] = len(await lock_cursor.fetchall())

    # ------------------------------------------------------------------
    # 5a. Identify teams the user was a member of and flag for rotation
    # ------------------------------------------------------------------
    team_cursor = await db.execute(
        "SELECT DISTINCT team_id FROM user_team_keys WHERE user_id = ?",
        (user_id,),
    )
    team_rows = await team_cursor.fetchall()
    team_ids = [r["team_id"] for r in team_rows]

    if team_ids:
        placeholders = ",".join("?" * len(team_ids))
        await db.execute(
            f"UPDATE teams SET rotation_pending = 1, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT "
            f"WHERE id IN ({placeholders})",
            team_ids,
        )
        result["teams_flagged"] = len(team_ids)

    # Delete wrapped key material so the revoked user's slot cannot be used
    # even if is_active is later restored without re-invitation.
    await db.execute("DELETE FROM user_team_keys WHERE user_id = ?", (user_id,))

    # ------------------------------------------------------------------
    # 5b. Strip team-scoped admin roles (team_owner, team_supervisor)
    # ------------------------------------------------------------------
    strip_cursor = await db.execute(
        "DELETE FROM user_roles WHERE user_id = ? AND scope_type = 'team' RETURNING id",
        (user_id,),
    )
    result["team_admin_roles_stripped"] = len(await strip_cursor.fetchall())

    # ------------------------------------------------------------------
    # 6. Notify escrow agents (optional, gated on admin_settings)
    # ------------------------------------------------------------------
    if body.notify_escrow and team_ids:
        cfg_cursor = await db.execute(
            "SELECT value FROM admin_settings WHERE key = 'notify_escrow_on_revocation'",
        )
        cfg_row = await cfg_cursor.fetchone()
        notify_enabled = cfg_row and cfg_row["value"] == "1"

        if notify_enabled:
            # Find users holding the escrow_agent role
            agent_cursor = await db.execute(
                "SELECT DISTINCT ur.user_id FROM user_roles ur "
                "WHERE ur.role_id = 'escrow_agent' AND ur.scope_type IS NULL",
            )
            agent_rows = await agent_cursor.fetchall()

            notification = {
                "type": "rotation_requested",
                "revoked_user_id": user_id,
                "team_ids": team_ids,
                "requested_by": admin.id,
                "requested_at": now,
            }
            for agent_row in agent_rows:
                sse_broker.publish(f"admin:{agent_row['user_id']}", notification)
                result["escrow_agents_notified"] += 1

    await db.commit()

    # ------------------------------------------------------------------
    # 7. Emit to event bus (after commit so the action is durable first)
    # ------------------------------------------------------------------
    event_bus.emit(SecurityEvent(
        event_type="admin.emergency_revocation",
        severity="critical",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
        target=EventTarget(type="user", id=user_id, name=target["username"]),
        admin_actor_id=admin.id,
        detail={
            "reason": body.reason,
            "scope": body.scope,
            "tokens_revoked": result["tokens_revoked"],
            "shares_revoked": result["shares_revoked"],
            "files_locked": result["files_locked"],
            "teams_flagged": result["teams_flagged"],
            "team_admin_roles_stripped": result["team_admin_roles_stripped"],
            "escrow_agents_notified": result["escrow_agents_notified"],
        },
    ))

    logger.warning(
        "Emergency revocation: admin=%s revoked user=%s scope=%s "
        "tokens=%d shares=%d files_locked=%d teams=%d",
        admin.username, target["username"], body.scope,
        result["tokens_revoked"], result["shares_revoked"],
        result["files_locked"], result["teams_flagged"],
    )

    return {"ok": True, "result": result}


# ---------------------------------------------------------------------------
# GET /admin/users/{user_id}/transfer-locks
# ---------------------------------------------------------------------------

@router.get("/users/{user_id}/transfer-locks")
async def list_transfer_locks(
    user_id: str,
    limit: int = 50,
    offset: int = 0,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """List files currently under a transfer lock applied to this user's account."""
    user_id = validate_uuid(user_id)
    limit, offset = validate_pagination(limit, offset)

    cursor = await db.execute(
        """
        SELECT f.id, f.sanitized_name, f.transfer_locked_at, f.transfer_locked_by,
               u.username AS locked_by_username
        FROM files f
        LEFT JOIN users u ON u.id = f.transfer_locked_by
        WHERE f.transfer_locked_by IS NOT NULL
          AND (
            f.owner_id = ?
            OR f.id IN (
                SELECT ftk.file_id
                FROM file_team_keys ftk
                JOIN user_team_keys utk ON utk.team_id = ftk.team_id
                WHERE utk.user_id = ?
            )
          )
        ORDER BY f.transfer_locked_at DESC
        LIMIT ? OFFSET ?
        """,
        (user_id, user_id, limit, offset),
    )
    rows = await cursor.fetchall()

    return {
        "files": [
            {
                "file_id": r["id"],
                "name": r["sanitized_name"],
                "locked_at": str(r["transfer_locked_at"]),
                "locked_by": r["locked_by_username"],
            }
            for r in rows
        ]
    }


# ---------------------------------------------------------------------------
# DELETE /admin/files/{file_id}/transfer-lock
# ---------------------------------------------------------------------------

@router.delete("/files/{file_id}/transfer-lock")
async def clear_transfer_lock(
    request: Request,
    file_id: str,
    admin: AuthenticatedUser = Depends(require_admin),
    db=Depends(get_db),
):
    """Explicitly clear the transfer lock on a single file.

    The admin who applies the lock (or any admin with FLAG_MANAGE_USERS) can
    clear it. Clearing is logged via the event bus.
    """
    file_id = validate_uuid(file_id)

    if not admin.has_flag(FLAG_MANAGE_USERS):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    cursor = await db.execute(
        "SELECT id, sanitized_name, owner_id, transfer_locked_at "
        "FROM files WHERE id = ?",
        (file_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="File not found")

    if row["transfer_locked_at"] is None:
        raise HTTPException(status_code=409, detail="File is not transfer-locked")

    await db.execute(
        "UPDATE files SET transfer_locked_at = NULL, transfer_locked_by = NULL WHERE id = ?",
        (file_id,),
    )
    await db.commit()

    event_bus.emit(SecurityEvent(
        event_type="file.lock.cleared",
        severity="info",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
        target=EventTarget(type="file", id=file_id, name=row["sanitized_name"]),
        admin_actor_id=admin.id,
        detail={"file_owner_id": row["owner_id"]},
    ))

    return {"ok": True, "file_id": file_id}
