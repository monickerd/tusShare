"""Admin MFA management routes.

Requires can_manage_user_mfa permission flag (Tier 2+).
Admin actions that modify a user's MFA state also require step-up authentication
because they are registered as sensitive functions.

Route map
─────────
GET    /admin/users/{user_id}/mfa              list a user's MFA credentials
DELETE /admin/users/{user_id}/mfa              wipe all MFA data (all credentials)
DELETE /admin/users/{user_id}/mfa/{cred_id}    remove a specific credential
POST   /admin/users/{user_id}/mfa/reset        wipe + set mfa_reset_required = 1
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.auth.mfa import list_active_credentials
from app.auth.stepup import log_security_event, verify_step_up_token
from app.database import Database, get_db
from app.middleware.rate_limit import _get_client_ip
from app.models.role import FLAG_MANAGE_USER_MFA
from app.routes._access import require_flag
from app.validation.sanitizers import validate_uuid
from typing import Annotated

logger = logging.getLogger(__name__)
router = APIRouter()

_ERR_PERM_MANAGE_MFA = "can_manage_user_mfa permission required"
_ERR_INVALID_USER_ID = "Invalid user ID"
_SQL_REVOKE_TOKENS   = "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?"


def _request_info(request: Request) -> tuple[str, str]:
    """Return (client_ip, user_agent) from a request for audit logging."""
    return _get_client_ip(request), request.headers.get("user-agent", "")


async def _resolve_user(db, user_id: str) -> None:
    """Raise 404 if user_id does not exist."""
    cursor = await db.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="User not found")  # NOSONAR — helper; 404 documented in callers


# ---------------------------------------------------------------------------
# List credentials for a user
# ---------------------------------------------------------------------------

@router.get("/users/{user_id}/mfa", responses={400: {"description": "Bad Request"}})
async def admin_list_mfa(
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """List active MFA credentials for a user."""
    require_flag(admin, FLAG_MANAGE_USER_MFA, _ERR_PERM_MANAGE_MFA)
    try:
        user_id = validate_uuid(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail=_ERR_INVALID_USER_ID)

    await _resolve_user(db, user_id)

    credentials = await list_active_credentials(db, user_id)

    cursor = await db.execute(
        "SELECT mfa_reset_required FROM users WHERE id = ?", (user_id,)
    )
    row = await cursor.fetchone()
    reset_required = bool(row["mfa_reset_required"]) if row else False

    return {"credentials": credentials, "reset_required": reset_required}


# ---------------------------------------------------------------------------
# Wipe all MFA data (remove credentials, clear reset flag)
# ---------------------------------------------------------------------------

@router.delete("/users/{user_id}/mfa", responses={400: {"description": "Bad Request"}})
async def admin_wipe_mfa(
    user_id: str,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Wipe all MFA credentials for a user.  Requires step-up."""
    require_flag(admin, FLAG_MANAGE_USER_MFA, _ERR_PERM_MANAGE_MFA)
    try:
        user_id = validate_uuid(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail=_ERR_INVALID_USER_ID)

    _check_step_up(request, admin, "auth.mfa.admin_remove")
    await _resolve_user(db, user_id)
    await _do_wipe_mfa(db, user_id, reset_flag=False)

    # Invalidate all sessions
    await db.execute(_SQL_REVOKE_TOKENS, (user_id,))
    await db.commit()

    client_ip, ua = _request_info(request)
    await log_security_event(
        db, "mfa_admin_removed", admin.id, client_ip, ua,
        username=admin.username,
        detail={"target_user_id": user_id},
    )
    return {"message": "MFA data removed"}


# ---------------------------------------------------------------------------
# Remove a specific credential
# ---------------------------------------------------------------------------

@router.delete("/users/{user_id}/mfa/{cred_id}", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}})
async def admin_remove_credential(
    user_id: str,
    cred_id: str,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Remove a specific MFA credential for a user.  Requires step-up."""
    require_flag(admin, FLAG_MANAGE_USER_MFA, _ERR_PERM_MANAGE_MFA)
    try:
        user_id = validate_uuid(user_id)
        cred_id = validate_uuid(cred_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid ID")

    _check_step_up(request, admin, "auth.mfa.admin_remove")
    await _resolve_user(db, user_id)

    cursor = await db.execute(
        "SELECT id, method FROM user_mfa_credentials "
        "WHERE id = ? AND user_id = ? AND is_active = 1",
        (cred_id, user_id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    await db.execute(
        "UPDATE user_mfa_credentials SET is_active = 0 WHERE id = ?", (cred_id,)
    )
    # Invalidate all sessions for the target user
    await db.execute(_SQL_REVOKE_TOKENS, (user_id,))
    await db.commit()

    client_ip, ua = _request_info(request)
    await log_security_event(
        db, "mfa_admin_removed", admin.id, client_ip, ua,
        username=admin.username,
        detail={"target_user_id": user_id, "credential_id": cred_id, "method": row["method"]},
    )
    return {"message": "Credential removed"}


# ---------------------------------------------------------------------------
# Force re-enrollment (wipe + set mfa_reset_required)
# ---------------------------------------------------------------------------

@router.post("/users/{user_id}/mfa/reset", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}})
async def admin_reset_mfa(
    user_id: str,
    request: Request,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Wipe all MFA credentials and force re-enrollment on next login.  Requires step-up."""
    require_flag(admin, FLAG_MANAGE_USER_MFA, _ERR_PERM_MANAGE_MFA)
    try:
        user_id = validate_uuid(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail=_ERR_INVALID_USER_ID)

    _check_step_up(request, admin, "auth.mfa.admin_reset")
    await _resolve_user(db, user_id)
    await _do_wipe_mfa(db, user_id, reset_flag=True)

    # Invalidate all sessions
    await db.execute(_SQL_REVOKE_TOKENS, (user_id,))
    await db.commit()

    client_ip, ua = _request_info(request)
    await log_security_event(
        db, "mfa_admin_reset", admin.id, client_ip, ua,
        username=admin.username,
        detail={"target_user_id": user_id},
    )
    return {"message": "MFA reset — user must re-enroll on next login"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_step_up(request: Request, admin: AuthenticatedUser, action_key: str) -> None:
    """Verify X-Step-Up-Token header for a sensitive admin MFA action."""
    token = request.headers.get("x-step-up-token", "")
    if not token or not verify_step_up_token(token, admin.id, action_key):
        raise HTTPException(  # NOSONAR — helper; 403 documented in callers
            status_code=403,
            detail={"error": "step_up_required", "action": action_key},
        )


async def _do_wipe_mfa(db, user_id: str, reset_flag: bool) -> None:
    """Delete all MFA credentials and optionally set mfa_reset_required."""
    await db.execute(
        "UPDATE user_mfa_credentials SET is_active = 0 WHERE user_id = ?",
        (user_id,),
    )
    reset_val = 1 if reset_flag else 0
    await db.execute(
        "UPDATE users SET mfa_reset_required = ?, mfa_banner_dismissed = 0 WHERE id = ?",
        (reset_val, user_id),
    )
    # Don't commit here — caller commits after adding more writes (session revoke)
