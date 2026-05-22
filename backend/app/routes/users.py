"""Admin user management routes.

Two separate creation flows:
  POST /users       — create a regular user (file storage account)
  POST /admins      — create an admin-only account (management, no file operations)

This separation ensures admin accounts never accidentally gain user privileges
and regular user creation cannot escalate to admin.
"""

import asyncio
import logging

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from typing import Literal

from app.auth.dependencies import require_admin
from app.auth.interface import AuthenticatedUser
from app.models.role import FLAG_USERS_VIEW, FLAG_USERS_MANAGE, FLAG_USERS_DELETE, FLAG_ROLES_MANAGE, FLAG_TEAMS_MANAGE
from app.routes.admin_scope import require_team_scope, scope_team_ids
from app.database import Database, db_session, get_db
from app.models.role import ADMIN_ROLE_IDS, ROLE_USER, ROLE_TIER, admin_best_tier, grant_role, revoke_role
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus, sse_broker
import app.storage.manager as storage
from app.models.user import User
from app.middleware.rate_limit import _get_client_ip
from app.validation.sanitizers import sanitize_username, validate_base64, validate_uuid
from app.validation.validators import validate_pagination
from typing import Annotated


_ERR_PERM_MANAGE_USERS = "users_manage permission required"
_ERR_USER_NOT_FOUND = "User not found"
_SQL_USERNAME_BY_ID = "SELECT username FROM users WHERE id = ?"

_bg_tasks: set = set()

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


class GrantRoleRequest(BaseModel):
    """Optional scope for a role grant (omit for a global grant)."""
    scope_type: Literal["team"] | None = None
    scope_id: str | None = None


# ---------------------------------------------------------------------------
# Role grant/revoke validation helpers
# ---------------------------------------------------------------------------

def _validate_role_grant_scope(
    admin: AuthenticatedUser,
    scope_type: str | None,
    scope_id: str | None,
    role_id: str,
) -> str | None:
    if scope_type is not None:
        if not scope_id:
            raise HTTPException(status_code=400, detail="scope_id required when scope_type is set")
        scope_id = validate_uuid(scope_id)
        require_team_scope(admin, scope_id, FLAG_TEAMS_MANAGE)
        return scope_id
    granted_tier = ROLE_TIER.get(role_id)
    if granted_tier is not None:
        my_tier = admin_best_tier(admin.roles)
        if granted_tier < my_tier:
            raise HTTPException(
                status_code=403,
                detail="Cannot grant a role with higher authority than your own tier",
            )
    return None


def _validate_role_revoke_scope(
    admin: AuthenticatedUser,
    user_id: str,
    scope_type: str | None,
    scope_id: str | None,
    role_id: str,
) -> str | None:
    if scope_type is not None:
        if scope_type != "team":
            raise HTTPException(status_code=400, detail="scope_type must be 'team'")
        if not scope_id:
            raise HTTPException(status_code=400, detail="scope_id required when scope_type is set")
        scope_id = validate_uuid(scope_id)
        require_team_scope(admin, scope_id, FLAG_TEAMS_MANAGE)
        return scope_id
    if user_id == admin.id and role_id in ADMIN_ROLE_IDS:
        raise HTTPException(status_code=400, detail="Cannot remove your own admin role")
    revoked_tier = ROLE_TIER.get(role_id)
    if revoked_tier is not None:
        my_tier = admin_best_tier(admin.roles)
        if revoked_tier < my_tier:
            raise HTTPException(
                status_code=403,
                detail="Cannot revoke a role with higher authority than your own tier",
            )
    return None


# ---------------------------------------------------------------------------
# Scope helper
# ---------------------------------------------------------------------------

async def _require_user_in_scope(db, admin: AuthenticatedUser, user_id: str) -> None:
    """Raise 403 if a scoped admin (FLAG_USERS_MANAGE) cannot act on this user.

    Scoped admins may only manage users who are members of their allowed teams.
    Org-wide admins (global FLAG_USERS_MANAGE grant) pass unconditionally.
    """
    allowed = scope_team_ids(admin, FLAG_USERS_MANAGE)
    if allowed is None:
        return  # org-wide grant — unrestricted
    if not allowed:
        raise HTTPException(status_code=403, detail="Admin scope has no teams with users_manage")  # NOSONAR
    placeholders = ",".join("?" * len(allowed))
    cursor = await db.execute(
        f"SELECT 1 FROM user_team_keys WHERE user_id = ? AND team_id IN ({placeholders}) LIMIT 1",
        (user_id, *allowed),
    )
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=403, detail="Admin scope does not include this user")  # NOSONAR


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", responses={403: {"description": "Forbidden"}})
async def list_users(
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    page: int = 1,
    limit: int = 20,
):
    """List all users with pagination."""
    if not (admin.has_flag(FLAG_USERS_VIEW) or admin.has_flag(FLAG_USERS_MANAGE)):
        raise HTTPException(status_code=403, detail="users_view or users_manage permission required")
    pagination = validate_pagination(page, limit)

    # scope: None = org-wide (unrestricted); set = team-scoped IDs.
    # Either manage or view flag satisfies the scope; take the union (None wins = unrestricted).
    _manage_scope = scope_team_ids(admin, FLAG_USERS_MANAGE)
    _view_scope   = scope_team_ids(admin, FLAG_USERS_VIEW)
    if _manage_scope is None or _view_scope is None:
        allowed = None  # at least one global grant → org-wide
    else:
        allowed = _manage_scope | _view_scope  # both scoped → union
    if allowed is None:
        # Org-wide: return all users.
        cursor = await db.execute(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (pagination.limit, pagination.offset),
        )
        rows = await cursor.fetchall()
        count_cursor = await db.execute("SELECT COUNT(*) FROM users")
        total = (await count_cursor.fetchone())[0]
    elif allowed:
        # Scoped: return only users who are members of the admin's teams.
        placeholders = ",".join("?" * len(allowed))
        cursor = await db.execute(
            f"SELECT users.* FROM users "
            f"WHERE users.id IN ("
            f"    SELECT DISTINCT utk.user_id FROM user_team_keys utk "
            f"    WHERE utk.team_id IN ({placeholders})"
            f") ORDER BY users.created_at DESC LIMIT ? OFFSET ?",
            (*allowed, pagination.limit, pagination.offset),
        )
        rows = await cursor.fetchall()
        count_cursor = await db.execute(
            f"SELECT COUNT(DISTINCT utk.user_id) FROM user_team_keys utk "
            f"WHERE utk.team_id IN ({placeholders})",
            tuple(allowed),
        )
        total = (await count_cursor.fetchone())[0]
    else:
        # Scoped admin with no teams in scope.
        return {"users": [], "total": 0, "page": pagination.page, "limit": pagination.limit}

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


@router.post("", responses={410: {"description": "Gone"}})
async def create_user(
    body: CreateUserRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
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


@router.post("/admins", responses={410: {"description": "Gone"}})
async def create_admin(
    body: CreateAdminRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Create an admin-only account — use the invite+role-grant flow instead.

    Direct password-based admin creation is not compatible with OPAQUE
    authentication.  Generate an invite via POST /api/v1/admin/invites,
    have the user register, then grant the admin role via
    POST /api/v1/admin/users/{id}/roles/server_admin.
    """
    raise HTTPException(
        status_code=410,
        detail=(
            "Direct admin creation is not supported with OPAQUE authentication. "
            "Use POST /api/v1/admin/invites to generate an invite link, "
            "have the user register via OPAQUE, then grant the admin role via "
            "POST /api/v1/admin/users/{user_id}/roles/server_admin."
        ),
    )


@router.get("/{user_id}", responses={404: {"description": "Not Found"}})
async def get_user(
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Get a single user's details including roles, permissions, teams, and recent audit."""
    user_id = validate_uuid(user_id)
    if admin.has_flag(FLAG_USERS_VIEW) or admin.has_flag(FLAG_USERS_MANAGE):
        await _require_user_in_scope(db, admin, user_id)
    cursor = await db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=_ERR_USER_NOT_FOUND)

    # Global role assignments
    role_cursor = await db.execute(
        "SELECT ur.role_id, r.name AS role_name, r.is_system "
        "FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
        "WHERE ur.user_id = ? AND ur.scope_type IS NULL",
        (user_id,),
    )
    role_rows = await role_cursor.fetchall()
    roles = [{"id": r["role_id"], "name": r["role_name"], "is_system": bool(r["is_system"])} for r in role_rows]

    # Effective permissions: OR across all global roles
    perm_cursor = await db.execute(
        "SELECT rp.flag, MAX(CASE WHEN rp.value = '1' THEN 1 ELSE 0 END) AS granted "
        "FROM user_roles ur "
        "JOIN role_permissions rp ON rp.role_id = ur.role_id "
        "WHERE ur.user_id = ? AND ur.scope_type IS NULL "
        "GROUP BY rp.flag",
        (user_id,),
    )
    perm_rows = await perm_cursor.fetchall()
    permissions = {r["flag"]: bool(r["granted"]) for r in perm_rows}

    # Team memberships — use user_team_keys as the authoritative membership source,
    # join user_roles (scope_type='team') for the built-in role name.
    team_cursor = await db.execute(
        """
        SELECT t.id AS team_id, t.name AS team_name,
               r.id AS role_id, r.name AS role_name,
               utk.key_confirmed,
               to_char(to_timestamp(utk.created_at), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS joined_at
        FROM user_team_keys utk
        JOIN teams t ON t.id = utk.team_id
        LEFT JOIN user_roles ur ON ur.user_id = utk.user_id
                                AND ur.scope_type = 'team'
                                AND ur.scope_id = utk.team_id
        LEFT JOIN roles r ON r.id = ur.role_id
        WHERE utk.user_id = ?
        ORDER BY t.name
        """,
        (user_id,),
    )
    team_rows = await team_cursor.fetchall()
    teams = [
        {
            "team_id":        r["team_id"],
            "team_name":      r["team_name"],
            "team_role_id":   r["role_id"],
            "team_role_name": r["role_name"],
            "key_confirmed":  bool(r["key_confirmed"]),
            "joined_at":      r["joined_at"],
        }
        for r in team_rows
    ]

    # MFA status
    mfa_cursor = await db.execute(
        "SELECT COUNT(*) AS cnt FROM user_mfa_credentials WHERE user_id = ? AND is_active = 1",
        (user_id,),
    )
    mfa_row = await mfa_cursor.fetchone()
    mfa_enabled = bool(mfa_row["cnt"]) if mfa_row else False

    # Last login timestamp and IP from most recent login security event
    login_cursor = await db.execute(
        "SELECT timestamp AS last_login_at, ip_address "
        "FROM security_events "
        "WHERE user_id = ? "
        "AND event_type IN ('opaque_login_success', 'ldap_login_success', 'oidc_login_success') "
        "ORDER BY timestamp DESC LIMIT 1",
        (user_id,),
    )
    login_row = await login_cursor.fetchone()
    last_login_at = str(login_row["last_login_at"]) if login_row and login_row["last_login_at"] else None
    last_login_ip = login_row["ip_address"] if login_row else None

    # Last 10 audit entries for this user
    audit_cursor = await db.execute(
        "SELECT event_type, severity, outcome, ip_address, timestamp "
        "FROM security_events WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10",
        (user_id,),
    )
    audit_rows = await audit_cursor.fetchall()
    recent_audit = [
        {
            "event_type": r["event_type"],
            "severity":   r["severity"],
            "outcome":    r["outcome"],
            "ip_address": r["ip_address"],
            "timestamp":  str(r["timestamp"]) if r["timestamp"] else None,
        }
        for r in audit_rows
    ]

    return {
        "user": {
            "id":              row["id"],
            "username":        row["username"],
            "auth_method":     row["auth_method"],
            "is_admin":        bool(row["is_admin"]),
            "is_active":       bool(row["is_active"]),
            "max_file_size":   row["max_file_size"],
            "disk_quota":      row["disk_quota"],
            "bandwidth_limit": row["bandwidth_limit"],
            "disk_used":       row["disk_used"],
            "created_at":      str(row["created_at"]) if row["created_at"] else None,
            "last_login_at":   last_login_at,
            "last_login_ip":   last_login_ip,
            "roles":           roles,
            "permissions":     permissions,
            "teams":           teams,
            "mfa_enabled":     mfa_enabled,
            "recent_audit":    recent_audit,
        }
    }


@router.post("/{user_id}/lock", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def lock_user(
    request: Request,
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Deactivate a user account (lock). Revokes all sessions and shares."""
    if not admin.has_flag(FLAG_USERS_MANAGE):
        raise HTTPException(status_code=403, detail=_ERR_PERM_MANAGE_USERS)
    user_id = validate_uuid(user_id)
    await _require_user_in_scope(db, admin, user_id)
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot lock your own account")
    result = await db.execute(
        "UPDATE users SET is_active = 0, updated_at = NOW() WHERE id = ?", (user_id,)
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail=_ERR_USER_NOT_FOUND)
    await _handle_activation_change(db, user_id, False, admin, request)
    return {"message": "User locked"}


@router.post("/{user_id}/unlock", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def unlock_user(
    request: Request,
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Reactivate a previously locked user account."""
    if not admin.has_flag(FLAG_USERS_MANAGE):
        raise HTTPException(status_code=403, detail=_ERR_PERM_MANAGE_USERS)
    user_id = validate_uuid(user_id)
    await _require_user_in_scope(db, admin, user_id)
    result = await db.execute(
        "UPDATE users SET is_active = 1, updated_at = NOW() WHERE id = ?", (user_id,)
    )
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail=_ERR_USER_NOT_FOUND)
    await db.commit()
    await _handle_activation_change(db, user_id, True, admin, request)
    return {"message": "User unlocked"}


@router.post("/{user_id}/reset-password", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def reset_user_password(
    request: Request,
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Force a user to re-authenticate by revoking all active sessions.

    OPAQUE does not support admin-set passwords. To change a user's password
    they must use the recovery-key flow or be re-invited via POST /admin/invites.
    This endpoint revokes all refresh tokens (forcing logout everywhere) and
    emits an audit event. Share an invite link via the invites API for full reset.
    """
    if not admin.has_flag(FLAG_USERS_MANAGE):
        raise HTTPException(status_code=403, detail=_ERR_PERM_MANAGE_USERS)
    user_id = validate_uuid(user_id)
    await _require_user_in_scope(db, admin, user_id)
    cursor = await db.execute(_SQL_USERNAME_BY_ID, (user_id,))
    target = await cursor.fetchone()
    if target is None:
        raise HTTPException(status_code=404, detail=_ERR_USER_NOT_FOUND)
    await db.execute("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
    await db.commit()
    event_bus.emit(SecurityEvent(
        event_type="admin.user.sessions_revoked",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
        target=EventTarget(type="user", id=user_id, name=target["username"]),
        detail={"reason": "admin_password_reset"},
    ))
    return {
        "message": "All sessions revoked. To complete a password reset, share a new invite link with the user via POST /api/v1/admin/invites.",
    }


async def _handle_activation_change(db, user_id: str, is_active, admin: AuthenticatedUser, request: Request) -> None:
    event_bus.emit(SecurityEvent(
        event_type="admin.user.deactivated" if not is_active else "admin.user.activated",
        severity="warning" if not is_active else "info",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
        target=EventTarget(type="user", id=user_id),
    ))
    if is_active is False:
        await db.execute("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
        await db.execute("DELETE FROM user_team_keys WHERE user_id = ?", (user_id,))
        await db.execute(
            "UPDATE shares SET expires_at = NOW() "
            "WHERE created_by = ? AND (expires_at IS NULL OR expires_at > NOW())",
            (user_id,),
        )
        await db.commit()
        sse_broker.publish(f"identity:{user_id}", {"type": "identity_changed", "reason": "deactivated"})


@router.put("/{user_id}", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def update_user(
    request: Request,
    user_id: str,
    body: UpdateUserRequest,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Update a user's settings (quotas, active status)."""
    if not admin.has_flag(FLAG_USERS_MANAGE):
        raise HTTPException(status_code=403, detail=_ERR_PERM_MANAGE_USERS)
    user_id = validate_uuid(user_id)
    await _require_user_in_scope(db, admin, user_id)

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
        raise HTTPException(status_code=404, detail=_ERR_USER_NOT_FOUND)

    if body.is_active is not None:
        await _handle_activation_change(db, user_id, body.is_active, admin, request)

    return {"message": "User updated"}


@router.get("/{user_id}/roles", responses={404: {"description": "Not Found"}})
async def list_user_roles(
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all role assignments for a user (global + scoped)."""
    user_id = validate_uuid(user_id)

    cursor = await db.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail=_ERR_USER_NOT_FOUND)

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


@router.post("/{user_id}/roles/{role_id}", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def add_role_to_user(
    request: Request,
    user_id: str,
    role_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    body: Annotated[GrantRoleRequest, Body(default_factory=GrantRoleRequest)],
):
    """Grant a role to a user — global or scoped to a team.

    Requires roles_manage.  For roles in the fixed tier hierarchy, the
    granted role's tier must be >= the granting admin's own best tier so that
    a lower-tier admin cannot promote anyone to a higher tier than themselves.
    Custom (non-tiered) roles have no tier restriction.

    To grant a team-scoped role (e.g. team_admin for a specific team), include
    {"scope_type": "team", "scope_id": "<team_uuid>"} in the request body.
    The calling admin must hold FLAG_TEAMS_MANAGE within that team's scope.
    """
    if not admin.has_flag(FLAG_ROLES_MANAGE):
        raise HTTPException(status_code=403, detail="roles_manage permission required")

    user_id = validate_uuid(user_id)

    scope_type = body.scope_type if body else None
    scope_id   = body.scope_id   if body else None

    scope_id = _validate_role_grant_scope(admin, scope_type, scope_id, role_id)

    # Verify role exists
    cursor = await db.execute("SELECT id FROM roles WHERE id = ?", (role_id,))
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="Role not found")

    # Verify user exists
    cursor = await db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    target_row = await cursor.fetchone()
    if target_row is None:
        raise HTTPException(status_code=404, detail=_ERR_USER_NOT_FOUND)

    await grant_role(db, user_id, role_id, granted_by=admin.id, scope_type=scope_type, scope_id=scope_id)

    # Keep legacy is_admin column in sync (global grants only).
    if scope_type is None and role_id in ADMIN_ROLE_IDS:
        await db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))

    await db.commit()

    event_bus.emit(SecurityEvent(
        event_type="admin.role.granted",
        severity="warning",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
        target=EventTarget(type="user", id=user_id, name=target_row["username"]),
        detail={"role_id": role_id, "scope_type": scope_type, "scope_id": scope_id},
    ))

    return {"message": f"Role {role_id} granted to user {user_id}", "scope_type": scope_type, "scope_id": scope_id}


@router.delete("/{user_id}/roles/{role_id}", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def remove_role_from_user(
    request: Request,
    user_id: str,
    role_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
    scope_type: str | None = None,
    scope_id: str | None = None,
):
    """Revoke a role from a user — global or scoped.

    Requires roles_manage.  The same tier cap as grant applies: you cannot
    revoke a role with higher authority than your own tier.

    To revoke a team-scoped role, pass ?scope_type=team&scope_id=<team_uuid>.
    The calling admin must hold FLAG_TEAMS_MANAGE within that team's scope.
    """
    if not admin.has_flag(FLAG_ROLES_MANAGE):
        raise HTTPException(status_code=403, detail="roles_manage permission required")

    user_id = validate_uuid(user_id)

    scope_id = _validate_role_revoke_scope(admin, user_id, scope_type, scope_id, role_id)

    # Fetch target username for the audit event before deletion
    cursor = await db.execute(_SQL_USERNAME_BY_ID, (user_id,))
    target_row = await cursor.fetchone()

    removed = await revoke_role(db, user_id, role_id, scope_type=scope_type, scope_id=scope_id)
    if not removed:
        raise HTTPException(status_code=404, detail="User does not have this role")

    # Keep legacy is_admin column in sync (global revokes only).
    if scope_type is None and role_id in ADMIN_ROLE_IDS:
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
        actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
        target=EventTarget(type="user", id=user_id, name=target_row["username"] if target_row else None),
        detail={"role_id": role_id, "scope_type": scope_type, "scope_id": scope_id},
    ))

    return {"message": f"Role {role_id} revoked from user {user_id}"}


@router.delete("/{user_id}", responses={400: {"description": "Bad Request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def delete_user(
    request: Request,
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Delete a user and all their data.

    Collects file storage keys before deleting (CASCADE removes DB rows),
    then cleans up blobs from disk in a background thread.
    """
    if not admin.has_flag(FLAG_USERS_DELETE):
        raise HTTPException(status_code=403, detail="users_delete permission required")

    user_id = validate_uuid(user_id)
    await _require_user_in_scope(db, admin, user_id)

    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    # Fetch username before deletion for the audit event
    cursor = await db.execute(_SQL_USERNAME_BY_ID, (user_id,))
    target_row = await cursor.fetchone()

    # Collect file id+key pairs before CASCADE deletes the file rows
    cursor = await db.execute(
        "SELECT id, storage_key FROM files WHERE owner_id = ?", (user_id,)
    )
    file_rows = await cursor.fetchall()

    result = await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    await db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail=_ERR_USER_NOT_FOUND)

    event_bus.emit(SecurityEvent(
        event_type="admin.user.deleted",
        severity="critical",
        outcome="success",
        actor=EventActor(user_id=admin.id, username=admin.username, ip=_get_client_ip(request)),
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
                    # Skip if another files row still shares this storage_key (B5 copy dedup)
                    cur = await _db.execute(
                        "SELECT COUNT(*) AS cnt FROM files WHERE storage_key = ?",
                        (row["storage_key"],)
                    )
                    cnt = await cur.fetchone()
                    if cnt and cnt["cnt"] > 0:
                        continue
                    await mgr.delete_blob(_db, row["id"], row["storage_key"])
                    cleaned += 1
                except Exception as exc:
                    logger.warning("Failed to delete blob %s: %s", row["storage_key"], exc)
        if cleaned:
            logger.info("Cleaned up %d file blobs for deleted user %s", cleaned, uid_snapshot)

    _t = asyncio.create_task(_cleanup_blobs())
    _bg_tasks.add(_t)
    _t.add_done_callback(_bg_tasks.discard)

    return {"message": "User deleted"}


@router.delete("/{user_id}/asymmetric-keys", responses={403: {"description": "Forbidden"}, 404: {"description": "Not Found"}})
async def clear_user_asymmetric_keys(
    user_id: str,
    admin: Annotated[AuthenticatedUser, Depends(require_admin)],
    db: Annotated[Database, Depends(get_db)],
):
    """Admin: clear a user's asymmetric public/private key material.

    Sets x25519_public_key, mlkem768_public_key, x25519_private_wrapped,
    mlkem768_private_wrapped, and asymmetric_key_iv to NULL. The user will be
    excluded from escrow-agent resolution and team-key wrapping until they
    re-register their keys via POST /auth/me/asymmetric-keys.

    Requires users_manage. Typical use: key revocation after suspected
    compromise, or resetting a test user's key state.
    """
    if not admin.has_flag(FLAG_USERS_MANAGE):
        raise HTTPException(status_code=403, detail=_ERR_PERM_MANAGE_USERS)

    user_id = validate_uuid(user_id)
    await _require_user_in_scope(db, admin, user_id)

    result = await db.execute(
        "UPDATE users SET "
        "x25519_public_key = NULL, mlkem768_public_key = NULL, "
        "x25519_private_wrapped = NULL, mlkem768_private_wrapped = NULL, "
        "asymmetric_key_iv = NULL, updated_at = NOW() "
        "WHERE id = ?",
        (user_id,),
    )
    await db.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail=_ERR_USER_NOT_FOUND)

    return {"message": "Asymmetric keys cleared"}
