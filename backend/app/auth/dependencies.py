"""FastAPI dependencies for authentication and authorization.

get_current_user reads JWT from httpOnly cookie OR Authorization Bearer header.
This dual-auth approach supports both browser sessions and API/deeplink access.
"""

import asyncio
import logging

import jwt
from fastapi import Depends, HTTPException, Request

from app.auth.interface import AuthenticatedUser
from app.auth.jwt import touch_session, verify_access_token
from app.auth.opaque_provider import OPAQUEAuthProvider
from app.conf.auth import COOKIE_ACCESS
from app.database import get_db

logger = logging.getLogger(__name__)

_bg_tasks: set = set()


def _get_auth_provider(db=Depends(get_db)) -> OPAQUEAuthProvider:
    """Return the active auth provider. Swap this for SSO support."""
    return OPAQUEAuthProvider(db)


async def get_current_user(
    request: Request,
    auth_provider=Depends(_get_auth_provider),
) -> AuthenticatedUser:
    """Extract and validate the authenticated user from the request.

    Checks (in order):
    1. access_token httpOnly cookie (browser sessions)
    2. Authorization: Bearer <token> header (API/deeplink access)

    When the JWT contains a sid (session ID) claim, last_active_at is updated
    for that refresh token row. The write is throttled inside touch_session so
    it fires at most once per minute per session regardless of request rate.
    """
    token = None

    # Method 1: httpOnly cookie
    cookie_token = request.cookies.get(COOKIE_ACCESS)
    if cookie_token:
        token = cookie_token

    # Method 2: Bearer header
    if token is None:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if token is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Service account tokens are identified by the 'sa_' prefix and bypass
    # the JWT path entirely — they authenticate directly against the key table.
    if token.startswith("sa_"):
        from app.auth.service_account import authenticate_service_account
        return await authenticate_service_account(token)

    try:
        payload = verify_access_token(token)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = await auth_provider.get_user_by_id(payload["sub"])
    if user is None:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    # Propagate session-level flags from the JWT claims onto the user object.
    if payload.get("pub"):
        user.is_public_device = True

    sid = payload.get("sid")
    if sid:
        # Bind step-up tokens to this session (T1-M3).
        user.session_id = sid
        # Fire-and-forget: update last_active_at for idle-timeout tracking.
        _t = asyncio.ensure_future(touch_session(sid))
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)

    return user


async def get_optional_user(
    request: Request,
    auth_provider=Depends(_get_auth_provider),
) -> AuthenticatedUser | None:
    """Like get_current_user, but returns None instead of raising 401."""
    try:
        return await get_current_user(request, auth_provider)
    except HTTPException:
        return None


def require_admin(
    user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Require the current user to hold the can_view_admin_panel permission."""
    from app.models.role import FLAG_VIEW_ADMIN_PANEL
    if not user.has_flag(FLAG_VIEW_ADMIN_PANEL):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def require_user_role(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
) -> AuthenticatedUser:
    """Require the current user to hold the 'user' role.

    Admin-only accounts are blocked from file/folder/upload operations.
    Also enforces MFA enrollment when mfa_enforcement='required'.

    Uses get_current_user for a shared DB connection within the same request.
    """
    if not user.is_user:
        raise HTTPException(
            status_code=403,
            detail="This operation requires a user account. Admin-only accounts cannot perform file operations.",
        )

    # MFA enforcement — check whether the user must enroll before accessing resources.
    # Only fires when enforcement is not 'off' so the overhead is zero in the default config.
    from app.auth.mfa import load_mfa_settings, get_active_methods
    mfa_settings = await load_mfa_settings(db)
    enforcement = mfa_settings["mfa_enforcement"]

    if enforcement != "off":
        cursor = await db.execute(
            "SELECT mfa_reset_required FROM users WHERE id = ?", (user.id,)
        )
        mfa_row = await cursor.fetchone()
        mfa_reset_required = bool(mfa_row["mfa_reset_required"]) if mfa_row else False

        if mfa_reset_required:
            # Admin forced re-enrollment: block regardless of enforcement mode
            raise HTTPException(
                status_code=403,
                detail={"error": "mfa_enrollment_required"},
            )

        if enforcement == "required":
            active = await get_active_methods(db, user.id)
            allowed = mfa_settings["mfa_allowed_methods"]
            satisfying = (active & set(allowed)) if allowed else active
            if not satisfying:
                raise HTTPException(
                    status_code=403,
                    detail={"error": "mfa_enrollment_required"},
                )

    return user
