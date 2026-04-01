"""FastAPI dependencies for authentication and authorization.

get_current_user reads JWT from httpOnly cookie OR Authorization Bearer header.
This dual-auth approach supports both browser sessions and API/deeplink access.
"""

import logging

import jwt
from fastapi import Depends, HTTPException, Request

from app.auth.interface import AuthenticatedUser
from app.auth.jwt import verify_access_token
from app.auth.local import LocalAuthProvider
from app.database import get_db

logger = logging.getLogger(__name__)


async def _get_auth_provider(db=Depends(get_db)) -> LocalAuthProvider:
    """Return the active auth provider. Swap this for SSO support."""
    return LocalAuthProvider(db)


async def get_current_user(
    request: Request,
    auth_provider=Depends(_get_auth_provider),
) -> AuthenticatedUser:
    """Extract and validate the authenticated user from the request.

    Checks (in order):
    1. access_token httpOnly cookie (browser sessions)
    2. Authorization: Bearer <token> header (API/deeplink access)
    """
    token = None

    # Method 1: httpOnly cookie
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        token = cookie_token

    # Method 2: Bearer header
    if token is None:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if token is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        payload = verify_access_token(token)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = await auth_provider.get_user_by_id(payload["sub"])
    if user is None:
        raise HTTPException(status_code=401, detail="User not found or inactive")

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


async def require_admin(
    user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Require the current user to be an admin."""
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def require_user_role(
    user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Require the current user to hold the 'user' role.

    Admin-only accounts are blocked from file/folder/upload operations.
    This enforces the separation between management and user activities.
    """
    if not user.is_user:
        raise HTTPException(
            status_code=403,
            detail="This operation requires a user account. Admin-only accounts cannot perform file operations.",
        )
    return user
