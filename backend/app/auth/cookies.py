"""Session cookie helpers shared by all login paths (OPAQUE, LDAP, OIDC)."""

from __future__ import annotations

from fastapi import Response

from app.auth.interface import AuthenticatedUser
from app.conf.auth import COOKIE_ACCESS, COOKIE_CSRF, COOKIE_REFRESH, REFRESH_TOKEN_COOKIE_PATH
from app.config import settings
from app.services import live_settings


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: str,
    max_age: int | None = None,
) -> None:
    """Write the three session cookies onto *response*.

    *max_age* overrides the default refresh-token / CSRF lifetime (seconds).
    Pass a shorter value for public-device sessions.
    """
    rt_max_age = max_age if max_age is not None else live_settings.get_int("refresh_token_expire_days", settings.REFRESH_TOKEN_EXPIRE_DAYS) * 86400
    response.set_cookie(
        key=COOKIE_ACCESS,
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
        max_age=live_settings.get_int("access_token_expire_minutes", settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60,
    )
    response.set_cookie(
        key=COOKIE_REFRESH,
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path=REFRESH_TOKEN_COOKIE_PATH,
        max_age=rt_max_age,
    )
    response.set_cookie(
        key=COOKIE_CSRF,
        value=csrf_token,
        httponly=False,
        secure=True,
        samesite="strict",
        path="/",
        max_age=rt_max_age,
    )


def clear_auth_cookies(response: Response) -> None:
    """Delete all three session cookies.

    secure=True and samesite="strict" must be repeated here — delete_cookie
    defaults secure=False, which causes browsers to reject the Set-Cookie
    header for __Host- and __Secure- prefixed cookies (both require Secure).
    """
    response.delete_cookie(key=COOKIE_ACCESS, path="/", secure=True, samesite="strict")
    response.delete_cookie(key=COOKIE_REFRESH, path=REFRESH_TOKEN_COOKIE_PATH, secure=True, samesite="strict")
    response.delete_cookie(key=COOKIE_CSRF, path="/", secure=True, samesite="strict")


def user_response_dict(user: AuthenticatedUser) -> dict:
    """Build the user object returned to the client on login / token refresh."""
    return {
        "id": user.id,
        "username": user.username,
        "auth_method": user.auth_method,
        "is_admin": user.is_admin,
        "is_admin_only": user.is_admin_only,
        "is_public_device": getattr(user, "is_public_device", False),
        "roles": sorted(user.roles),
        "flags": user.flags,
        "wrapped_master_key": user.wrapped_master_key,
        "wrapped_master_key_iv": user.wrapped_master_key_iv,
        "recovery_key_wrapped": user.recovery_key_wrapped,
        "recovery_key_iv": user.recovery_key_iv,
        "x25519_public_key": getattr(user, "x25519_public_key", None),
        "mlkem768_public_key": getattr(user, "mlkem768_public_key", None),
        "x25519_private_wrapped": getattr(user, "x25519_private_wrapped", None),
        "mlkem768_private_wrapped": getattr(user, "mlkem768_private_wrapped", None),
        "asymmetric_key_iv": getattr(user, "asymmetric_key_iv", None),
        "upload_rate_limit":      live_settings.get_int("rate_limit_upload",      settings.RATE_LIMIT_UPLOAD),
        "step_up_window_seconds": live_settings.get_int("step_up_window_seconds", settings.STEP_UP_WINDOW_SECONDS),
    }
