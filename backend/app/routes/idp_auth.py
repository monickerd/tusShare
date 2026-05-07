"""LDAP and OIDC authentication routes.

Endpoints
─────────
GET  /auth/idp/providers        — list active providers (name + type, no secrets)
POST /auth/ldap/login           — authenticate with LDAP username + password
GET  /auth/oidc/{id}/begin      — begin OIDC flow (returns redirect URL)
GET  /auth/oidc/callback        — handle IdP redirect (code exchange → session)

MFA wiring
──────────────────────────
After successful LDAP or OIDC authentication, both paths check for active MFA
credentials and apply the same pending_token gate used by OPAQUE login:
  1. If the user has active MFA credentials (or mfa_reset_required=1) →
     return {mfa_required: true, pending_token: ...} without cookies.
  2. The client uses the existing MFA challenge flow (totp/verify, webauthn).
  3. mfa_oidc_exempt: if set to '1' in admin_settings, LDAP/OIDC users bypass
     enforcement (unless mfa_reset_required overrides it).

LDAP users and the KEK gap
──────────────────────────
LDAP/OIDC users are created without wrapped_master_key — they have no OPAQUE
KEK so personal file encryption is unavailable.  The client must handle a null
wrapped_master_key gracefully.  Team files and user-share KEM are fully usable.

OIDC callback security
──────────────────────
The state parameter is a 32-byte cryptographically random nonce stored in
oidc_states.  The callback validates it (consumed atomically) before doing
anything.  redirect_to (app-internal post-auth path) is stored in oidc_states
and never originates from the query string — it cannot be manipulated by the IdP
redirect to redirect the user to an arbitrary external URL.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, field_validator

from app.auth.cookies import set_auth_cookies
from app.auth.dependencies import get_current_user
from app.auth.jwt import create_access_token, create_refresh_token, generate_csrf_token, store_refresh_token
from app.auth.ldap_provider import ldap_authenticate, _validate_ldap_username
from app.auth.oidc_provider import begin_oidc_flow, handle_oidc_callback, sweep_expired_oidc_states
from app.auth.idp_crypto import decrypt_idp_config, encrypt_token
from app.auth.mfa import (
    get_active_methods,
    issue_pending_token,
    store_pending_token,
    extract_pending_jti,
    load_mfa_settings,
)
from app.auth.stepup import log_security_event
from app.config import settings
from app.database import Database, DuplicateError, get_db
from app.models.role import ROLE_USER, grant_role
from app.middleware.rate_limit import _counter, _get_client_ip
from app.validation.sanitizers import validate_uuid
from typing import Annotated

_bg_tasks: set = set()

logger = logging.getLogger(__name__)

router = APIRouter()

_LDAP_LOGIN_RATE_LIMIT  = 5
_LDAP_LOGIN_RATE_WINDOW = 900   # 5 attempts per 15 minutes per IP
_OIDC_ERROR_URL = "/?oidc_error=1"

# ---------------------------------------------------------------------------
# OIDC MFA challenge store (RT-07)
#
# After a successful OIDC login that requires MFA, the pending_token must not
# appear in the redirect URL (it would be logged by nginx/access logs and stored
# in browser history).  Instead we store it server-side keyed by a random
# challenge_id and redirect with only the challenge_id.  The frontend exchanges
# the challenge_id for the pending_token via a one-time GET endpoint.
#
# Note: this store is per-process.  In multi-worker deployments the OIDC
# callback and the challenge exchange must hit the same worker (use sticky
# sessions in nginx / Cloudflare) or migrate this to Redis.
# ---------------------------------------------------------------------------

class _OidcMfaChallengeStore:
    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float]] = {}

    def put(self, pending_token: str, ttl: int = 120) -> str:
        challenge_id = secrets.token_urlsafe(32)
        self._store[challenge_id] = (pending_token, time.monotonic() + ttl)
        return challenge_id

    def pop(self, challenge_id: str) -> str | None:
        entry = self._store.pop(challenge_id, None)
        if entry is None:
            return None
        token, expires_at = entry
        if time.monotonic() > expires_at:
            return None
        return token

    def sweep(self) -> None:
        now = time.monotonic()
        expired = [k for k, (_, exp) in self._store.items() if exp < now]
        for k in expired:
            del self._store[k]


_oidc_mfa_challenges = _OidcMfaChallengeStore()


@router.get("/mfa/challenge/{challenge_id}", responses={404: {"description": "Not Found"}, 500: {"description": "Internal Server Error"}})
async def exchange_mfa_challenge(challenge_id: str):
    """One-time exchange: challenge_id → pending_token.

    Called by the SPA immediately after an OIDC redirect that requires MFA.
    The pending_token is returned once and then deleted from the store.
    Returns 404 if the challenge_id is unknown or expired.
    """
    pending_token = _oidc_mfa_challenges.pop(challenge_id)
    if pending_token is None:
        raise HTTPException(status_code=404, detail="Challenge not found or expired")
    return {"pending_token": pending_token}


async def _issue_session_or_mfa_challenge(
    db,
    response: Response,
    user_id: str,
    _identity_provider_id: str,
    is_public_device: bool = False,
) -> dict:
    """Issue session cookies or return an MFA pending_token, depending on user's MFA state.

    This is the common finalisation step shared by LDAP and OIDC login paths.
    Mirrors the logic in opaque_auth.py login/finish.
    """
    # Load MFA state
    cursor = await db.execute(
        "SELECT mfa_reset_required FROM users WHERE id = ?", (user_id,)
    )
    mfa_row = await cursor.fetchone()
    mfa_reset_required = bool(mfa_row["mfa_reset_required"]) if mfa_row else False

    active_methods = await get_active_methods(db, user_id)

    # MFA gate: if user has active credentials or admin forced re-enrollment
    if active_methods or mfa_reset_required:
        # Check oidc_exempt: if admin set mfa_oidc_exempt=1, LDAP/OIDC users skip MFA
        # (unless mfa_reset_required overrides it)
        if not mfa_reset_required:
            mfa_settings = await load_mfa_settings(db)
            if mfa_settings["mfa_oidc_exempt"]:
                # Exempt — fall through to cookie issuance
                return await _finish_with_cookies(db, response, user_id, is_public_device, active_methods)

        pending_token = issue_pending_token(user_id)
        jti = extract_pending_jti(pending_token)
        await store_pending_token(db, jti, user_id, is_public_device)
        await db.commit()

        return {
            "mfa_required": True,
            "methods": sorted(active_methods),
            "reset_required": mfa_reset_required,
            "pending_token": pending_token,
        }

    return await _finish_with_cookies(db, response, user_id, is_public_device, active_methods)


async def _finish_with_cookies(
    db,
    response: Response,
    user_id: str,
    is_public_device: bool,
    active_methods: set,
) -> dict:
    """Issue session cookies and return the user response dict."""
    if is_public_device:
        rt_expire_minutes = settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES
        rt_max_age = rt_expire_minutes * 60
    else:
        rt_expire_minutes = None
        rt_max_age = None

    raw_refresh, rt_hash = create_refresh_token()
    token_id = await store_refresh_token(
        db, user_id, rt_hash,
        expire_minutes=rt_expire_minutes,
        is_public_device=is_public_device,
    )
    access_token = create_access_token(user_id, session_id=token_id, is_public_device=is_public_device)
    csrf_token = generate_csrf_token()
    set_auth_cookies(response, access_token, raw_refresh, csrf_token, max_age=rt_max_age)

    # Load the user record for the response
    cursor = await db.execute(
        "SELECT id, username, is_admin, is_active, "
        "wrapped_master_key, wrapped_master_key_iv, "
        "x25519_public_key, mlkem768_public_key, "
        "x25519_private_wrapped, mlkem768_private_wrapped, asymmetric_key_iv "
        "FROM users WHERE id = ?",
        (user_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=500, detail="User record not found after authentication")  # NOSONAR — helper; 500 documented in callers

    # Load roles
    cursor2 = await db.execute(
        "SELECT role_id FROM user_roles WHERE user_id = ? AND scope_type IS NULL", (user_id,)
    )
    role_rows = await cursor2.fetchall()
    roles = sorted(r["role_id"] for r in role_rows)

    mfa_enrollment_required = False
    if not active_methods:
        mfa_settings = await load_mfa_settings(db)
        mfa_enrollment_required = mfa_settings["mfa_enforcement"] == "required"

    user_dict = {
        "id": row["id"],
        "username": row["username"],
        "auth_method": "idp",
        "is_admin": bool(row["is_admin"]),
        "roles": roles,
        "wrapped_master_key": row["wrapped_master_key"],
        "wrapped_master_key_iv": row["wrapped_master_key_iv"],
        "x25519_public_key": row["x25519_public_key"],
        "mlkem768_public_key": row["mlkem768_public_key"],
        "x25519_private_wrapped": row["x25519_private_wrapped"],
        "mlkem768_private_wrapped": row["mlkem768_private_wrapped"],
        "asymmetric_key_iv": row["asymmetric_key_iv"],
    }

    resp: dict = {"user": user_dict}
    if mfa_enrollment_required:
        resp["mfa_enrollment_required"] = True
    return resp


async def _ensure_idp_user(
    db,
    provider_id: str,
    provider_type: str,
    external_id: str,
    display_username: str,
    claims_json: str | None = None,
    refresh_token: str | None = None,
) -> str:
    """Find or create the tusShare user record for an IdP identity.

    Returns the internal user_id.

    - Looks up identity_provider_users by (provider_id, external_id).
    - If found: updates oidc_claims_cache and oidc_refresh_token_enc, returns user_id.
    - If not found: creates a new user row + identity_provider_users row + grants ROLE_USER.
      New IdP users have NULL wrapped_master_key (no OPAQUE KEK).
    """
    # Try to find existing mapping
    cursor = await db.execute(
        "SELECT user_id FROM identity_provider_users WHERE provider_id = ? AND external_id = ?",
        (provider_id, external_id),
    )
    row = await cursor.fetchone()

    refresh_token_enc = encrypt_token(refresh_token) if refresh_token else None

    if row is not None:
        user_id = row["user_id"]
        # Update claims cache and refresh token
        await db.execute(
            "UPDATE users SET oidc_claims_cache = ?, oidc_refresh_token_enc = ? WHERE id = ?",
            (claims_json, refresh_token_enc, user_id),
        )
        await db.commit()
        return user_id

    # Create a new user
    user_id = str(uuid.uuid4())
    ipu_id = str(uuid.uuid4())

    await db.execute("BEGIN")
    try:
        await db.execute(
            "INSERT INTO users "
            "(id, username, auth_method, identity_provider_id, "
            " oidc_claims_cache, oidc_refresh_token_enc, is_admin) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)",
            (
                user_id,
                display_username,
                provider_type,   # 'ldap' or 'oidc' — stored as auth_method
                provider_id,
                claims_json,
                refresh_token_enc,
            ),
        )
        await db.execute(
            "INSERT INTO identity_provider_users (id, provider_id, user_id, external_id) "
            "VALUES (?, ?, ?, ?)",
            (ipu_id, provider_id, user_id, external_id),
        )
        await grant_role(db, user_id, ROLE_USER)
        await db.commit()
    except DuplicateError:
        await db.rollback()
        # Username conflict: append a short suffix and retry once
        username_alt = display_username + "_" + str(uuid.uuid4())[:8]
        await db.execute("BEGIN")
        await db.execute(
            "INSERT INTO users "
            "(id, username, auth_method, identity_provider_id, "
            " oidc_claims_cache, oidc_refresh_token_enc, is_admin) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)",
            (user_id, username_alt, provider_type, provider_id, claims_json, refresh_token_enc),
        )
        await db.execute(
            "INSERT INTO identity_provider_users (id, provider_id, user_id, external_id) "
            "VALUES (?, ?, ?, ?)",
            (ipu_id, provider_id, user_id, external_id),
        )
        await grant_role(db, user_id, ROLE_USER)
        await db.commit()

    logger.info("New IdP user created: user_id=%s provider=%s external_id=%s", user_id, provider_id, external_id)
    return user_id


def _fire_policy_eval(user_id: str) -> None:
    """Fire-and-forget background policy evaluation for a newly logged-in IdP user."""
    import asyncio as _asyncio
    try:
        from app.models.policy import evaluate_user_policies as _eval
        from app.database import db_session as _dbs
        async def _bg():
            try:
                async with _dbs() as _bg_db:
                    await _eval(_bg_db, user_id)
            except Exception:
                pass
        _t = _asyncio.create_task(_bg())
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# List active providers (used by login page to render buttons)
# ---------------------------------------------------------------------------

@router.get("/idp/providers")
async def list_active_providers(db: Annotated[Database, Depends(get_db)]):
    """Return name + type for all active identity providers.

    Used by the login page to render 'Sign in with X' buttons.
    No authentication required; secrets are never returned.
    """
    cursor = await db.execute(
        "SELECT id, provider_type, name FROM identity_providers "
        "WHERE is_active = 1 ORDER BY name"
    )
    rows = await cursor.fetchall()
    return {"providers": [{"id": r["id"], "provider_type": r["provider_type"], "name": r["name"]} for r in rows]}


# ---------------------------------------------------------------------------
# LDAP login
# ---------------------------------------------------------------------------

class LDAPLoginRequest(BaseModel):
    provider_id: str
    username: str
    password: str
    is_public_device: bool = False

    @field_validator("provider_id")
    @classmethod
    def val_provider_id(cls, v: str) -> str:
        try:
            return validate_uuid(v)
        except ValueError:
            raise ValueError("provider_id must be a valid UUID")

    @field_validator("username")
    @classmethod
    def val_username(cls, v: str) -> str:
        try:
            return _validate_ldap_username(v)
        except ValueError as exc:
            raise ValueError(str(exc))

    @field_validator("password")
    @classmethod
    def val_password(cls, v: str) -> str:
        if not v or v.strip() == "" or len(v) > 1024:
            raise ValueError("password must be 1–1024 characters")
        return v


@router.post("/ldap/login", responses={400: {"description": "Bad Request"}, 401: {"description": "Unauthorized"}, 429: {"description": "Too Many Requests"}})
async def ldap_login(
    body: LDAPLoginRequest,
    request: Request,
    response: Response,
    db: Annotated[Database, Depends(get_db)],
):
    """Authenticate with LDAP username + password.

    Rate-limited to 5 attempts per 15 minutes per IP (same as OPAQUE login).
    On success: creates/updates the user record and issues session cookies (or
    returns a pending_token if MFA is required).
    """
    client_ip = _get_client_ip(request)
    allowed = await _counter.is_allowed(
        f"ldap_login:{client_ip}", _LDAP_LOGIN_RATE_LIMIT, _LDAP_LOGIN_RATE_WINDOW
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": str(_LDAP_LOGIN_RATE_WINDOW)},
        )

    # Load the provider
    cursor = await db.execute(
        "SELECT id, config_enc FROM identity_providers "
        "WHERE id = ? AND provider_type = 'ldap' AND is_active = 1",
        (body.provider_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=400, detail="LDAP provider not found or inactive")

    attrs = await ldap_authenticate(row["config_enc"], body.username, body.password)
    if attrs is None:
        user_agent = request.headers.get("user-agent", "")[:512]
        await log_security_event(db, "ldap_login_failed", None, client_ip, user_agent, body.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Use the username as the stable external_id for LDAP (assumes sAMAccountName / uid is stable)
    external_id = body.username

    # Serialise LDAP attributes as JSON for claims cache
    claims_json = json.dumps(
        {k: str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v
         for k, v in attrs.items()},
        default=str,
    )

    user_id = await _ensure_idp_user(
        db,
        provider_id=body.provider_id,
        provider_type="ldap",
        external_id=external_id,
        display_username=body.username,
        claims_json=claims_json,
        refresh_token=None,
    )

    user_agent = request.headers.get("user-agent", "")[:512]
    logger.info("LDAP login: user_id=%s username=%s ip=%s", user_id, body.username, client_ip)

    _fire_policy_eval(user_id)

    return await _issue_session_or_mfa_challenge(
        db, response, user_id, body.provider_id, body.is_public_device
    )


# ---------------------------------------------------------------------------
# OIDC begin
# ---------------------------------------------------------------------------

@router.get("/oidc/{provider_id}/begin", responses={404: {"description": "Not Found"}, 500: {"description": "Internal Server Error"}})
async def oidc_begin(
    provider_id: str,
    request: Request,
    db: Annotated[Database, Depends(get_db)],
    redirect_to: str | None = None,
):
    """Begin an OIDC authorization flow.

    Returns {"redirect_url": "..."} — the frontend should redirect the browser
    to this URL so the IdP can authenticate the user.

    redirect_to (optional) is an app-internal path to send the user after
    successful authentication (stored server-side in oidc_states; never
    forwarded to the IdP).
    """
    try:
        validate_uuid(provider_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Provider not found")

    cursor = await db.execute(
        "SELECT id, config_enc FROM identity_providers "
        "WHERE id = ? AND provider_type = 'oidc' AND is_active = 1",
        (provider_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="OIDC provider not found or inactive")

    # Sanitise redirect_to: must be a relative path, not an external URL
    safe_redirect = None
    if redirect_to:
        if redirect_to.startswith("/") and not redirect_to.startswith("//"):
            safe_redirect = redirect_to[:512]

    try:
        redirect_url = await begin_oidc_flow(db, provider_id, row["config_enc"], safe_redirect)
    except Exception as exc:
        logger.error("OIDC begin error for provider=%s: %s", provider_id, exc)
        raise HTTPException(status_code=500, detail="Failed to build OIDC authorization URL")

    return {"redirect_url": redirect_url}


# ---------------------------------------------------------------------------
# OIDC callback
# ---------------------------------------------------------------------------

@router.get("/oidc/callback")
async def oidc_callback(
    db: Annotated[Database, Depends(get_db)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    request: Request = None,
    response: Response = None,
):
    """Handle the IdP redirect after user authentication.

    On success: sets session cookies and redirects to redirect_to (from the
    state nonce row) or to '/'.
    On failure: redirects to '/?oidc_error=1'.
    """
    client_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:512] if request else ""

    if error:
        logger.warning("OIDC callback error: %s — %s", error, error_description)
        await log_security_event(db, "oidc_login_failed", None, client_ip, user_agent,
                                 f"IdP error: {error}")
        return RedirectResponse(url=_OIDC_ERROR_URL, status_code=302)

    if not code or not state:
        return RedirectResponse(url=_OIDC_ERROR_URL, status_code=302)

    # Validate state length to prevent abuse
    if len(state) > 128:
        return RedirectResponse(url=_OIDC_ERROR_URL, status_code=302)

    # Look up state to find provider — we need this before consuming it
    cursor = await db.execute(
        "SELECT provider_id, redirect_to FROM oidc_states "
        "WHERE id = ? AND expires_at > ?",
        (state, int(time.time())),
    )
    state_row = await cursor.fetchone()
    if state_row is None:
        logger.warning("OIDC callback: unknown/expired state")
        await log_security_event(db, "oidc_login_failed", None, client_ip, user_agent,
                                 "unknown or expired state nonce")
        return RedirectResponse(url=_OIDC_ERROR_URL, status_code=302)

    provider_id = state_row["provider_id"]
    redirect_to = state_row["redirect_to"] or "/"

    cursor = await db.execute(
        "SELECT id, config_enc FROM identity_providers "
        "WHERE id = ? AND provider_type = 'oidc' AND is_active = 1",
        (provider_id,),
    )
    prov_row = await cursor.fetchone()
    if prov_row is None:
        logger.warning("OIDC callback: provider %s not found or inactive", provider_id)
        return RedirectResponse(url=_OIDC_ERROR_URL, status_code=302)

    try:
        identity = await handle_oidc_callback(
            db, provider_id, prov_row["config_enc"], code, state
        )
    except Exception as exc:
        logger.error("OIDC callback exchange error provider=%s: %s", provider_id, exc)
        await log_security_event(db, "oidc_login_failed", None, client_ip, user_agent,
                                 f"token exchange error provider={provider_id}")
        return RedirectResponse(url=_OIDC_ERROR_URL, status_code=302)

    if identity is None:
        return RedirectResponse(url=_OIDC_ERROR_URL, status_code=302)

    claims_json = json.dumps(identity["claims"], default=str)

    user_id = await _ensure_idp_user(
        db,
        provider_id=provider_id,
        provider_type="oidc",
        external_id=identity["sub"],
        display_username=identity["username_attr"],
        claims_json=claims_json,
        refresh_token=identity.get("refresh_token"),
    )

    logger.info("OIDC login: user_id=%s provider=%s sub=%s ip=%s",
                user_id, provider_id, identity["sub"], client_ip)
    await log_security_event(db, "oidc_login_success", user_id, client_ip, user_agent,
                             provider_id)

    _fire_policy_eval(user_id)

    # Use a Response object so we can set cookies and then redirect
    redir_response = RedirectResponse(url=redirect_to, status_code=302)

    # Issue session or MFA challenge.  For OIDC the response is a redirect,
    # so we build a temporary Response, copy the cookies, then redirect.
    temp_response = Response()
    result = await _issue_session_or_mfa_challenge(
        db, temp_response, user_id, provider_id, False
    )

    if result.get("mfa_required"):
        # Store pending_token server-side; redirect with an opaque challenge_id only.
        # This prevents the token from appearing in nginx access logs or browser history.
        challenge_id = _oidc_mfa_challenges.put(result["pending_token"])
        mfa_url = "/?mfa_challenge=" + challenge_id
        return RedirectResponse(url=mfa_url, status_code=302)

    # Copy session cookies from temp_response to the redirect response
    for header_name, header_value in temp_response.headers.items():
        if header_name.lower() == "set-cookie":
            redir_response.headers.append(header_name, header_value)

    return redir_response
