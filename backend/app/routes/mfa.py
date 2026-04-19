"""MFA routes — TOTP enrollment/verify, WebAuthn reg/auth, recovery, credential management.

All routes that require an existing authenticated session use get_current_user directly,
not require_user_role, so that enrollment endpoints remain reachable even when
mfa_enforcement=required and the user has no credentials yet (avoiding a deadlock).
Routes that operate on a pending_token (post-login MFA challenge) are unauthenticated
by design — the pending_token itself is the bearer credential.

Route map
─────────
POST /auth/totp/enroll/start                   begin TOTP enrollment (authenticated)
POST /auth/totp/enroll/finish                  confirm TOTP code and activate credential
POST /auth/totp/verify                         verify TOTP code using a pending_token

POST /auth/webauthn/register/begin             begin WebAuthn registration (authenticated)
POST /auth/webauthn/register/finish            complete WebAuthn registration
POST /auth/webauthn/authenticate/begin         begin WebAuthn login challenge (pending_token)
POST /auth/webauthn/authenticate/finish        complete WebAuthn authentication

POST /auth/mfa/verify-recovery                 verify a recovery code using a pending_token
POST /auth/mfa/unlock/webauthn/begin           WebAuthn session-unlock begin (authenticated)
POST /auth/mfa/unlock/webauthn/finish          WebAuthn session-unlock finish
GET  /auth/mfa/credentials                     list own MFA credentials
DELETE /auth/mfa/credentials/{id}              remove own credential (with proof)
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, field_validator

from app.auth.dependencies import get_current_user
from app.auth.interface import AuthenticatedUser
from app.auth.jwt import create_access_token, create_refresh_token, generate_csrf_token, store_refresh_token
from app.auth.mfa import (
    consume_pending_token,
    encrypt_credential,
    list_active_credentials,
    get_active_methods,
    store_pending_token,
)
from app.auth.totp import enroll_start, enroll_finish, verify_totp, verify_recovery_code
from app.auth.webauthn_helper import (
    begin_authentication,
    begin_registration,
    finish_authentication,
    finish_registration,
)
from app.auth.stepup import log_security_event
from app.conf.auth import COOKIE_ACCESS, COOKIE_CSRF, COOKIE_REFRESH, REFRESH_TOKEN_COOKIE_PATH
from app.config import settings
from app.database import get_db
from app.middleware.rate_limit import _get_client_ip
from app.validation.sanitizers import validate_uuid

logger = logging.getLogger(__name__)
router = APIRouter()

# Re-use cookie helpers from auth.py to avoid duplication
from app.routes.auth import _set_auth_cookies, _clear_auth_cookies


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def _check_pending_token(v: str) -> str:
    if not v or len(v) > 1024:
        raise ValueError("Invalid pending_token")
    return v


def _check_name(v: str) -> str:
    v = v.strip()
    if not v or len(v) > 128:
        raise ValueError("name must be 1–128 characters")
    return v


# ---------------------------------------------------------------------------
# TOTP enrollment
# ---------------------------------------------------------------------------

class TotpEnrollStartResponse(BaseModel):
    totp_uri: str
    secret_b32: str
    cred_id: str


@router.post("/totp/enroll/start")
async def totp_enroll_start(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Begin TOTP enrollment: generate secret, store inactive credential, return QR URI."""
    totp_uri, secret_b32, cred_id = await enroll_start(
        db, user.id, issuer=settings.WEBAUTHN_RP_NAME
    )
    return {"totp_uri": totp_uri, "secret_b32": secret_b32, "cred_id": cred_id}


class TotpEnrollFinishRequest(BaseModel):
    cred_id: str
    totp_code: str
    name: str

    @field_validator("cred_id")
    @classmethod
    def val_cred_id(cls, v: str) -> str:
        try:
            return validate_uuid(v)
        except ValueError:
            raise ValueError("cred_id must be a valid UUID")

    @field_validator("totp_code")
    @classmethod
    def val_code(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("totp_code must be 6 digits")
        return v

    @field_validator("name")
    @classmethod
    def val_name(cls, v: str) -> str:
        return _check_name(v)


@router.post("/totp/enroll/finish")
async def totp_enroll_finish(
    body: TotpEnrollFinishRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Confirm the TOTP code, activate credential, return one-time recovery codes."""
    recovery_codes = await enroll_finish(db, user.id, body.cred_id, body.totp_code, body.name)
    if recovery_codes is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid TOTP code or enrollment session expired. Please start enrollment again.",
        )
    return {"recovery_codes": recovery_codes}


# ---------------------------------------------------------------------------
# TOTP verification (post-login MFA challenge)
# ---------------------------------------------------------------------------

class TotpVerifyRequest(BaseModel):
    pending_token: str
    totp_code: str

    @field_validator("pending_token")
    @classmethod
    def val_pending(cls, v: str) -> str:
        return _check_pending_token(v)

    @field_validator("totp_code")
    @classmethod
    def val_code(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("totp_code must be 6 digits")
        return v


@router.post("/totp/verify")
async def totp_verify(
    body: TotpVerifyRequest,
    response: Response,
    request: Request,
    db=Depends(get_db),
):
    """Verify a TOTP code after OPAQUE login. Issues session cookies on success."""
    result = await consume_pending_token(db, body.pending_token)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    user_id, is_public_device = result

    ok = await verify_totp(db, user_id, body.totp_code)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    await _issue_session(db, response, user_id, is_public_device)

    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    await log_security_event(db, "mfa_totp_verified", user_id, client_ip, ua)
    return {"message": "MFA verified"}


# ---------------------------------------------------------------------------
# WebAuthn registration
# ---------------------------------------------------------------------------

@router.post("/webauthn/register/begin")
async def webauthn_register_begin(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Begin WebAuthn credential registration for an authenticated user."""
    challenge_id, options_dict = await begin_registration(db, user.id)
    return {"challenge_id": challenge_id, "options": options_dict}


class WebAuthnRegisterFinishRequest(BaseModel):
    challenge_id: str
    attestation: dict
    name: str

    @field_validator("challenge_id")
    @classmethod
    def val_cid(cls, v: str) -> str:
        try:
            return validate_uuid(v)
        except ValueError:
            raise ValueError("challenge_id must be a valid UUID")

    @field_validator("name")
    @classmethod
    def val_name(cls, v: str) -> str:
        return _check_name(v)


@router.post("/webauthn/register/finish")
async def webauthn_register_finish(
    body: WebAuthnRegisterFinishRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Complete WebAuthn registration and store the new credential."""
    try:
        cred_id = await finish_registration(
            db, user.id, body.challenge_id, body.attestation, body.name
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"credential_id": cred_id}


# ---------------------------------------------------------------------------
# WebAuthn authentication (post-login MFA challenge)
# ---------------------------------------------------------------------------

class WebAuthnAuthBeginRequest(BaseModel):
    pending_token: str

    @field_validator("pending_token")
    @classmethod
    def val_pending(cls, v: str) -> str:
        return _check_pending_token(v)


@router.post("/webauthn/authenticate/begin")
async def webauthn_authenticate_begin(
    body: WebAuthnAuthBeginRequest,
    db=Depends(get_db),
):
    """Begin a WebAuthn authentication challenge for a pending-token login."""
    from app.auth.mfa import _decode_pending_token
    payload = _decode_pending_token(body.pending_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid MFA token")

    challenge_id, options_dict = await begin_authentication(db, user_id, "authentication")
    return {"challenge_id": challenge_id, "options": options_dict}


class WebAuthnAuthFinishRequest(BaseModel):
    pending_token: str
    challenge_id: str
    assertion: dict

    @field_validator("pending_token")
    @classmethod
    def val_pending(cls, v: str) -> str:
        return _check_pending_token(v)

    @field_validator("challenge_id")
    @classmethod
    def val_cid(cls, v: str) -> str:
        try:
            return validate_uuid(v)
        except ValueError:
            raise ValueError("challenge_id must be a valid UUID")


@router.post("/webauthn/authenticate/finish")
async def webauthn_authenticate_finish(
    body: WebAuthnAuthFinishRequest,
    response: Response,
    request: Request,
    db=Depends(get_db),
):
    """Verify a WebAuthn assertion and issue session cookies."""
    result = await consume_pending_token(db, body.pending_token)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    user_id, is_public_device = result

    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")

    async def _emit(event_type, detail):
        await log_security_event(db, event_type, user_id, client_ip, ua, detail=detail)

    ok = await finish_authentication(
        db, user_id, body.challenge_id, body.assertion, "authentication",
        emit_security_event=_emit,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="WebAuthn verification failed")

    await _issue_session(db, response, user_id, is_public_device)
    await log_security_event(db, "mfa_webauthn_verified", user_id, client_ip, ua)
    return {"message": "MFA verified"}


# ---------------------------------------------------------------------------
# Recovery code verification (post-login)
# ---------------------------------------------------------------------------

class RecoveryVerifyRequest(BaseModel):
    pending_token: str
    recovery_code: str

    @field_validator("pending_token")
    @classmethod
    def val_pending(cls, v: str) -> str:
        return _check_pending_token(v)

    @field_validator("recovery_code")
    @classmethod
    def val_code(cls, v: str) -> str:
        v = v.strip().upper()
        if not v or len(v) > 64:
            raise ValueError("Invalid recovery code")
        return v


@router.post("/mfa/verify-recovery")
async def verify_recovery(
    body: RecoveryVerifyRequest,
    response: Response,
    request: Request,
    db=Depends(get_db),
):
    """Verify a recovery code after OPAQUE login. Issues session cookies on success."""
    result = await consume_pending_token(db, body.pending_token)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    user_id, is_public_device = result

    ok = await verify_recovery_code(db, user_id, body.recovery_code)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid recovery code")

    await _issue_session(db, response, user_id, is_public_device)

    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    await log_security_event(db, "mfa_recovery_code_used", user_id, client_ip, ua)
    return {"message": "Recovery code accepted"}


# ---------------------------------------------------------------------------
# Session unlock via WebAuthn (tab still open, grace period expired)
# ---------------------------------------------------------------------------

@router.post("/mfa/unlock/webauthn/begin")
async def unlock_webauthn_begin(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Begin a WebAuthn challenge for session unlock (grace period re-auth)."""
    methods = await get_active_methods(db, user.id)
    if "webauthn" not in methods:
        raise HTTPException(status_code=400, detail="No WebAuthn credentials enrolled")

    challenge_id, options_dict = await begin_authentication(db, user.id, "unlock")
    return {"challenge_id": challenge_id, "options": options_dict}


class UnlockWebAuthnFinishRequest(BaseModel):
    challenge_id: str
    assertion: dict

    @field_validator("challenge_id")
    @classmethod
    def val_cid(cls, v: str) -> str:
        try:
            return validate_uuid(v)
        except ValueError:
            raise ValueError("challenge_id must be a valid UUID")


@router.post("/mfa/unlock/webauthn/finish")
async def unlock_webauthn_finish(
    body: UnlockWebAuthnFinishRequest,
    request: Request,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Verify WebAuthn assertion for session unlock. Returns {unlocked: true} on success."""
    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")

    async def _emit(event_type, detail):
        await log_security_event(db, event_type, user.id, client_ip, ua, detail=detail)

    ok = await finish_authentication(
        db, user.id, body.challenge_id, body.assertion, "unlock",
        emit_security_event=_emit,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="WebAuthn verification failed")

    await log_security_event(db, "session_unlock_webauthn", user.id, client_ip, ua)
    return {"unlocked": True}


# ---------------------------------------------------------------------------
# Credential management (self-service)
# ---------------------------------------------------------------------------

@router.get("/mfa/credentials")
async def list_credentials(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """List the current user's active MFA credentials (no secrets)."""
    credentials = await list_active_credentials(db, user.id)
    return {"credentials": credentials}


@router.delete("/mfa/credentials/{cred_id}")
async def delete_credential(
    cred_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Remove an MFA credential (self-service).

    The user must retain at least one other active non-recovery credential unless
    mfa_enforcement is 'off' or 'optional'.  The last credential cannot be removed
    when enforcement is 'required' and no other satisfying credential exists.
    """
    try:
        cred_id = validate_uuid(cred_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid credential ID")

    cursor = await db.execute(
        "SELECT id, method FROM user_mfa_credentials "
        "WHERE id = ? AND user_id = ? AND is_active = 1",
        (cred_id, user.id),
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Credential not found")

    from app.auth.mfa import load_mfa_settings
    mfa_settings = await load_mfa_settings(db)
    enforcement = mfa_settings["mfa_enforcement"]

    if enforcement == "required" and row["method"] != "recovery":
        # Check remaining credentials after removal
        cursor = await db.execute(
            "SELECT COUNT(*) FROM user_mfa_credentials "
            "WHERE user_id = ? AND is_active = 1 AND method != 'recovery' AND id != ?",
            (user.id, cred_id),
        )
        count = (await cursor.fetchone())[0]
        if count == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot remove the last MFA credential while enforcement is 'required'.",
            )

    await db.execute(
        "UPDATE user_mfa_credentials SET is_active = 0 WHERE id = ?", (cred_id,)
    )
    await db.commit()

    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    await log_security_event(
        db, "mfa_credential_removed", user.id, client_ip, ua,
        detail={"credential_id": cred_id, "method": row["method"]},
    )
    return {"message": "Credential removed"}


# ---------------------------------------------------------------------------
# MFA status (for frontend gating / banner)
# ---------------------------------------------------------------------------

@router.get("/mfa/status")
async def mfa_status(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Return MFA enrollment status and enforcement policy for the current user."""
    from app.auth.mfa import load_mfa_settings
    credentials = await list_active_credentials(db, user.id)
    mfa_settings = await load_mfa_settings(db)

    cursor = await db.execute(
        "SELECT mfa_reset_required, mfa_banner_dismissed FROM users WHERE id = ?",
        (user.id,),
    )
    row = await cursor.fetchone()
    reset_required = bool(row["mfa_reset_required"]) if row else False
    banner_dismissed = bool(row["mfa_banner_dismissed"]) if row else False

    return {
        "enforcement": mfa_settings["mfa_enforcement"],
        "allowed_methods": mfa_settings["mfa_allowed_methods"],
        "oidc_exempt": mfa_settings["mfa_oidc_exempt"],
        "credentials": credentials,
        "active_count": len(credentials),
        "reset_required": reset_required,
        "banner_dismissed": banner_dismissed,
    }


@router.post("/mfa/banner/dismiss")
async def dismiss_mfa_banner(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Dismiss the MFA enrollment nudge banner (optional-mode only)."""
    await db.execute(
        "UPDATE users SET mfa_banner_dismissed = 1 WHERE id = ?", (user.id,)
    )
    await db.commit()
    return {"message": "Banner dismissed"}


# ---------------------------------------------------------------------------
# Pending token info (used by OIDC callback to render correct MFA challenge)
# ---------------------------------------------------------------------------

class PendingInfoRequest(BaseModel):
    pending_token: str


@router.post("/mfa/pending-info")
async def mfa_pending_info(
    body: PendingInfoRequest,
    db=Depends(get_db),
):
    """Return the MFA methods available for a pending_token without consuming it.

    Used by the OIDC callback flow: after the server redirects to /?mfa_pending=...,
    the client calls this endpoint to learn which methods (totp, webauthn) the user
    has enrolled so the correct challenge UI can be rendered.

    Rate-limited by the same token decode/validation; the token is NOT consumed.
    Returns {"methods": [...]} or 400 if the token is invalid/expired.
    """
    from app.auth.mfa import _decode_pending_token, get_active_methods
    import time

    payload = _decode_pending_token(body.pending_token)
    if payload is None:
        raise HTTPException(status_code=400, detail="Invalid or expired pending token")

    user_id = payload.get("sub")
    jti = payload.get("jti")
    if not user_id or not jti:
        raise HTTPException(status_code=400, detail="Invalid pending token")

    # Verify the jti row still exists (token not yet consumed)
    cursor = await db.execute(
        "SELECT 1 FROM mfa_pending_tokens WHERE jti = ? AND user_id = ? AND expires_at > ?",
        (jti, user_id, int(time.time())),
    )
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=400, detail="Invalid or expired pending token")

    methods = await get_active_methods(db, user_id)
    return {"methods": sorted(methods)}


# ---------------------------------------------------------------------------
# Shared: issue session cookies after successful MFA
# ---------------------------------------------------------------------------

async def _issue_session(db, response: Response, user_id: str, is_public_device: bool) -> None:
    """Store a refresh token and set session cookies for a post-MFA login."""
    from app.auth.opaque_provider import OPAQUEAuthProvider
    provider = OPAQUEAuthProvider(db)
    user = await provider.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    from datetime import timedelta
    if is_public_device:
        rt_expire_minutes = settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES
        rt_max_age = rt_expire_minutes * 60
    else:
        rt_expire_minutes = None
        rt_max_age = None

    raw_refresh, rt_hash = create_refresh_token()
    token_id = await store_refresh_token(
        db, user.id, rt_hash,
        expire_minutes=rt_expire_minutes,
        is_public_device=is_public_device,
    )
    access_token = create_access_token(user.id, session_id=token_id, is_public_device=is_public_device)
    csrf_token = generate_csrf_token()
    _set_auth_cookies(response, access_token, raw_refresh, csrf_token, max_age=rt_max_age)
