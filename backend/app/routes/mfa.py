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

import base64
import io
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, field_validator

from app.auth.cookies import set_auth_cookies
from app.auth.dependencies import get_current_user
from app.auth.interface import AuthenticatedUser
from app.auth.jwt import create_access_token, create_refresh_token, generate_csrf_token, store_refresh_token
from app.auth.mfa import (
    consume_pending_token,
    decrypt_credential,
    get_active_methods,
    list_active_credentials,
    peek_pending_token,
)
from app.auth.stepup import log_security_event
from app.auth.totp import enroll_finish, enroll_start, verify_recovery_code, verify_totp
from app.auth.webauthn_helper import (
    begin_authentication,
    begin_prf_enroll,
    begin_registration,
    finish_authentication,
    finish_registration,
    get_challenge_prf_salt,
)
from app.config import settings
from app.database import Database, get_db
from app.middleware.rate_limit import _get_client_ip
from app.services import live_settings
from app.validation.sanitizers import validate_uuid

logger = logging.getLogger(__name__)
router = APIRouter()


def _make_qr_data_url(data: str) -> str:
    """Return an SVG QR code for *data* as a base64 data URL (no external dependency)."""
    import qrcode
    import qrcode.image.svg as _svg

    img = qrcode.make(data, image_factory=_svg.SvgFillImage)
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


_ERR_INVALID_MFA_TOKEN = "Invalid or expired MFA token"
_ERR_INVALID_CHALLENGE_ID = "challenge_id must be a valid UUID"


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
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Begin TOTP enrollment: generate secret, store inactive credential, return QR URI."""
    totp_uri, secret_b32, cred_id = await enroll_start(
        db, user.id, issuer=live_settings.get("webauthn_rp_name", settings.WEBAUTHN_RP_NAME)
    )
    qr_data_url = _make_qr_data_url(totp_uri)
    return {"totp_uri": totp_uri, "secret_b32": secret_b32, "cred_id": cred_id, "qr_data_url": qr_data_url}


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


@router.post("/totp/enroll/finish", responses={400: {"description": "Bad Request"}})
async def totp_enroll_finish(
    body: TotpEnrollFinishRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Confirm the TOTP code, activate credential, return one-time recovery codes."""
    recovery_codes = await enroll_finish(db, user.id, body.cred_id, body.totp_code, body.name)
    if recovery_codes is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid TOTP code or enrollment session expired. Please start enrollment again.",
        )
    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    await log_security_event(
        db,
        "mfa_credential_enrolled",
        user.id,
        client_ip,
        ua,
        username=user.username,
        detail={"method": "totp"},
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


@router.post("/totp/verify", responses={401: {"description": "Unauthorized"}})
async def totp_verify(
    body: TotpVerifyRequest,
    response: Response,
    request: Request,
    db: Annotated[Database, Depends(get_db)],
):
    """Verify a TOTP code after OPAQUE login. Issues session cookies on success."""
    # Peek first so a wrong code doesn't consume (and destroy) the pending token,
    # which would lock the user out of all retry attempts.
    result = await peek_pending_token(db, body.pending_token)
    if result is None:
        raise HTTPException(status_code=401, detail=_ERR_INVALID_MFA_TOKEN)

    user_id, is_public_device = result

    ok = await verify_totp(db, user_id, body.totp_code)
    if not ok:
        raise HTTPException(status_code=401, detail="This code isn't valid")

    # TOTP accepted — now atomically consume the pending token.
    consumed = await consume_pending_token(db, body.pending_token)
    if consumed is None:
        raise HTTPException(status_code=401, detail=_ERR_INVALID_MFA_TOKEN)

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
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
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
            raise ValueError(_ERR_INVALID_CHALLENGE_ID)

    @field_validator("name")
    @classmethod
    def val_name(cls, v: str) -> str:
        return _check_name(v)


@router.post("/webauthn/register/finish", responses={400: {"description": "Bad Request"}})
async def webauthn_register_finish(
    body: WebAuthnRegisterFinishRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Complete WebAuthn registration and store the new credential."""
    try:
        cred_id = await finish_registration(db, user.id, body.challenge_id, body.attestation, body.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    await log_security_event(
        db,
        "mfa_credential_enrolled",
        user.id,
        client_ip,
        ua,
        username=user.username,
        detail={"method": "webauthn", "credential_id": cred_id},
    )
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


@router.post("/webauthn/authenticate/begin", responses={401: {"description": "Unauthorized"}})
async def webauthn_authenticate_begin(
    body: WebAuthnAuthBeginRequest,
    db: Annotated[Database, Depends(get_db)],
):
    """Begin a WebAuthn authentication challenge for a pending-token login."""
    from app.auth.mfa import _decode_pending_token

    payload = _decode_pending_token(body.pending_token)
    if payload is None:
        raise HTTPException(status_code=401, detail=_ERR_INVALID_MFA_TOKEN)

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
            raise ValueError(_ERR_INVALID_CHALLENGE_ID)


@router.post("/webauthn/authenticate/finish", responses={401: {"description": "Unauthorized"}})
async def webauthn_authenticate_finish(
    body: WebAuthnAuthFinishRequest,
    response: Response,
    request: Request,
    db: Annotated[Database, Depends(get_db)],
):
    """Verify a WebAuthn assertion and issue session cookies."""
    result = await consume_pending_token(db, body.pending_token)
    if result is None:
        raise HTTPException(status_code=401, detail=_ERR_INVALID_MFA_TOKEN)

    user_id, is_public_device = result

    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")

    async def _emit(event_type, detail):
        await log_security_event(db, event_type, user_id, client_ip, ua, detail=detail)

    ok = await finish_authentication(
        db,
        user_id,
        body.challenge_id,
        body.assertion,
        "authentication",
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


@router.post("/mfa/verify-recovery", responses={401: {"description": "Unauthorized"}})
async def verify_recovery(
    body: RecoveryVerifyRequest,
    response: Response,
    request: Request,
    db: Annotated[Database, Depends(get_db)],
):
    """Verify a recovery code after OPAQUE login. Issues session cookies on success."""
    result = await peek_pending_token(db, body.pending_token)
    if result is None:
        raise HTTPException(status_code=401, detail=_ERR_INVALID_MFA_TOKEN)

    user_id, is_public_device = result

    ok = await verify_recovery_code(db, user_id, body.recovery_code)
    if not ok:
        raise HTTPException(status_code=401, detail="This code isn't valid")

    consumed = await consume_pending_token(db, body.pending_token)
    if consumed is None:
        raise HTTPException(status_code=401, detail=_ERR_INVALID_MFA_TOKEN)

    await _issue_session(db, response, user_id, is_public_device)

    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    await log_security_event(db, "mfa_recovery_code_used", user_id, client_ip, ua)
    return {"message": "Recovery code accepted"}


# ---------------------------------------------------------------------------
# Session unlock via WebAuthn (tab still open, grace period expired)
# ---------------------------------------------------------------------------


@router.post("/mfa/unlock/webauthn/begin", responses={400: {"description": "Bad Request"}})
async def unlock_webauthn_begin(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
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
            raise ValueError(_ERR_INVALID_CHALLENGE_ID)


@router.post("/mfa/unlock/webauthn/finish", responses={401: {"description": "Unauthorized"}})
async def unlock_webauthn_finish(
    body: UnlockWebAuthnFinishRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Verify WebAuthn assertion for session unlock. Returns {unlocked: true} on success."""
    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")

    async def _emit(event_type, detail):
        await log_security_event(db, event_type, user.id, client_ip, ua, username=user.username, detail=detail)

    ok = await finish_authentication(
        db,
        user.id,
        body.challenge_id,
        body.assertion,
        "unlock",
        emit_security_event=_emit,
    )
    if not ok:
        raise HTTPException(status_code=401, detail="WebAuthn verification failed")

    await log_security_event(db, "session_unlock_webauthn", user.id, client_ip, ua, username=user.username)
    return {"unlocked": True}


# ---------------------------------------------------------------------------
# Credential management (self-service)
# ---------------------------------------------------------------------------


@router.get("/mfa/credentials")
async def list_credentials(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """List the current user's active MFA credentials (no secrets)."""
    credentials = await list_active_credentials(db, user.id)
    return {"credentials": credentials}


@router.delete(
    "/mfa/credentials/{cred_id}", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}}
)
async def delete_credential(
    cred_id: str,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
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
        "SELECT id, method FROM user_mfa_credentials WHERE id = ? AND user_id = ? AND is_active = 1",
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

    await db.execute("UPDATE user_mfa_credentials SET is_active = 0 WHERE id = ?", (cred_id,))

    # If this WebAuthn credential is the user's PRF binding, clear the binding atomically.
    if row["method"] == "webauthn":
        try:
            payload = decrypt_credential(row["credential"])
            prf_cursor = await db.execute(
                "SELECT prf_credential_id FROM users WHERE id = ?", (user.id,)
            )
            prf_row = await prf_cursor.fetchone()
            if prf_row and prf_row["prf_credential_id"] == payload.get("credential_id"):
                await db.execute(
                    "UPDATE users SET prf_credential_id = NULL, prf_wrapped_master_key = NULL, "
                    "prf_wrapped_master_key_iv = NULL, prf_salt = NULL WHERE id = ?",
                    (user.id,),
                )
        except Exception:
            pass  # Non-critical: PRF binding can be re-enrolled; don't block deletion

    await db.commit()

    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    await log_security_event(
        db,
        "mfa_credential_removed",
        user.id,
        client_ip,
        ua,
        username=user.username,
        detail={"credential_id": cred_id, "method": row["method"]},
    )
    return {"message": "Credential removed"}


# ---------------------------------------------------------------------------
# MFA status (for frontend gating / banner)
# ---------------------------------------------------------------------------


@router.get("/mfa/status")
async def mfa_status(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
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
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Dismiss the MFA enrollment nudge banner (optional-mode only)."""
    await db.execute("UPDATE users SET mfa_banner_dismissed = 1 WHERE id = ?", (user.id,))
    await db.commit()
    return {"message": "Banner dismissed"}


# ---------------------------------------------------------------------------
# Pending token info (used by OIDC callback to render correct MFA challenge)
# ---------------------------------------------------------------------------


class PendingInfoRequest(BaseModel):
    pending_token: str


@router.post("/mfa/pending-info", responses={400: {"description": "Bad Request"}, 401: {"description": "Unauthorized"}})
async def mfa_pending_info(
    body: PendingInfoRequest,
    db: Annotated[Database, Depends(get_db)],
):
    """Return the MFA methods available for a pending_token without consuming it.

    Used by the OIDC callback flow: after the server redirects to /?mfa_pending=...,
    the client calls this endpoint to learn which methods (totp, webauthn) the user
    has enrolled so the correct challenge UI can be rendered.

    Rate-limited by the same token decode/validation; the token is NOT consumed.
    Returns {"methods": [...]} or 400 if the token is invalid/expired.
    """
    import time

    from app.auth.mfa import _decode_pending_token, get_active_methods

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
# WebAuthn PRF key binding enrollment
#
# Three endpoints:
#   POST /auth/prf/enroll/begin   — generate challenge + PRF salt (authenticated)
#   POST /auth/prf/enroll/finish  — verify assertion, store wrapped master key
#   DELETE /auth/prf/enrollment   — remove PRF binding
# ---------------------------------------------------------------------------


@router.post("/prf/enroll/begin", responses={400: {"description": "Bad Request"}})
async def prf_enroll_begin(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Begin WebAuthn PRF key-binding enrollment.

    Returns a WebAuthn authentication challenge (not a registration — PRF uses
    navigator.credentials.get) alongside the per-user PRF salt.  The client
    calls navigator.credentials.get() with extensions.prf.eval.first = prf_salt,
    wraps the current master key with the PRF output, then POSTs to finish.
    """
    methods = await get_active_methods(db, user.id)
    if "webauthn" not in methods:
        raise HTTPException(
            status_code=400,
            detail="No WebAuthn credentials enrolled. Register a security key first.",
        )

    challenge_id, options_dict, prf_salt_b64url = await begin_prf_enroll(db, user.id)
    return {"challenge_id": challenge_id, "options": options_dict, "prf_salt": prf_salt_b64url}


class PrfEnrollFinishRequest(BaseModel):
    challenge_id: str
    assertion: dict
    wrapped_mk_prf: str
    prf_iv: str

    @field_validator("challenge_id")
    @classmethod
    def val_cid(cls, v: str) -> str:
        try:
            return validate_uuid(v)
        except ValueError:
            raise ValueError(_ERR_INVALID_CHALLENGE_ID)

    @field_validator("wrapped_mk_prf", "prf_iv")
    @classmethod
    def val_b64(cls, v: str) -> str:
        from app.validation.sanitizers import validate_base64
        validate_base64(v)
        return v


@router.post("/prf/enroll/finish", responses={400: {"description": "Bad Request"}})
async def prf_enroll_finish(
    body: PrfEnrollFinishRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Complete PRF key-binding enrollment and store the wrapped master key.

    The server verifies the WebAuthn assertion to confirm authenticator possession,
    then stores the client-wrapped master key and the credential ID used for PRF.
    The PRF output itself never reaches the server — only the AES-GCM ciphertext.
    """
    # Read the PRF salt from the challenge before finish_authentication consumes it.
    prf_salt_b64url = await get_challenge_prf_salt(db, body.challenge_id, user.id)
    if prf_salt_b64url is None:
        raise HTTPException(status_code=400, detail="Challenge not found or expired")

    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")

    async def _emit(event_type, detail):
        await log_security_event(db, event_type, user.id, client_ip, ua, detail=detail)

    ok = await finish_authentication(
        db, user.id, body.challenge_id, body.assertion, "prf",
        emit_security_event=_emit,
    )
    if not ok:
        raise HTTPException(status_code=400, detail="WebAuthn verification failed")

    credential_id = body.assertion.get("rawId") or body.assertion.get("id", "")
    if not credential_id:
        raise HTTPException(status_code=400, detail="Missing credential ID in assertion")

    await db.execute(
        "UPDATE users SET prf_credential_id = ?, prf_wrapped_master_key = ?, "
        "prf_wrapped_master_key_iv = ?, prf_salt = ? WHERE id = ?",
        (credential_id, body.wrapped_mk_prf, body.prf_iv, prf_salt_b64url, user.id),
    )
    await db.commit()

    await log_security_event(
        db, "prf_enrollment_complete", user.id, client_ip, ua,
        username=user.username,
        detail={"credential_id": credential_id},
    )
    return {"message": "PRF key binding enrolled successfully"}


@router.delete("/prf/enrollment", responses={200: {"description": "OK"}})
async def prf_enrollment_delete(
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Remove the WebAuthn PRF key binding for the current user.

    After this call the login flow falls back to the OPAQUE KEK path and the
    key grace period (sessionStorage) is re-enabled.
    """
    await db.execute(
        "UPDATE users SET prf_credential_id = NULL, prf_wrapped_master_key = NULL, "
        "prf_wrapped_master_key_iv = NULL, prf_salt = NULL WHERE id = ?",
        (user.id,),
    )
    await db.commit()

    client_ip = _get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    await log_security_event(
        db, "prf_enrollment_removed", user.id, client_ip, ua, username=user.username,
    )
    return {"message": "PRF key binding removed"}


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

    if is_public_device:
        rt_expire_minutes = live_settings.get_int(
            "public_device_refresh_minutes", settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES
        )
        rt_max_age = rt_expire_minutes * 60
    else:
        rt_expire_minutes = None
        rt_max_age = None

    raw_refresh, rt_hash = create_refresh_token()
    token_id = await store_refresh_token(
        db,
        user.id,
        rt_hash,
        expire_minutes=rt_expire_minutes,
        is_public_device=is_public_device,
    )
    access_token = create_access_token(user.id, session_id=token_id, is_public_device=is_public_device)
    csrf_token = generate_csrf_token()
    set_auth_cookies(response, access_token, raw_refresh, csrf_token, max_age=rt_max_age)
