"""OPAQUE aPAKE authentication routes.

Implements the two-round-trip registration and login flows for OPAQUE users,
plus a step-up start endpoint that initiates an OPAQUE challenge for an already-
authenticated user.

All crypto runs in the `tusshare_opaque` PyO3 module via `asyncio.to_thread` to
avoid blocking the event loop.

Endpoints:
  POST /auth/opaque/register/start   — registration round 1
  POST /auth/opaque/register/finish  — registration round 2 (consumes invite)
  POST /auth/opaque/login/start      — login round 1
  POST /auth/opaque/login/finish     — login round 2
  POST /auth/opaque/step-up/start    — initiate OPAQUE step-up challenge
  POST /auth/opaque/recover/start    — password recovery round 1
  POST /auth/opaque/recover/finish   — password recovery round 2
"""

import asyncio
import base64
import hashlib
import hmac as _hmac
import logging
import secrets
import uuid
from datetime import datetime, timezone

import tusshare_opaque
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, field_validator

import app.sensitive_config as sensitive_config
from app.auth.stepup import log_security_event, verify_step_up_token
from app.auth.dependencies import get_current_user, require_user_role
from app.middleware.rate_limit import _counter, _get_client_ip
from app.auth.interface import AuthenticatedUser
from app.auth.jwt import create_access_token, create_refresh_token, generate_csrf_token, store_refresh_token
from app.auth.opaque_provider import OPAQUEAuthProvider
from app.conf.auth import COOKIE_ACCESS, COOKIE_CSRF, COOKIE_REFRESH, REFRESH_TOKEN_COOKIE_PATH
from app.config import settings
from app.database import DuplicateError, get_db
from app.models.role import ROLE_USER, grant_role
from app.validation.sanitizers import sanitize_username, validate_base64, validate_uuid

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Shared helpers (mirrors auth.py — kept local to avoid circular imports)
# ---------------------------------------------------------------------------

def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: str,
    refresh_max_age: int | None = None,
) -> None:
    rt_max_age = refresh_max_age if refresh_max_age is not None else settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    response.set_cookie(
        key=COOKIE_ACCESS, value=access_token,
        httponly=True, secure=True, samesite="strict", path="/",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key=COOKIE_REFRESH, value=refresh_token,
        httponly=True, secure=True, samesite="strict",
        path=REFRESH_TOKEN_COOKIE_PATH,
        max_age=rt_max_age,
    )
    response.set_cookie(
        key=COOKIE_CSRF, value=csrf_token,
        httponly=False, secure=True, samesite="strict", path="/",
        max_age=rt_max_age,
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(key=COOKIE_ACCESS, path="/", secure=True, samesite="strict")
    response.delete_cookie(key=COOKIE_REFRESH, path=REFRESH_TOKEN_COOKIE_PATH, secure=True, samesite="strict")
    response.delete_cookie(key=COOKIE_CSRF, path="/", secure=True, samesite="strict")


def _user_response_dict(user: AuthenticatedUser) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "auth_method": user.auth_method,
        "is_admin": user.is_admin,
        "is_admin_only": user.is_admin_only,
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
    }


def _decode_b64_field(value: str, field_name: str) -> bytes:
    """Decode a client-supplied OPAQUE field to bytes.

    @serenity-kit/opaque v1.1.0 uses base64url (- and _, no = padding) in both
    directions.  urlsafe_b64decode handles both - / _ and standard + / /; adding
    padding covers unpadded strings.  atob() must NOT be used on these values —
    it is standard-base64 only and rejects - and _.
    """
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded)
    except Exception:
        raise HTTPException(status_code=422, detail=f"{field_name}: invalid base64")


# ---------------------------------------------------------------------------
# Size bounds for OPAQUE protocol fields
# ---------------------------------------------------------------------------
# opaque-ke Ristretto255/TripleDH/SHA-512 protocol message sizes (raw bytes)
# are fixed and small. We bound at 2× theoretical max to absorb future library
# changes while still rejecting clearly oversized payloads.
_OPAQUE_REG_REQUEST_B64_MAX  = 128   # RegistrationRequest  ~32 bytes  → 44 b64
_OPAQUE_REG_RECORD_B64_MAX   = 512   # RegistrationUpload   ~256 bytes → 344 b64
_OPAQUE_LOGIN_START_B64_MAX  = 128   # CredentialRequest    ~32 bytes  → 44 b64
_OPAQUE_LOGIN_FINISH_B64_MAX = 512   # CredentialFinalization ~256 bytes → 344 b64
_WRAPPED_KEY_B64_MAX         = 128   # AES-256-GCM ciphertext ~48 bytes → 64 b64
_IV_B64_MAX                  = 64    # 12–24-byte IVs → 32 b64
_X25519_PUB_B64_MAX          = 60    # 32 bytes → 44 b64
_MLKEM_PUB_B64_MAX           = 1700  # 1184 bytes → ~1580 b64
_X25519_PRIV_WRAPPED_B64_MAX = 80    # wrapped 48-byte key → 64 b64
_MLKEM_PRIV_WRAPPED_B64_MAX  = 3400  # wrapped ~2416-byte key → ~3224 b64


# ---------------------------------------------------------------------------
# Registration models
# ---------------------------------------------------------------------------

class OpaqueRegisterStartRequest(BaseModel):
    token: str                         # invite token — validated (not consumed) at start
    username: str
    client_registration_request: str   # base64 RegistrationRequest bytes

    @field_validator("token")
    @classmethod
    def val_token(cls, v: str) -> str:
        if not v or len(v) > 200:
            raise ValueError("Invalid token")
        return v

    @field_validator("username")
    @classmethod
    def val_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("client_registration_request")
    @classmethod
    def val_reg_request(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_REG_REQUEST_B64_MAX)
        return v


class OpaqueRegisterFinishRequest(BaseModel):
    token: str                          # invite token — consumed atomically here
    username: str
    client_registration_record: str     # base64 RegistrationUpload bytes from client
    wrapped_master_key: str
    wrapped_master_key_iv: str
    recovery_key_wrapped: str | None = None
    recovery_key_iv: str | None = None
    recovery_key_hash: str | None = None
    x25519_public_key: str | None = None
    mlkem768_public_key: str | None = None
    x25519_private_wrapped: str | None = None
    mlkem768_private_wrapped: str | None = None
    asymmetric_key_iv: str | None = None

    @field_validator("token")
    @classmethod
    def val_token(cls, v: str) -> str:
        if not v or len(v) > 200:
            raise ValueError("Invalid token")
        return v

    @field_validator("username")
    @classmethod
    def val_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("client_registration_record")
    @classmethod
    def val_reg_record(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_REG_RECORD_B64_MAX)
        return v

    @field_validator("wrapped_master_key", "wrapped_master_key_iv")
    @classmethod
    def val_required_key_fields(cls, v: str) -> str:
        validate_base64(v, max_length=_WRAPPED_KEY_B64_MAX)
        return v

    @field_validator("recovery_key_wrapped")
    @classmethod
    def val_recovery_key_wrapped(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_WRAPPED_KEY_B64_MAX)
        return v

    @field_validator("recovery_key_iv", "asymmetric_key_iv")
    @classmethod
    def val_iv_fields(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_IV_B64_MAX)
        return v

    @field_validator("x25519_public_key")
    @classmethod
    def val_x25519_pub(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_X25519_PUB_B64_MAX)
        return v

    @field_validator("mlkem768_public_key")
    @classmethod
    def val_mlkem_pub(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_MLKEM_PUB_B64_MAX)
        return v

    @field_validator("x25519_private_wrapped")
    @classmethod
    def val_x25519_priv(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_X25519_PRIV_WRAPPED_B64_MAX)
        return v

    @field_validator("mlkem768_private_wrapped")
    @classmethod
    def val_mlkem_priv(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_MLKEM_PRIV_WRAPPED_B64_MAX)
        return v

    @field_validator("recovery_key_hash")
    @classmethod
    def val_recovery_hash(cls, v: str | None) -> str | None:
        if v is not None and (not v or len(v) > 128 or not all(c in "0123456789abcdef" for c in v)):
            raise ValueError("Invalid recovery_key_hash (expected hex)")
        return v


# ---------------------------------------------------------------------------
# Login models
# ---------------------------------------------------------------------------

class OpaqueLoginStartRequest(BaseModel):
    username: str
    client_login_start: str    # base64 CredentialRequest bytes

    @field_validator("username")
    @classmethod
    def val_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("client_login_start")
    @classmethod
    def val_login_start(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_LOGIN_START_B64_MAX)
        return v


class OpaqueLoginFinishRequest(BaseModel):
    username: str
    session_id: str
    client_login_finish: str   # base64 CredentialFinalization bytes
    is_public_device: bool = False

    @field_validator("username")
    @classmethod
    def val_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("session_id")
    @classmethod
    def val_session_id(cls, v: str) -> str:
        try:
            return validate_uuid(v)
        except ValueError:
            raise ValueError("session_id must be a valid UUID")

    @field_validator("client_login_finish")
    @classmethod
    def val_login_finish(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_LOGIN_FINISH_B64_MAX)
        return v


# ---------------------------------------------------------------------------
# Step-up model
# ---------------------------------------------------------------------------

class OpaqueStepUpStartRequest(BaseModel):
    action_key: str
    payload_hash: str         # SHA-256 hex of the request body the client will send
    timestamp: int            # unix seconds
    client_step_up_start: str  # base64 CredentialRequest bytes (same as login start)

    @field_validator("action_key")
    @classmethod
    def val_action_key(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("action_key must be 1–128 characters")
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._*")
        if not all(c in allowed for c in v):
            raise ValueError("action_key contains invalid characters")
        return v

    @field_validator("payload_hash")
    @classmethod
    def val_payload_hash(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("payload_hash must be a 64-char hex string (SHA-256)")
        return v

    @field_validator("timestamp")
    @classmethod
    def val_timestamp(cls, v: int) -> int:
        import time
        if abs(int(time.time()) - v) > 600:
            raise ValueError("timestamp is too far from server time")
        return v

    @field_validator("client_step_up_start")
    @classmethod
    def val_step_up_start(cls, v: str) -> str:
        validate_base64(v)
        return v


# ---------------------------------------------------------------------------
# Registration routes
# ---------------------------------------------------------------------------

@router.post("/register/start")
async def opaque_register_start(
    body: OpaqueRegisterStartRequest,
    db=Depends(get_db),
):
    """OPAQUE registration round 1.

    Validates the invite token (without consuming it) and returns the
    RegistrationResponse for the client to complete its local registration.
    The invite is consumed in /register/finish.
    """
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    cursor = await db.execute(
        "SELECT id FROM invites WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        (token_hash, now),
    )
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=400, detail="Invalid, expired, or already-used invite")

    reg_request_bytes = _decode_b64_field(body.client_registration_request, "client_registration_request")
    setup_bytes = sensitive_config.get_opaque_server_setup()
    username_bytes = body.username.encode("utf-8")

    try:
        reg_response_bytes = await asyncio.to_thread(
            tusshare_opaque.server_start_registration,
            setup_bytes, reg_request_bytes, username_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE register/start failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid registration request")

    return {"registration_response": base64.urlsafe_b64encode(reg_response_bytes).decode().rstrip("=")}


@router.post("/register/finish")
async def opaque_register_finish(
    body: OpaqueRegisterFinishRequest,
    request: Request,
    response: Response,
    db=Depends(get_db),
):
    """OPAQUE registration round 2.

    Finalises the OPAQUE registration record, then atomically consumes the
    invite and creates the user account in a single transaction — so the
    invite is never burned on a user-creation failure.  Sets auth cookies
    so the client is immediately logged in.
    """
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Finalise OPAQUE registration to get the server-side record blob.
    # Pure computation — done before the transaction so DB time is minimised.
    reg_upload_bytes = _decode_b64_field(body.client_registration_record, "client_registration_record")

    try:
        reg_record_bytes = await asyncio.to_thread(
            tusshare_opaque.server_finish_registration,
            reg_upload_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE register/finish failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid registration upload")

    # Atomically consume invite + create user in a single transaction.
    # Rolling back here also reverts the invite consumption, so a failed
    # user creation (e.g. duplicate username) does NOT burn the invite.
    user_id = str(uuid.uuid4())
    await db.execute("BEGIN")
    try:
        cursor = await db.execute(
            "SELECT id FROM invites WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
            (token_hash, now),
        )
        invite_row = await cursor.fetchone()
        if invite_row is None:
            await db.rollback()
            raise HTTPException(status_code=400, detail="Invalid, expired, or already-used invite")

        await db.execute(
            "INSERT INTO users ("
            "  id, username, auth_method, opaque_registration_record, is_admin, "
            "  wrapped_master_key, wrapped_master_key_iv, "
            "  recovery_key_wrapped, recovery_key_iv, recovery_key_hash, "
            "  x25519_public_key, mlkem768_public_key, "
            "  x25519_private_wrapped, mlkem768_private_wrapped, asymmetric_key_iv"
            ") VALUES (?, ?, 'opaque', ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user_id, body.username, reg_record_bytes,
                body.wrapped_master_key, body.wrapped_master_key_iv,
                body.recovery_key_wrapped, body.recovery_key_iv, body.recovery_key_hash,
                body.x25519_public_key, body.mlkem768_public_key,
                body.x25519_private_wrapped, body.mlkem768_private_wrapped, body.asymmetric_key_iv,
            ),
        )
        await grant_role(db, user_id, ROLE_USER)

        client_ip = _get_client_ip(request)
        await db.execute(
            "UPDATE invites SET used_at = ?, used_by_ip = ?, used_by_user_id = ? WHERE id = ?",
            (now, client_ip, user_id, invite_row["id"]),
        )
        await db.commit()
    except DuplicateError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Username already exists")
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise

    # Build a minimal AuthenticatedUser for the token/response — mirrors OPAQUEAuthProvider.create_user
    user = AuthenticatedUser(
        id=user_id,
        username=body.username,
        auth_method="opaque",
        roles={ROLE_USER},
        wrapped_master_key=body.wrapped_master_key,
        wrapped_master_key_iv=body.wrapped_master_key_iv,
        recovery_key_wrapped=body.recovery_key_wrapped,
        recovery_key_iv=body.recovery_key_iv,
        x25519_public_key=body.x25519_public_key,
        mlkem768_public_key=body.mlkem768_public_key,
        x25519_private_wrapped=body.x25519_private_wrapped,
        mlkem768_private_wrapped=body.mlkem768_private_wrapped,
        asymmetric_key_iv=body.asymmetric_key_iv,
    )

    access_token = create_access_token(user.id)
    raw_refresh, rt_hash = create_refresh_token()
    await store_refresh_token(db, user.id, rt_hash)
    csrf_token = generate_csrf_token()
    _set_auth_cookies(response, access_token, raw_refresh, csrf_token)

    logger.info("New OPAQUE user registered: %s (id=%s)", user.username, user.id)

    # Tell the client if they need to enroll MFA before accessing resources.
    # New users never have credentials, so only the enforcement mode matters.
    from app.auth.mfa import load_mfa_settings as _load_mfa
    mfa_settings = await _load_mfa(db)
    mfa_enrollment_required = mfa_settings["mfa_enforcement"] == "required"

    return {"user": _user_response_dict(user), "mfa_enrollment_required": mfa_enrollment_required}


# ---------------------------------------------------------------------------
# Login routes
# ---------------------------------------------------------------------------

@router.post("/login/start")
async def opaque_login_start(
    body: OpaqueLoginStartRequest,
    db=Depends(get_db),
):
    """OPAQUE login round 1.

    Returns a CredentialResponse regardless of whether the username exists —
    non-existent users receive a fake response that will fail MAC verification
    at finish, preventing user-enumeration timing attacks.
    """
    provider = OPAQUEAuthProvider(db)
    reg_record_bytes, canonical_username = await provider.get_registration_record_with_canonical(body.username)

    login_start_bytes = _decode_b64_field(body.client_login_start, "client_login_start")
    setup_bytes = sensitive_config.get_opaque_server_setup()
    # Use the stored canonical username as the OPAQUE identifier so that login
    # succeeds regardless of the case the user typed (e.g. "groupfolder" finds
    # the record registered as "GroupFolder" and uses "GroupFolder" in the
    # OPAQUE crypto — the client must use the same value in finishLogin).
    identifier = (canonical_username or body.username).encode("utf-8")

    try:
        login_response_bytes, server_state_bytes = await asyncio.to_thread(
            tusshare_opaque.server_start_login,
            setup_bytes, reg_record_bytes, login_start_bytes, identifier,
        )
    except ValueError as exc:
        logger.warning("OPAQUE login/start failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid login request")

    session_id = str(uuid.uuid4())
    canonical = canonical_username or body.username
    await provider.store_login_session(session_id, canonical, server_state_bytes)

    return {
        "login_response": base64.urlsafe_b64encode(login_response_bytes).decode().rstrip("="),
        "session_id": session_id,
        # Return canonical username so the client uses the same identifier in
        # finishLogin that was used at registration time.
        "username": canonical,
    }


@router.post("/login/finish")
async def opaque_login_finish(
    body: OpaqueLoginFinishRequest,
    response: Response,
    db=Depends(get_db),
):
    """OPAQUE login round 2.

    Atomically consumes the in-flight session, verifies the OPAQUE KE3 message,
    and issues auth cookies on success.
    """
    provider = OPAQUEAuthProvider(db)

    session = await provider.consume_login_session(body.session_id)
    if session is None:
        # Session expired, not found, or already consumed — uniform error to
        # prevent distinguishing between "wrong password" and "no session"
        raise HTTPException(status_code=401, detail="Invalid credentials")

    stored_username, server_state_bytes = session

    # Username in the finish request must match what was used at start
    if stored_username.lower() != body.username.lower():
        raise HTTPException(status_code=401, detail="Invalid credentials")

    login_finish_bytes = _decode_b64_field(body.client_login_finish, "client_login_finish")
    # Use the canonical username stored in the session (set at login/start) so
    # the OPAQUE identifier matches what was used at registration.
    identifier = stored_username.encode("utf-8")

    try:
        session_key = await asyncio.to_thread(
            tusshare_opaque.server_finish_login,
            server_state_bytes, login_finish_bytes, identifier,
        )
    except ValueError as exc:
        logger.warning("OPAQUE login/finish error: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if session_key is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Auth succeeded — load the full user record and issue tokens
    user = await provider.get_user_by_username(body.username)
    if user is None:
        # Should never happen if get_registration_record and consume_login_session
        # both succeeded, but guard anyway
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # MFA gate — check for active MFA credentials and enforcement policy.
    # If MFA is required, return a pending_token instead of session cookies so
    # the client can complete the MFA challenge.  mfa_reset_required bypasses
    # the "no credentials → skip" path and forces the user to enrollment.
    from app.auth.mfa import (
        get_active_methods,
        issue_pending_token,
        store_pending_token,
        extract_pending_jti,
    )
    cursor = await db.execute(
        "SELECT mfa_reset_required FROM users WHERE id = ?", (user.id,)
    )
    mfa_row = await cursor.fetchone()
    mfa_reset_required = bool(mfa_row["mfa_reset_required"]) if mfa_row else False

    active_methods = await get_active_methods(db, user.id)

    if active_methods or mfa_reset_required:
        # User has MFA enrolled (or admin forced re-enrollment) — issue pending token
        pending_token = issue_pending_token(user.id)
        jti = extract_pending_jti(pending_token)
        is_public_device = body.is_public_device
        await store_pending_token(db, jti, user.id, is_public_device)
        await db.commit()

        logger.info(
            "OPAQUE login: user=%s (id=%s) — MFA required (methods=%s reset=%s)",
            user.username, user.id, sorted(active_methods), mfa_reset_required,
        )

        # Fire-and-forget policy eval (same as normal login path)
        try:
            from app.models.policy import evaluate_user_policies as _eval_mfa_policies
            from app.database import db_session as _db_session_mfa
            _mfa_uid = user.id
            async def _bg_mfa_eval() -> None:
                try:
                    async with _db_session_mfa() as _bg_db:
                        await _eval_mfa_policies(_bg_db, _mfa_uid)
                except Exception:
                    pass
            asyncio.create_task(_bg_mfa_eval())
        except Exception:
            pass

        return {
            "mfa_required": True,
            "methods": sorted(active_methods),
            "reset_required": mfa_reset_required,
            "pending_token": pending_token,
        }

    # Public device sessions get a shorter-lived refresh token to limit exposure
    # if the user forgets to log out.  Key material stays in sessionStorage only
    # (cleared on tab close) — enforced on the client side.
    is_public_device = body.is_public_device
    if is_public_device:
        rt_expire_minutes = settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES
        rt_max_age = rt_expire_minutes * 60
    else:
        rt_expire_minutes = None  # uses default REFRESH_TOKEN_EXPIRE_DAYS
        rt_max_age = None

    raw_refresh, rt_hash = create_refresh_token()
    token_id = await store_refresh_token(
        db, user.id, rt_hash,
        expire_minutes=rt_expire_minutes,
        is_public_device=is_public_device,
    )
    access_token = create_access_token(user.id, session_id=token_id, is_public_device=is_public_device)
    csrf_token = generate_csrf_token()
    _set_auth_cookies(response, access_token, raw_refresh, csrf_token, refresh_max_age=rt_max_age)

    logger.info(
        "OPAQUE login: user=%s (id=%s) public_device=%s",
        user.username, user.id, is_public_device,
    )

    # Tell the client if MFA enrollment is required (enforcement=required, no credentials).
    # active_methods is already loaded above and is empty at this point.
    mfa_enrollment_required = False
    if not active_methods:
        from app.auth.mfa import load_mfa_settings as _load_mfa_login
        _login_mfa_settings = await _load_mfa_login(db)
        mfa_enrollment_required = _login_mfa_settings["mfa_enforcement"] == "required"

    # Trigger 1 — evaluate policies on every password-entry event.
    # Runs fire-and-forget so login latency is unaffected.  Debounce inside
    # evaluate_user_policies prevents redundant LDAP queries on rapid
    # login → step-up sequences.
    #
    # IMPORTANT: uses its own db_session() connection, NOT the request's `db`
    # connection.  Passing the request connection to a background task is unsafe:
    # get_db() releases it to the pool when this handler returns, and another
    # request could acquire the same connection while the task is still using it.
    try:
        from app.models.policy import evaluate_user_policies as _eval_policies
        from app.database import db_session as _db_session
        _uid = user.id
        async def _bg_eval() -> None:
            try:
                async with _db_session() as _bg_db:
                    await _eval_policies(_bg_db, _uid)
            except Exception:
                pass
        asyncio.create_task(_bg_eval())
    except Exception:
        pass  # policy engine must not block authentication

    resp_body = {"user": _user_response_dict(user)}
    if mfa_enrollment_required:
        resp_body["mfa_enrollment_required"] = True
    return resp_body


# ---------------------------------------------------------------------------
# Step-up start (Phase 6 — OPAQUE step-up challenge)
# ---------------------------------------------------------------------------

@router.post("/step-up/start")
async def opaque_step_up_start(
    body: OpaqueStepUpStartRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Initiate an OPAQUE step-up challenge for an already-authenticated user.

    The client generates a CredentialRequest (same as login round 1) and sends it
    here.  The server returns a CredentialResponse and a session_id.

    The client then:
      1. Calls opaque.client.finishLogin({loginResponse, password}) → session_key
      2. Derives signing_key = HKDF-SHA256(session_key, salt=action_key,
                                            info="tusShare-stepup-v2")
      3. Computes hmac = HMAC-SHA256(signing_key,
                                      action_key|payload_hash|timestamp_bucket)
      4. POSTs to /auth/step-up with:
           {session_id, client_login_finish, action_key, payload_hash, timestamp, hmac}
    """
    if not sensitive_config.is_sensitive(body.action_key):
        raise HTTPException(status_code=400, detail="action_key is not a sensitive function")

    if user.auth_method != "opaque":
        raise HTTPException(
            status_code=400,
            detail="This endpoint is only for OPAQUE-authenticated users. "
                   "Legacy users should POST to /auth/step-up directly.",
        )

    provider = OPAQUEAuthProvider(db)
    reg_record_bytes = await provider.get_registration_record(user.username)
    if reg_record_bytes is None:
        logger.error("OPAQUE step-up: registration record missing for user %s", user.id)
        raise HTTPException(status_code=500, detail="Step-up unavailable")

    step_up_start_bytes = _decode_b64_field(body.client_step_up_start, "client_step_up_start")
    setup_bytes = sensitive_config.get_opaque_server_setup()
    username_bytes = user.username.encode("utf-8")

    try:
        login_response_bytes, server_state_bytes = await asyncio.to_thread(
            tusshare_opaque.server_start_login,
            setup_bytes, reg_record_bytes, step_up_start_bytes, username_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE step-up/start failed for user %s: %s", user.id, exc)
        raise HTTPException(status_code=400, detail="Invalid step-up request")

    session_id = str(uuid.uuid4())
    # Use a shorter TTL for step-up sessions (30 s) — the client has the
    # CredentialResponse already and needs minimal time to finish locally.
    await provider.store_login_session(session_id, user.username, server_state_bytes, ttl_seconds=30)

    return {
        "login_response": base64.urlsafe_b64encode(login_response_bytes).decode().rstrip("="),
        "session_id": session_id,
        "username": user.username,
    }


# ---------------------------------------------------------------------------
# Legacy→OPAQUE migration (Step 9 — upgrade existing bcrypt users)
# ---------------------------------------------------------------------------

_MIGRATE_RATE_LIMIT = 5       # attempts
_MIGRATE_RATE_WINDOW = 300    # seconds (5 minutes)


class OpaqueMigrateStartRequest(BaseModel):
    client_registration_request: str   # base64 RegistrationRequest bytes

    @field_validator("client_registration_request")
    @classmethod
    def val_reg_request(cls, v: str) -> str:
        validate_base64(v)
        return v


class OpaqueMigrateFinishRequest(BaseModel):
    client_registration_record: str    # base64 RegistrationUpload bytes
    wrapped_master_key: str
    wrapped_master_key_iv: str

    @field_validator("client_registration_record", "wrapped_master_key", "wrapped_master_key_iv")
    @classmethod
    def val_b64_fields(cls, v: str) -> str:
        validate_base64(v)
        return v


@router.post("/migrate/start")
async def opaque_migrate_start(
    body: OpaqueMigrateStartRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """OPAQUE migration round 1 — initiate OPAQUE registration for an existing legacy user.

    The user must be authenticated.  No invite token is required.  Returns the
    RegistrationResponse for the client to derive its exportKey and registration record.
    """
    if user.auth_method != "legacy":
        # Already migrated — nothing to do (idempotent 200)
        return {"already_migrated": True}

    reg_request_bytes = _decode_b64_field(body.client_registration_request, "client_registration_request")
    setup_bytes = sensitive_config.get_opaque_server_setup()
    username_bytes = user.username.encode("utf-8")

    try:
        reg_response_bytes = await asyncio.to_thread(
            tusshare_opaque.server_start_registration,
            setup_bytes, reg_request_bytes, username_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE migrate/start failed for user %s: %s", user.id, exc)
        raise HTTPException(status_code=400, detail="Invalid registration request")

    return {"registration_response": base64.urlsafe_b64encode(reg_response_bytes).decode().rstrip("=")}


@router.post("/migrate/finish")
async def opaque_migrate_finish(
    body: OpaqueMigrateFinishRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """OPAQUE migration round 2 — atomically upgrade a legacy account to OPAQUE.

    Stores the OPAQUE registration record, updates auth_method to 'opaque', and
    replaces the wrapped master key (re-wrapped under the new OPAQUE KEK client-side).
    Clears password_hash and encryption_salt.

    The UPDATE uses AND auth_method='legacy' so a double-submit is a safe no-op.
    Rate-limited to 5 attempts per 5 minutes per user to prevent brute-force.
    """
    allowed = await _counter.is_allowed(
        f"opaque_migrate:{user.id}", _MIGRATE_RATE_LIMIT, _MIGRATE_RATE_WINDOW
    )
    if not allowed:
        logger.warning("OPAQUE migrate rate-limited: user=%s", user.id)
        raise HTTPException(
            status_code=429,
            detail="Too many migration attempts. Please try again later.",
            headers={"Retry-After": str(_MIGRATE_RATE_WINDOW)},
        )

    if user.auth_method != "legacy":
        # Already migrated — return current user record (idempotent)
        provider = OPAQUEAuthProvider(db)
        current = await provider.get_user_by_id(user.id)
        return {"user": _user_response_dict(current or user)}

    reg_upload_bytes = _decode_b64_field(body.client_registration_record, "client_registration_record")

    try:
        reg_record_bytes = await asyncio.to_thread(
            tusshare_opaque.server_finish_registration,
            reg_upload_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE migrate/finish failed for user %s: %s", user.id, exc)
        raise HTTPException(status_code=400, detail="Invalid registration upload")

    # Atomic upgrade: only proceeds if still legacy (double-submit safe)
    result = await db.execute(
        "UPDATE users SET "
        "  auth_method = 'opaque', "
        "  opaque_registration_record = ?, "
        "  wrapped_master_key = ?, "
        "  wrapped_master_key_iv = ? "
        "WHERE id = ? AND auth_method = 'legacy'",
        (
            reg_record_bytes,
            body.wrapped_master_key,
            body.wrapped_master_key_iv,
            user.id,
        ),
    )
    await db.commit()

    if result.rowcount == 0:
        logger.info("OPAQUE migrate/finish: user %s already migrated (no-op)", user.id)
    else:
        logger.info("OPAQUE migration complete: user=%s (id=%s)", user.username, user.id)

    # Return updated user record
    provider = OPAQUEAuthProvider(db)
    updated = await provider.get_user_by_id(user.id)
    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to load updated user record")

    return {"user": _user_response_dict(updated)}


# ---------------------------------------------------------------------------
# Password recovery via recovery key (unauthenticated, two-round)
# ---------------------------------------------------------------------------
# The server never sees the raw recovery key.  Round 1 returns the user's
# encrypted recovery key material so the client can verify the key locally by
# attempting an AES-GCM unwrap.  Round 2 requires the client to prove it held
# the old key by sending SHA-256(old_recovery_key_string), which the server
# compares (constant-time) against the stored recovery_key_hash.
# ---------------------------------------------------------------------------


class OpaqueRecoverStartRequest(BaseModel):
    username: str
    client_registration_request: str   # base64 RegistrationRequest for the new password

    @field_validator("username")
    @classmethod
    def val_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("client_registration_request")
    @classmethod
    def val_reg_request(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_REG_REQUEST_B64_MAX)
        return v


class OpaqueRecoverFinishRequest(BaseModel):
    username: str
    session_id: str
    client_registration_record: str    # base64 RegistrationUpload for the new password
    wrapped_master_key: str            # master key re-wrapped under new OPAQUE KEK
    wrapped_master_key_iv: str
    recovery_key_wrapped: str          # master key wrapped under new recovery key
    recovery_key_iv: str
    recovery_key_hash: str             # SHA-256 hex of new recovery key string
    old_recovery_key_proof: str        # SHA-256 hex of old recovery key string (proof of possession)

    @field_validator("username")
    @classmethod
    def val_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("session_id")
    @classmethod
    def val_session_id(cls, v: str) -> str:
        try:
            return validate_uuid(v)
        except ValueError:
            raise ValueError("session_id must be a valid UUID")

    @field_validator("client_registration_record")
    @classmethod
    def val_reg_record(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_REG_RECORD_B64_MAX)
        return v

    @field_validator("wrapped_master_key", "recovery_key_wrapped")
    @classmethod
    def val_wrapped_key_fields(cls, v: str) -> str:
        validate_base64(v, max_length=_WRAPPED_KEY_B64_MAX)
        return v

    @field_validator("wrapped_master_key_iv", "recovery_key_iv")
    @classmethod
    def val_iv_fields(cls, v: str) -> str:
        validate_base64(v, max_length=_IV_B64_MAX)
        return v

    @field_validator("recovery_key_hash", "old_recovery_key_proof")
    @classmethod
    def val_hex_fields(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or len(v) > 128 or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("Must be a hex string (SHA-256)")
        return v


def _fake_recovery_blob(username: str) -> str:
    """Deterministic fake recovery_key_wrapped for non-existent users.

    Prevents the oracle where recovery_key_wrapped=null unambiguously reveals
    that the username does not exist. The fake blob is 48 bytes (matches the
    real AES-GCM ciphertext length: 32-byte key + 16-byte auth tag).
    """
    secret = settings.JWT_SECRET.encode()
    uname = username.lower().encode()
    ciphertext = _hmac.new(secret, b"fake-rk-v1:" + uname, hashlib.sha256).digest()
    tag = _hmac.new(secret, b"fake-rk-tag:" + uname, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(ciphertext + tag).rstrip(b"=").decode()


def _fake_recovery_iv(username: str) -> str:
    """Deterministic fake recovery_key_iv for non-existent users (12 bytes)."""
    secret = settings.JWT_SECRET.encode()
    iv = _hmac.new(secret, b"fake-iv-v1:" + username.lower().encode(), hashlib.sha256).digest()[:12]
    return base64.urlsafe_b64encode(iv).rstrip(b"=").decode()


@router.post("/recover/start")
async def opaque_recover_start(
    body: OpaqueRecoverStartRequest,
    db=Depends(get_db),
):
    """Password recovery round 1.

    Runs the OPAQUE registration start for the new password (server-side is
    stateless between registration rounds, so no state is stored for this).
    Also returns the user's encrypted recovery key material so the client can
    verify the recovery key locally — by attempting AES-GCM unwrap — without
    ever transmitting the raw key to the server.

    Always performs the full OPAQUE computation and stores a recovery session
    regardless of whether the username exists, to keep response timing uniform.
    Non-existent users receive null recovery_key_wrapped/iv; the client shows
    the same "Invalid username or recovery key" error either way.
    """
    reg_request_bytes = _decode_b64_field(body.client_registration_request, "client_registration_request")
    setup_bytes = sensitive_config.get_opaque_server_setup()
    username_bytes = body.username.encode("utf-8")

    try:
        reg_response_bytes = await asyncio.to_thread(
            tusshare_opaque.server_start_registration,
            setup_bytes, reg_request_bytes, username_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE recover/start failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid registration request")

    provider = OPAQUEAuthProvider(db)
    user_fields = await provider.get_recovery_key_fields(body.username)

    session_id = str(uuid.uuid4())
    await provider.store_recovery_session(session_id, body.username)

    return {
        "registration_response": base64.urlsafe_b64encode(reg_response_bytes).decode().rstrip("="),
        "session_id": session_id,
        "recovery_key_wrapped": user_fields["recovery_key_wrapped"] if user_fields else _fake_recovery_blob(body.username),
        "recovery_key_iv": user_fields["recovery_key_iv"] if user_fields else _fake_recovery_iv(body.username),
    }


@router.post("/recover/finish")
async def opaque_recover_finish(
    body: OpaqueRecoverFinishRequest,
    request: Request,
    response: Response,
    db=Depends(get_db),
):
    """Password recovery round 2.

    Verifies the recovery session token (consumed atomically to prevent replay),
    then checks that the client supplied SHA-256(old_recovery_key_string) as proof
    of possession — compared constant-time against the stored recovery_key_hash.

    On success, atomically replaces the OPAQUE registration record, the wrapped
    master key, and all recovery key fields, then revokes all existing refresh
    tokens so the user must log in fresh with the new password.

    Does NOT issue auth cookies — the client is redirected to log in.
    """
    provider = OPAQUEAuthProvider(db)

    stored_username = await provider.consume_recovery_session(body.session_id)
    if stored_username is None:
        raise HTTPException(status_code=400, detail="Invalid or expired recovery session")

    if stored_username.lower() != body.username.lower():
        raise HTTPException(status_code=400, detail="Invalid or expired recovery session")

    user_fields = await provider.get_recovery_key_fields(body.username)
    if user_fields is None:
        # User doesn't exist or isn't an OPAQUE user — same error as wrong key
        raise HTTPException(status_code=400, detail="Invalid recovery key")

    stored_hash = user_fields["recovery_key_hash"] or ""
    if not secrets.compare_digest(body.old_recovery_key_proof.lower(), stored_hash.lower()):
        logger.warning("OPAQUE recover/finish: wrong key proof for user_id=%s", user_fields["id"])
        raise HTTPException(status_code=400, detail="Invalid recovery key")

    reg_upload_bytes = _decode_b64_field(body.client_registration_record, "client_registration_record")
    try:
        new_reg_record_bytes = await asyncio.to_thread(
            tusshare_opaque.server_finish_registration,
            reg_upload_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE recover/finish: registration error for user_id=%s: %s", user_fields["id"], exc)
        raise HTTPException(status_code=400, detail="Invalid registration data")

    user_id = user_fields["id"]

    await db.execute("BEGIN")
    try:
        await db.execute(
            "UPDATE users SET "
            "  opaque_registration_record = ?, "
            "  wrapped_master_key = ?, wrapped_master_key_iv = ?, "
            "  recovery_key_wrapped = ?, recovery_key_iv = ?, recovery_key_hash = ? "
            "WHERE id = ?",
            (
                new_reg_record_bytes,
                body.wrapped_master_key, body.wrapped_master_key_iv,
                body.recovery_key_wrapped, body.recovery_key_iv, body.recovery_key_hash,
                user_id,
            ),
        )
        await db.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
            (user_id,),
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    # Clear any existing auth cookies so a stale access-token JWT doesn't leave
    # the user stranded on the key-prompt screen after reset.
    _clear_auth_cookies(response)

    client_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:512]
    logger.info("Password reset via recovery key: user_id=%s ip=%s", user_id, client_ip)
    await log_security_event(
        db, "password_reset_via_recovery_key", user_id, client_ip, user_agent,
    )

    return {"success": True}


# ---------------------------------------------------------------------------
# Password change (authenticated, step-up gated)
# ---------------------------------------------------------------------------
# Two-round OPAQUE re-registration for already-authenticated OPAQUE users.
# The step-up in /finish proves the user knows their current password before
# the new OPAQUE record and re-wrapped master key are written.

class OpaquePasswordChangeStartRequest(BaseModel):
    client_registration_request: str   # base64 RegistrationRequest bytes

    @field_validator("client_registration_request")
    @classmethod
    def val_reg_request(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_REG_REQUEST_B64_MAX)
        return v


class OpaquePasswordChangeFinishRequest(BaseModel):
    client_registration_record: str    # base64 RegistrationUpload bytes (new password)
    wrapped_master_key: str            # master key re-wrapped under new OPAQUE KEK
    wrapped_master_key_iv: str

    @field_validator("client_registration_record")
    @classmethod
    def val_reg_record(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_REG_RECORD_B64_MAX)
        return v

    @field_validator("wrapped_master_key")
    @classmethod
    def val_wrapped_key(cls, v: str) -> str:
        validate_base64(v, max_length=_WRAPPED_KEY_B64_MAX)
        return v

    @field_validator("wrapped_master_key_iv")
    @classmethod
    def val_iv(cls, v: str) -> str:
        validate_base64(v, max_length=_IV_B64_MAX)
        return v


@router.post("/password-change/start")
async def opaque_password_change_start(
    body: OpaquePasswordChangeStartRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Password change round 1 — initiate OPAQUE re-registration.

    Returns the RegistrationResponse for the client to complete local
    registration with the new password.  Only available to OPAQUE users.
    """
    if user.auth_method != "opaque":
        raise HTTPException(
            status_code=400,
            detail="Password change is only available for OPAQUE accounts",
        )

    reg_request_bytes = _decode_b64_field(body.client_registration_request, "client_registration_request")
    setup_bytes = sensitive_config.get_opaque_server_setup()
    username_bytes = user.username.encode("utf-8")

    try:
        reg_response_bytes = await asyncio.to_thread(
            tusshare_opaque.server_start_registration,
            setup_bytes, reg_request_bytes, username_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE password-change/start failed for user %s: %s", user.id, exc)
        raise HTTPException(status_code=400, detail="Invalid registration request")

    return {"registration_response": base64.urlsafe_b64encode(reg_response_bytes).decode().rstrip("=")}


@router.post("/password-change/finish")
async def opaque_password_change_finish(
    body: OpaquePasswordChangeFinishRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Password change round 2 — commit new OPAQUE record.

    Requires X-Step-Up-Token header proving the user authenticated with their
    current password.  Atomically replaces the OPAQUE registration record and
    master key wrapping, then revokes all other sessions.
    """
    if user.auth_method != "opaque":
        raise HTTPException(
            status_code=400,
            detail="Password change is only available for OPAQUE accounts",
        )

    token = request.headers.get("x-step-up-token", "")
    if not token or not verify_step_up_token(
        token, user.id, "user.change_password", session_id=user.session_id
    ):
        raise HTTPException(
            status_code=403,
            detail={"error": "step_up_required", "action": "user.change_password"},
        )

    reg_upload_bytes = _decode_b64_field(body.client_registration_record, "client_registration_record")
    try:
        new_reg_record_bytes = await asyncio.to_thread(
            tusshare_opaque.server_finish_registration,
            reg_upload_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE password-change/finish failed for user %s: %s", user.id, exc)
        raise HTTPException(status_code=400, detail="Invalid registration data")

    await db.execute("BEGIN")
    try:
        await db.execute(
            "UPDATE users SET "
            "  opaque_registration_record = ?, "
            "  wrapped_master_key = ?, wrapped_master_key_iv = ? "
            "WHERE id = ?",
            (
                new_reg_record_bytes,
                body.wrapped_master_key, body.wrapped_master_key_iv,
                user.id,
            ),
        )
        # Revoke other sessions so old-password JWTs cannot be replayed.
        # The current session (identified by user.session_id) is preserved.
        if user.session_id:
            await db.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND id != ?",
                (user.id, user.session_id),
            )
        else:
            await db.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
                (user.id,),
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    client_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:512]
    logger.info("Password changed: user=%s id=%s ip=%s", user.username, user.id, client_ip)
    await log_security_event(
        db, "user.password_changed", user.id, client_ip, user_agent,
    )

    return {"success": True}


# ---------------------------------------------------------------------------
# Bootstrap registration (first-run admin account)
# ---------------------------------------------------------------------------
# The bootstrap token is a secrets.token_urlsafe(32) value stored as a
# SHA-256 hash in admin_settings under 'bootstrap_token_hash'.  It is
# generated by _bootstrap_admin() on first run when the users table is empty
# and consumed (deleted) atomically when /bootstrap/finish succeeds.

_BOOTSTRAP_RATE_LIMIT  = 10
_BOOTSTRAP_RATE_WINDOW = 300  # 10 attempts per 5 minutes per IP


class OpaqueBootstrapStartRequest(BaseModel):
    token: str
    username: str
    client_registration_request: str   # base64 RegistrationRequest bytes

    @field_validator("token")
    @classmethod
    def val_token(cls, v: str) -> str:
        if not v or len(v) > 200:
            raise ValueError("Invalid token")
        return v

    @field_validator("username")
    @classmethod
    def val_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("client_registration_request")
    @classmethod
    def val_reg_request(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_REG_REQUEST_B64_MAX)
        return v


class OpaqueBootstrapFinishRequest(BaseModel):
    token: str
    username: str
    client_registration_record: str     # base64 RegistrationUpload bytes
    wrapped_master_key: str
    wrapped_master_key_iv: str
    recovery_key_wrapped: str | None = None
    recovery_key_iv: str | None = None
    recovery_key_hash: str | None = None
    x25519_public_key: str | None = None
    mlkem768_public_key: str | None = None
    x25519_private_wrapped: str | None = None
    mlkem768_private_wrapped: str | None = None
    asymmetric_key_iv: str | None = None

    @field_validator("token")
    @classmethod
    def val_token(cls, v: str) -> str:
        if not v or len(v) > 200:
            raise ValueError("Invalid token")
        return v

    @field_validator("username")
    @classmethod
    def val_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("client_registration_record")
    @classmethod
    def val_reg_record(cls, v: str) -> str:
        validate_base64(v, max_length=_OPAQUE_REG_RECORD_B64_MAX)
        return v

    @field_validator("wrapped_master_key", "wrapped_master_key_iv")
    @classmethod
    def val_required_key_fields(cls, v: str) -> str:
        validate_base64(v, max_length=_WRAPPED_KEY_B64_MAX)
        return v

    @field_validator("recovery_key_wrapped")
    @classmethod
    def val_recovery_key_wrapped(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_WRAPPED_KEY_B64_MAX)
        return v

    @field_validator("recovery_key_iv", "asymmetric_key_iv")
    @classmethod
    def val_iv_fields(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_IV_B64_MAX)
        return v

    @field_validator("x25519_public_key")
    @classmethod
    def val_x25519_pub(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_X25519_PUB_B64_MAX)
        return v

    @field_validator("mlkem768_public_key")
    @classmethod
    def val_mlkem_pub(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_MLKEM_PUB_B64_MAX)
        return v

    @field_validator("x25519_private_wrapped")
    @classmethod
    def val_x25519_priv(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_X25519_PRIV_WRAPPED_B64_MAX)
        return v

    @field_validator("mlkem768_private_wrapped")
    @classmethod
    def val_mlkem_priv(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=_MLKEM_PRIV_WRAPPED_B64_MAX)
        return v

    @field_validator("recovery_key_hash")
    @classmethod
    def val_recovery_hash(cls, v: str | None) -> str | None:
        if v is not None and (not v or len(v) > 128 or not all(c in "0123456789abcdef" for c in v)):
            raise ValueError("Invalid recovery_key_hash (expected hex)")
        return v


async def _validate_bootstrap_token(token: str, db) -> None:
    """Raise 400 if the bootstrap token is absent, already used, or wrong."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    cursor = await db.execute(
        "SELECT value FROM admin_settings WHERE key = 'bootstrap_token_hash'"
    )
    row = await cursor.fetchone()
    if row is None or row["value"] != token_hash:
        raise HTTPException(status_code=400, detail="Invalid or already-used bootstrap token")


@router.get("/bootstrap/status")
async def opaque_bootstrap_status(db=Depends(get_db)):
    """Return whether first-run admin bootstrap is still pending.

    Returns {"needs_bootstrap": true} only when both conditions hold:
      - the users table is empty (no accounts registered yet), and
      - a bootstrap_token_hash is present in admin_settings (token was generated).

    The frontend uses this to show the bootstrap UI instead of the login form.
    """
    cursor = await db.execute("SELECT COUNT(*) FROM users")
    user_count = (await cursor.fetchone())[0]
    if user_count > 0:
        return {"needs_bootstrap": False}

    cursor = await db.execute(
        "SELECT 1 FROM admin_settings WHERE key = 'bootstrap_token_hash'"
    )
    token_pending = (await cursor.fetchone()) is not None
    return {"needs_bootstrap": token_pending}


@router.post("/bootstrap/start")
async def opaque_bootstrap_start(
    body: OpaqueBootstrapStartRequest,
    db=Depends(get_db),
):
    """Bootstrap registration round 1.

    Validates the bootstrap token and returns the OPAQUE RegistrationResponse.
    The token is not consumed here — it is consumed atomically in /bootstrap/finish.
    This endpoint is only usable while the users table is empty.
    """
    # Refuse if any user already exists — bootstrap is first-run only
    cursor = await db.execute("SELECT COUNT(*) FROM users")
    row = await cursor.fetchone()
    if row[0] > 0:
        raise HTTPException(status_code=403, detail="Bootstrap already complete")

    await _validate_bootstrap_token(body.token, db)

    reg_request_bytes = _decode_b64_field(body.client_registration_request, "client_registration_request")
    setup_bytes = sensitive_config.get_opaque_server_setup()
    username_bytes = body.username.encode("utf-8")

    try:
        reg_response_bytes = await asyncio.to_thread(
            tusshare_opaque.server_start_registration,
            setup_bytes, reg_request_bytes, username_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE bootstrap/start failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid registration request")

    return {"registration_response": base64.urlsafe_b64encode(reg_response_bytes).decode().rstrip("=")}


@router.post("/bootstrap/finish")
async def opaque_bootstrap_finish(
    body: OpaqueBootstrapFinishRequest,
    response: Response,
    db=Depends(get_db),
):
    """Bootstrap registration round 2.

    Validates the bootstrap token, finalises OPAQUE registration, creates the
    initial admin user, and atomically consumes the bootstrap token — all in a
    single transaction.  Sets auth cookies so the admin is immediately logged in.
    """
    from app.models.role import ROLE_ADMIN

    # Refuse if any user already exists
    cursor = await db.execute("SELECT COUNT(*) FROM users")
    row = await cursor.fetchone()
    if row[0] > 0:
        raise HTTPException(status_code=403, detail="Bootstrap already complete")

    await _validate_bootstrap_token(body.token, db)

    reg_upload_bytes = _decode_b64_field(body.client_registration_record, "client_registration_record")
    try:
        reg_record_bytes = await asyncio.to_thread(
            tusshare_opaque.server_finish_registration,
            reg_upload_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE bootstrap/finish failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid registration upload")

    user_id = str(uuid.uuid4())
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()

    await db.execute("BEGIN")
    try:
        # Re-validate and consume the token atomically
        cursor = await db.execute(
            "DELETE FROM admin_settings WHERE key = 'bootstrap_token_hash' AND value = ? "
            "RETURNING key",
            (token_hash,),
        )
        if await cursor.fetchone() is None:
            await db.rollback()
            raise HTTPException(status_code=400, detail="Invalid or already-used bootstrap token")

        await db.execute(
            "INSERT INTO users ("
            "  id, username, auth_method, opaque_registration_record, is_admin, "
            "  wrapped_master_key, wrapped_master_key_iv, "
            "  recovery_key_wrapped, recovery_key_iv, recovery_key_hash, "
            "  x25519_public_key, mlkem768_public_key, "
            "  x25519_private_wrapped, mlkem768_private_wrapped, asymmetric_key_iv"
            ") VALUES (?, ?, 'opaque', ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user_id, body.username, reg_record_bytes,
                body.wrapped_master_key, body.wrapped_master_key_iv,
                body.recovery_key_wrapped, body.recovery_key_iv, body.recovery_key_hash,
                body.x25519_public_key, body.mlkem768_public_key,
                body.x25519_private_wrapped, body.mlkem768_private_wrapped, body.asymmetric_key_iv,
            ),
        )
        await grant_role(db, user_id, ROLE_ADMIN)
        await grant_role(db, user_id, ROLE_USER)
        await db.commit()
    except DuplicateError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Username already exists")
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise

    user = AuthenticatedUser(
        id=user_id,
        username=body.username,
        auth_method="opaque",
        roles={ROLE_ADMIN, ROLE_USER},
        wrapped_master_key=body.wrapped_master_key,
        wrapped_master_key_iv=body.wrapped_master_key_iv,
        recovery_key_wrapped=body.recovery_key_wrapped,
        recovery_key_iv=body.recovery_key_iv,
        x25519_public_key=body.x25519_public_key,
        mlkem768_public_key=body.mlkem768_public_key,
        x25519_private_wrapped=body.x25519_private_wrapped,
        mlkem768_private_wrapped=body.mlkem768_private_wrapped,
        asymmetric_key_iv=body.asymmetric_key_iv,
    )

    access_token = create_access_token(user.id)
    raw_refresh, rt_hash = create_refresh_token()
    await store_refresh_token(db, user.id, rt_hash)
    csrf_token = generate_csrf_token()
    _set_auth_cookies(response, access_token, raw_refresh, csrf_token)

    logger.info("Bootstrap admin registered: %s (id=%s)", user.username, user.id)
    return {"user": _user_response_dict(user)}
