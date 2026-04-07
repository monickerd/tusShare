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
"""

import asyncio
import base64
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timezone

import tusshare_opaque
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, field_validator

import app.sensitive_config as sensitive_config
from app.auth.dependencies import get_current_user, require_user_role
from app.middleware.rate_limit import _counter
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

def _set_auth_cookies(response: Response, access_token: str, refresh_token: str, csrf_token: str) -> None:
    response.set_cookie(
        key=COOKIE_ACCESS, value=access_token,
        httponly=True, secure=True, samesite="strict", path="/",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key=COOKIE_REFRESH, value=refresh_token,
        httponly=True, secure=True, samesite="strict",
        path=REFRESH_TOKEN_COOKIE_PATH,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )
    response.set_cookie(
        key=COOKIE_CSRF, value=csrf_token,
        httponly=False, secure=True, samesite="strict", path="/",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


def _user_response_dict(user: AuthenticatedUser) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "auth_method": user.auth_method,
        "is_admin": user.is_admin,
        "is_admin_only": user.is_admin_only,
        "roles": sorted(user.roles),
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
            "UPDATE invites SET used_at = ? WHERE id = ?",
            (now, invite_row["id"]),
        )

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

    access_token = create_access_token(user.id, user.is_admin)
    raw_refresh, rt_hash = create_refresh_token()
    await store_refresh_token(db, user.id, rt_hash)
    csrf_token = generate_csrf_token()
    _set_auth_cookies(response, access_token, raw_refresh, csrf_token)

    logger.info("New OPAQUE user registered: %s (id=%s)", user.username, user.id)
    return {"user": _user_response_dict(user)}


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
    reg_record_bytes: bytes | None = await provider.get_registration_record(body.username)

    login_start_bytes = _decode_b64_field(body.client_login_start, "client_login_start")
    setup_bytes = sensitive_config.get_opaque_server_setup()
    username_bytes = body.username.encode("utf-8")

    try:
        login_response_bytes, server_state_bytes = await asyncio.to_thread(
            tusshare_opaque.server_start_login,
            setup_bytes, reg_record_bytes, login_start_bytes, username_bytes,
        )
    except ValueError as exc:
        logger.warning("OPAQUE login/start failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid login request")

    session_id = str(uuid.uuid4())
    await provider.store_login_session(session_id, body.username, server_state_bytes)

    return {
        "login_response": base64.urlsafe_b64encode(login_response_bytes).decode().rstrip("="),
        "session_id": session_id,
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
    username_bytes = body.username.encode("utf-8")

    try:
        session_key = await asyncio.to_thread(
            tusshare_opaque.server_finish_login,
            server_state_bytes, login_finish_bytes, username_bytes,
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

    raw_refresh, rt_hash = create_refresh_token()
    token_id = await store_refresh_token(db, user.id, rt_hash)
    access_token = create_access_token(user.id, user.is_admin, session_id=token_id)
    csrf_token = generate_csrf_token()
    _set_auth_cookies(response, access_token, raw_refresh, csrf_token)

    logger.info("OPAQUE login: user=%s (id=%s)", user.username, user.id)
    return {"user": _user_response_dict(user)}


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

    access_token = create_access_token(user.id, user.is_admin)
    raw_refresh, rt_hash = create_refresh_token()
    await store_refresh_token(db, user.id, rt_hash)
    csrf_token = generate_csrf_token()
    _set_auth_cookies(response, access_token, raw_refresh, csrf_token)

    logger.info("Bootstrap admin registered: %s (id=%s)", user.username, user.id)
    return {"user": _user_response_dict(user)}
