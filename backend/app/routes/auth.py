"""Authentication routes: logout, refresh, profile, and step-up re-auth.

Registration and login are handled by the OPAQUE routes in opaque_auth.py.
"""

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, field_validator

from app.auth.dependencies import get_current_user, require_user_role, _get_auth_provider
from app.auth.interface import AuthenticatedUser
from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    generate_csrf_token,
    hash_refresh_token,
)
from app.auth.stepup import (
    StepUpContext,
    create_step_up_token,
    failure_tracker,
    get_verifier,
    log_security_event,
)
from app.conf.auth import COOKIE_ACCESS, COOKIE_CSRF, COOKIE_REFRESH, REFRESH_TOKEN_COOKIE_PATH
from app.config import settings
from app.database import get_db
from app.middleware.rate_limit import _get_client_ip
from app.validation.sanitizers import sanitize_username, validate_base64, validate_uuid
import app.sensitive_config as sensitive_config

logger = logging.getLogger(__name__)

router = APIRouter()


def _user_response_dict(user) -> dict:
    """Build the user dict returned to the client, including key wrapping blobs and roles."""
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
        # Asymmetric PQ key material (Phase 5b)
        "x25519_public_key": getattr(user, "x25519_public_key", None),
        "mlkem768_public_key": getattr(user, "mlkem768_public_key", None),
        "x25519_private_wrapped": getattr(user, "x25519_private_wrapped", None),
        "mlkem768_private_wrapped": getattr(user, "mlkem768_private_wrapped", None),
        "asymmetric_key_iv": getattr(user, "asymmetric_key_iv", None),
    }


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: str,
    max_age: int | None = None,
) -> None:
    """Set authentication cookies on a response.

    max_age overrides the default refresh-token / CSRF max-age (seconds).
    Pass a shorter value for public-device sessions.
    """
    rt_max_age = max_age if max_age is not None else settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    response.set_cookie(
        key=COOKIE_ACCESS,
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
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


def _clear_auth_cookies(response: Response) -> None:
    """Clear all authentication cookies.

    secure=True and samesite="strict" must be repeated here — delete_cookie
    defaults secure=False, which causes browsers to reject the Set-Cookie header
    for __Host- and __Secure- prefixed cookies (both require the Secure flag).
    """
    response.delete_cookie(key=COOKIE_ACCESS, path="/", secure=True, samesite="strict")
    response.delete_cookie(key=COOKIE_REFRESH, path=REFRESH_TOKEN_COOKIE_PATH, secure=True, samesite="strict")
    response.delete_cookie(key=COOKIE_CSRF, path="/", secure=True, samesite="strict")


@router.post("/logout")
async def logout(
    response: Response,
    request: Request,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Revoke refresh token and clear cookies."""
    refresh_token = request.cookies.get(COOKIE_REFRESH)
    if refresh_token:
        token_hash = hash_refresh_token(refresh_token)
        await db.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
            (token_hash,),
        )
        await db.commit()

    _clear_auth_cookies(response)
    return {"message": "Logged out"}


@router.post("/refresh")
async def refresh(
    request: Request,
    response: Response,
    db=Depends(get_db),
    auth_provider=Depends(_get_auth_provider),
):
    """Issue a new access token from a valid refresh token. Rotates the refresh token.

    Uses an atomic transaction: validate, revoke, and issue are done inside a
    single BEGIN IMMEDIATE block so concurrent requests with the same token
    cannot both succeed (the second sees revoked=1 and fails).
    """
    raw_refresh = request.cookies.get(COOKIE_REFRESH)
    if not raw_refresh:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    token_hash = hash_refresh_token(raw_refresh)
    now = datetime.now(timezone.utc).isoformat()

    # Atomic: validate + revoke + issue in a single write transaction
    await db.execute("BEGIN")
    try:
        # Validate: find a non-revoked, non-expired token
        cursor = await db.execute(
            "SELECT id, user_id, is_public_device FROM refresh_tokens "
            "WHERE token_hash = ? AND revoked = 0 AND expires_at > ?",
            (token_hash, now),
        )
        row = await cursor.fetchone()
        if row is None:
            await db.rollback()
            _clear_auth_cookies(response)
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        token_id = row["id"]
        user_id = row["user_id"]
        is_public_device = bool(row["is_public_device"])

        # Revoke atomically — use WHERE revoked = 0 so a concurrent request
        # that already revoked this token causes 0 rows changed (RETURNING returns nothing)
        revoke_result = await db.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE id = ? AND revoked = 0 RETURNING id",
            (token_id,),
        )
        if await revoke_result.fetchone() is None:
            await db.rollback()
            _clear_auth_cookies(response)
            raise HTTPException(status_code=401, detail="Token already used")

        # Look up user (still inside transaction)
        user = await auth_provider.get_user_by_id(user_id)
        if user is None:
            await db.rollback()
            _clear_auth_cookies(response)
            raise HTTPException(status_code=401, detail="User not found or inactive")

        # Issue new tokens inside same transaction — preserve is_public_device
        new_raw_refresh, new_token_hash = create_refresh_token()
        new_token_id = str(uuid.uuid4())
        new_now = datetime.now(timezone.utc).isoformat()
        if is_public_device:
            new_expires_at = (
                datetime.now(timezone.utc) + timedelta(minutes=settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES)
            ).isoformat()
        else:
            new_expires_at = (
                datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            ).isoformat()
        await db.execute(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, last_active_at, is_public_device) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (new_token_id, user_id, new_token_hash, new_expires_at, new_now, 1 if is_public_device else 0),
        )

        await db.commit()
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise

    access_token = create_access_token(user.id, session_id=new_token_id, is_public_device=is_public_device)
    csrf_token = generate_csrf_token()
    rt_max_age = settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES * 60 if is_public_device else None
    _set_auth_cookies(response, access_token, new_raw_refresh, csrf_token, max_age=rt_max_age)

    return {"message": "Token refreshed"}


@router.get("/me")
async def me(
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Return the current user's profile including key wrapping blobs."""
    # E5: check whether any team the user belongs to is covered by an active
    # escrow policy. Returns true when either:
    #   (a) a policy with escrow_enabled=1 has a team_member effect on that team, OR
    #   (b) a team_escrow effect with escrow_override=1 targets that team.
    cursor = await db.execute(
        """
        SELECT EXISTS (
            SELECT 1 FROM user_team_keys utk
            WHERE utk.user_id = ?
            AND (
                EXISTS (
                    SELECT 1 FROM policy_effects pe
                    JOIN policies p ON p.id = pe.policy_id
                    WHERE pe.effect_type = 'team_member'
                    AND pe.target_id = utk.team_id
                    AND p.escrow_enabled = 1
                )
                OR EXISTS (
                    SELECT 1 FROM policy_effects pe2
                    WHERE pe2.effect_type = 'team_escrow'
                    AND pe2.target_id = utk.team_id
                    AND pe2.escrow_override = 1
                )
            )
        ) AS escrow_active
        """,
        (user.id,),
    )
    row = await cursor.fetchone()
    escrow_active = bool(row["escrow_active"]) if row else False
    return {"user": {**_user_response_dict(user), "escrow_active": escrow_active}}


# ---------------------------------------------------------------------------
# Asymmetric key registration (Phase 5b — PQ-KEM sharing)
# ---------------------------------------------------------------------------

# Max lengths for asymmetric key fields (generous margin over theoretical sizes)
_X25519_PUB_MAX    = 60      # 32 bytes → 44 base64 chars
_MLKEM_PUB_MAX     = 1700    # 1184 bytes → ~1580 base64 chars
_X25519_PRIV_MAX   = 80      # 48 bytes ciphertext → 64 base64 chars
_MLKEM_PRIV_MAX    = 3400    # ~2416 bytes ciphertext → ~3224 base64 chars
_ASYM_IV_MAX       = 36      # 24 bytes (two packed 12-byte IVs) → 32 base64 chars


class RegisterAsymmetricKeysRequest(BaseModel):
    """All five fields are required — keys are always registered atomically."""
    x25519_public_key: str
    mlkem768_public_key: str
    x25519_private_wrapped: str
    mlkem768_private_wrapped: str
    asymmetric_key_iv: str

    @field_validator("x25519_public_key")
    @classmethod
    def val_x25519_pub(cls, v: str) -> str:
        return validate_base64(v, max_length=_X25519_PUB_MAX)

    @field_validator("mlkem768_public_key")
    @classmethod
    def val_mlkem_pub(cls, v: str) -> str:
        return validate_base64(v, max_length=_MLKEM_PUB_MAX)

    @field_validator("x25519_private_wrapped")
    @classmethod
    def val_x25519_priv(cls, v: str) -> str:
        return validate_base64(v, max_length=_X25519_PRIV_MAX)

    @field_validator("mlkem768_private_wrapped")
    @classmethod
    def val_mlkem_priv(cls, v: str) -> str:
        return validate_base64(v, max_length=_MLKEM_PRIV_MAX)

    @field_validator("asymmetric_key_iv")
    @classmethod
    def val_asym_iv(cls, v: str) -> str:
        return validate_base64(v, max_length=_ASYM_IV_MAX)


@router.post("/me/asymmetric-keys")
async def register_asymmetric_keys(
    body: RegisterAsymmetricKeysRequest,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Register or update the current user's hybrid X25519 + ML-KEM-768 key pair.

    All five fields (two public, two wrapped private, one IV) are required.
    Private keys are wrapped with the user's masterKey client-side — the server
    never sees raw private key material.
    """
    await db.execute(
        "UPDATE users SET "
        "x25519_public_key = ?, mlkem768_public_key = ?, "
        "x25519_private_wrapped = ?, mlkem768_private_wrapped = ?, "
        "asymmetric_key_iv = ?, "
        "updated_at = NOW() "
        "WHERE id = ?",
        (
            body.x25519_public_key, body.mlkem768_public_key,
            body.x25519_private_wrapped, body.mlkem768_private_wrapped,
            body.asymmetric_key_iv, user.id,
        ),
    )
    await db.commit()
    return {"message": "Asymmetric keys registered"}


# ---------------------------------------------------------------------------
# Invite validation (consumed during OPAQUE register/finish)
# ---------------------------------------------------------------------------

@router.get("/invite/{token}")
async def validate_invite(token: str, db=Depends(get_db)):
    """Validate a registration invite token.

    Returns 200 if the token is valid, unexpired, and unused.
    Returns 404 otherwise (same response for expired/used/nonexistent
    to prevent oracle attacks on the token space).
    """
    if not token or len(token) > 200:
        raise HTTPException(status_code=404, detail="Invalid invite")

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    cursor = await db.execute(
        "SELECT id FROM invites WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        (token_hash, now),
    )
    if await cursor.fetchone() is None:
        raise HTTPException(status_code=404, detail="Invite not found, expired, or already used")

    return {"valid": True}


@router.get("/users/{username}/public-keys")
async def get_user_public_keys(
    username: str,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Look up another user's X25519 + ML-KEM-768 public keys.

    Used during share creation to encrypt file keys for a specific recipient.
    Returns only public key material — never private key blobs.
    Returns 404 if the user does not exist or has not registered PQ keys yet.
    """
    username = sanitize_username(username)

    cursor = await db.execute(
        "SELECT username, x25519_public_key, mlkem768_public_key FROM users "
        "WHERE LOWER(username) = LOWER(?) AND is_active = 1",
        (username,),
    )
    row = await cursor.fetchone()

    if row is None or row["x25519_public_key"] is None or row["mlkem768_public_key"] is None:
        raise HTTPException(
            status_code=404,
            detail="User not found or has not set up sharing keys yet. "
                   "They must log in once before they can receive shares.",
        )

    return {
        "username": row["username"],
        "x25519_public_key": row["x25519_public_key"],
        "mlkem768_public_key": row["mlkem768_public_key"],
    }


# ---------------------------------------------------------------------------
# Step-up authentication (sensitive action re-auth)
# ---------------------------------------------------------------------------

class StepUpRequest(BaseModel):
    action_key: str
    payload_hash: str     # SHA-256 hex of the request body the client will send
    timestamp: int        # unix seconds (client clock)
    hmac: str             # hex HMAC-SHA256 proving key derivation

    # OPAQUE path fields
    session_id: str | None = None
    client_login_finish: str | None = None   # base64 CredentialFinalization bytes

    @field_validator("action_key")
    @classmethod
    def validate_action_key(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("action_key must be 1–128 characters")
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._*")
        if not all(c in allowed for c in v):
            raise ValueError("action_key contains invalid characters")
        return v

    @field_validator("payload_hash")
    @classmethod
    def validate_payload_hash(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("payload_hash must be a 64-char hex string (SHA-256)")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: int) -> int:
        import time
        now = int(time.time())
        if abs(now - v) > 600:
            raise ValueError("timestamp is too far from server time")
        return v

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                return validate_uuid(v)
            except ValueError:
                raise ValueError("session_id must be a valid UUID")
        return v

    @field_validator("client_login_finish")
    @classmethod
    def validate_client_login_finish(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v, max_length=512)  # CredentialFinalization ~256 bytes → 344 b64
        return v

    @field_validator("hmac")
    @classmethod
    def validate_hmac(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 64 or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("hmac must be a 64-char hex string")
        return v


@router.post("/step-up")
async def step_up(
    body: StepUpRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_user_role),
    db=Depends(get_db),
):
    """Issue a step-up token after verifying OPAQUE re-authentication credentials.

    The client re-runs an OPAQUE login exchange (via /auth/opaque/step-up/start),
    computes an HMAC over the pending action payload, and POSTs here.  On success
    a short-lived JWT is returned.  The client attaches it as
    X-Step-Up-Token: <token> when retrying the sensitive request.
    """
    client_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    if not sensitive_config.is_sensitive(body.action_key):
        raise HTTPException(status_code=400, detail="action_key is not a sensitive function")

    if not body.session_id or not body.client_login_finish:
        raise HTTPException(
            status_code=422,
            detail="OPAQUE step-up requires session_id and client_login_finish",
        )

    verifier = get_verifier("opaque")
    credential = (body.session_id, body.client_login_finish)

    context = StepUpContext(
        action_key=body.action_key,
        payload_hash=body.payload_hash,
        timestamp=body.timestamp,
        hmac_hex=body.hmac,
    )

    verified = await verifier.verify(credential, context, user, db)

    if not verified:
        count = await failure_tracker.record_failure(user.id)
        logger.warning(
            "Step-up failed: user=%s action=%s ip=%s (failure %d/%d)",
            user.id, body.action_key, client_ip, count, settings.STEP_UP_MAX_FAILURES,
        )
        await log_security_event(
            db, "step_up_failed", user.id, client_ip, user_agent,
            action_key=body.action_key,
            detail={"failure_count": count, "max_failures": settings.STEP_UP_MAX_FAILURES},
        )

        if count >= settings.STEP_UP_MAX_FAILURES:
            await db.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
                (user.id,),
            )
            await db.commit()
            await log_security_event(
                db, "step_up_lockout", user.id, client_ip, user_agent,
                action_key=body.action_key,
                detail={"failure_count": count},
            )
            logger.warning(
                "Step-up lockout: user=%s — all sessions revoked after %d failures",
                user.id, count,
            )
            raise HTTPException(
                status_code=403,
                detail="Too many failed attempts. Your session has been invalidated for security.",
            )

        raise HTTPException(status_code=403, detail="Step-up verification failed")

    await failure_tracker.reset(user.id)
    token = create_step_up_token(user.id, body.action_key, body.payload_hash)

    await log_security_event(
        db, "step_up_granted", user.id, client_ip, user_agent,
        action_key=body.action_key,
        detail={
            "payload_hash": body.payload_hash,
            "window_seconds": settings.STEP_UP_WINDOW_SECONDS,
        },
    )
    logger.info(
        "Step-up granted: user=%s action=%s ip=%s window=%ds",
        user.id, body.action_key, client_ip, settings.STEP_UP_WINDOW_SECONDS,
    )

    # Trigger 1 — fire-and-forget policy evaluation on step-up (E3).
    # Step-up confirms the user knows their password; treat it the same as login
    # for policy freshness.  Do not await — step-up response returns immediately.
    # Uses its own db_session() connection (see opaque_auth.py Trigger 1 note).
    try:
        from app.models.policy import evaluate_user_policies as _eval_policies
        from app.database import db_session as _db_session
        _uid = user.id
        async def _bg_step_up_eval() -> None:
            try:
                async with _db_session() as _bg_db:
                    await _eval_policies(_bg_db, _uid)
            except Exception:
                pass
        asyncio.create_task(_bg_step_up_eval())
    except Exception:
        pass  # policy engine must not block step-up

    return {"step_up_token": token}
