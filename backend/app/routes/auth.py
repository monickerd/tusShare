"""Authentication routes: login, logout, refresh, profile, and registration."""

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone

import base64 as _b64

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, field_validator

from app.auth.dependencies import get_current_user, require_user_role, _get_auth_provider
from app.auth.interface import AuthenticatedUser, LocalCredentials
from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    generate_csrf_token,
    hash_refresh_token,
    store_refresh_token,
)
from app.auth.local import LocalAuthProvider
from app.conf.auth import BCRYPT_ROUNDS, PASSWORD_LOGIN_MIN_LENGTH, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, REFRESH_TOKEN_COOKIE_PATH
from app.config import settings
from app.database import get_db
from app.models.role import ROLE_USER
from app.validation.sanitizers import sanitize_username, validate_base64

logger = logging.getLogger(__name__)

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < PASSWORD_LOGIN_MIN_LENGTH or len(v) > PASSWORD_MAX_LENGTH:
            raise ValueError(f"Password must be {PASSWORD_LOGIN_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    new_encryption_salt: str
    new_wrapped_master_key: str
    new_wrapped_master_key_iv: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < PASSWORD_MIN_LENGTH or len(v) > PASSWORD_MAX_LENGTH:
            raise ValueError(f"Password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters")
        return v

    @field_validator("new_encryption_salt")
    @classmethod
    def validate_salt(cls, v: str) -> str:
        # Minimum 64 hex chars = 32 bytes, matching ENCRYPTION_SALT_BYTES.
        # A shorter salt weakens the uniqueness guarantee PBKDF2 relies on.
        if not v or len(v) < 64 or len(v) > 128 or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("Invalid encryption salt (expected 64–128 hex chars)")
        return v

    @field_validator("new_wrapped_master_key")
    @classmethod
    def validate_wrapped_key(cls, v: str) -> str:
        validate_base64(v)
        # AES-256-GCM wrap of a 32-byte key = 32 bytes key + 16 bytes tag = 48 bytes minimum
        try:
            raw_len = len(_b64.b64decode(v + "=="))
        except Exception:
            raise ValueError("Invalid base64 encoding for new_wrapped_master_key")
        if raw_len < 48:
            raise ValueError(
                "new_wrapped_master_key is too short to be a valid AES-256-GCM ciphertext"
            )
        return v

    @field_validator("new_wrapped_master_key_iv")
    @classmethod
    def validate_wrapped_key_iv(cls, v: str) -> str:
        validate_base64(v)
        # AES-GCM IV must be at least 12 bytes
        try:
            raw_len = len(_b64.b64decode(v + "=="))
        except Exception:
            raise ValueError("Invalid base64 encoding for new_wrapped_master_key_iv")
        if raw_len < 12:
            raise ValueError(
                "new_wrapped_master_key_iv is too short to be a valid AES-GCM IV"
            )
        return v


def _user_response_dict(user) -> dict:
    """Build the user dict returned to the client, including key wrapping blobs and roles.

    Includes wrapped private keys so the client can unwrap them after login
    using the masterKey.  Public keys are also returned for informational use.
    """
    return {
        "id": user.id,
        "username": user.username,
        "is_admin": user.is_admin,
        "is_admin_only": user.is_admin_only,
        "roles": sorted(user.roles),
        "encryption_salt": user.encryption_salt,
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


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str, csrf_token: str) -> None:
    """Set authentication cookies on a response."""
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path=REFRESH_TOKEN_COOKIE_PATH,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=True,
        samesite="strict",
        path="/",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


def _clear_auth_cookies(response: Response) -> None:
    """Clear all authentication cookies."""
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path=REFRESH_TOKEN_COOKIE_PATH)
    response.delete_cookie(key="csrf_token", path="/")


@router.post("/login")
async def login(
    body: LoginRequest,
    response: Response,
    auth_provider=Depends(_get_auth_provider),
    db=Depends(get_db),
):
    """Authenticate with username/password. Sets JWT cookies on success."""
    credentials = LocalCredentials(username=body.username, password=body.password)
    user = await auth_provider.authenticate(credentials)

    if user is None:
        # Deliberately vague — same message for wrong password and nonexistent user
        raise HTTPException(status_code=401, detail="Invalid credentials")

    raw_refresh, token_hash = create_refresh_token()
    token_id = await store_refresh_token(db, user.id, token_hash)
    access_token = create_access_token(user.id, user.is_admin, session_id=token_id)
    csrf_token = generate_csrf_token()

    _set_auth_cookies(response, access_token, raw_refresh, csrf_token)

    return {"user": _user_response_dict(user)}


@router.post("/logout")
async def logout(
    response: Response,
    request: Request,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    """Revoke refresh token and clear cookies."""
    refresh_token = request.cookies.get("refresh_token")
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
    raw_refresh = request.cookies.get("refresh_token")
    if not raw_refresh:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    token_hash = hash_refresh_token(raw_refresh)
    now = datetime.now(timezone.utc).isoformat()

    # Atomic: validate + revoke + issue in a single write transaction
    await db.execute("BEGIN IMMEDIATE")
    try:
        # Validate: find a non-revoked, non-expired token
        cursor = await db.execute(
            "SELECT id, user_id FROM refresh_tokens "
            "WHERE token_hash = ? AND revoked = 0 AND expires_at > ?",
            (token_hash, now),
        )
        row = await cursor.fetchone()
        if row is None:
            await db.execute("ROLLBACK")
            _clear_auth_cookies(response)
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        token_id = row["id"]
        user_id = row["user_id"]

        # Revoke atomically — use WHERE revoked = 0 so a concurrent request
        # that already revoked this token causes 0 rows changed
        await db.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE id = ? AND revoked = 0",
            (token_id,),
        )
        changes_cursor = await db.execute("SELECT changes()")
        changes_row = await changes_cursor.fetchone()
        if changes_row[0] == 0:
            await db.execute("ROLLBACK")
            _clear_auth_cookies(response)
            raise HTTPException(status_code=401, detail="Token already used")

        # Look up user (still inside transaction)
        user = await auth_provider.get_user_by_id(user_id)
        if user is None:
            await db.execute("ROLLBACK")
            _clear_auth_cookies(response)
            raise HTTPException(status_code=401, detail="User not found or inactive")

        # Issue new tokens inside same transaction
        new_raw_refresh, new_token_hash = create_refresh_token()
        new_token_id = str(uuid.uuid4())
        new_now = datetime.now(timezone.utc).isoformat()
        new_expires_at = (
            datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        ).isoformat()
        await db.execute(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, last_active_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (new_token_id, user_id, new_token_hash, new_expires_at, new_now),
        )

        await db.commit()
    except HTTPException:
        raise
    except Exception:
        await db.execute("ROLLBACK")
        raise

    access_token = create_access_token(user.id, user.is_admin, session_id=new_token_id)
    csrf_token = generate_csrf_token()
    _set_auth_cookies(response, access_token, new_raw_refresh, csrf_token)

    return {"message": "Token refreshed"}


@router.get("/me")
async def me(user: AuthenticatedUser = Depends(get_current_user)):
    """Return the current user's profile including key wrapping blobs."""
    return {"user": _user_response_dict(user)}


@router.put("/me/password")
async def change_password(
    body: ChangePasswordRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
    auth_provider=Depends(_get_auth_provider),
):
    """Change the current user's password.

    The client must also send the re-wrapped master key (encrypted under the
    new password-derived KEK) so the master key survives the password change.
    """
    # Verify current password
    credentials = LocalCredentials(username=user.username, password=body.current_password)
    verified = await auth_provider.authenticate(credentials)
    if verified is None:
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # Hash new password
    new_hash = bcrypt.hashpw(
        body.new_password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("utf-8")

    # Update password hash and key wrapping blobs atomically.
    # All three wrapped-key fields are required (validated in ChangePasswordRequest)
    # so the master key is always re-wrapped under the new KEK in the same transaction.
    await db.execute("BEGIN IMMEDIATE")
    try:
        await db.execute(
            "UPDATE users SET password_hash = ?, encryption_salt = ?, "
            "wrapped_master_key = ?, wrapped_master_key_iv = ?, "
            "updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') "
            "WHERE id = ?",
            (new_hash, body.new_encryption_salt,
             body.new_wrapped_master_key, body.new_wrapped_master_key_iv, user.id),
        )

        # Revoke all existing refresh tokens (force re-login on other sessions)
        await db.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
            (user.id,),
        )
        await db.commit()
    except Exception:
        await db.execute("ROLLBACK")
        raise

    return {"message": "Password changed. Please log in again on other devices."}


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

    Note: replacing existing keys will make any previously received user shares
    undecryptable until those shares are re-created by senders.  This will be
    enforced more strictly when team PRE rotation is added in Phase 6.
    """
    await db.execute(
        "UPDATE users SET "
        "x25519_public_key = ?, mlkem768_public_key = ?, "
        "x25519_private_wrapped = ?, mlkem768_private_wrapped = ?, "
        "asymmetric_key_iv = ?, "
        "updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') "
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
# Invite validation + registration (Phase 7)
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    """Full registration payload. Client generates all crypto material
    client-side so the server never sees plaintext passwords or key material."""
    token: str
    username: str
    password: str
    encryption_salt: str
    wrapped_master_key: str
    wrapped_master_key_iv: str
    recovery_key_wrapped: str | None = None
    recovery_key_iv: str | None = None
    recovery_key_hash: str | None = None
    # Asymmetric PQ keys (optional — can be set on first post-login key setup)
    x25519_public_key: str | None = None
    mlkem768_public_key: str | None = None
    x25519_private_wrapped: str | None = None
    mlkem768_private_wrapped: str | None = None
    asymmetric_key_iv: str | None = None

    @field_validator("token")
    @classmethod
    def validate_token(cls, v: str) -> str:
        if not v or len(v) > 200:
            raise ValueError("Invalid token")
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return sanitize_username(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < PASSWORD_MIN_LENGTH or len(v) > PASSWORD_MAX_LENGTH:
            raise ValueError(f"Password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters")
        return v

    @field_validator("encryption_salt")
    @classmethod
    def validate_salt(cls, v: str) -> str:
        if not v or len(v) < 64 or len(v) > 128 or not all(c in "0123456789abcdef" for c in v):
            raise ValueError("Invalid encryption salt (expected 64–128 hex chars)")
        return v

    @field_validator("wrapped_master_key")
    @classmethod
    def validate_wrapped_key(cls, v: str) -> str:
        validate_base64(v)
        try:
            raw_len = len(_b64.b64decode(v + "=="))
        except Exception:
            raise ValueError("Invalid base64 for wrapped_master_key")
        if raw_len < 48:
            raise ValueError("wrapped_master_key too short for AES-256-GCM ciphertext")
        return v

    @field_validator("wrapped_master_key_iv")
    @classmethod
    def validate_wrapped_key_iv(cls, v: str) -> str:
        validate_base64(v)
        try:
            raw_len = len(_b64.b64decode(v + "=="))
        except Exception:
            raise ValueError("Invalid base64 for wrapped_master_key_iv")
        if raw_len < 12:
            raise ValueError("wrapped_master_key_iv too short for AES-GCM IV")
        return v

    @field_validator(
        "recovery_key_wrapped", "recovery_key_iv",
        "x25519_public_key", "mlkem768_public_key",
        "x25519_private_wrapped", "mlkem768_private_wrapped",
        "asymmetric_key_iv",
    )
    @classmethod
    def validate_optional_blobs(cls, v: str | None) -> str | None:
        if v is not None:
            validate_base64(v)
        return v

    @field_validator("recovery_key_hash")
    @classmethod
    def validate_recovery_hash(cls, v: str | None) -> str | None:
        if v is not None and (not v or len(v) > 128 or not all(c in "0123456789abcdef" for c in v)):
            raise ValueError("Invalid recovery_key_hash (expected hex)")
        return v


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


@router.post("/register")
async def register(
    body: RegisterRequest,
    response: Response,
    db=Depends(get_db),
):
    """Register a new account using a single-use invite token.

    Invite validation and consumption are atomic (BEGIN IMMEDIATE) to prevent
    two concurrent requests from using the same token. User creation runs in its
    own transaction after the invite is consumed. If user creation fails the
    invite is consumed but no account is created — admin can issue a new invite.

    On success, auth cookies are set and the user is effectively logged in.
    """
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Step 1: Atomically validate and consume the invite
    await db.execute("BEGIN IMMEDIATE")
    try:
        cursor = await db.execute(
            "SELECT id FROM invites WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
            (token_hash, now),
        )
        row = await cursor.fetchone()
        if row is None:
            await db.execute("ROLLBACK")
            raise HTTPException(
                status_code=400,
                detail="Invalid, expired, or already-used invite",
            )

        await db.execute(
            "UPDATE invites SET used_at = ? WHERE id = ?",
            (now, row["id"]),
        )
        await db.commit()
    except HTTPException:
        raise
    except Exception:
        await db.execute("ROLLBACK")
        raise

    # Step 2: Create the user (LocalAuthProvider handles its own transaction)
    provider = LocalAuthProvider(db)
    try:
        user = await provider.create_user(
            username=body.username,
            password=body.password,
            role=ROLE_USER,
            encryption_salt=body.encryption_salt,
            wrapped_master_key=body.wrapped_master_key,
            wrapped_master_key_iv=body.wrapped_master_key_iv,
            recovery_key_wrapped=body.recovery_key_wrapped,
            recovery_key_iv=body.recovery_key_iv,
            recovery_key_hash=body.recovery_key_hash,
            x25519_public_key=body.x25519_public_key,
            mlkem768_public_key=body.mlkem768_public_key,
            x25519_private_wrapped=body.x25519_private_wrapped,
            mlkem768_private_wrapped=body.mlkem768_private_wrapped,
            asymmetric_key_iv=body.asymmetric_key_iv,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    # Issue auth cookies so the client is immediately logged in
    access_token = create_access_token(user.id, user.is_admin)
    raw_refresh, token_hash_rt = create_refresh_token()
    await store_refresh_token(db, user.id, token_hash_rt)
    csrf_token = generate_csrf_token()
    _set_auth_cookies(response, access_token, raw_refresh, csrf_token)

    logger.info("New user registered via invite: %s (id=%s)", user.username, user.id)
    return {"user": _user_response_dict(user)}


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
        "SELECT x25519_public_key, mlkem768_public_key FROM users "
        "WHERE username = ? AND is_active = 1",
        (username,),
    )
    row = await cursor.fetchone()

    if row is None or row["x25519_public_key"] is None or row["mlkem768_public_key"] is None:
        # Same message for both "no such user" and "user has no keys" to prevent
        # authenticated username enumeration via differing 404 bodies.
        raise HTTPException(
            status_code=404,
            detail="User not found or has not set up sharing keys yet. "
                   "They must log in once before they can receive shares.",
        )

    return {
        "username": username,
        "x25519_public_key": row["x25519_public_key"],
        "mlkem768_public_key": row["mlkem768_public_key"],
    }
