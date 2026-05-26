"""Authentication routes: logout, refresh, profile, and step-up re-auth.

Registration and login are handled by the OPAQUE routes in opaque_auth.py.
"""

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, field_validator

import app.sensitive_config as sensitive_config
import app.storage.manager as storage
from app.auth.cookies import clear_auth_cookies, set_auth_cookies, user_response_dict
from app.auth.dependencies import _get_auth_provider, get_current_user, require_user_role
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
    get_verifier,
    log_security_event,
)
from app.conf.auth import COOKIE_REFRESH
from app.config import settings
from app.database import Database, db_session, get_db
from app.middleware.rate_limit import _get_client_ip
from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services import event_bus, live_settings
from app.util.db import get_admin_setting
from app.validation.sanitizers import sanitize_username, validate_base64, validate_uuid

_bg_tasks: set = set()

logger = logging.getLogger(__name__)


async def _delete_user_blobs(rows_snapshot: list) -> None:
    mgr = storage.get_manager()
    async with db_session() as _db:
        for row in rows_snapshot:
            try:
                cur = await _db.execute(
                    "SELECT COUNT(*) AS cnt FROM files WHERE storage_key = ?", (row["storage_key"],)
                )
                cnt = await cur.fetchone()
                if cnt and cnt["cnt"] > 0:
                    continue
                await mgr.delete_blob(_db, row["id"], row["storage_key"])
            except Exception as exc:
                logger.warning("Failed to delete blob %s during self-delete: %s", row["storage_key"], exc)


router = APIRouter()


@router.post("/logout")
async def logout(
    response: Response,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
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

    clear_auth_cookies(response)
    event_bus.emit(
        SecurityEvent(
            event_type="auth.logout",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=str(user.id), username=user.username, ip=_get_client_ip(request)),
        )
    )
    return {"message": "Logged out"}


@router.post("/refresh", responses={401: {"description": "Unauthorized"}})
async def refresh(
    request: Request,
    response: Response,
    db: Annotated[Database, Depends(get_db)],
    auth_provider: Annotated[None, Depends(_get_auth_provider)],
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
            clear_auth_cookies(response)
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
            # A non-revoked token was found in the SELECT but was already revoked
            # by the time we tried to claim it — concurrent consumption detected.
            # Treat as a theft signal: revoke every session for this user and
            # commit so the revocations persist even though the rotation failed.
            await db.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
                (user_id,),
            )
            await db.commit()
            clear_auth_cookies(response)
            event_bus.emit(
                SecurityEvent(
                    event_type="auth.session.force_terminated",
                    severity="critical",
                    outcome="success",
                    actor=EventActor(user_id=str(user_id), ip=_get_client_ip(request)),
                    detail={"reason": "refresh_token_reuse_detected"},
                )
            )
            raise HTTPException(status_code=401, detail="Session invalidated. Please log in again.")

        # Look up user (still inside transaction)
        user = await auth_provider.get_user_by_id(user_id)
        if user is None:
            await db.rollback()
            clear_auth_cookies(response)
            raise HTTPException(status_code=401, detail="User not found or inactive")

        # Issue new tokens inside same transaction — preserve is_public_device
        new_raw_refresh, new_token_hash = create_refresh_token()
        new_token_id = str(uuid.uuid4())
        new_now = datetime.now(timezone.utc).isoformat()
        if is_public_device:
            new_expires_at = (
                datetime.now(timezone.utc)
                + timedelta(
                    minutes=live_settings.get_int(
                        "public_device_refresh_minutes", settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES
                    )
                )
            ).isoformat()
        else:
            new_expires_at = (
                datetime.now(timezone.utc)
                + timedelta(days=live_settings.get_int("refresh_token_expire_days", settings.REFRESH_TOKEN_EXPIRE_DAYS))
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
    rt_max_age = (
        live_settings.get_int("public_device_refresh_minutes", settings.PUBLIC_DEVICE_REFRESH_TOKEN_MINUTES) * 60
        if is_public_device
        else None
    )
    set_auth_cookies(response, access_token, new_raw_refresh, csrf_token, max_age=rt_max_age)

    return {"message": "Token refreshed"}


@router.get("/me")
async def me(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return the current user's profile including key wrapping blobs."""
    # check whether any team the user belongs to is covered by an active
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
    return {"user": {**user_response_dict(user), "escrow_active": escrow_active}}


# ---------------------------------------------------------------------------
# User preferences (UI layout etc.)
# ---------------------------------------------------------------------------


@router.get("/me/prefs")
async def get_my_prefs(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return the current user's UI preferences blob."""
    cursor = await db.execute("SELECT ui_prefs FROM users WHERE id = ?", (user.id,))
    row = await cursor.fetchone()
    prefs = json.loads(row["ui_prefs"]) if row and row["ui_prefs"] else {}
    return {"ui_prefs": prefs}


_MAX_PINS = 100
_PIN_STR_MAX = 255


def _clean_pinned_folders(items: list) -> list:
    cleaned = []
    for item in items[:_MAX_PINS]:
        if not isinstance(item, dict):
            continue
        fid = str(item.get("id", ""))[:64]
        name = str(item.get("name", ""))[:_PIN_STR_MAX]
        hash_ = str(item.get("hash", ""))[:_PIN_STR_MAX]
        if fid:
            team_id = str(item.get("team_id", "") or "")[:64] or None
            team_name = str(item.get("team_name", "") or "")[:_PIN_STR_MAX] or None
            path = str(item.get("path", "") or "")[:_PIN_STR_MAX] or None
            cleaned.append(
                {"id": fid, "name": name, "hash": hash_, "team_id": team_id, "team_name": team_name, "path": path}
            )
    return cleaned


class UpdatePrefsRequest(BaseModel):
    admin_layout: dict | None = None
    pinned_folders: list | None = None
    role_order: list | None = None
    teams_view: str | None = None
    team_folders_view: str | None = None


@router.patch("/me/prefs")
async def update_my_prefs(
    body: UpdatePrefsRequest,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Merge the supplied preference keys into the user's ui_prefs blob."""
    cursor = await db.execute("SELECT ui_prefs FROM users WHERE id = ?", (user.id,))
    row = await cursor.fetchone()
    prefs = json.loads(row["ui_prefs"]) if row and row["ui_prefs"] else {}

    if body.admin_layout is not None:
        prefs["admin_layout"] = body.admin_layout

    if body.role_order is not None:
        cleaned_order = [str(x)[:64] for x in body.role_order if isinstance(x, str)]
        prefs["role_order"] = cleaned_order

    if body.teams_view in ("tile", "list"):
        prefs["teams_view"] = body.teams_view

    if body.team_folders_view in ("tile", "list"):
        prefs["team_folders_view"] = body.team_folders_view

    if body.pinned_folders is not None:
        prefs["pinned_folders"] = _clean_pinned_folders(body.pinned_folders)

    await db.execute(
        "UPDATE users SET ui_prefs = ? WHERE id = ?",
        (json.dumps(prefs), user.id),
    )
    await db.commit()
    return {"ui_prefs": prefs}


# ---------------------------------------------------------------------------
# Recent folder activity
# ---------------------------------------------------------------------------

_RECENT_MAX = 4
_RECENT_STR_MAX = 255


@router.get("/me/recent-folders")
async def get_recent_folders(
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return up to 4 most-recently-interacted folders for the current user."""
    cursor = await db.execute(
        """
        SELECT folder_id, team_id, folder_name, team_name, interacted_at
        FROM   user_folder_recent
        WHERE  user_id = ?
        ORDER  BY interacted_at DESC
        LIMIT  ?
        """,
        (user.id, _RECENT_MAX),
    )
    rows = await cursor.fetchall()
    return {
        "recent_folders": [
            {
                "folder_id": r["folder_id"],
                "team_id": r["team_id"],
                "folder_name": r["folder_name"],
                "team_name": r["team_name"],
                "interacted_at": r["interacted_at"],
                "hash": (f"#/team-folders/{r['folder_id']}" if r["team_id"] else f"#/files/{r['folder_id']}"),
            }
            for r in rows
        ]
    }


async def record_folder_activity(
    db: Database,
    user_id: str,
    folder_id: str,
    team_id: str | None,
    folder_name: str,
    team_name: str | None,
) -> None:
    """Upsert a recent-folder row for user_id/folder_id; evict 5th+ oldest rows."""
    folder_name = str(folder_name or "")[:_RECENT_STR_MAX]
    team_name = str(team_name or "")[:_RECENT_STR_MAX] or None
    await db.execute(
        """
        INSERT INTO user_folder_recent
               (user_id, folder_id, team_id, folder_name, team_name, interacted_at)
        VALUES (?, ?, ?, ?, ?, NOW())
        ON CONFLICT (user_id, folder_id) DO UPDATE
            SET team_id       = EXCLUDED.team_id,
                folder_name   = EXCLUDED.folder_name,
                team_name     = EXCLUDED.team_name,
                interacted_at = EXCLUDED.interacted_at
        """,
        (user_id, folder_id, team_id, folder_name, team_name),
    )
    # Evict rows beyond the max (keep the 4 most recent)
    await db.execute(
        """
        DELETE FROM user_folder_recent
        WHERE  user_id = ?
          AND  folder_id NOT IN (
              SELECT folder_id FROM user_folder_recent
              WHERE  user_id = ?
              ORDER  BY interacted_at DESC
              LIMIT  ?
          )
        """,
        (user_id, user_id, _RECENT_MAX),
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Asymmetric key registration (Phase 5b — PQ-KEM sharing)
# ---------------------------------------------------------------------------

# Max lengths for asymmetric key fields (generous margin over theoretical sizes)
_X25519_PUB_MAX = 60  # 32 bytes → 44 base64 chars
_MLKEM_PUB_MAX = 1700  # 1184 bytes → ~1580 base64 chars
_X25519_PRIV_MAX = 80  # 48 bytes ciphertext → 64 base64 chars
_MLKEM_PRIV_MAX = 3400  # ~2416 bytes ciphertext → ~3224 base64 chars
_ASYM_IV_MAX = 36  # 24 bytes (two packed 12-byte IVs) → 32 base64 chars


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
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
            body.x25519_public_key,
            body.mlkem768_public_key,
            body.x25519_private_wrapped,
            body.mlkem768_private_wrapped,
            body.asymmetric_key_iv,
            user.id,
        ),
    )
    await db.commit()
    return {"message": "Asymmetric keys registered"}


# ---------------------------------------------------------------------------
# Invite validation (consumed during OPAQUE register/finish)
# ---------------------------------------------------------------------------


@router.get("/invite/{token}", responses={404: {"description": "Not Found"}})
async def validate_invite(token: str, db: Annotated[Database, Depends(get_db)]):
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


@router.get("/public-settings")
async def get_public_settings(db: Annotated[Database, Depends(get_db)]):
    """Return public configuration that unauthenticated clients need before login.

    Exposes the server-enforced upload chunk size so the client uses the correct
    value when creating a new tus upload.  No auth required.
    """
    cs_val = await get_admin_setting(db, "default_chunk_size")
    chunk_size = int(cs_val) if cs_val is not None else settings.DEFAULT_CHUNK_SIZE
    allow_delete = await get_admin_setting(db, "allow_user_delete_own_account") or "false"
    can_delete_owned = await get_admin_setting(db, "can_delete_owned_shared") or "false"
    return {
        "chunk_size": chunk_size,
        "allow_user_delete_own_account": allow_delete,
        "can_delete_owned_shared": can_delete_owned,
    }


@router.get("/users/{username}/public-keys", responses={404: {"description": "Not Found"}})
async def get_user_public_keys(
    username: str,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
    payload_hash: str  # SHA-256 hex of the request body the client will send
    timestamp: int  # unix seconds (client clock)
    hmac: str  # hex HMAC-SHA256 proving key derivation

    # OPAQUE path fields
    session_id: str | None = None
    client_login_finish: str | None = None  # base64 CredentialFinalization bytes

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


async def _count_step_up_failures(db, user_id: str) -> int:
    """Count step-up failures since the last granted/lockout event (persists across restarts)."""
    cursor = await db.execute(
        "SELECT COUNT(*) AS cnt FROM security_events "
        "WHERE user_id = ? AND event_type = 'step_up_failed' "
        "AND timestamp > COALESCE("
        "  (SELECT MAX(timestamp) FROM security_events "
        "   WHERE user_id = ? AND event_type IN ('step_up_granted', 'step_up_lockout')), "
        "  '1970-01-01'::timestamptz"
        ")",
        (user_id, user_id),
    )
    row = await cursor.fetchone()
    return int(row[0]) if row else 0


@router.post(
    "/step-up",
    responses={
        400: {"description": "Bad Request"},
        403: {"description": "Forbidden"},
        422: {"description": "Unprocessable Entity"},
    },
)
async def step_up(
    body: StepUpRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_user_role)],
    db: Annotated[Database, Depends(get_db)],
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
        # Log the failure first so the DB count includes it, then query for persistence.
        _step_up_max = live_settings.get_int("step_up_max_failures", settings.STEP_UP_MAX_FAILURES)
        await log_security_event(
            db,
            "step_up_failed",
            user.id,
            client_ip,
            user_agent,
            username=user.username,
            action_key=body.action_key,
            detail={"max_failures": _step_up_max},
        )
        count = await _count_step_up_failures(db, user.id)
        logger.warning(  # NOSONAR — server-side audit log; values are Pydantic-validated
            "Step-up failed: user=%s action=%s ip=%s (failure %d/%d)",
            user.id,
            body.action_key,
            client_ip,
            count,
            _step_up_max,
        )

        if count >= _step_up_max:
            await db.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
                (user.id,),
            )
            await db.commit()
            await log_security_event(
                db,
                "step_up_lockout",
                user.id,
                client_ip,
                user_agent,
                username=user.username,
                action_key=body.action_key,
                detail={"failure_count": count},
            )
            logger.warning(
                "Step-up lockout: user=%s — all sessions revoked after %d failures",
                user.id,
                count,
            )
            raise HTTPException(
                status_code=403,
                detail="Too many failed attempts. Your session has been invalidated for security.",
            )

        raise HTTPException(status_code=403, detail="Step-up verification failed")

    token = create_step_up_token(user.id, body.action_key, body.payload_hash, session_id=user.session_id)

    await log_security_event(
        db,
        "step_up_granted",
        user.id,
        client_ip,
        user_agent,
        username=user.username,
        action_key=body.action_key,
        detail={
            "payload_hash": body.payload_hash,
            "window_seconds": live_settings.get_int("step_up_window_seconds", settings.STEP_UP_WINDOW_SECONDS),
        },
    )
    logger.info(  # NOSONAR — server-side audit log; values are Pydantic-validated
        "Step-up granted: user=%s action=%s ip=%s window=%ds",
        user.id,
        body.action_key,
        client_ip,
        live_settings.get_int("step_up_window_seconds", settings.STEP_UP_WINDOW_SECONDS),
    )

    # Trigger 1 — fire-and-forget policy evaluation on step-up.
    # Step-up confirms the user knows their password; treat it the same as login
    # for policy freshness.  Do not await — step-up response returns immediately.
    # Uses its own db_session() connection (see opaque_auth.py Trigger 1 note).
    try:
        from app.database import db_session as _db_session
        from app.models.policy import evaluate_user_policies as _eval_policies

        _uid = user.id

        async def _bg_step_up_eval() -> None:
            try:
                async with _db_session() as _bg_db:
                    await _eval_policies(_bg_db, _uid)
            except Exception:
                pass

        _t = asyncio.create_task(_bg_step_up_eval())
        _bg_tasks.add(_t)
        _t.add_done_callback(_bg_tasks.discard)
    except Exception:
        pass  # policy engine must not block step-up

    return {"step_up_token": token}


# ---------------------------------------------------------------------------
# Session management (self-service)
# ---------------------------------------------------------------------------


@router.get("/me/sessions")
async def list_my_sessions(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """List all active sessions for the current user. The current session is flagged."""
    cursor = await db.execute(
        """
        SELECT id, created_at, last_active_at, expires_at, is_public_device
        FROM refresh_tokens
        WHERE user_id = ? AND revoked = 0 AND expires_at > NOW()
        ORDER BY last_active_at DESC NULLS LAST
        """,
        (user.id,),
    )
    rows = await cursor.fetchall()
    return {
        "sessions": [
            {
                "id": row["id"],
                "created_at": str(row["created_at"]),
                "last_active_at": str(row["last_active_at"]) if row["last_active_at"] else None,
                "expires_at": str(row["expires_at"]),
                "is_public_device": bool(row["is_public_device"]),
                "is_current": row["id"] == user.session_id,
            }
            for row in rows
        ]
    }


@router.delete(
    "/me/sessions/{token_id}", responses={400: {"description": "Bad Request"}, 404: {"description": "Not Found"}}
)
async def revoke_session(
    token_id: str,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Revoke a specific session. Cannot revoke the current session."""
    token_id = validate_uuid(token_id)
    if token_id == user.session_id:
        raise HTTPException(status_code=400, detail="Cannot revoke the current session; use logout instead")
    result = await db.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE id = ? AND user_id = ? AND revoked = 0",
        (token_id, user.id),
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    event_bus.emit(
        SecurityEvent(
            event_type="auth.session.revoked",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=str(user.id), username=user.username, ip=_get_client_ip(request)),
            detail={"scope": "single", "session_id": token_id},
        )
    )
    return {"message": "Session revoked"}


@router.delete("/me/sessions")
async def revoke_other_sessions(
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Revoke all sessions except the current one."""
    result = await db.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND id != ? AND revoked = 0",
        (user.id, user.session_id or ""),
    )
    await db.commit()
    event_bus.emit(
        SecurityEvent(
            event_type="auth.session.revoked",
            severity="info",
            outcome="success",
            actor=EventActor(user_id=str(user.id), username=user.username, ip=_get_client_ip(request)),
            detail={"scope": "all_others", "count": result.rowcount},
        )
    )
    return {"revoked": result.rowcount}


# ---------------------------------------------------------------------------
# User activity log (self-service — hard-filtered to caller's own events)
# ---------------------------------------------------------------------------


@router.get("/me/activity")
async def my_activity(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
    page: int = 1,
    activity_filter: str | None = None,
):
    """Return paginated activity events for the calling user.

    Merges security_events (login, MFA, step-up) with access_logs (file
    upload/download/delete/share). Filtered strictly by user_id —
    never taken from a query param.

    Query params:
      page            — 1-based page number (20 events per page)
      activity_filter — "notifications" returns only file-access events
    """
    page = max(1, page)
    page_size = 20
    offset = (page - 1) * page_size

    if activity_filter == "notifications":
        cursor = await db.execute(
            """
            SELECT 'access'::text AS source, al.action AS event_type,
                   NULL::text AS severity, NULL::text AS outcome, al.ip_address,
                   NULL::text AS actor_session_id, al.timestamp,
                   'file'::text AS target_type, al.file_id AS target_id,
                   f.original_name AS target_name, NULL::text AS detail
            FROM access_logs al
            LEFT JOIN files f ON f.id = al.file_id
            WHERE al.user_id = ?
            ORDER BY al.timestamp DESC
            LIMIT ? OFFSET ?
            """,
            (user.id, page_size + 1, offset),
        )
    else:
        cursor = await db.execute(
            """
            SELECT source, event_type, severity, outcome, ip_address, actor_session_id,
                   timestamp, target_type, target_id, target_name, detail
            FROM (
                SELECT 'security'::text AS source, event_type, severity, outcome, ip_address,
                       actor_session_id, timestamp, target_type, target_id, target_name, detail
                FROM security_events
                WHERE user_id = ?
                UNION ALL
                SELECT 'access'::text AS source, al.action AS event_type,
                       NULL::text AS severity, NULL::text AS outcome, al.ip_address,
                       NULL::text AS actor_session_id, al.timestamp,
                       'file'::text AS target_type, al.file_id AS target_id,
                       f.original_name AS target_name, NULL::text AS detail
                FROM access_logs al
                LEFT JOIN files f ON f.id = al.file_id
                WHERE al.user_id = ?
            ) combined
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            (user.id, user.id, page_size + 1, offset),
        )

    rows = await cursor.fetchall()
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    return {
        "events": [
            {
                "source": row["source"],
                "event_type": row["event_type"],
                "severity": row["severity"] or "info",
                "outcome": row["outcome"],
                "ip_address": row["ip_address"],
                "session_id": row["actor_session_id"],
                "timestamp": str(row["timestamp"]),
                "target_type": row["target_type"],
                "target_id": row["target_id"],
                "target_name": row["target_name"],
                "detail": (json.loads(row["detail"]) if row["detail"] else None),
            }
            for row in rows
        ],
        "has_more": has_more,
        "page": page,
    }


# ---------------------------------------------------------------------------
# Self-delete account
# ---------------------------------------------------------------------------


@router.get("/me/owned-shared")
async def get_owned_shared(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Return teams the calling user is the sole owner of.

    Used by the frontend to warn before account deletion — if any teams are
    returned, the user should promote another owner before proceeding.
    """
    cursor = await db.execute(
        "SELECT id, name FROM teams WHERE owner_id = ? ORDER BY name",
        (user.id,),
    )
    rows = await cursor.fetchall()
    return {
        "owned_teams": [{"id": row["id"], "name": row["name"]} for row in rows],
    }


@router.delete("/me", responses={403: {"description": "Forbidden"}, 409: {"description": "Conflict"}})
async def delete_my_account(
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    db: Annotated[Database, Depends(get_db)],
):
    """Delete the calling user's own account and all associated files.

    Requires the allow_user_delete_own_account admin setting to be 'true'.
    Admin-only accounts (no user role) are not permitted to self-delete.

    If the user is the owner of any teams, the can_delete_owned_shared setting
    governs whether those teams are deleted (true) or the request is rejected
    (false) with a 409 listing the owned teams.
    """
    if not user.is_user:
        raise HTTPException(status_code=403, detail="Admin-only accounts cannot self-delete")

    cursor = await db.execute(
        "SELECT key, value FROM admin_settings "
        "WHERE key IN ('allow_user_delete_own_account', 'can_delete_owned_shared')"
    )
    settings_rows = await cursor.fetchall()
    settings = {row["key"]: row["value"] for row in settings_rows}

    if settings.get("allow_user_delete_own_account") != "true":
        raise HTTPException(status_code=403, detail="Self-deletion is not enabled on this server")

    # Check for owned teams
    cursor = await db.execute("SELECT id, name FROM teams WHERE owner_id = ?", (user.id,))
    owned_teams = await cursor.fetchall()

    if owned_teams:
        if settings.get("can_delete_owned_shared") != "true":
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "owned_teams",
                    "message": "You are the owner of teams that must be managed before deleting your account.",
                    "teams": [{"id": row["id"], "name": row["name"]} for row in owned_teams],
                },
            )
        # Delete owned teams first (cascades to team_folders, file_team_keys, etc.)
        for team_row in owned_teams:
            await db.execute("DELETE FROM teams WHERE id = ?", (team_row["id"],))

    # Collect file storage keys before CASCADE deletes them
    cursor = await db.execute("SELECT id, storage_key FROM files WHERE owner_id = ?", (user.id,))
    file_rows = await cursor.fetchall()

    await db.execute("DELETE FROM users WHERE id = ?", (user.id,))
    await db.commit()

    event_bus.emit(
        SecurityEvent(
            event_type="user.self_deleted",
            severity="warning",
            outcome="success",
            actor=EventActor(user_id=user.id, username=user.username, ip=_get_client_ip(request)),
            target=EventTarget(type="user", id=user.id, name=user.username),
            detail={"owned_teams_deleted": len(owned_teams)} if owned_teams else {},
        )
    )

    rows_snapshot = list(file_rows)

    _t = asyncio.create_task(_delete_user_blobs(rows_snapshot))
    _bg_tasks.add(_t)
    _t.add_done_callback(_bg_tasks.discard)

    return {"message": "Account deleted"}
