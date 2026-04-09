"""JWT token creation and validation."""

import asyncio
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt

from app.conf.auth import CSRF_TOKEN_BYTES, REFRESH_TOKEN_BYTES
from app.config import settings
from app.database import db_session

logger = logging.getLogger(__name__)


def create_access_token(
    user_id: str,
    is_admin: bool,
    session_id: str | None = None,
    is_public_device: bool = False,
) -> str:
    """Create a short-lived JWT access token.

    session_id (sid claim) is the refresh_tokens.id for this session.  When
    present, get_current_user uses it to touch last_active_at on each request
    so the idle-timeout cleanup task can accurately track inactivity.

    is_public_device (pub claim) is stored so the client can detect a public
    device session after tab close (when sessionStorage has been cleared) and
    skip the key-prompt screen in favour of the login screen.
    """
    now = datetime.now(timezone.utc)
    payload: dict = {
        "sub": user_id,
        "admin": is_admin,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "type": "access",
    }
    if session_id:
        payload["sid"] = session_id
    if is_public_device:
        payload["pub"] = True
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_access_token(token: str) -> dict:
    """Verify and decode an access token. Raises jwt.PyJWTError on failure."""
    payload = jwt.decode(
        token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
    )
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Not an access token")
    return payload


def create_refresh_token() -> tuple[str, str]:
    """Create a refresh token.

    Returns (raw_token, token_hash). The raw token goes to the client cookie;
    the hash is stored in the database.
    """
    raw_token = secrets.token_urlsafe(REFRESH_TOKEN_BYTES)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash


def hash_refresh_token(raw_token: str) -> str:
    """Hash a raw refresh token for database lookup."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


async def store_refresh_token(
    db,
    user_id: str,
    token_hash: str,
    expire_minutes: int | None = None,
    is_public_device: bool = False,
) -> str:
    """Store a refresh token hash in the database. Returns the token row ID.

    expire_minutes overrides the default REFRESH_TOKEN_EXPIRE_DAYS TTL.
    is_public_device is stored in the row for admin audit and future policy use.

    Also prunes expired or revoked tokens for this user to prevent unbounded
    accumulation when a user logs in many times without logging out.
    """
    token_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    if expire_minutes is not None:
        expires_at = (now + timedelta(minutes=expire_minutes)).isoformat()
    else:
        expires_at = (now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)).isoformat()
    now_iso = now.isoformat()

    # Remove stale tokens for this user before inserting the new one
    await db.execute(
        "DELETE FROM refresh_tokens WHERE user_id = ? AND (expires_at < ? OR revoked = 1)",
        (user_id, now_iso),
    )
    await db.execute(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, last_active_at, is_public_device) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (token_id, user_id, token_hash, expires_at, now_iso, 1 if is_public_device else 0),
    )
    await db.commit()
    return token_id


async def validate_refresh_token(db, raw_token: str) -> dict | None:
    """Validate a refresh token and return user_id if valid.

    Returns None if token is invalid, expired, or revoked.
    """
    token_hash = hash_refresh_token(raw_token)
    now = datetime.now(timezone.utc).isoformat()

    cursor = await db.execute(
        "SELECT id, user_id FROM refresh_tokens "
        "WHERE token_hash = ? AND revoked = 0 AND expires_at > ?",
        (token_hash, now),
    )
    row = await cursor.fetchone()
    if row is None:
        return None

    return {"token_id": row["id"], "user_id": row["user_id"]}


async def revoke_refresh_token(db, token_id: str) -> None:
    """Revoke a specific refresh token."""
    await db.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE id = ?",
        (token_id,),
    )
    await db.commit()


async def revoke_user_refresh_tokens(db, user_id: str) -> None:
    """Revoke all refresh tokens for a user."""
    await db.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
        (user_id,),
    )
    await db.commit()


async def touch_session(token_id: str) -> None:
    """Record activity for a session to keep the idle timeout from expiring it.

    The WHERE guard (last_active_at < now - 1 minute) makes this a no-op when
    called within a minute of the last update, limiting DB writes to at most
    once per session per minute regardless of request frequency.

    Acquires its own DB connection so it is safe to run as a background task
    after the request-scoped connection has been released back to the pool.
    """
    async with db_session() as db:
        await db.execute(
            "UPDATE refresh_tokens "
            "SET last_active_at = NOW() "
            "WHERE id = ? AND revoked = 0 "
            "AND last_active_at < NOW() - INTERVAL '1 minute'",
            (token_id,),
        )


def create_share_session_token(share_id: str, client_ip: str, user_agent: str) -> str:
    """Create a short-lived JWT scoped to a specific share, client IP, and User-Agent.

    The token is returned to the public client on share resolution and must be
    presented as Authorization: Bearer on subsequent chunk/content requests.
    Binding to IP hash + UA hash prevents token hand-off to a different machine.
    """
    now = datetime.now(timezone.utc)
    ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:32]
    ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:32]
    payload = {
        "sub": share_id,
        "type": "share_session",
        "ip": ip_hash,
        "ua": ua_hash,
        "iat": now,
        "exp": now + timedelta(hours=settings.SHARE_SESSION_EXPIRE_HOURS),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_share_session_token(
    token: str, share_id: str, client_ip: str, user_agent: str
) -> bool:
    """Verify a share session token for a specific share and client.

    Returns True only if the token is valid, unexpired, scoped to the correct
    share_id, and was issued to the same IP + User-Agent.
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
    except jwt.PyJWTError:
        return False
    if payload.get("type") != "share_session":
        return False
    if payload.get("sub") != share_id:
        return False
    ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:32]
    ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:32]
    if payload.get("ip") != ip_hash or payload.get("ua") != ua_hash:
        return False
    return True


def generate_csrf_token() -> str:
    """Generate a random CSRF token."""
    return secrets.token_hex(CSRF_TOKEN_BYTES)


async def cleanup_expired_tokens(db) -> int:
    """Revoke idle sessions then delete expired/revoked tokens.

    Two-phase:
      1. Mark sessions revoked when last_active_at has not advanced within
         SESSION_IDLE_TIMEOUT_MINUTES. This is checked every minute so the
         effective idle window is tight.
      2. Hard-delete all revoked or calendar-expired rows.

    Returns the number of rows deleted in phase 2.
    """
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    idle_cutoff = (now - timedelta(minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES)).isoformat()

    # Phase 1: revoke idle-but-otherwise-valid sessions
    await db.execute(
        "UPDATE refresh_tokens SET revoked = 1 "
        "WHERE revoked = 0 AND expires_at > ? AND last_active_at IS NOT NULL AND last_active_at < ?",
        (now_iso, idle_cutoff),
    )

    # Phase 2: delete everything that is expired or revoked
    result = await db.execute(
        "DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = 1",
        (now_iso,),
    )
    await db.commit()
    count = result.rowcount if result.rowcount >= 0 else 0
    if count > 0:
        logger.debug("Cleaned up %d expired/revoked refresh tokens", count)
    return count


async def run_token_cleanup(db_factory, interval: float = 60.0) -> None:
    """Periodic background task — runs cleanup every `interval` seconds.

    Defaults to 60 s so idle sessions are reaped promptly. db_factory is an
    async context manager factory (e.g. db_session from app.database).
    """
    while True:
        await asyncio.sleep(interval)
        try:
            async with db_factory() as db:
                await cleanup_expired_tokens(db)
        except Exception:
            logger.exception("Token cleanup task failed")
