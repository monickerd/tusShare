"""Step-up authentication — re-auth gate for sensitive actions.

Flow:
  1. Client attempts a sensitive action → require_step_up() dependency returns
     HTTP 403 {"error": "step_up_required", "action": ..., "challenge_type": ...}
  2. Client shows the appropriate challenge modal (password / TOTP / WebAuthn).
  3. Client POSTs to /auth/step-up with credentials + HMAC of the action payload.
  4. Server verifies credentials and HMAC, then issues a short-lived step-up JWT.
  5. Client re-submits the original request with X-Step-Up-Token: <jwt>.
  6. require_step_up() dependency validates the token and allows the action.

The HMAC (password challenge) uses:
  signing_key = HKDF-SHA256(KEK, salt=action_key, info="tusShare-stepup-v1")
  hmac = HMAC-SHA256(signing_key, action_key + "|" + payload_hash + "|" + timestamp_bucket)
  timestamp_bucket = floor(unix_seconds / STEP_UP_TIMESTAMP_TOLERANCE)

This proves the client both (a) knows the current password and (b) can derive
the same KEK, binding the signature to the specific action payload.
"""

import asyncio
import hashlib
import hmac as _hmac
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.conf.auth import PBKDF2_ITERATIONS, STEP_UP_TIMESTAMP_TOLERANCE
from app.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869) — stdlib only, no cryptography package needed
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t, okm, i = b"", b"", 0
    while len(okm) < length:
        i += 1
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def hkdf_sha256(ikm: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 (RFC 5869). Matches WebCrypto deriveKey({name:'HKDF', hash:'SHA-256'})."""
    return _hkdf_expand(_hkdf_extract(salt, ikm), info, length)


# ---------------------------------------------------------------------------
# Step-up token (JWT)
# ---------------------------------------------------------------------------

def create_step_up_token(user_id: str, action_key: str, payload_hash: str) -> str:
    """Issue a step-up JWT.

    scope is "*" when STEP_UP_WINDOW_SECONDS > 0 (sudo window — token covers
    any sensitive action until expiry).  When window == 0 the scope is the
    exact payload_hash, binding the token to a single specific request.
    """
    now = datetime.now(timezone.utc)
    window = settings.STEP_UP_WINDOW_SECONDS

    if window > 0:
        scope = "*"
        exp = now + timedelta(seconds=window)
    else:
        scope = payload_hash
        # Single-use tokens get a generous grace period (2× tolerance) so clock
        # skew between the challenge issuance and the follow-up request is handled.
        exp = now + timedelta(seconds=STEP_UP_TIMESTAMP_TOLERANCE * 2)

    payload = {
        "sub": user_id,
        "type": "step_up",
        "action": action_key,
        "scope": scope,
        "iat": now,
        "exp": exp,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_step_up_token(token: str, user_id: str, action_key: str, payload_hash: str | None = None) -> bool:
    """Verify a step-up token for a given user and action.

    For windowed tokens (scope="*"): checks user + action match and token not expired.
    For single-use tokens (scope=payload_hash): additionally checks scope == payload_hash.
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
    except jwt.PyJWTError:
        return False

    if payload.get("type") != "step_up":
        return False
    if payload.get("sub") != user_id:
        return False
    if payload.get("action") != action_key:
        return False

    scope = payload.get("scope", "")
    if scope != "*":
        # Single-use: scope must match the payload_hash of the incoming request
        if payload_hash is None or scope != payload_hash:
            return False

    return True


# ---------------------------------------------------------------------------
# StepUpVerifier — pluggable challenge verification
# ---------------------------------------------------------------------------

@dataclass
class StepUpContext:
    action_key: str
    payload_hash: str
    timestamp: int       # unix seconds provided by client
    hmac_hex: str        # hex HMAC from client


class StepUpVerifier(ABC):
    challenge_type: str

    @abstractmethod
    async def verify(self, password: str, context: StepUpContext, user, db) -> bool:
        """Verify the step-up credentials.

        Args:
            password:  Raw credential (password string for password challenge;
                       TOTP code, etc. for other types).
            context:   StepUpContext with action/payload/timestamp/hmac.
            user:      AuthenticatedUser — carries encryption_salt, username, etc.
            db:        DB connection for any lookups needed.

        Returns True if the challenge is satisfied, False otherwise.
        """
        ...


class PasswordStepUpVerifier(StepUpVerifier):
    """Password + HMAC step-up verifier.

    Verifies:
      1. bcrypt password check (via authenticate()).
      2. Timestamp within STEP_UP_TIMESTAMP_TOLERANCE seconds of server time.
      3. HMAC-SHA256 over (action_key|payload_hash|timestamp_bucket) using a
         signing key derived from HKDF-SHA256(KEK, salt=action_key, info=INFO).

    The HMAC proves the client correctly derived the KEK (i.e. they can unwrap
    the masterKey), not merely that they knew the password at login time.
    """

    challenge_type = "password"
    _INFO = b"tusShare-stepup-v1"

    async def verify(self, password: str, context: StepUpContext, user, db) -> bool:
        # 1. bcrypt check — run in thread to avoid blocking the event loop
        cursor = await db.execute(
            "SELECT password_hash FROM users WHERE id = ? AND is_active = 1",
            (user.id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return False

        stored_hash = row["password_hash"].encode("utf-8")
        password_ok = await asyncio.to_thread(
            bcrypt.checkpw, password.encode("utf-8"), stored_hash
        )
        if not password_ok:
            return False

        # 2. Timestamp check
        server_now = int(time.time())
        if abs(server_now - context.timestamp) > STEP_UP_TIMESTAMP_TOLERANCE:
            logger.warning(
                "Step-up timestamp outside tolerance: client=%d server=%d diff=%d",
                context.timestamp, server_now, abs(server_now - context.timestamp),
            )
            return False

        # 3. HMAC verification — PBKDF2 is expensive, run in thread
        salt_bytes = bytes.fromhex(user.encryption_salt)
        kek = await asyncio.to_thread(
            hashlib.pbkdf2_hmac, "sha256", password.encode("utf-8"), salt_bytes, PBKDF2_ITERATIONS
        )

        timestamp_bucket = context.timestamp // STEP_UP_TIMESTAMP_TOLERANCE
        action_salt = context.action_key.encode("utf-8")
        signing_key = hkdf_sha256(kek, 32, action_salt, self._INFO)

        msg = f"{context.action_key}|{context.payload_hash}|{timestamp_bucket}".encode()
        expected_hmac = _hmac.new(signing_key, msg, hashlib.sha256).hexdigest()

        # Constant-time comparison to prevent timing oracle on HMAC
        if not _hmac.compare_digest(expected_hmac, context.hmac_hex.lower()):
            logger.warning(
                "Step-up HMAC mismatch for user=%s action=%s",
                user.id, context.action_key,
            )
            return False

        return True


# Singleton verifier instances
_VERIFIERS: dict[str, StepUpVerifier] = {
    "password": PasswordStepUpVerifier(),
    # "totp": TOTPStepUpVerifier(),     # stubbed — implement when TOTP is added
    # "webauthn": WebAuthnStepUpVerifier(),  # stubbed — implement when WebAuthn is added
}


def get_verifier(challenge_type: str) -> StepUpVerifier:
    """Return the verifier for the given challenge type. Defaults to password."""
    return _VERIFIERS.get(challenge_type, _VERIFIERS["password"])


# ---------------------------------------------------------------------------
# Failure tracker (in-memory, resets on restart)
# ---------------------------------------------------------------------------

class _StepUpFailureTracker:
    """Tracks per-user step-up failure counts.

    On lockout (count >= STEP_UP_MAX_FAILURES), the caller is responsible for
    revoking the user's sessions and logging the lockout event.
    Counts reset on a successful step-up.
    """

    def __init__(self):
        self._counts: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def record_failure(self, user_id: str) -> int:
        """Increment and return the new failure count."""
        async with self._lock:
            self._counts[user_id] += 1
            return self._counts[user_id]

    async def reset(self, user_id: str) -> None:
        """Reset count after a successful step-up."""
        async with self._lock:
            self._counts.pop(user_id, None)

    async def get_count(self, user_id: str) -> int:
        async with self._lock:
            return self._counts.get(user_id, 0)


failure_tracker = _StepUpFailureTracker()


# ---------------------------------------------------------------------------
# Security event logging helper
# ---------------------------------------------------------------------------

async def log_security_event(
    db,
    event_type: str,
    user_id: str | None,
    ip_address: str,
    user_agent: str,
    action_key: str | None = None,
    detail: dict | None = None,
) -> None:
    """Insert a row into security_events (best-effort; never raises)."""
    try:
        await db.execute(
            "INSERT INTO security_events "
            "(id, user_id, ip_address, user_agent, event_type, action_key, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                user_id,
                ip_address,
                user_agent,
                event_type,
                action_key,
                json.dumps(detail) if detail else None,
            ),
        )
        await db.commit()
    except Exception:
        logger.exception("Failed to log security event: %s", event_type)
