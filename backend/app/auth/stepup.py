"""Step-up authentication — re-auth gate for sensitive actions.

Flow:
  1. Client attempts a sensitive action → require_step_up() dependency returns
     HTTP 403 {"error": "step_up_required", "action": ..., "challenge_type": ...}
  2. Client shows the OPAQUE re-authentication modal.
  3. Client runs an OPAQUE login exchange via /auth/opaque/step-up/start, then
     POSTs to /auth/step-up with the KE3 message + HMAC of the action payload.
  4. Server verifies the OPAQUE exchange and HMAC, then issues a short-lived step-up JWT.
  5. Client re-submits the original request with X-Step-Up-Token: <jwt>.
  6. require_step_up() dependency validates the token and allows the action.

--- OPAQUE HMAC ---
  OPAQUE login/step-up produces an identical session_key on both sides (64-byte
  SHA-512 output from the 3DH key exchange). Both client and server derive:
  signing_key = HKDF-SHA256(session_key, salt=action_key, info="tusShare-stepup-v2")
  hmac = HMAC-SHA256(signing_key, action_key + "|" + payload_hash + "|" + timestamp_bucket)
  timestamp_bucket = floor(unix_seconds / STEP_UP_TIMESTAMP_TOLERANCE)
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

import jwt

from app.conf.auth import STEP_UP_TIMESTAMP_TOLERANCE
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
    async def verify(self, credential, context: StepUpContext, user, db) -> bool:
        """Verify the step-up credentials.

        Args:
            credential: Auth-method-specific credential.
                        - PasswordStepUpVerifier: str (plaintext password)
                        - OPAQUEStepUpVerifier:   (session_id: str, client_login_finish: str)
            context:    StepUpContext with action/payload/timestamp/hmac.
            user:       AuthenticatedUser — carries auth_method, username, etc.
            db:         DB connection for any lookups needed.

        Returns True if the challenge is satisfied, False otherwise.
        """
        ...


class OPAQUEStepUpVerifier(StepUpVerifier):
    """OPAQUE-based step-up verifier.

    The client re-runs a full OPAQUE login exchange against
    POST /auth/opaque/step-up/start (round 1) and then submits the result
    here as part of POST /auth/step-up (round 2).

    Verification:
      1. Atomically consume the opaque_login_sessions row.
      2. Run tusshare_opaque.server_finish_login → session_key (or None).
      3. Verify timestamp within tolerance.
      4. Re-derive signing_key = HKDF-SHA256(session_key, salt=action_key,
                                              info="tusShare-stepup-v2").
      5. Verify HMAC-SHA256(signing_key, action_key|payload_hash|timestamp_bucket).

    This proves the client knows the current OPAQUE password and can derive the
    same session_key — binding the signature to the specific action payload.
    """

    challenge_type = "opaque"
    _INFO = b"tusShare-stepup-v2"

    async def verify(self, credential: tuple[str, str], context: StepUpContext, user, db) -> bool:
        session_id, client_login_finish_b64 = credential

        # 1. Consume the login session atomically
        from app.auth.opaque_provider import OPAQUEAuthProvider
        provider = OPAQUEAuthProvider(db)
        session = await provider.consume_login_session(session_id)
        if session is None:
            logger.warning("OPAQUE step-up: session not found or expired (user=%s)", user.id)
            return False

        stored_username, server_state_bytes = session

        # Username in session must match authenticated user (belt-and-suspenders)
        if stored_username.lower() != user.username.lower():
            logger.warning(
                "OPAQUE step-up: session username mismatch (session=%s user=%s)",
                stored_username, user.username,
            )
            return False

        # 2. Finish OPAQUE login — returns session_key bytes or None
        try:
            import base64
            padded = client_login_finish_b64 + "=" * (-len(client_login_finish_b64) % 4)
            login_finish_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            return False

        try:
            import tusshare_opaque
            session_key: bytes | None = await asyncio.to_thread(
                tusshare_opaque.server_finish_login,
                server_state_bytes,
                login_finish_bytes,
                user.username.encode("utf-8"),
            )
        except Exception as exc:
            logger.warning("OPAQUE step-up: server_finish_login error (user=%s): %s", user.id, exc)
            return False

        if session_key is None:
            return False

        # 3. Timestamp check
        server_now = int(time.time())
        if abs(server_now - context.timestamp) > STEP_UP_TIMESTAMP_TOLERANCE:
            logger.warning(
                "OPAQUE step-up timestamp outside tolerance: client=%d server=%d diff=%d",
                context.timestamp, server_now, abs(server_now - context.timestamp),
            )
            return False

        # 4–5. Re-derive signing key and verify HMAC
        action_salt = context.action_key.encode("utf-8")
        signing_key = hkdf_sha256(session_key, 32, action_salt, self._INFO)

        timestamp_bucket = context.timestamp // STEP_UP_TIMESTAMP_TOLERANCE
        msg = f"{context.action_key}|{context.payload_hash}|{timestamp_bucket}".encode()
        expected_hmac = _hmac.new(signing_key, msg, hashlib.sha256).hexdigest()

        if not _hmac.compare_digest(expected_hmac, context.hmac_hex.lower()):
            logger.warning(
                "OPAQUE step-up HMAC mismatch for user=%s action=%s",
                user.id, context.action_key,
            )
            return False

        return True


# Singleton verifier instances
_VERIFIERS: dict[str, StepUpVerifier] = {
    "opaque": OPAQUEStepUpVerifier(),
    # "totp": TOTPStepUpVerifier(),     # stubbed — implement when TOTP is added
    # "webauthn": WebAuthnStepUpVerifier(),  # stubbed — implement when WebAuthn is added
}


def get_verifier(challenge_type: str) -> StepUpVerifier:
    """Return the verifier for the given challenge type."""
    return _VERIFIERS.get(challenge_type, _VERIFIERS["opaque"])


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
