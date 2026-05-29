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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.util import jwt_impl as jwt

from app.conf.auth import STEP_UP_TIMESTAMP_TOLERANCE
from app.config import settings
from app.schemas.security_event import EventActor, SecurityEvent
from app.services import event_bus, live_settings

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


def create_step_up_token(user_id: str, action_key: str, payload_hash: str, session_id: str | None = None) -> str:
    """Issue a step-up JWT.

    scope is "*" when STEP_UP_WINDOW_SECONDS > 0 (sudo window — token covers
    any sensitive action until expiry).  When window == 0 the scope is the
    exact payload_hash, binding the token to a single specific request.

    session_id (sid claim): when present, verify_step_up_token will reject the
    token if it is presented from a different session (T1-M3).
    """
    now = datetime.now(timezone.utc)
    window = live_settings.get_int("step_up_window_seconds", settings.STEP_UP_WINDOW_SECONDS)

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
        "payload_hash": payload_hash,
        "iat": now,
        "exp": exp,
    }
    if session_id:
        payload["sid"] = session_id
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_step_up_token(
    token: str,
    user_id: str,
    action_key: str,
    payload_hash: str | None = None,
    session_id: str | None = None,
) -> bool:
    """Verify a step-up token for a given user and action.

    When payload_hash is provided, the token's stored payload_hash claim must match —
    for both windowed ("*") and single-use tokens.  A windowed token is therefore
    bound to the same request payload it was issued for; replaying it against a
    different payload is rejected.

    When payload_hash is omitted (e.g., middleware without body access), windowed
    tokens still pass and single-use tokens still fail (unchanged legacy behaviour).

    session_id: when the token carries a sid claim, the caller's session_id must match.
    Tokens without a sid claim pass this check unconditionally (backward compat).
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError:
        return False

    if payload.get("type") != "step_up":
        return False
    if payload.get("sub") != user_id:
        return False
    if payload.get("action") != action_key:
        return False

    token_sid = payload.get("sid")
    if token_sid is not None and (session_id is None or token_sid != session_id):
        return False

    stored_hash = payload.get("payload_hash")
    if payload_hash is not None:
        # Caller supplied a hash — enforce it against the JWT claim for both
        # windowed ("*") and single-use tokens.
        if stored_hash is None or stored_hash != payload_hash:
            return False
    elif payload.get("scope", "") != "*":
        # Caller did not supply a hash but token is single-use (legacy path where
        # scope field carries the hash directly rather than a dedicated claim).
        if payload_hash is None or payload.get("scope") != payload_hash:
            return False

    return True


# ---------------------------------------------------------------------------
# StepUpVerifier — pluggable challenge verification
# ---------------------------------------------------------------------------


@dataclass
class StepUpContext:
    action_key: str
    payload_hash: str
    timestamp: int  # unix seconds provided by client
    hmac_hex: str  # hex HMAC from client


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
                stored_username,
                user.username,
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
                context.timestamp,
                server_now,
                abs(server_now - context.timestamp),
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
                user.id,
                context.action_key,
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
# Security event logging helper
# ---------------------------------------------------------------------------

# Maps legacy flat event_type strings to (dot_namespaced_type, severity, outcome, extra_detail).
# extra_detail is merged under caller-supplied detail (caller values win).
_EVENT_MAP: dict[str, tuple[str, str, str, dict]] = {
    "step_up_failed": ("auth.stepup.failure", "warning", "failure", {}),
    "step_up_lockout": ("auth.stepup.blocked", "warning", "blocked", {}),
    "step_up_granted": ("auth.stepup.success", "info", "success", {}),
    "mfa_admin_removed": ("admin.mfa.credential_removed", "warning", "success", {}),
    "mfa_admin_reset": ("admin.mfa.credential_reset", "warning", "success", {}),
    "opaque_login_success": ("auth.opaque.login", "info", "success", {}),
    "ldap_login_failed": ("auth.ldap.login", "warning", "failure", {}),
    "ldap_login_success": ("auth.ldap.login", "info", "success", {}),
    "oidc_login_failed": ("auth.oidc.login", "warning", "failure", {}),
    "oidc_login_success": ("auth.oidc.login", "info", "success", {}),
    "mfa_totp_verified": ("auth.mfa.challenged", "info", "success", {"method": "totp"}),
    "mfa_webauthn_verified": ("auth.mfa.challenged", "info", "success", {"method": "webauthn"}),
    "mfa_recovery_code_used": ("auth.recovery.used", "warning", "success", {"method": "recovery_code"}),
    "session_unlock_webauthn": ("auth.session.unlocked", "info", "success", {"method": "webauthn"}),
    "mfa_credential_removed": ("auth.mfa.credential_removed", "info", "success", {}),
    "password_reset_via_recovery_key": ("auth.recovery.used", "warning", "success", {}),
}


async def log_security_event(
    db,
    event_type: str,
    user_id: str | None,
    ip_address: str,
    user_agent: str,
    username: str | None = None,
    action_key: str | None = None,
    detail: dict | None = None,
) -> None:
    """Insert a row into security_events (best-effort; never raises).

    Also fans the event out to SIEM subscribers (SSE stream, syslog, webhook)
    via emit_fanout_only — the inline DB write above is the canonical record,
    so the bus skips re-persisting to avoid duplicate rows.
    """
    if user_id and username is None:
        try:
            cur = await db.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            row = await cur.fetchone()
            if row:
                username = row["username"]
        except Exception:
            pass

    try:
        await db.execute(
            "INSERT INTO security_events "
            "(id, user_id, actor_username, ip_address, user_agent, event_type, action_key, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                user_id,
                username,
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

    try:
        mapped_type, severity, outcome, extra = _EVENT_MAP.get(event_type, (event_type, "info", None, {}))
        merged: dict = {**extra, **(detail or {})}
        if action_key:
            merged.setdefault("action_key", action_key)
        event_bus.emit_fanout_only(
            SecurityEvent(
                event_type=mapped_type,
                severity=severity,
                outcome=outcome,
                actor=EventActor(user_id=user_id, username=username, ip=ip_address),
                detail=merged,
            )
        )
    except Exception:
        logger.exception("Failed to fan out security event to bus: %s", event_type)
