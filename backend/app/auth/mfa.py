"""Shared MFA helpers — encryption, pending tokens, enforcement evaluation.

Credential encryption
─────────────────────
Each MFA credential's JSON payload is encrypted with AES-256-GCM before being
stored in user_mfa_credentials.credential.  The server key is derived from
TUSSHARE_MFA_ENCRYPTION_KEY (32 bytes, base64url) if set, or from
TUSSHARE_JWT_SECRET via HKDF if not.  The stored value is:
  base64url(iv[12] || ciphertext || tag[16])

Pending tokens
──────────────
After OPAQUE login/finish succeeds for a user with active MFA credentials, the
server returns a short-lived pending token instead of session cookies.  The
token is a JWT {sub, jti, purpose, exp}; the jti row in mfa_pending_tokens
acts as the single-use gate.  Consuming the token (mfa_check_pending_token)
deletes the row and returns the user_id + is_public_device.

Enforcement evaluation
──────────────────────
user_satisfies_mfa_enforcement() reads admin_settings and returns True when
the given user may proceed without MFA, and False when they must enroll/verify.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import uuid
from typing import Any

import jwt

from app.auth.stepup import hkdf_sha256
from app.config import settings
from app.services import live_settings
from app.util.crypto import aesgcm_decrypt_blob, aesgcm_encrypt_blob

# ---------------------------------------------------------------------------
# Credential encryption
# ---------------------------------------------------------------------------

def _get_mfa_key() -> bytes:
    """Return the 32-byte AES key used for credential encryption.

    Prefers TUSSHARE_MFA_ENCRYPTION_KEY (base64url, 32 bytes).
    Falls back to HKDF over JWT_SECRET so deployments without the new var work.
    """
    if settings.MFA_ENCRYPTION_KEY:
        raw = settings.MFA_ENCRYPTION_KEY + "=" * (-len(settings.MFA_ENCRYPTION_KEY) % 4)
        key = base64.urlsafe_b64decode(raw)
        if len(key) != 32:
            raise RuntimeError("TUSSHARE_MFA_ENCRYPTION_KEY must encode exactly 32 bytes")
        return key
    return hkdf_sha256(
        settings.JWT_SECRET.encode(),
        length=32,
        salt=b"mfa-cred-enc-v1",
        info=b"tusShare-mfa-credential-encryption",
    )


def encrypt_credential(payload: dict[str, Any]) -> str:
    """AES-256-GCM encrypt a credential dict; return base64url-encoded blob."""
    return aesgcm_encrypt_blob(_get_mfa_key(), payload)


def decrypt_credential(blob: str) -> dict[str, Any]:
    """Decrypt a credential blob produced by encrypt_credential."""
    return aesgcm_decrypt_blob(_get_mfa_key(), blob)


# ---------------------------------------------------------------------------
# Pending token (OPAQUE login → MFA challenge bridge)
# ---------------------------------------------------------------------------

_MFA_PENDING_PURPOSE = "mfa_challenge"


def issue_pending_token(user_id: str) -> str:
    """Mint a short-lived JWT for the MFA challenge bridge.

    The JWT carries a jti that maps to a row in mfa_pending_tokens.
    The caller must INSERT the jti row into the DB before returning
    the token to the client.
    """
    now = int(time.time())
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "jti": jti,
        "purpose": _MFA_PENDING_PURPOSE,
        "iat": now,
        "exp": now + live_settings.get_int("mfa_pending_token_ttl", settings.MFA_PENDING_TOKEN_TTL),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def _decode_pending_token(token: str) -> dict | None:
    """Decode and validate a pending token JWT; return payload or None."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None
    if payload.get("purpose") != _MFA_PENDING_PURPOSE:
        return None
    return payload


async def consume_pending_token(db, token: str) -> tuple[str, bool] | None:
    """Atomically consume a pending token row.

    Returns (user_id, is_public_device) on success, or None if the token is
    invalid, expired, or already consumed.
    """
    payload = _decode_pending_token(token)
    if payload is None:
        return None

    jti = payload.get("jti")
    user_id = payload.get("sub")
    if not jti or not user_id:
        return None

    now = int(time.time())

    # Atomically delete the row — if nothing is deleted the token was already used
    result = await db.execute(
        "DELETE FROM mfa_pending_tokens WHERE jti = ? AND user_id = ? AND expires_at > ? "
        "RETURNING is_public_device",
        (jti, user_id, now),
    )
    row = await result.fetchone()
    if row is None:
        return None

    return user_id, bool(row["is_public_device"])


async def store_pending_token(db, jti: str, user_id: str, is_public_device: bool) -> None:
    """Insert the jti row that backs an issued pending token."""
    now = int(time.time())
    expires_at = now + live_settings.get_int("mfa_pending_token_ttl", settings.MFA_PENDING_TOKEN_TTL)
    await db.execute(
        "INSERT INTO mfa_pending_tokens (jti, user_id, created_at, expires_at, is_public_device) "
        "VALUES (?, ?, ?, ?, ?)",
        (jti, user_id, now, expires_at, 1 if is_public_device else 0),
    )


def extract_pending_jti(token: str) -> str | None:
    """Return the jti from a pending token without consuming it."""
    payload = _decode_pending_token(token)
    if payload is None:
        return None
    return payload.get("jti")


# ---------------------------------------------------------------------------
# MFA credential list helper
# ---------------------------------------------------------------------------

async def list_active_credentials(db, user_id: str) -> list[dict]:
    """Return all active non-recovery credentials for a user (no secrets)."""
    cursor = await db.execute(
        "SELECT id, method, name, created_at, last_used_at "
        "FROM user_mfa_credentials "
        "WHERE user_id = ? AND is_active = 1 AND method != 'recovery' "
        "ORDER BY created_at",
        (user_id,),
    )
    rows = await cursor.fetchall()
    return [
        {
            "id": r["id"],
            "method": r["method"],
            "name": r["name"],
            "created_at": r["created_at"],
            "last_used_at": r["last_used_at"],
        }
        for r in rows
    ]


async def get_active_methods(db, user_id: str) -> set[str]:
    """Return the set of active (non-recovery) MFA method names for a user."""
    cursor = await db.execute(
        "SELECT DISTINCT method FROM user_mfa_credentials "
        "WHERE user_id = ? AND is_active = 1 AND method != 'recovery'",
        (user_id,),
    )
    rows = await cursor.fetchall()
    return {r["method"] for r in rows}


# ---------------------------------------------------------------------------
# Enforcement evaluation
# ---------------------------------------------------------------------------

async def load_mfa_settings(db) -> dict:
    """Load MFA-related admin_settings rows into a dict."""
    cursor = await db.execute(
        "SELECT key, value FROM admin_settings "
        "WHERE key IN ('mfa_enforcement', 'mfa_allowed_methods', 'mfa_oidc_exempt')"
    )
    rows = await cursor.fetchall()
    result = {
        "mfa_enforcement": "off",
        "mfa_allowed_methods": None,
        "mfa_oidc_exempt": True,
    }
    for row in rows:
        if row["key"] == "mfa_enforcement":
            result["mfa_enforcement"] = row["value"]
        elif row["key"] == "mfa_allowed_methods":
            try:
                result["mfa_allowed_methods"] = json.loads(row["value"])
            except Exception:
                result["mfa_allowed_methods"] = None
        elif row["key"] == "mfa_oidc_exempt":
            result["mfa_oidc_exempt"] = row["value"] == "1"
    return result


async def user_satisfies_mfa_enforcement(
    db,
    user_id: str,
    identity_provider_id: str | None,
    mfa_reset_required: bool,
) -> bool:
    """Return True if the user is allowed to proceed without completing MFA.

    False means the user must enroll (required mode, no credentials) or must
    complete a challenge (active credentials exist, enforcement requires them).
    """
    mfa_settings = await load_mfa_settings(db)
    enforcement = mfa_settings["mfa_enforcement"]

    if enforcement == "off":
        return True

    # OIDC/LDAP exemption — overridden by admin-forced reset
    if mfa_settings["mfa_oidc_exempt"] and identity_provider_id and not mfa_reset_required:
        return True

    active = await get_active_methods(db, user_id)
    allowed_methods = mfa_settings["mfa_allowed_methods"]
    if allowed_methods is not None:
        satisfying = active & set(allowed_methods)
    else:
        satisfying = active  # any method counts

    return bool(satisfying)


async def sweep_expired_pending_tokens(db) -> int:
    """Delete expired pending-token rows; return the count removed."""
    now = int(time.time())
    result = await db.execute(
        "DELETE FROM mfa_pending_tokens WHERE expires_at <= ?", (now,)
    )
    await db.commit()
    return result.rowcount or 0


async def sweep_expired_webauthn_challenges(db) -> int:
    """Delete WebAuthn challenge rows older than 5 minutes."""
    cutoff = int(time.time()) - 300
    result = await db.execute(
        "DELETE FROM webauthn_challenges WHERE created_at <= ?", (cutoff,)
    )
    await db.commit()
    return result.rowcount or 0
