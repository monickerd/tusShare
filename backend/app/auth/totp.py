"""TOTP enrollment, verification, and recovery code helpers.

Enrollment flow
───────────────
1. enroll_start(db, user_id)
   → generates secret, stores inactive credential row, returns (totp_uri, secret_b32, cred_id)
2. enroll_finish(db, user_id, cred_id, totp_code, name)
   → verifies code against the inactive row, activates it, generates 10 recovery codes,
     stores bcrypt hashes in a 'recovery' row, returns plaintext codes (one-time only).
   On failure: clears the inactive row.

Verification
────────────
verify_totp(db, user_id, code)
   → checks code against all active TOTP credentials; enforces replay protection via
     totp_used_codes; prunes old entries each call.

Recovery
────────
verify_recovery_code(db, user_id, code)
   → bcrypt-checks the provided plaintext code against stored hashes; invalidates
     the matched hash so each recovery code is single-use.
"""

from __future__ import annotations

import asyncio
import base64
import secrets
import time
import uuid

import bcrypt

from app.auth.mfa import decrypt_credential, encrypt_credential
from app.util import totp_impl as pyotp

# TOTP window: accept ±1 step (30 s each) to tolerate minor clock skew
_TOTP_WINDOW = 1

# How long (seconds) to keep used-code entries before pruning
_REPLAY_TTL = 90

# Number of recovery codes to generate per enrollment
_RECOVERY_CODE_COUNT = 10

# Each recovery code is 16 random bytes encoded as uppercase base32 (26 chars)
_RECOVERY_CODE_BYTES = 16


# ---------------------------------------------------------------------------
# Enrollment helpers
# ---------------------------------------------------------------------------


async def enroll_start(db, user_id: str, issuer: str = "tusShare") -> tuple[str, str, str]:
    """Begin TOTP enrollment.

    Returns (totp_uri, secret_b32, cred_id).  The credential row is inactive
    until enroll_finish confirms a valid code.  Any pre-existing inactive TOTP
    rows for this user are deleted first (re-start is a clean slate).
    """
    await db.execute(
        "DELETE FROM user_mfa_credentials WHERE user_id = ? AND method = 'totp' AND is_active = 0",
        (user_id,),
    )
    await db.commit()

    secret_b32 = pyotp.random_base32()
    cred_id = str(uuid.uuid4())
    now = int(time.time())

    # Look up username for the TOTP URI
    cursor = await db.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = await cursor.fetchone()
    username = row["username"] if row else user_id

    totp_uri = pyotp.totp.TOTP(secret_b32).provisioning_uri(name=username, issuer_name=issuer)

    credential_blob = encrypt_credential({"secret_b32": secret_b32})
    await db.execute(
        "INSERT INTO user_mfa_credentials "
        "(id, user_id, method, name, created_at, credential, is_active) "
        "VALUES (?, ?, 'totp', ?, ?, ?, 0)",
        (cred_id, user_id, "Authenticator App", now, credential_blob),
    )
    await db.commit()

    return totp_uri, secret_b32, cred_id


async def enroll_finish(db, user_id: str, cred_id: str, totp_code: str, name: str) -> list[str] | None:
    """Complete TOTP enrollment after the user confirms a valid code.

    Returns the list of 10 plaintext recovery codes on success, or None if the
    code is wrong or the pending credential row is not found.  On failure the
    inactive row is deleted so the user must restart enrollment.
    """
    cursor = await db.execute(
        "SELECT credential FROM user_mfa_credentials "
        "WHERE id = ? AND user_id = ? AND method = 'totp' AND is_active = 0",
        (cred_id, user_id),
    )
    row = await cursor.fetchone()
    if row is None:
        return None

    try:
        payload = decrypt_credential(row["credential"])
        secret_b32 = payload["secret_b32"]
    except Exception:
        await db.execute("DELETE FROM user_mfa_credentials WHERE id = ?", (cred_id,))
        await db.commit()
        return None

    totp = pyotp.TOTP(secret_b32)
    code_valid = await asyncio.to_thread(totp.verify, totp_code, valid_window=_TOTP_WINDOW)

    if not code_valid:
        await db.execute("DELETE FROM user_mfa_credentials WHERE id = ?", (cred_id,))
        await db.commit()
        return None

    # Activate the credential with the user's chosen name
    now = int(time.time())
    await db.execute(
        "UPDATE user_mfa_credentials SET is_active = 1, name = ?, last_used_at = ? WHERE id = ?",
        (name[:128], now, cred_id),
    )

    # Generate recovery codes and store as a single 'recovery' credential row
    plaintext_codes, hashed_payload = _generate_recovery_codes()
    recovery_blob = encrypt_credential(hashed_payload)
    await db.execute(
        "INSERT INTO user_mfa_credentials "
        "(id, user_id, method, name, created_at, credential, is_active) "
        "VALUES (?, ?, 'recovery', 'Recovery Codes', ?, ?, 1)",
        (str(uuid.uuid4()), user_id, now, recovery_blob),
    )
    await db.commit()

    return plaintext_codes


def _generate_recovery_codes() -> tuple[list[str], dict]:
    """Generate 10 one-time recovery codes.

    Returns (plaintext_list, {"codes": [bcrypt_hash, ...]}).
    Each code is 128 bits of randomness encoded as base32 (uppercase, 26 chars).
    """
    codes = []
    hashes = []
    for _ in range(_RECOVERY_CODE_COUNT):
        raw = secrets.token_bytes(_RECOVERY_CODE_BYTES)
        code = base64.b32encode(raw).decode().rstrip("=")
        code_hash = bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode()
        codes.append(code)
        hashes.append(code_hash)
    return codes, {"codes": hashes}


# ---------------------------------------------------------------------------
# TOTP verification (login gate / step-up)
# ---------------------------------------------------------------------------


async def verify_totp(db, user_id: str, code: str) -> bool:
    """Verify a TOTP code for a user.

    Returns True and records the used code (replay protection) on success.
    Returns False if no active TOTP credential matches or the code was already used.
    """
    if not code or not code.strip().isdigit() or len(code.strip()) != 6:
        return False
    code = code.strip()

    now = int(time.time())

    # Prune old replay-protection entries
    cutoff = now - _REPLAY_TTL
    await db.execute(
        "DELETE FROM totp_used_codes WHERE user_id = ? AND used_at < ?",
        (user_id, cutoff),
    )

    # Check replay
    cursor = await db.execute(
        "SELECT 1 FROM totp_used_codes WHERE user_id = ? AND code = ?",
        (user_id, code),
    )
    if await cursor.fetchone() is not None:
        return False

    cursor = await db.execute(
        "SELECT id, credential FROM user_mfa_credentials WHERE user_id = ? AND method = 'totp' AND is_active = 1",
        (user_id,),
    )
    rows = await cursor.fetchall()

    for row in rows:
        try:
            payload = decrypt_credential(row["credential"])
            secret_b32 = payload["secret_b32"]
        except Exception:
            continue

        totp = pyotp.TOTP(secret_b32)
        valid = await asyncio.to_thread(totp.verify, code, valid_window=_TOTP_WINDOW)
        if valid:
            await db.execute(
                "INSERT INTO totp_used_codes (user_id, code, used_at) VALUES (?, ?, ?) "
                "ON CONFLICT (user_id, code) DO NOTHING",
                (user_id, code, now),
            )
            await db.execute(
                "UPDATE user_mfa_credentials SET last_used_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            await db.commit()
            return True

    return False


# ---------------------------------------------------------------------------
# Recovery code verification
# ---------------------------------------------------------------------------


async def verify_recovery_code(db, user_id: str, code: str) -> bool:
    """Check a plaintext recovery code and invalidate it if correct.

    Returns True on success (code matched and marked used).
    """
    if not code:
        return False
    code = code.strip().upper()

    cursor = await db.execute(
        "SELECT id, credential FROM user_mfa_credentials "
        "WHERE user_id = ? AND method = 'recovery' AND is_active = 1 "
        "ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        return False

    try:
        payload = decrypt_credential(row["credential"])
        stored_hashes: list[str] = payload["codes"]
    except Exception:
        return False

    matched_idx = None
    for i, h in enumerate(stored_hashes):
        try:
            if await asyncio.to_thread(bcrypt.checkpw, code.encode(), h.encode()):
                matched_idx = i
                break
        except Exception:
            continue

    if matched_idx is None:
        return False

    # Remove the matched hash (single-use)
    new_hashes = [h for i, h in enumerate(stored_hashes) if i != matched_idx]
    new_payload = {"codes": new_hashes}
    new_blob = encrypt_credential(new_payload)

    now = int(time.time())
    await db.execute(
        "UPDATE user_mfa_credentials SET credential = ?, last_used_at = ? WHERE id = ?",
        (new_blob, now, row["id"]),
    )
    await db.commit()
    return True
