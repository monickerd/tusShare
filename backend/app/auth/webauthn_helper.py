"""WebAuthn registration and authentication helpers.

Uses py-webauthn (import `webauthn`) for CBOR parsing, signature verification,
and options generation.

Registration flow
─────────────────
1. begin_registration(db, user_id) → (challenge_id, options_dict)
   Server creates a webauthn_challenges row and returns PublicKeyCredentialCreationOptions.
2. finish_registration(db, user_id, challenge_id, attestation_dict, name)
   Verifies the attestation, stores credential in user_mfa_credentials, returns cred_id.

Authentication flow (login gate, step-up, session unlock)
──────────────────────────────────────────────────────────
1. begin_authentication(db, user_id, purpose) → (challenge_id, options_dict)
2. finish_authentication(db, user_id, challenge_id, assertion_dict, purpose)
   Returns True on success (also updates sign_count and last_used_at).

sign_count anomaly: if count goes backwards, a security event is emitted but
authentication is not blocked (per WebAuthn spec recommendation §6.1 step 21).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid

import webauthn
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.auth.mfa import decrypt_credential, encrypt_credential
from app.config import settings

logger = logging.getLogger(__name__)

_WEBAUTHN_CHALLENGE_BYTES = 32
_CHALLENGE_TTL = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Challenge management
# ---------------------------------------------------------------------------

async def _create_challenge(db, user_id: str, purpose: str) -> tuple[str, bytes]:
    """Create and store a WebAuthn challenge row. Returns (challenge_id, challenge_bytes)."""
    challenge_id = str(uuid.uuid4())
    challenge_bytes = os.urandom(_WEBAUTHN_CHALLENGE_BYTES)
    challenge_b64 = bytes_to_base64url(challenge_bytes)
    now = int(time.time())

    await db.execute(
        "INSERT INTO webauthn_challenges (id, user_id, purpose, challenge, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (challenge_id, user_id, purpose, challenge_b64, now),
    )
    await db.commit()
    return challenge_id, challenge_bytes


async def _consume_challenge(db, challenge_id: str, user_id: str, purpose: str) -> bytes | None:
    """Atomically consume a challenge row. Returns the challenge bytes or None."""
    now = int(time.time())
    cutoff = now - _CHALLENGE_TTL

    result = await db.execute(
        "DELETE FROM webauthn_challenges "
        "WHERE id = ? AND user_id = ? AND purpose = ? AND created_at > ? "
        "RETURNING challenge",
        (challenge_id, user_id, purpose, cutoff),
    )
    row = await result.fetchone()
    if row is None:
        return None
    return base64url_to_bytes(row["challenge"])


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

async def begin_registration(db, user_id: str) -> tuple[str, dict]:
    """Generate a WebAuthn registration challenge.

    Returns (challenge_id, options_dict) where options_dict is JSON-serialisable
    PublicKeyCredentialCreationOptions suitable for navigator.credentials.create().
    """
    cursor = await db.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = await cursor.fetchone()
    if row is None:
        raise ValueError("User not found")
    username = row["username"]

    # Collect existing credential IDs to exclude from new registration
    cursor = await db.execute(
        "SELECT credential FROM user_mfa_credentials "
        "WHERE user_id = ? AND method = 'webauthn' AND is_active = 1",
        (user_id,),
    )
    cred_rows = await cursor.fetchall()
    exclude_ids: list[PublicKeyCredentialDescriptor] = []
    for cr in cred_rows:
        try:
            payload = decrypt_credential(cr["credential"])
            exclude_ids.append(
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(payload["credential_id"]))
            )
        except Exception:
            pass

    options = webauthn.generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=user_id.encode(),
        user_name=username,
        user_display_name=username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=exclude_ids,
    )

    challenge_id, _ = await _create_challenge(db, user_id, "registration")
    # Override the challenge in the DB with what py-webauthn generated
    challenge_b64 = bytes_to_base64url(options.challenge)
    await db.execute(
        "UPDATE webauthn_challenges SET challenge = ? WHERE id = ?",
        (challenge_b64, challenge_id),
    )
    await db.commit()

    options_dict = json.loads(webauthn.options_to_json(options))
    return challenge_id, options_dict


async def finish_registration(
    db, user_id: str, challenge_id: str, attestation_dict: dict, name: str
) -> str:
    """Verify a WebAuthn registration response and store the credential.

    Returns the new credential row ID.
    Raises ValueError on verification failure.
    """
    challenge_bytes = await _consume_challenge(db, challenge_id, user_id, "registration")
    if challenge_bytes is None:
        raise ValueError("Challenge not found, expired, or already consumed")

    try:
        credential = RegistrationCredential.parse_raw(json.dumps(attestation_dict))
        verification = await asyncio.to_thread(
            webauthn.verify_registration_response,
            credential=credential,
            expected_challenge=challenge_bytes,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=f"https://{settings.WEBAUTHN_RP_ID}",
            require_user_verification=False,
        )
    except Exception as exc:
        raise ValueError(f"WebAuthn registration verification failed: {exc}") from exc

    cred_id = str(uuid.uuid4())
    now = int(time.time())

    transports = attestation_dict.get("response", {}).get("transports", [])
    aaguid = str(verification.aaguid) if verification.aaguid else ""

    payload = {
        "credential_id": bytes_to_base64url(verification.credential_id),
        "public_key_cbor": bytes_to_base64url(verification.credential_public_key),
        "sign_count": verification.sign_count,
        "aaguid": aaguid,
        "transports": transports,
    }
    credential_blob = encrypt_credential(payload)

    await db.execute(
        "INSERT INTO user_mfa_credentials "
        "(id, user_id, method, name, created_at, credential, is_active) "
        "VALUES (?, ?, 'webauthn', ?, ?, ?, 1)",
        (cred_id, user_id, name[:128], now, credential_blob),
    )
    await db.commit()
    return cred_id


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

async def begin_authentication(db, user_id: str, purpose: str) -> tuple[str, dict]:
    """Generate a WebAuthn authentication challenge.

    Returns (challenge_id, options_dict) suitable for navigator.credentials.get().
    purpose must be one of: 'authentication', 'step_up', 'unlock'.
    """
    cursor = await db.execute(
        "SELECT credential FROM user_mfa_credentials "
        "WHERE user_id = ? AND method = 'webauthn' AND is_active = 1",
        (user_id,),
    )
    cred_rows = await cursor.fetchall()

    allow_credentials: list[PublicKeyCredentialDescriptor] = []
    for cr in cred_rows:
        try:
            payload = decrypt_credential(cr["credential"])
            transports = payload.get("transports", [])
            allow_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(payload["credential_id"]),
                    transports=transports or None,
                )
            )
        except Exception:
            pass

    options = webauthn.generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    challenge_id, _ = await _create_challenge(db, user_id, purpose)
    challenge_b64 = bytes_to_base64url(options.challenge)
    await db.execute(
        "UPDATE webauthn_challenges SET challenge = ? WHERE id = ?",
        (challenge_b64, challenge_id),
    )
    await db.commit()

    options_dict = json.loads(webauthn.options_to_json(options))
    return challenge_id, options_dict


async def finish_authentication(
    db,
    user_id: str,
    challenge_id: str,
    assertion_dict: dict,
    purpose: str,
    emit_security_event=None,
) -> bool:
    """Verify a WebAuthn assertion.

    Returns True on success.  Emits a security_event if sign_count goes
    backwards (possible credential cloning).  Does not block on anomaly
    per WebAuthn spec §6.1 step 21.

    emit_security_event: optional async callable(event_type, detail) for cloning alerts.
    """
    challenge_bytes = await _consume_challenge(db, challenge_id, user_id, purpose)
    if challenge_bytes is None:
        return False

    raw_cred_id = assertion_dict.get("rawId") or assertion_dict.get("id", "")
    if not raw_cred_id:
        return False

    asserted_cred_id_bytes = base64url_to_bytes(raw_cred_id)

    cursor = await db.execute(
        "SELECT id, credential FROM user_mfa_credentials "
        "WHERE user_id = ? AND method = 'webauthn' AND is_active = 1",
        (user_id,),
    )
    cred_rows = await cursor.fetchall()

    matched_row = None
    matched_payload = None
    for cr in cred_rows:
        try:
            payload = decrypt_credential(cr["credential"])
            stored_cred_id = base64url_to_bytes(payload["credential_id"])
            if stored_cred_id == asserted_cred_id_bytes:
                matched_row = cr
                matched_payload = payload
                break
        except Exception:
            continue

    if matched_row is None:
        return False

    public_key_cbor = base64url_to_bytes(matched_payload["public_key_cbor"])
    sign_count_before = matched_payload.get("sign_count", 0)

    try:
        credential = AuthenticationCredential.parse_raw(json.dumps(assertion_dict))
        verification = await asyncio.to_thread(
            webauthn.verify_authentication_response,
            credential=credential,
            expected_challenge=challenge_bytes,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=f"https://{settings.WEBAUTHN_RP_ID}",
            credential_public_key=public_key_cbor,
            credential_current_sign_count=sign_count_before,
            require_user_verification=False,
        )
    except Exception as exc:
        logger.warning("WebAuthn authentication failed for user %s: %s", user_id, exc)
        return False

    new_sign_count = verification.new_sign_count

    # Sign-count anomaly detection
    if new_sign_count > 0 and sign_count_before > 0 and new_sign_count <= sign_count_before:
        logger.warning(
            "WebAuthn sign_count anomaly for user %s: stored=%d asserted=%d "
            "(possible credential clone)",
            user_id, sign_count_before, new_sign_count,
        )
        if emit_security_event:
            await emit_security_event(
                "webauthn_sign_count_anomaly",
                {"stored_count": sign_count_before, "asserted_count": new_sign_count},
            )

    # Update stored credential with new sign_count
    now = int(time.time())
    matched_payload["sign_count"] = new_sign_count
    new_blob = encrypt_credential(matched_payload)
    await db.execute(
        "UPDATE user_mfa_credentials SET credential = ?, last_used_at = ? WHERE id = ?",
        (new_blob, now, matched_row["id"]),
    )
    await db.commit()
    return True
