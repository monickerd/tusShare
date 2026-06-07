"""K_audit singleton — AES-256-GCM key for encrypting security_events.detail_enc.

K_audit is generated on first use, encrypted under a server-side wrapping key
derived from JWT_SECRET via HKDF, and stored in admin_settings.  It is loaded
into memory at startup and used by event_bus._persist to encrypt sensitive
fields before writing them to the DB.

Threat model: protects against DB-dump-only attackers (SQL injection, stolen
backup). A server-level compromise is out of scope — the server holds K_audit
in plaintext.

audit_key_grants: for human users (audit_log_view flag) the server wraps
K_audit under the user's stored X25519 public key using standard X25519 ECDH +
HKDF-SHA256 + AES-GCM, matching the pattern used elsewhere in the codebase.
"""

from __future__ import annotations

import base64
import json
import logging
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.auth.stepup import hkdf_sha256
from app.config import settings
from app.util.crypto import aesgcm_decrypt_bytes, aesgcm_encrypt_bytes

logger = logging.getLogger(__name__)

_ADMIN_SETTINGS_KEY = "audit_encryption_key"

# Loaded once at startup.  None means K_audit has not been initialised yet
# (first call to ensure_loaded() will generate and persist it).
_k_audit: bytes | None = None


def _wrapping_key() -> bytes:
    """Server-side AES-256 key used to protect K_audit at rest in admin_settings."""
    return hkdf_sha256(
        settings.JWT_SECRET.encode(),
        length=32,
        salt=b"k-audit-wrap-v1",
        info=b"tusShare-audit-key-wrapping",
    )


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


async def ensure_loaded(db_session_factory) -> None:
    """Load K_audit from admin_settings, generating it if absent.

    Called once during application lifespan startup.  After this the
    get_k_audit() function returns immediately without I/O.
    """
    global _k_audit
    try:
        async with db_session_factory() as db:
            cursor = await db.execute(
                "SELECT value FROM admin_settings WHERE key = ?",
                (_ADMIN_SETTINGS_KEY,),
            )
            row = await cursor.fetchone()
            if row and row["value"]:
                _k_audit = aesgcm_decrypt_bytes(_wrapping_key(), row["value"])
                logger.info("audit_key: K_audit loaded from admin_settings")
                return

            # First use: generate and persist.
            _k_audit = os.urandom(32)
            blob = aesgcm_encrypt_bytes(_wrapping_key(), _k_audit)
            await db.execute(
                "INSERT INTO admin_settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (_ADMIN_SETTINGS_KEY, blob),
            )
            await db.commit()
            logger.info("audit_key: K_audit generated and stored")
    except Exception:
        logger.exception("audit_key: failed to load/generate K_audit — detail_enc will be skipped")


def get_k_audit() -> bytes | None:
    """Return the in-memory K_audit, or None if not yet initialised."""
    return _k_audit


# ---------------------------------------------------------------------------
# Encrypt / decrypt helpers
# ---------------------------------------------------------------------------


def encrypt_detail(payload: dict) -> str | None:
    """AES-256-GCM encrypt a detail dict and return a base64url blob.

    Returns None if K_audit is not loaded (graceful degradation).
    """
    if _k_audit is None:
        return None
    try:
        return aesgcm_encrypt_bytes(_k_audit, json.dumps(payload, separators=(",", ":")).encode())
    except Exception:
        logger.exception("audit_key: encrypt_detail failed")
        return None


def decrypt_detail(blob: str) -> dict | None:
    """Decrypt a detail_enc blob.  Returns None on any failure."""
    if _k_audit is None or not blob:
        return None
    try:
        return json.loads(aesgcm_decrypt_bytes(_k_audit, blob))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# audit_key_grants — wrap K_audit under a user's X25519 public key
# ---------------------------------------------------------------------------


def wrap_k_audit_for_user(user_x25519_pub_b64: str) -> dict:
    """Wrap K_audit under a user's X25519 public key.

    Returns a dict with the fields needed for the audit_key_grants table:
        ephemeral_x25519_pub, kem_ciphertext (unused/empty), encrypted_k_audit, sk_iv (unused/empty)

    Wrapping scheme:
    1. Generate ephemeral X25519 key pair.
    2. ECDH(ephemeral_priv, recipient_pub) → shared_secret.
    3. HKDF-SHA256(shared_secret, salt="audit-kek-v1") → wrapping_key (32 bytes).
    4. AES-256-GCM-encrypt(wrapping_key, K_audit) → encrypted_k_audit.
    5. Store ephemeral_pub + encrypted_k_audit in audit_key_grants.
    """
    if _k_audit is None:
        raise RuntimeError("K_audit not loaded")

    padded = user_x25519_pub_b64 + "=" * (-len(user_x25519_pub_b64) % 4)
    recipient_pub_bytes = base64.urlsafe_b64decode(padded)
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_pub_bytes)

    eph_priv = X25519PrivateKey.generate()
    eph_pub  = eph_priv.public_key()
    shared   = eph_priv.exchange(recipient_pub)

    wrapping_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"audit-kek-v1", info=b"tusShare-audit-key-grant",
    ).derive(shared)

    encrypted_k_audit = aesgcm_encrypt_bytes(wrapping_key, _k_audit)
    eph_pub_bytes = eph_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    eph_pub_b64 = base64.urlsafe_b64encode(eph_pub_bytes).rstrip(b"=").decode()

    return {
        "ephemeral_x25519_pub": eph_pub_b64,
        "kem_ciphertext":       "",   # unused in X25519-only mode
        "encrypted_k_audit":   encrypted_k_audit,
        "sk_iv":                "",   # unused (IV is embedded in encrypted_k_audit blob)
    }
