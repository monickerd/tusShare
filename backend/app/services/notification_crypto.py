"""AES-256-GCM encryption for notification channel signing secrets.

Same envelope as storage/crypto.py (iv[12] || ct+tag, base64url) but with its
own HKDF context so the key can be rotated independently.

Key precedence:
  1. TUSSHARE_NOTIF_ENCRYPTION_KEY (32 bytes, base64url)
  2. HKDF-SHA256 over JWT_SECRET with a dedicated salt/info context
"""
from __future__ import annotations

import base64

from app.auth.stepup import hkdf_sha256
from app.config import settings
from app.util.crypto import aesgcm_decrypt_bytes, aesgcm_encrypt_bytes


def _get_notif_key() -> bytes:
    if settings.NOTIF_ENCRYPTION_KEY:
        raw = settings.NOTIF_ENCRYPTION_KEY + "=" * (-len(settings.NOTIF_ENCRYPTION_KEY) % 4)
        key = base64.urlsafe_b64decode(raw)
        if len(key) != 32:
            raise RuntimeError("TUSSHARE_NOTIF_ENCRYPTION_KEY must encode exactly 32 bytes")
        return key
    return hkdf_sha256(
        settings.JWT_SECRET.encode(),
        length=32,
        salt=b"notification-channel-secret-v1",
        info=b"tusShare-notification-channel-encryption",
    )


def encrypt_channel_secret(plaintext: str) -> str:
    return aesgcm_encrypt_bytes(_get_notif_key(), plaintext.encode())


def decrypt_channel_secret(blob: str) -> str:
    return aesgcm_decrypt_bytes(_get_notif_key(), blob).decode()
