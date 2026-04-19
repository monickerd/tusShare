"""AES-256-GCM encryption for storage volume credentials.

Uses the same envelope format as idp_crypto.py (iv[12] || ct || tag[16],
base64url-encoded) but with its own HKDF context so the key can be rotated
independently from IdP and MFA keys.

Key precedence:
  1. TUSSHARE_STORAGE_ENCRYPTION_KEY (32 bytes, base64url)
  2. HKDF-SHA256 over JWT_SECRET with a dedicated salt/info context
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.auth.stepup import hkdf_sha256
from app.config import settings


def _get_storage_key() -> bytes:
    if settings.STORAGE_ENCRYPTION_KEY:
        raw = settings.STORAGE_ENCRYPTION_KEY + "=" * (-len(settings.STORAGE_ENCRYPTION_KEY) % 4)
        key = base64.urlsafe_b64decode(raw)
        if len(key) != 32:
            raise RuntimeError("TUSSHARE_STORAGE_ENCRYPTION_KEY must encode exactly 32 bytes")
        return key
    return hkdf_sha256(
        settings.JWT_SECRET.encode(),
        length=32,
        salt=b"storage-config-enc-v1",
        info=b"tusShare-storage-config-encryption",
    )


def encrypt_volume_config(payload: dict[str, Any]) -> str:
    key = _get_storage_key()
    iv = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    ct_and_tag = AESGCM(key).encrypt(iv, plaintext, None)
    return base64.urlsafe_b64encode(iv + ct_and_tag).rstrip(b"=").decode()


def decrypt_volume_config(blob: str) -> dict[str, Any]:
    key = _get_storage_key()
    padded = blob + "=" * (-len(blob) % 4)
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) < 28:
        raise ValueError("Storage config blob too short")
    plaintext = AESGCM(key).decrypt(raw[:12], raw[12:], None)
    return json.loads(plaintext)
