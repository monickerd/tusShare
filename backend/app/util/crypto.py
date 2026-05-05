"""Shared low-level crypto primitives used across the auth layer."""

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def sha256_hex(s: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(s.encode()).hexdigest()


def aesgcm_encrypt_blob(key: bytes, payload: dict[str, Any]) -> str:
    """AES-256-GCM encrypt a dict and return a base64url-encoded blob.

    Blob layout: base64url(iv[12] || ciphertext || gcm_tag[16])
    """
    iv = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    ct_and_tag = AESGCM(key).encrypt(iv, plaintext, None)
    return base64.urlsafe_b64encode(iv + ct_and_tag).rstrip(b"=").decode()


def aesgcm_decrypt_blob(key: bytes, blob: str) -> dict[str, Any]:
    """Decrypt a blob produced by aesgcm_encrypt_blob.

    Raises ValueError if the blob is malformed or authentication fails.
    """
    padded = blob + "=" * (-len(blob) % 4)
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) < 28:  # 12 iv + 16 tag minimum
        raise ValueError("Encrypted blob too short")
    plaintext = AESGCM(key).decrypt(raw[:12], raw[12:], None)
    return json.loads(plaintext)
