"""Shared low-level crypto primitives used across the auth layer."""

import base64
import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def sha256_hex(s: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(s.encode()).hexdigest()


def hmac_sha256_hex(secret: str, body: bytes) -> str:
    """Return hex(HMAC-SHA256(secret, body)).  Returns '' when secret is empty."""
    if not secret:
        return ""
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def aesgcm_encrypt_bytes(key: bytes, data: bytes) -> str:
    """AES-256-GCM encrypt raw bytes and return a base64url blob (iv[12] || ct+tag)."""
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, data, None)
    return base64.urlsafe_b64encode(iv + ct).rstrip(b"=").decode()


def aesgcm_decrypt_bytes(key: bytes, blob: str) -> bytes:
    """Decrypt a blob produced by aesgcm_encrypt_bytes.

    Raises ValueError if the blob is malformed or authentication fails.
    """
    padded = blob + "=" * (-len(blob) % 4)
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) < 28:  # 12 iv + 16 tag minimum
        raise ValueError("Encrypted blob too short")
    return AESGCM(key).decrypt(raw[:12], raw[12:], None)


def aesgcm_encrypt_blob(key: bytes, payload: dict[str, Any]) -> str:
    """AES-256-GCM encrypt a dict and return a base64url-encoded blob."""
    return aesgcm_encrypt_bytes(key, json.dumps(payload, separators=(",", ":")).encode())


def aesgcm_decrypt_blob(key: bytes, blob: str) -> dict[str, Any]:
    """Decrypt a blob produced by aesgcm_encrypt_blob."""
    return json.loads(aesgcm_decrypt_bytes(key, blob))
