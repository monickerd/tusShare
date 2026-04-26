"""AES-256-GCM encryption helpers for identity provider secrets.

All secrets stored by the identity provider subsystem — LDAP bind_password,
OIDC client_secret, OIDC refresh tokens — are encrypted with this module before
being written to the database, so a plaintext DB dump does not expose credentials.

Key derivation
──────────────
Prefers TUSSHARE_IDP_ENCRYPTION_KEY (32 bytes, base64url).
Falls back to HKDF-SHA256 over JWT_SECRET with a dedicated salt/info context,
so deployments that do not set the new env var still work correctly.

Stored blob format
──────────────────
base64url(iv[12] || ciphertext || tag[16])  — same envelope as mfa.py
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.auth.stepup import hkdf_sha256
from app.config import settings


def _get_idp_key() -> bytes:
    if settings.IDP_ENCRYPTION_KEY:
        raw = settings.IDP_ENCRYPTION_KEY + "=" * (-len(settings.IDP_ENCRYPTION_KEY) % 4)
        key = base64.urlsafe_b64decode(raw)
        if len(key) != 32:
            raise RuntimeError("TUSSHARE_IDP_ENCRYPTION_KEY must encode exactly 32 bytes")
        return key
    return hkdf_sha256(
        settings.JWT_SECRET.encode(),
        length=32,
        salt=b"idp-config-enc-v1",
        info=b"tusShare-idp-config-encryption",
    )


def encrypt_idp_config(payload: dict[str, Any]) -> str:
    """AES-256-GCM encrypt a provider config dict; return base64url-encoded blob."""
    key = _get_idp_key()
    iv = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext, None)
    blob = iv + ct_and_tag
    return base64.urlsafe_b64encode(blob).rstrip(b"=").decode()


def decrypt_idp_config(blob: str) -> dict[str, Any]:
    """Decrypt a config blob produced by encrypt_idp_config."""
    key = _get_idp_key()
    padded = blob + "=" * (-len(blob) % 4)
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) < 28:
        raise ValueError("IdP config blob too short")
    iv = raw[:12]
    ct_and_tag = raw[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ct_and_tag, None)
    return json.loads(plaintext)


def encrypt_token(token: str) -> str:
    """Encrypt a short string (e.g. an OIDC refresh token) using the IdP key."""
    return encrypt_idp_config({"t": token})


def decrypt_token(blob: str) -> str:
    """Decrypt a token blob produced by encrypt_token."""
    return decrypt_idp_config(blob)["t"]
