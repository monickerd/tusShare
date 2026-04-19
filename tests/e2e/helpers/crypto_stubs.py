"""
Cryptographic stub generators for E2E tests.

The server validates format (base64, size, compression flags) but does not
verify that key material is semantically valid (curve-point membership, KEM
consistency, etc.). These helpers produce format-valid blobs that satisfy
every server-side validator without performing real cryptographic operations.

Intentionally NOT interoperable with the real client — test use only.
"""

from __future__ import annotations

import base64
import hashlib
import os


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def fake_g2_point() -> str:
    """96-byte BLS12-381 G2 compressed point stub.

    validate_g2_point only checks: 96 bytes, first byte has MSB set.
    Does not verify the point lies on the curve.
    """
    data = bytearray(os.urandom(96))
    data[0] |= 0x80  # compression flag required by the validator
    return _b64(bytes(data))


def fake_x25519_pub() -> str:
    """32-byte X25519 public key stub (44-char base64, within ≤60-char limit)."""
    return _b64(os.urandom(32))


def fake_kem_ciphertext() -> str:
    """Fake ML-KEM ciphertext (base64, well under the 1500-char limit)."""
    return _b64(os.urandom(64))


def fake_encrypted_sk() -> str:
    """48-byte fake encrypted team secret key (64-char base64, ≤68-char limit)."""
    return _b64(os.urandom(48))


def fake_iv_12() -> str:
    """12-byte AES-GCM IV (16-char base64, within ≤20-char limit)."""
    return _b64(os.urandom(12))


def fake_aes256_key() -> str:
    """32-byte AES-256 key (44-char base64, within ≤4096-char default limit)."""
    return _b64(os.urandom(32))


def fake_asymmetric_keys() -> dict:
    """Stub payload for POST /auth/me/asymmetric-keys.

    All fields pass server-side format validation.  Private key blobs are not
    actually encrypted with anything meaningful — test use only.
    """
    return {
        "x25519_public_key":      _b64(os.urandom(32)),     # 44 chars ≤ 60
        "mlkem768_public_key":    _b64(os.urandom(64)),     # 88 chars ≤ 1700
        "x25519_private_wrapped": _b64(os.urandom(48)),     # 64 chars ≤ 80
        "mlkem768_private_wrapped": _b64(os.urandom(64)),   # 88 chars ≤ 3400
        "asymmetric_key_iv":      _b64(os.urandom(24)),     # 32 chars ≤ 36
    }


def fake_kem_bundle() -> dict:
    """KEM-wrapped key fields shared by create_team and invite_member requests."""
    return {
        "ephemeral_x25519_pub": fake_x25519_pub(),
        "kem_ciphertext":       fake_kem_ciphertext(),
        "encrypted_sk":         fake_encrypted_sk(),
        "sk_iv":                fake_iv_12(),
    }


def chunk_hash(data: bytes) -> str:
    """Build a valid X-Chunk-Hash header value for the given chunk bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()
