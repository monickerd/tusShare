"""Minimal TOTP code generator for E2E tests.

Replaces the pyotp dependency in tests.  Implements the same RFC 4226/6238
algorithm as backend/app/util/totp_impl.py using stdlib only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import struct
import time


def totp_now(secret_b32: str, digits: int = 6, interval: int = 30) -> str:
    """Generate the current TOTP code for a given base32 secret."""
    padding = -len(secret_b32) % 8
    key = base64.b32decode(secret_b32.upper() + "=" * padding)
    counter = int(time.time() / interval)
    msg = struct.pack(">Q", counter)
    digest = _hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    (code_int,) = struct.unpack(
        ">I",
        bytes([digest[offset] & 0x7F]) + digest[offset + 1 : offset + 4],
    )
    return str(code_int % (10 ** digits)).zfill(digits)
