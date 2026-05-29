"""Minimal TOTP implementation (RFC 4226 / RFC 6238).

Replaces pyotp for TOTP enrollment and verification.

Drop-in for the subset of pyotp used in this project:
  random_base32()                                          -> str
  TOTP(secret_b32).at(timestamp)                          -> str
  TOTP(secret_b32).verify(code, valid_window=N)           -> bool
  TOTP(secret_b32).provisioning_uri(name, issuer_name)    -> str
  totp.TOTP  (submodule shim, same class)
"""

import base64
import hashlib
import hmac as _hmac
import secrets
import struct
import time
import urllib.parse


def random_base32(length: int = 32) -> str:
    """Return a random uppercase base32 secret (no padding), default 32 chars = 160 bits."""
    byte_count = (length * 5 + 7) // 8
    raw = secrets.token_bytes(byte_count)
    return base64.b32encode(raw).decode().rstrip("=")[:length]


def _hotp(key_b32: str, counter: int, digits: int = 6) -> str:
    """Compute an HMAC-based OTP (RFC 4226)."""
    padding = -len(key_b32) % 8
    key = base64.b32decode(key_b32.upper() + "=" * padding)
    msg = struct.pack(">Q", counter)
    digest = _hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    (code_int,) = struct.unpack(">I", bytes([digest[offset] & 0x7F]) + digest[offset + 1 : offset + 4])
    return str(code_int % (10**digits)).zfill(digits)


class TOTP:
    def __init__(self, secret_b32: str, digits: int = 6, interval: int = 30):
        self.secret_b32 = secret_b32
        self.digits = digits
        self.interval = interval

    def at(self, for_time: float | None = None) -> str:
        counter = int((for_time if for_time is not None else time.time()) / self.interval)
        return _hotp(self.secret_b32, counter, self.digits)

    def verify(self, code: str, valid_window: int = 0, for_time: float | None = None) -> bool:
        if not code or len(code) != self.digits or not code.isdigit():
            return False
        now = for_time if for_time is not None else time.time()
        base_counter = int(now / self.interval)
        for offset in range(-valid_window, valid_window + 1):
            expected = _hotp(self.secret_b32, base_counter + offset, self.digits)
            if _hmac.compare_digest(expected, code):
                return True
        return False

    def provisioning_uri(self, name: str, issuer_name: str = "") -> str:
        label = f"{issuer_name}:{name}" if issuer_name else name
        params: dict[str, str] = {
            "secret": self.secret_b32,
            "algorithm": "SHA1",
            "digits": str(self.digits),
            "period": str(self.interval),
        }
        if issuer_name:
            params["issuer"] = issuer_name
        return f"otpauth://totp/{urllib.parse.quote(label, safe='')}?{urllib.parse.urlencode(params)}"


class _TotpSubmodule:
    """Shim so pyotp.totp.TOTP(...) works the same as pyotp.TOTP(...)."""
    TOTP = TOTP


totp = _TotpSubmodule()
