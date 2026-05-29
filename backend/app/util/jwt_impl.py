"""Minimal JWT implementation (HMAC algorithms only).

Replaces pyjwt for internal token operations. Supports HS256, HS384, HS512.
External OIDC token validation (RS256/ES256 via JWKS) continues to use authlib.

Drop-in for the subset of pyjwt used in this project:
  jwt.encode(payload, key, algorithm=...)  -> str
  jwt.decode(token, key, algorithms=[...]) -> dict
  jwt.PyJWTError / jwt.InvalidTokenError / jwt.ExpiredSignatureError
"""

import base64
import hashlib
import hmac as _hmac
import json
import time


class PyJWTError(Exception):
    pass


class InvalidTokenError(PyJWTError):
    pass


class ExpiredSignatureError(InvalidTokenError):
    pass


class DecodeError(InvalidTokenError):
    pass


_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def _to_key_bytes(key: str | bytes) -> bytes:
    return key.encode("utf-8") if isinstance(key, str) else key


def encode(payload: dict, key: str | bytes, algorithm: str = "HS256") -> str:
    if algorithm not in _ALGORITHMS:
        raise InvalidTokenError(f"Unsupported algorithm: {algorithm!r}")

    normalized: dict = {}
    for k, v in payload.items():
        if hasattr(v, "timestamp"):
            normalized[k] = int(v.timestamp())
        else:
            normalized[k] = v

    header = _b64url_encode(json.dumps({"alg": algorithm, "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url_encode(json.dumps(normalized, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}".encode()

    sig = _hmac.new(_to_key_bytes(key), signing_input, _ALGORITHMS[algorithm]).digest()
    return f"{header}.{body}.{_b64url_encode(sig)}"


def decode(
    token: str,
    key: str | bytes,
    algorithms: list[str] | None = None,
    options: dict | None = None,
) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise DecodeError("Token must have three dot-separated parts")

        try:
            header = json.loads(_b64url_decode(parts[0]))
        except Exception as exc:
            raise DecodeError("Invalid header encoding") from exc

        alg = header.get("alg", "")
        if algorithms is not None and alg not in algorithms:
            raise InvalidTokenError(f"Algorithm {alg!r} is not in the allowed list")
        if alg not in _ALGORITHMS:
            raise InvalidTokenError(f"Unsupported algorithm: {alg!r}")

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected = _hmac.new(_to_key_bytes(key), signing_input, _ALGORITHMS[alg]).digest()

        try:
            given = _b64url_decode(parts[2])
        except Exception as exc:
            raise DecodeError("Invalid signature encoding") from exc

        if not _hmac.compare_digest(expected, given):
            raise InvalidTokenError("Signature verification failed")

        try:
            payload = json.loads(_b64url_decode(parts[1]))
        except Exception as exc:
            raise DecodeError("Invalid payload encoding") from exc

        opts = options or {}
        if opts.get("verify_exp", True):
            exp = payload.get("exp")
            if exp is not None and time.time() > exp:
                raise ExpiredSignatureError("Token has expired")

        return payload

    except PyJWTError:
        raise
    except Exception as exc:
        raise DecodeError(f"Token decode failed: {exc}") from exc
