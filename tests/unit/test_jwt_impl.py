"""Unit tests for app.util.jwt_impl — the stdlib HMAC JWT implementation.

Verifies encode/decode round-trips, expiry enforcement, signature validation,
algorithm selection, and the exception hierarchy that callers depend on.

Run with: pytest tests/unit/
"""
from __future__ import annotations

import os
import time

os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests-only")

from app.util.jwt_impl import (
    DecodeError,
    ExpiredSignatureError,
    InvalidTokenError,
    PyJWTError,
    decode,
    encode,
)

_KEY = "test-signing-key-32-bytes-long!!"


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

def test_encode_decode_roundtrip():
    payload = {"sub": "user-1", "role": "admin"}
    token = encode(payload, _KEY)
    result = decode(token, _KEY, algorithms=["HS256"])
    assert result["sub"] == "user-1"
    assert result["role"] == "admin"


def test_roundtrip_preserves_all_standard_claims():
    now = int(time.time())
    payload = {"sub": "u", "iat": now, "exp": now + 3600, "jti": "abc"}
    token = encode(payload, _KEY)
    result = decode(token, _KEY, algorithms=["HS256"])
    assert result["sub"] == "u"
    assert result["iat"] == now
    assert result["exp"] == now + 3600
    assert result["jti"] == "abc"


# ---------------------------------------------------------------------------
# Algorithm selection
# ---------------------------------------------------------------------------

def test_hs384_roundtrip():
    payload = {"sub": "u"}
    token = encode(payload, _KEY, algorithm="HS384")
    result = decode(token, _KEY, algorithms=["HS384"])
    assert result["sub"] == "u"


def test_hs512_roundtrip():
    payload = {"sub": "u"}
    token = encode(payload, _KEY, algorithm="HS512")
    result = decode(token, _KEY, algorithms=["HS512"])
    assert result["sub"] == "u"


def test_wrong_algorithm_in_allowed_list_rejected():
    payload = {"sub": "u"}
    token = encode(payload, _KEY, algorithm="HS256")
    try:
        decode(token, _KEY, algorithms=["HS512"])
        assert False, "Expected InvalidTokenError"
    except InvalidTokenError:
        pass


def test_unsupported_algorithm_raises():
    try:
        encode({"sub": "u"}, _KEY, algorithm="RS256")
        assert False, "Expected InvalidTokenError"
    except InvalidTokenError:
        pass


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

def test_expired_token_raises_expired_signature_error():
    payload = {"sub": "u", "exp": int(time.time()) - 10}
    token = encode(payload, _KEY)
    try:
        decode(token, _KEY, algorithms=["HS256"])
        assert False, "Expected ExpiredSignatureError"
    except ExpiredSignatureError:
        pass


def test_expired_token_with_verify_exp_false_succeeds():
    payload = {"sub": "u", "exp": int(time.time()) - 10}
    token = encode(payload, _KEY)
    result = decode(token, _KEY, algorithms=["HS256"], options={"verify_exp": False})
    assert result["sub"] == "u"


def test_future_token_not_expired():
    payload = {"sub": "u", "exp": int(time.time()) + 3600}
    token = encode(payload, _KEY)
    result = decode(token, _KEY, algorithms=["HS256"])
    assert result["sub"] == "u"


def test_no_exp_claim_does_not_raise():
    payload = {"sub": "u"}
    token = encode(payload, _KEY)
    result = decode(token, _KEY, algorithms=["HS256"])
    assert result["sub"] == "u"


# ---------------------------------------------------------------------------
# Signature validation
# ---------------------------------------------------------------------------

def test_wrong_key_raises_invalid_token_error():
    token = encode({"sub": "u"}, _KEY)
    try:
        decode(token, "wrong-key", algorithms=["HS256"])
        assert False, "Expected InvalidTokenError"
    except InvalidTokenError:
        pass


def test_tampered_payload_raises():
    import base64, json
    token = encode({"sub": "u", "role": "user"}, _KEY)
    parts = token.split(".")
    # Tamper: elevate role to admin in the payload
    bad_payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "u", "role": "admin"}, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    tampered = f"{parts[0]}.{bad_payload}.{parts[2]}"
    try:
        decode(tampered, _KEY, algorithms=["HS256"])
        assert False, "Expected InvalidTokenError"
    except InvalidTokenError:
        pass


def test_truncated_token_raises_decode_error():
    try:
        decode("only.two", _KEY, algorithms=["HS256"])
        assert False, "Expected DecodeError"
    except DecodeError:
        pass


def test_garbage_token_raises_decode_error():
    try:
        decode("not.a.jwt", _KEY, algorithms=["HS256"])
        assert False, "Expected PyJWTError"
    except PyJWTError:
        pass


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

def test_expired_is_subclass_of_invalid_token():
    assert issubclass(ExpiredSignatureError, InvalidTokenError)


def test_invalid_token_is_subclass_of_pyjwt_error():
    assert issubclass(InvalidTokenError, PyJWTError)


def test_decode_error_is_subclass_of_invalid_token():
    assert issubclass(DecodeError, InvalidTokenError)


# ---------------------------------------------------------------------------
# Key type: bytes vs str
# ---------------------------------------------------------------------------

def test_bytes_key_accepted():
    key_bytes = b"test-key-bytes"
    token = encode({"sub": "u"}, key_bytes)
    result = decode(token, key_bytes, algorithms=["HS256"])
    assert result["sub"] == "u"


def test_str_key_and_bytes_key_equivalent():
    payload = {"sub": "u"}
    t1 = encode(payload, "my-key")
    t2 = encode(payload, b"my-key")
    # Same signing input → same token
    assert t1 == t2
