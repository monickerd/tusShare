"""Unit tests for D3 — step-up windowed token payload_hash enforcement.

Verifies that:
  - A windowed token is rejected when presented with a different payload_hash
    than it was issued for (prevents replay across different requests).
  - A windowed token is accepted when presented with the same payload_hash.
  - A windowed token is accepted when NO payload_hash is provided by the caller
    (backward compat for middleware that cannot read the request body).
  - A single-use token (window=0) is accepted/rejected correctly.

Run with: pytest tests/unit/
"""
from __future__ import annotations

import os

# Provide minimal required env so Settings can be instantiated.
os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests-only")

from app.auth.stepup import create_step_up_token, verify_step_up_token
from app.services import live_settings


USER_ID = "user-abc"
ACTION = "admin.escrow.enable"
HASH_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HASH_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _with_window(seconds: int, fn):
    """Run fn() with step_up_window_seconds overridden in live_settings cache."""
    live_settings.update_many({"step_up_window_seconds": seconds})
    try:
        return fn()
    finally:
        live_settings.update_many({"step_up_window_seconds": None})


# ---------------------------------------------------------------------------
# Windowed tokens (scope="*")
# ---------------------------------------------------------------------------

def test_windowed_token_same_hash_accepted():
    def _run():
        tok = create_step_up_token(USER_ID, ACTION, HASH_A)
        assert verify_step_up_token(tok, USER_ID, ACTION, payload_hash=HASH_A)
    _with_window(300, _run)


def test_windowed_token_different_hash_rejected():
    """D3 fix: stolen windowed token replayed with different payload is rejected."""
    def _run():
        tok = create_step_up_token(USER_ID, ACTION, HASH_A)
        assert not verify_step_up_token(tok, USER_ID, ACTION, payload_hash=HASH_B)
    _with_window(300, _run)


def test_windowed_token_no_hash_provided_accepted():
    """Middleware that cannot read the body still works (backward compat)."""
    def _run():
        tok = create_step_up_token(USER_ID, ACTION, HASH_A)
        assert verify_step_up_token(tok, USER_ID, ACTION)  # no payload_hash
    _with_window(300, _run)


def test_windowed_token_wrong_user_rejected():
    def _run():
        tok = create_step_up_token(USER_ID, ACTION, HASH_A)
        assert not verify_step_up_token(tok, "other-user", ACTION, payload_hash=HASH_A)
    _with_window(300, _run)


def test_windowed_token_wrong_action_rejected():
    def _run():
        tok = create_step_up_token(USER_ID, ACTION, HASH_A)
        assert not verify_step_up_token(tok, USER_ID, "other.action", payload_hash=HASH_A)
    _with_window(300, _run)


# ---------------------------------------------------------------------------
# Single-use tokens (window=0, scope=payload_hash)
# ---------------------------------------------------------------------------

def test_single_use_token_correct_hash_accepted():
    def _run():
        tok = create_step_up_token(USER_ID, ACTION, HASH_A)
        assert verify_step_up_token(tok, USER_ID, ACTION, payload_hash=HASH_A)
    _with_window(0, _run)


def test_single_use_token_wrong_hash_rejected():
    def _run():
        tok = create_step_up_token(USER_ID, ACTION, HASH_A)
        assert not verify_step_up_token(tok, USER_ID, ACTION, payload_hash=HASH_B)
    _with_window(0, _run)
