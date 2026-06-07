"""Unit tests for app.util.bls_verify — py_ecc import availability.

Regression tests for commit 3a720d1 (Fix BLS verification: correct py_ecc
import path for 7.0.0): the wrong import path caused _BLS_AVAILABLE = False,
making verify_rk_consistency, verify_dleq_proof, and verify_schnorr_pok all
silently return False regardless of input correctness.  Every team key rotation
and Schnorr PoK confirmation was therefore rejected with 422.

Run with: pytest tests/unit/
"""
from __future__ import annotations

import os

os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests-only")

from app.util.bls_verify import (
    _BLS_AVAILABLE,
    verify_batch_dleq,
    verify_dleq_proof,
    verify_rk_consistency,
    verify_schnorr_pok,
)

# ---------------------------------------------------------------------------
# Import availability
# ---------------------------------------------------------------------------

def test_bls_available_is_true():
    """py_ecc import must succeed; _BLS_AVAILABLE=False silences all checks."""
    assert _BLS_AVAILABLE is True, (
        "py_ecc BLS12-381 import failed — all server-side BLS verification returns "
        "False silently.  Check py_ecc install and import path: must use "
        "py_ecc.optimized_bls12_381, NOT py_ecc.bls12_381.bls12_381 (removed in v7)."
    )


def test_verify_functions_are_callable():
    """The four verification entry points must be callable."""
    assert callable(verify_rk_consistency)
    assert callable(verify_dleq_proof)
    assert callable(verify_batch_dleq)
    assert callable(verify_schnorr_pok)


# ---------------------------------------------------------------------------
# Garbage-input safety — functions must return False, not raise
# ---------------------------------------------------------------------------

def test_verify_rk_consistency_returns_false_for_garbage():
    """Malformed base64 must return False, not propagate an exception."""
    assert verify_rk_consistency("AAAA", "BBBB", "CCCC") is False


def test_verify_dleq_proof_returns_false_for_garbage():
    assert verify_dleq_proof("AAAA", "BBBB", "CCCC", "DDDD", "EEEE", "FFFF") is False


def test_verify_schnorr_pok_returns_false_for_garbage():
    assert verify_schnorr_pok("AAAA", "BBBB", "CCCC") is False


def test_verify_batch_dleq_returns_false_for_garbage():
    garbage_proof = {
        "rk_point":   "AAAA",
        "c1_old":     "BBBB",
        "c1_new":     "CCCC",
        "dleq_s":     "DDDD",
        "dleq_r1":    "EEEE",
        "dleq_r2":    "FFFF",
    }
    assert verify_batch_dleq([garbage_proof]) is False


def test_verify_batch_dleq_empty_list_returns_true():
    """Empty batch (no proofs to check) must be vacuously true."""
    assert verify_batch_dleq([]) is True
