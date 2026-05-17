"""BLS12-381 server-side verification helpers for DLEQ proof checking.

Implements three families of checks:

  1. rk_consistency  — pairing check e(rk_point, pk_new) == e(G1, pk_old)
                       proves the rotation key rk is consistent with pk_old → pk_new.

  2. dleq_proof      — Fiat-Shamir Chaum-Pedersen DLEQ proof per file
                       proves the same scalar rk was used for rk_point = rk×G1
                       and C1_new = rk×C1_old.

  3. schnorr_pok     — Schnorr proof-of-knowledge on G2
                       proves the submitter holds sk_new whose pk = sk_new×G2
                       matches the team's current pre_public_key.

Point encodings:
  G1 points: 48-byte ZCash compressed format (same as @noble/curves output)
  G2 points: 96-byte ZCash compressed format
  All transmitted as standard (non-URL-safe) base64.

Scalar encoding:
  32-byte big-endian unsigned integer (mod Fr).

Fiat-Shamir challenge (DLEQ):
  SHA-256( G1_base ‖ C1_old ‖ rk_point ‖ C1_new ‖ R1 ‖ R2 ) mod Fr
  where each element is its 48-byte compressed G1 representation.

Fiat-Shamir challenge (Schnorr PoK):
  SHA-256( pk_new_96bytes ‖ R_96bytes ) mod Fr
"""
import base64
import hashlib
import logging

log = logging.getLogger(__name__)

# BLS12-381 scalar field order (Fr)
_FR_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

try:
    from py_ecc.optimized_bls12_381 import G1, G2, pairing, multiply, add, eq
    from py_ecc.bls.point_compression import (
        compress_G1, decompress_G1,
        compress_G2, decompress_G2,
    )
    _BLS_AVAILABLE = True
except Exception:
    log.warning("py_ecc BLS12-381 import failed; all verification will return False")
    _BLS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64_decode(b64: str) -> bytes:
    return base64.b64decode(b64)


def _g1_from_b64(b64: str):
    """Deserialize a base64 48-byte compressed G1 point."""
    raw = _b64_decode(b64)
    if len(raw) != 48:
        raise ValueError(f"G1 point must be 48 bytes, got {len(raw)}")
    return decompress_G1(int.from_bytes(raw, "big"))


def _g2_from_b64(b64: str):
    """Deserialize a base64 96-byte compressed G2 point."""
    raw = _b64_decode(b64)
    if len(raw) != 96:
        raise ValueError(f"G2 point must be 96 bytes, got {len(raw)}")
    # py_ecc G2Compressed is (z1, z2): z1 = first 48 bytes (imag part + flags), z2 = next 48 bytes (real part)
    return decompress_G2((int.from_bytes(raw[:48], "big"), int.from_bytes(raw[48:], "big")))


def _scalar_from_b64(b64: str) -> int:
    """Deserialize a base64 32-byte big-endian scalar."""
    raw = _b64_decode(b64)
    if len(raw) != 32:
        raise ValueError(f"Scalar must be 32 bytes, got {len(raw)}")
    return int.from_bytes(raw, "big")


def _g1_to_bytes(point) -> bytes:
    """Serialize a py_ecc G1 point to 48-byte compressed form."""
    return compress_G1(point).to_bytes(48, "big")


# ---------------------------------------------------------------------------
# Public verification functions
# ---------------------------------------------------------------------------

def verify_rk_consistency(rk_point_b64: str, pk_old_b64: str, pk_new_b64: str) -> bool:
    """Check e(rk_point, pk_new) == e(G1, pk_old) via BLS12-381 pairings.

    Proves that rk_point = rk × G1 is consistent with the key transition
    pk_old → pk_new without the server learning sk_old or sk_new.

    Derivation:
      e(rk×G1, sk_new×G2) = e(G1,G2)^{rk×sk_new}
                           = e(G1,G2)^{sk_old}          (since rk = sk_old/sk_new)
                           = e(G1, sk_old×G2)
                           = e(G1, pk_old)

    Args:
        rk_point_b64: Base64 compressed G1 point (48 bytes) — rk × G1.
        pk_old_b64:   Base64 compressed G2 point (96 bytes) — old team public key.
        pk_new_b64:   Base64 compressed G2 point (96 bytes) — new team public key.
    """
    if not _BLS_AVAILABLE:
        log.error("verify_rk_consistency: py_ecc not available")
        return False
    try:
        rk_point = _g1_from_b64(rk_point_b64)
        pk_old   = _g2_from_b64(pk_old_b64)
        pk_new   = _g2_from_b64(pk_new_b64)
        # pairing(Q, P) in py_ecc: Q ∈ G2, P ∈ G1
        lhs = pairing(pk_new, rk_point)   # e(rk_point, pk_new)
        rhs = pairing(pk_old, G1)          # e(G1_gen, pk_old)
        return lhs == rhs
    except Exception:
        log.exception("verify_rk_consistency: error during verification")
        return False


def verify_dleq_proof(
    rk_point_b64: str,
    c1_old_b64: str,
    c1_new_b64: str,
    dleq_s: str,
    dleq_r1: str,
    dleq_r2: str,
) -> bool:
    """Verify a Chaum-Pedersen DLEQ proof for a single C1 re-encryption.

    Proves the same scalar rk was used for rk_point = rk×G1 and C1_new = rk×C1_old.

    Fiat-Shamir challenge (must match client computation):
      c = SHA-256(G1_base ‖ C1_old ‖ rk_point ‖ C1_new ‖ R1 ‖ R2) mod Fr
      (each element is its 48-byte compressed G1 serialization)

    Verifier equations:
      s × G1       + c × rk_point == R1
      s × C1_old   + c × C1_new   == R2

    Args:
        rk_point_b64: Base64 G1 — rk × G1 (from rotation payload, shared by all files).
        c1_old_b64:   Base64 G1 — C1 before rotation (from DB).
        c1_new_b64:   Base64 G1 — C1 after rotation (from payload).
        dleq_s:       Base64 32-byte scalar — Fiat-Shamir response.
        dleq_r1:      Base64 G1 — blinding commitment r × G1.
        dleq_r2:      Base64 G1 — blinding commitment r × C1_old.
    """
    if not _BLS_AVAILABLE:
        log.error("verify_dleq_proof: py_ecc not available")
        return False
    try:
        rk_point = _g1_from_b64(rk_point_b64)
        c1_old   = _g1_from_b64(c1_old_b64)
        c1_new   = _g1_from_b64(c1_new_b64)
        R1       = _g1_from_b64(dleq_r1)
        R2       = _g1_from_b64(dleq_r2)
        s        = _scalar_from_b64(dleq_s)

        # Fiat-Shamir challenge — byte-exact match with client SHA-256 computation.
        # Client hashes: [G1_base, C1_old, rk_point, C1_new, R1, R2] as raw bytes.
        # We use the raw decoded base64 bytes for the transmitted points so we match
        # exactly; G1_base is serialized from py_ecc to ensure same encoding.
        hash_input = (
            _g1_to_bytes(G1)          # G1 generator compressed (48 bytes)
            + _b64_decode(c1_old_b64)  # C1_old  (48 bytes)
            + _b64_decode(rk_point_b64)  # rk_point (48 bytes)
            + _b64_decode(c1_new_b64)  # C1_new  (48 bytes)
            + _b64_decode(dleq_r1)     # R1      (48 bytes)
            + _b64_decode(dleq_r2)     # R2      (48 bytes)
        )
        c = int.from_bytes(hashlib.sha256(hash_input).digest(), "big") % _FR_ORDER

        # Check s × G1 + c × rk_point == R1
        lhs1 = add(multiply(G1, s), multiply(rk_point, c))
        if not eq(lhs1, R1):
            log.debug("verify_dleq_proof: equation 1 failed (R1 mismatch)")
            return False

        # Check s × C1_old + c × C1_new == R2
        lhs2 = add(multiply(c1_old, s), multiply(c1_new, c))
        if not eq(lhs2, R2):
            log.debug("verify_dleq_proof: equation 2 failed (R2 mismatch)")
            return False

        return True
    except Exception:
        log.exception("verify_dleq_proof: error during verification")
        return False


def verify_batch_dleq(proofs: list[dict]) -> bool:
    """Verify a list of DLEQ proofs (one per file in a rotation).

    Each proof dict must contain:
      rk_point, c1_old, c1_new, dleq_s, dleq_r1, dleq_r2  (all base64 strings)

    All proofs in one rotation share the same rk_point.  Returns False on the
    first failing proof and logs which index failed.

    Note: a random-linear-combination batch optimisation (reducing to 2 group
    ops + 1 pairing) is possible since rk_point is constant across all proofs;
    implemented as sequential verification for now.
    """
    if not _BLS_AVAILABLE:
        log.error("verify_batch_dleq: py_ecc not available")
        return False
    for i, proof in enumerate(proofs):
        try:
            ok = verify_dleq_proof(
                proof["rk_point"],
                proof["c1_old"],
                proof["c1_new"],
                proof["dleq_s"],
                proof["dleq_r1"],
                proof["dleq_r2"],
            )
        except KeyError:
            log.exception("verify_batch_dleq: proof[%d] missing field", i)
            return False
        if not ok:
            log.warning("verify_batch_dleq: proof[%d] failed", i)
            return False
    return True


def verify_schnorr_pok(schnorr_r_b64: str, schnorr_s_b64: str, pk_new_b64: str) -> bool:
    """Verify a Schnorr PoK that the caller holds sk_new.

    Proves: the submitter knows sk_new such that pk_new = sk_new × G2.
    Used post-rotation to confirm each member can decrypt their new key slot.

    Fiat-Shamir challenge:
      c = SHA-256( pk_new_96bytes ‖ R_96bytes ) mod Fr

    Verifier equation:
      s × G2_base + c × pk_new == R

    Args:
        schnorr_r_b64:  Base64 G2 point (96 bytes) — blinding commitment r × G2.
        schnorr_s_b64:  Base64 32-byte scalar — Fiat-Shamir response.
        pk_new_b64:     Base64 G2 point (96 bytes) — team's current public key.
    """
    if not _BLS_AVAILABLE:
        log.error("verify_schnorr_pok: py_ecc not available")
        return False
    try:
        R      = _g2_from_b64(schnorr_r_b64)
        pk_new = _g2_from_b64(pk_new_b64)
        s      = _scalar_from_b64(schnorr_s_b64)

        # Fiat-Shamir challenge — must match client: SHA-256(pk_new ‖ R) mod Fr
        hash_input = _b64_decode(pk_new_b64) + _b64_decode(schnorr_r_b64)
        c = int.from_bytes(hashlib.sha256(hash_input).digest(), "big") % _FR_ORDER

        # Verify: s × G2 + c × pk_new == R
        lhs = add(multiply(G2, s), multiply(pk_new, c))
        return eq(lhs, R)
    except Exception:
        log.exception("verify_schnorr_pok: error during verification")
        return False
