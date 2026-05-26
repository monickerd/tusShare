"""
Hardware capability scan.

Probes PBKDF2 throughput, CPU core count, available RAM, and local-volume
disk space, then emits recommended configuration values.

All probes run synchronously -- callers must use asyncio.to_thread.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import time

logger = logging.getLogger(__name__)

# Target wall-clock for one PBKDF2-HMAC-SHA256 call (OWASP recommendation).
_KDF_TARGET_MS = 200

# OWASP minimum floor for PBKDF2-HMAC-SHA256 (2023 guidance).
_MIN_PBKDF2_ITERS = 600_000

# Calibration base — low enough to complete in <100 ms even on slow hardware.
_CALIB_ITERS = 10_000

# PRE batch: target max wall-clock per DB transaction for re-encryption batches.
_PRE_BATCH_TARGET_MS = 500


# ---------------------------------------------------------------------------
# Individual probes
# ---------------------------------------------------------------------------


def _probe_pbkdf2() -> dict:
    """Time PBKDF2-HMAC-SHA256 and extrapolate recommended iteration count."""
    key = os.urandom(32)
    salt = os.urandom(16)

    t0 = time.perf_counter()
    hashlib.pbkdf2_hmac("sha256", key, salt, _CALIB_ITERS)  # NOSONAR — calibration benchmark, not key derivation
    calib_ms = (time.perf_counter() - t0) * 1000.0

    ms_per_iter = calib_ms / _CALIB_ITERS
    raw = int(_KDF_TARGET_MS / ms_per_iter)
    recommended = max(_MIN_PBKDF2_ITERS, raw)

    # Verify the recommended count so the caller sees a real measured time.
    t1 = time.perf_counter()
    hashlib.pbkdf2_hmac("sha256", key, salt, recommended)
    verify_ms = (time.perf_counter() - t1) * 1000.0

    return {
        "calibration_iterations": _CALIB_ITERS,
        "calibration_ms": round(calib_ms, 2),
        "recommended_iterations": recommended,
        "expected_ms": round(verify_ms, 1),
        "target_ms": _KDF_TARGET_MS,
        "min_floor": _MIN_PBKDF2_ITERS,
        "floored": recommended == _MIN_PBKDF2_ITERS,
    }


def _probe_cpu() -> dict:
    """Return CPU count and recommended thread pool depth."""
    logical = os.cpu_count() or 1

    # One thread per logical core for CPU-bound crypto work.
    # Leave head-room for the event loop and I/O threads (min 4).
    recommended_pool = max(4, logical)

    return {
        "logical_cores": logical,
        "recommended_thread_pool": recommended_pool,
    }


def _probe_ram() -> dict:
    """Return total and available RAM in bytes."""
    # Try psutil first (cross-platform).
    try:
        import psutil  # type: ignore[import]

        vm = psutil.virtual_memory()
        return {
            "total_bytes": vm.total,
            "available_bytes": vm.available,
            "used_pct": round(vm.percent, 1),
        }
    except ImportError:
        pass

    # Fallback: Linux /proc/meminfo.
    try:
        mem: dict[str, int] = {}
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                k, v = line.split(":")
                mem[k.strip()] = int(v.strip().split()[0]) * 1024
        total = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", 0)
        return {
            "total_bytes": total,
            "available_bytes": avail,
            "used_pct": round(100.0 * (1 - avail / max(total, 1)), 1),
        }
    except Exception:
        pass

    return {"error": "unavailable"}


def _probe_disk(local_volumes: list) -> list[dict]:
    """Return disk usage for each local storage volume."""
    results: list[dict] = []
    for vol in local_volumes:
        # LocalProvider stores files under 'files_dir'; fall back to nothing.
        path = vol.config.get("files_dir") or vol.config.get("path") or ""
        if not path:
            results.append(
                {
                    "volume_id": vol.id,
                    "volume_name": vol.name,
                    "error": "no path configured",
                }
            )
            continue
        try:
            usage = shutil.disk_usage(path)
            results.append(
                {
                    "volume_id": vol.id,
                    "volume_name": vol.name,
                    "path": path,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "used_pct": round(100.0 * usage.used / usage.total, 1) if usage.total else 0,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "volume_id": vol.id,
                    "volume_name": vol.name,
                    "error": str(exc),
                }
            )
    return results


def _probe_pre_batch(_cpu: dict) -> dict:
    """Estimate a safe PRE re-encryption batch size.

    BLS12-381 pairing is client-side; the server's cost per batch is DB I/O.
    We proxy DB insert overhead with SHA-256 throughput (order-of-magnitude
    estimate only) and target _PRE_BATCH_TARGET_MS per transaction.
    """
    n = 1_000
    data = os.urandom(64)

    t0 = time.perf_counter()
    for _ in range(n):
        hashlib.sha256(data).digest()
    probe_ms = (time.perf_counter() - t0) * 1000.0

    ms_per_op = probe_ms / n
    # Each PRE key insert ≈ 10× a raw hash (JSON parsing + DB row overhead).
    ops_in_budget = int(_PRE_BATCH_TARGET_MS / (ms_per_op * 10))
    recommended = max(50, min(ops_in_budget, 5_000))

    return {
        "probe_n": n,
        "probe_ms": round(probe_ms, 2),
        "ms_per_op_estimate": round(ms_per_op * 10, 3),
        "recommended_batch_size": recommended,
        "target_ms": _PRE_BATCH_TARGET_MS,
        "note": (
            "PRE re-encryption is client-side (BLS12-381). This estimate bounds DB write throughput per transaction."
        ),
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_scan(local_volumes: list) -> dict:
    """Run all hardware probes and return a combined result dict.

    Must be called via asyncio.to_thread — probes are synchronous and may
    take 1–3 seconds depending on PBKDF2 calibration.
    """
    cpu = _probe_cpu()
    ram = _probe_ram()
    pbkdf2 = _probe_pbkdf2()
    pre = _probe_pre_batch(cpu)
    disk = _probe_disk(local_volumes)

    return {
        "cpu": cpu,
        "ram": ram,
        "pbkdf2": pbkdf2,
        "pre_batch": pre,
        "disk": disk,
        "recommendations": {
            "pbkdf2_iterations": pbkdf2["recommended_iterations"],
            "thread_pool_size": cpu["recommended_thread_pool"],
            "pre_batch_size": pre["recommended_batch_size"],
        },
    }
