"""
Artifact integrity checking.

Loads manifest.json (written by backend/scripts/build_manifest.py) at server
startup and verifies that every tracked file's SHA-256 hash matches the
recorded value.  The check runs once per process; the result is cached and
exposed via the /api/v1/health endpoint.

The manifest lives at backend/app/manifest.json so it is baked into the Docker
image by the existing `COPY backend/app ./app` step.  Tracked paths in the
manifest are relative to the app root (/app/ in Docker), which is the parent
directory of the app/ package.

Gate: only runs when settings.DEBUG is False -- callers are responsible for
checking this before invoking check_integrity().
"""

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Resolved once at import time.
_APP_DIR = Path(__file__).resolve().parent.parent      # …/app/app/
_MANIFEST_PATH = _APP_DIR / "manifest.json"            # …/app/app/manifest.json
_APP_ROOT = _APP_DIR.parent                            # …/app/  (container root)

_result: "IntegrityResult | None" = None


@dataclass
class IntegrityResult:
    ok: bool
    missing: list[str] = field(default_factory=list)
    tampered: list[str] = field(default_factory=list)
    manifest_missing: bool = False
    total: int = 0


def _sha256_b64(path: Path) -> str:
    # Normalize CRLF→LF to match build_manifest.py's hashing convention.
    data = path.read_bytes().replace(b"\r\n", b"\n")
    digest = hashlib.sha256(data).digest()
    return "sha256-" + base64.b64encode(digest).decode()


def check_integrity() -> IntegrityResult:
    """Verify tracked file hashes against manifest.json.

    Results are cached — the check runs exactly once per process regardless of
    how many times this function is called.  Call only when DEBUG is False.
    """
    global _result
    if _result is not None:
        return _result

    if not _MANIFEST_PATH.exists():
        logger.warning(
            "Integrity manifest not found at %s — skipping verification "
            "(run backend/scripts/build_manifest.py to generate it)",
            _MANIFEST_PATH,
        )
        _result = IntegrityResult(ok=True, manifest_missing=True)
        return _result

    manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    files: dict[str, str] = manifest.get("files", {})
    missing: list[str] = []
    tampered: list[str] = []

    for rel, expected in files.items():
        path = _APP_ROOT / rel
        if not path.exists():
            missing.append(rel)
            logger.error("Integrity FAIL: missing %s", rel)
            continue
        actual = _sha256_b64(path)
        if actual != expected:
            tampered.append(rel)
            logger.error("Integrity FAIL: tampered %s (expected %s, got %s)", rel, expected, actual)

    ok = not missing and not tampered
    if ok:
        logger.info("Integrity check passed (%d files verified)", len(files))
    else:
        logger.error(
            "Integrity check FAILED — %d missing, %d tampered",
            len(missing),
            len(tampered),
        )

    _result = IntegrityResult(ok=ok, missing=missing, tampered=tampered, total=len(files))
    return _result


def get_result() -> "IntegrityResult | None":
    """Return the cached result, or None if the check has not yet run."""
    return _result
