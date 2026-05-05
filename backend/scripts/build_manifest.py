#!/usr/bin/env python3
"""Generate the artifact integrity manifest (C2).

Run this from the project root after any change to a tracked file, before
building or deploying:

    python backend/scripts/build_manifest.py

Writes backend/app/manifest.json with SHA-256 hashes for every tracked
frontend asset and requirements.txt.  The manifest is baked into the Docker
image via `COPY backend/app ./app` and verified at startup by
app/util/integrity.py.

Tracked paths in the manifest are relative to the app root (/app/ in Docker),
matching the directory layout produced by the Dockerfile.  Files that move
between the source tree and the Docker image (e.g. requirements.txt) are
stored under their Docker destination paths.
"""

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Project root — two levels up from this script (backend/scripts/ → backend/ → root)
ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND = ROOT / "backend"
MANIFEST_PATH = BACKEND / "app" / "manifest.json"

# ---------------------------------------------------------------------------
# Tracked file sets
# ---------------------------------------------------------------------------

_CSS_GLOB = "*.css"

# Glob patterns relative to ROOT.  The manifest key equals the path relative
# to ROOT (which matches the runtime path relative to /app/ in Docker).
TRACKED_GLOBS: list[tuple[str, str]] = [
    ("frontend/js",         "*.js"),
    ("frontend/js/lib",     "*.js"),
    ("frontend/css",        _CSS_GLOB),
    ("frontend/themes/default", _CSS_GLOB),
    ("frontend/themes/light",   _CSS_GLOB),
]

# Files whose Docker destination differs from their source path.
# (source_rel_to_ROOT, manifest_key)
TRACKED_FILES_MAPPED: list[tuple[str, str]] = [
    ("backend/requirements.txt", "requirements.txt"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_b64(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).digest()
    return "sha256-" + base64.b64encode(digest).decode()


def main() -> int:
    files: dict[str, str] = {}
    warnings = 0

    for dir_rel, pattern in TRACKED_GLOBS:
        d = ROOT / dir_rel
        if not d.is_dir():
            print(f"Warning: directory not found, skipping: {d}", file=sys.stderr)
            warnings += 1
            continue
        for p in sorted(d.glob(pattern)):
            key = p.relative_to(ROOT).as_posix()
            files[key] = _sha256_b64(p)

    for src_rel, dest_key in TRACKED_FILES_MAPPED:
        p = ROOT / src_rel
        if not p.exists():
            print(f"Warning: file not found, skipping: {p}", file=sys.stderr)
            warnings += 1
            continue
        files[dest_key] = _sha256_b64(p)

    manifest = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "files": files,
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote {len(files)} file hashes to {MANIFEST_PATH.relative_to(ROOT)}")
    if warnings:
        print(f"{warnings} warning(s) — see stderr", file=sys.stderr)

    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
