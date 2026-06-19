#!/usr/bin/env python3
"""Generate all project integrity artifacts.

Stage 1 — pip wheel hashes
  Downloads each package listed in backend/requirements.txt (direct deps only;
  transitive deps are resolved at install time) and writes
  backend/requirements-hashed.txt in pip --require-hashes format.

  pip's --platform flag is used to request Alpine/musl wheels for both target
  architectures regardless of the host OS, so the script works correctly on
  Windows, macOS, and Linux without Docker.  Pure-Python packages produce a
  single platform-independent hash; packages with compiled C extensions produce
  two hashes (one per arch).  pip accepts any matching hash at install time, so
  the same file covers both build targets.

Stage 2 — file integrity manifest
  Computes SHA-256 hashes for all tracked frontend assets, requirements.txt, and
  requirements-hashed.txt, then writes backend/app/manifest.json.  The manifest
  is baked into the Docker image via the existing `COPY backend/app ./app` step
  and verified at startup by app/util/integrity.py.

Run from the project root after any change to a tracked file or to
requirements.txt, before committing:

    python backend/scripts/build_manifest.py

Tracked paths in the manifest are relative to the app root (/app/ in Docker),
matching the directory layout produced by the Dockerfile.
"""

import base64
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND = ROOT / "backend"
MANIFEST_PATH = BACKEND / "app" / "manifest.json"
REQUIREMENTS_PATH = BACKEND / "requirements.txt"
HASHED_REQUIREMENTS_PATH = BACKEND / "requirements-hashed.txt"

_CSS_GLOB = "*.css"

# Glob patterns relative to ROOT.  The manifest key equals the path relative
# to ROOT, which matches the runtime path relative to /app/ in Docker.
TRACKED_GLOBS: list[tuple[str, str]] = [
    ("frontend/js",             "*.js"),
    ("frontend/js/lib",         "*.js"),
    ("frontend/css",            _CSS_GLOB),
    ("frontend/themes/default", _CSS_GLOB),
    ("frontend/themes/light",   _CSS_GLOB),
]

# Files whose Docker destination differs from their source path.
# (source_rel_to_ROOT, manifest_key)
TRACKED_FILES_MAPPED: list[tuple[str, str]] = [
    ("backend/requirements.txt",        "requirements.txt"),
    ("backend/requirements-hashed.txt", "requirements-hashed.txt"),
]

# Alpine target architectures that the Docker build produces (see release.yml).
# Each tuple is (pip_platform_tag, abi_tag).  pip accepts multiple --hash=
# entries per package, so both sets of hashes live in one requirements-hashed.txt
# and whichever matches the build platform is used.
_ALPINE_TARGETS: list[tuple[str, str]] = [
    ("musllinux_1_2_x86_64",  "cp312"),  # linux/amd64
    ("musllinux_1_2_aarch64", "cp312"),  # linux/arm64
]
_PYTHON_VERSION = "312"
_IMPLEMENTATION = "cp"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_b64(path: Path) -> str:
    # Normalize CRLF→LF so hashes match on both Windows (where editors write
    # CRLF despite eol=lf in .gitattributes) and Linux (always LF).
    data = path.read_bytes().replace(b"\r\n", b"\n")
    digest = hashlib.sha256(data).digest()
    return "sha256-" + base64.b64encode(digest).decode()


def _sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _spec_from_filename(path: Path) -> str:
    """Derive 'name==version' from a wheel or sdist filename."""
    name = path.name
    if name.endswith(".whl"):
        # wheel: {name}-{version}-{python_tag}-{abi_tag}-{platform_tag}.whl
        pkg, version = name[:-4].split("-")[:2]
    elif name.endswith(".tar.gz"):
        # sdist: {name}-{version}.tar.gz
        pkg, version = name[:-7].rsplit("-", 1)
    else:
        raise ValueError(f"Unexpected file type: {name!r}")
    return f"{pkg.replace('_', '-')}=={version}"


# ---------------------------------------------------------------------------
# Stage 1: pip wheel hashes
# ---------------------------------------------------------------------------

def generate_pip_hashes() -> int:
    """Download direct-dep wheels for all Alpine targets and write requirements-hashed.txt.

    Uses pip's --platform flag so the correct Alpine/musl wheels are fetched
    regardless of the host OS (Windows, macOS, any Linux distribution).

    Returns the number of distinct packages written.
    """
    print(
        f"Fetching Alpine wheels from PyPI "
        f"(host: {platform.system()} {platform.machine()}) ..."
    )

    # Map spec ->list of unique SHA-256 hex digests.  A pure-Python package
    # produces one entry shared by both arches; a compiled package produces two.
    hashes: dict[str, list[str]] = defaultdict(list)

    with tempfile.TemporaryDirectory() as tmp_root:
        for plat, abi in _ALPINE_TARGETS:
            dest = Path(tmp_root) / plat
            dest.mkdir()
            print(f"  {plat} ...", flush=True)
            subprocess.run(
                [
                    sys.executable, "-m", "pip", "download",
                    "--no-deps",
                    "--only-binary", ":all:",
                    "--platform",       plat,
                    "--python-version", _PYTHON_VERSION,
                    "--implementation", _IMPLEMENTATION,
                    "--abi",            abi,
                    "--dest",           str(dest),
                    "-r",               str(REQUIREMENTS_PATH),
                ],
                check=True,
            )
            for f in sorted(dest.glob("*.whl")) + sorted(dest.glob("*.tar.gz")):
                spec = _spec_from_filename(f)
                digest = _sha256_hex(f)
                if digest not in hashes[spec]:
                    hashes[spec].append(digest)

    lines: list[str] = []
    for spec in sorted(hashes):
        hash_flags = " \\\n    ".join(f"--hash=sha256:{h}" for h in hashes[spec])
        lines.append(f"{spec} \\\n    {hash_flags}")

    # Write with explicit LF endings so the manifest hash (stage 2) is the same
    # regardless of the host OS line-ending convention.
    HASHED_REQUIREMENTS_PATH.write_bytes(
        ("\n".join(lines) + "\n").encode("utf-8")
    )
    print(f"Wrote {len(lines)} package(s) ->{HASHED_REQUIREMENTS_PATH.relative_to(ROOT)}")
    return len(lines)


# ---------------------------------------------------------------------------
# Stage 2: file integrity manifest
# ---------------------------------------------------------------------------

def build_manifest() -> int:
    """Hash all tracked files and write manifest.json.

    Returns the number of warnings (missing files/dirs).
    """
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
    MANIFEST_PATH.write_bytes((json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
    print(f"Wrote {len(files)} file hashes ->{MANIFEST_PATH.relative_to(ROOT)}")
    return warnings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    generate_pip_hashes()
    warnings = build_manifest()
    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
