#!/usr/bin/env bash
# Generate requirements-hashed.txt for pip --require-hashes installs (C2).
#
# Run from the project root:
#   bash backend/scripts/pin_pip_hashes.sh
#
# The output file (backend/requirements-hashed.txt) pins every package with
# its SHA-256 wheel hash so `pip install --require-hashes` can verify the
# supply chain without network access to PyPI.
#
# Regenerate after any version bump in requirements.txt.
# Commit requirements-hashed.txt alongside requirements.txt.
#
# Usage in Docker (replace the existing pip install line):
#   RUN pip install --no-cache-dir --require-hashes -r requirements-hashed.txt
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"
TMP_DIR="$(mktemp -d)"
OUT="$BACKEND_DIR/requirements-hashed.txt"

echo "Downloading wheels to $TMP_DIR ..."
pip download \
    --no-deps \
    --dest "$TMP_DIR" \
    -r "$BACKEND_DIR/requirements.txt"

echo "Computing hashes ..."
pip hash "$TMP_DIR"/*.whl "$TMP_DIR"/*.tar.gz 2>/dev/null \
    | awk '
        /^[A-Za-z]/ { pkg=$0 }
        /--hash=sha256:/ { printf "%s \\\n    %s\n", pkg, $0 }
    ' > "$OUT"

rm -rf "$TMP_DIR"
echo "Written: $OUT"
echo "Build with: pip install --no-cache-dir --require-hashes -r $OUT"
