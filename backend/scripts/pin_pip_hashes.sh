#!/usr/bin/env sh
# Superseded by backend/scripts/build_manifest.py, which generates both
# requirements-hashed.txt (stage 1) and manifest.json (stage 2) in a single pass.
#
# Run from the project root:
#   python backend/scripts/build_manifest.py
echo "pin_pip_hashes.sh is deprecated — use: python backend/scripts/build_manifest.py" >&2
exit 1
