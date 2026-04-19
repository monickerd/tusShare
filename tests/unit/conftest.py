"""
Unit test configuration.

Adds the backend/ directory to sys.path so that `app.*` imports work
without a running server or Docker container.  These tests are purely
synchronous and have no external dependencies.
"""
import sys
from pathlib import Path

# backend/ sits two levels above this conftest.py (project_root/backend/)
_backend = Path(__file__).resolve().parents[2] / "backend"
if str(_backend) not in sys.path:
    sys.path.insert(0, str(_backend))
