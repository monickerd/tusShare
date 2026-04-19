"""
Database reset helper.

Resets the test database to a completely clean state between test groups by:
  1. Dropping and recreating the database via a superuser psql connection
  2. Restarting the app container so it re-runs migrations and regenerates
     the first-run bootstrap token
  3. Waiting for the app to become healthy again
  4. Extracting the bootstrap token from container logs

Each test group calls reset_db() in a module-scoped fixture so that failures
in one group don't contaminate the next.
"""

from __future__ import annotations

import os
import re
import subprocess
import time

# ---------------------------------------------------------------------------
# Container / connection constants (mirror docker-compose.test.yml)
# ---------------------------------------------------------------------------

PROJECT = os.getenv("TEST_PROJECT_NAME", "tusshare_test")
APP_URL  = os.getenv("TEST_APP_URL",     "http://localhost:8001")

CONTAINER_POSTGRES = f"{PROJECT}_postgres"
CONTAINER_APP      = f"{PROJECT}_app"

PG_SUPERUSER   = "postgres"
PG_SUPERPASS   = "test_superpass"
PG_DB_NAME     = "tusshare_test"
PG_APP_USER    = "tusshare_app"
PG_APP_PASS    = "test_apppass"

HEALTH_ENDPOINT   = f"{APP_URL}/api/v1/health"
HEALTH_TIMEOUT_S  = 60   # max seconds to wait for app after restart
HEALTH_POLL_S     = 2


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def reset_db() -> str:
    """
    Full database reset + app restart.

    Drops and recreates tusshare_test, restarts the app container so
    migrations run fresh and a new bootstrap token is generated, waits
    for the app to become healthy, then returns the bootstrap token string.

    Call this at the top of every module-scoped fixture that requires a
    clean slate (all groups except test_00, which tests the raw bootstrap
    flow itself).
    """
    _drop_and_recreate_db()
    _restart_app()
    _wait_for_healthy()
    return get_bootstrap_token()


def get_bootstrap_token() -> str:
    """
    Parse the one-time bootstrap token from the app container logs.

    The token is logged at CRITICAL level in the format:
        TUSSHARE FIRST-RUN BOOTSTRAP
        Register the initial admin account with this one-time token:
        <token>
        POST to /api/v1/auth/opaque/bootstrap/start then /finish

    Returns the token string (43-char base64url from secrets.token_urlsafe(32)).
    Raises RuntimeError if not found.
    """
    logs = _get_app_logs(tail=300)
    idx = logs.rfind("TUSSHARE FIRST-RUN BOOTSTRAP")
    if idx == -1:
        raise RuntimeError(
            "Bootstrap token not found in app container logs. "
            "Is this a fresh instance? Run reset_db() first."
        )

    section = logs[idx:]
    # secrets.token_urlsafe(32) → exactly 43 base64url characters, possibly
    # starting with '-'.  Scan line-by-line so the token is matched whole even
    # when it starts with '-' (which \b would strip in a regex word-boundary).
    for line in section.splitlines():
        stripped = line.strip()
        if re.fullmatch(r'[A-Za-z0-9_-]{40,50}', stripped):
            return stripped
    raise RuntimeError(
        f"Could not parse bootstrap token from log section:\n{section[:500]}"
    )


def wait_for_healthy(timeout: int = HEALTH_TIMEOUT_S) -> None:
    """Block until the app health endpoint returns 200."""
    _wait_for_healthy(timeout)


def restart_app_and_wait(timeout: int = HEALTH_TIMEOUT_S) -> None:
    """Restart the app container and wait for it to become healthy again.

    Used by storage tests to force the storage manager to reload volumes after
    a direct DB seed (bypassing the admin API).
    """
    _restart_app()
    _wait_for_healthy(timeout)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _psql(sql: str, db: str = "postgres") -> None:
    """Run a SQL command in the postgres container as superuser."""
    subprocess.run(
        [
            "docker", "exec", CONTAINER_POSTGRES,
            "psql", "-U", PG_SUPERUSER, "-d", db, "-c", sql,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def _psql_fetch(sql: str, db: str = "postgres") -> list[str]:
    """Run a SELECT in the postgres container and return rows as a list of strings.

    Each row is returned as a tab-separated string (-A -t flags suppress
    headers and alignment).  Empty result set returns an empty list.
    """
    result = subprocess.run(
        [
            "docker", "exec", CONTAINER_POSTGRES,
            "psql", "-U", PG_SUPERUSER, "-d", db, "-t", "-A", "-c", sql,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def _drop_and_recreate_db() -> None:
    """Drop and recreate the test database, re-granting app-user privileges."""
    # WITH (FORCE) terminates any active connections atomically before dropping,
    # avoiding the race between pg_terminate_backend and a pool reconnect.
    _psql(f"DROP DATABASE IF EXISTS {PG_DB_NAME} WITH (FORCE);")
    _psql(f"CREATE DATABASE {PG_DB_NAME} OWNER {PG_SUPERUSER};")

    # Re-grant privileges to the limited app user.
    # (The user was created by init-app-user.sh at container start and persists
    # across DB drops, but its privileges on the new DB must be re-granted.)
    _psql(f"GRANT ALL PRIVILEGES ON DATABASE {PG_DB_NAME} TO {PG_APP_USER};", db=PG_DB_NAME)
    _psql(f"GRANT CREATE ON SCHEMA public TO {PG_APP_USER};", db=PG_DB_NAME)


def _restart_app() -> None:
    """Restart the app container so migrations run fresh."""
    subprocess.run(
        ["docker", "restart", CONTAINER_APP],
        check=True,
        capture_output=True,
    )
    # Brief pause to let the container exit before we start polling health
    time.sleep(2)


def _wait_for_healthy(timeout: int = HEALTH_TIMEOUT_S) -> None:
    """Poll GET /api/v1/health until 200 or timeout."""
    import urllib.request
    import urllib.error

    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_ENDPOINT, timeout=3) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
        time.sleep(HEALTH_POLL_S)

    raise TimeoutError(
        f"App did not become healthy within {timeout}s. "
        f"Last error: {last_error}\n"
        f"Logs:\n{_get_app_logs(tail=50)}"
    )


def _get_app_logs(tail: int = 200) -> str:
    result = subprocess.run(
        ["docker", "logs", "--tail", str(tail), CONTAINER_APP],
        capture_output=True,
        text=True,
    )
    return result.stdout + result.stderr
