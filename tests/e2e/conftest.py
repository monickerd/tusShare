"""
Top-level pytest configuration and shared fixtures.

Fixture scopes
--------------
session     — one browser process for the entire test run
module      — seeded_env: full DB reset + admin bootstrap, once per test group
function    — fresh pages, per-test contexts

The browser process is shared across all groups to avoid the startup cost, but
each group gets isolated browser contexts so cookies / sessions never bleed
across groups.

Environment variables (set by test-run.sh, or manually when running a subset)
--------------
TEST_APP_URL      — base URL of the running app, default http://localhost:8001
TEST_HEADED       — set to "1" to show the browser window (debug mode)
TEST_PROJECT_NAME — docker compose project name, default tusshare_test

Admin credentials used for group seeding
--------------
Defined as module-level constants here so every test file imports them from
a single place. Change them here if needed.
"""

from __future__ import annotations

import datetime
import os
import subprocess
import pytest
from playwright.async_api import async_playwright, Browser

# All async tests in this suite must share the session event loop so that
# Playwright browser objects (created in the session-scoped browser fixture)
# can be awaited from within tests without cross-loop deadlocks.
pytestmark = pytest.mark.asyncio(loop_scope="session")

from tests.e2e.helpers.auth  import bootstrap_admin, login, UserSession
from tests.e2e.helpers.db    import reset_db, get_bootstrap_token, wait_for_healthy
from tests.e2e.helpers.admin import AdminClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_URL  = os.getenv("TEST_APP_URL",      "http://localhost:8001")
HEADED   = os.getenv("TEST_HEADED", "0") == "1"

# Credentials used for the seeded admin in every group except test_00
ADMIN_USERNAME = "testadmin"
ADMIN_PASSWORD = "Str0ng!TestPwd99"

# Credentials for a second admin used in some tests
ADMIN2_USERNAME = "testadmin2"
ADMIN2_PASSWORD = "Str0ng!Admin2Pwd"


# ---------------------------------------------------------------------------
# Session-scoped: one browser for the whole run
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
async def browser():
    async with async_playwright() as p:
        b = await p.chromium.launch(
            headless=not HEADED,
            args=["--disable-web-security"] if HEADED else [],
        )
        yield b
        await b.close()


# ---------------------------------------------------------------------------
# Module-scoped: fresh DB + seeded admin for each test group
#
# Test groups that need a completely clean environment (all except test_00)
# use the `seeded_env` fixture.  test_00 calls reset_db() manually to test
# the bootstrap flow itself.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
async def seeded_env(browser: Browser):
    """
    Reset the database, bootstrap the admin, and return a dict with:
        admin_session  — UserSession (browser context logged in as admin)
        admin_client   — AdminClient (httpx client for admin API calls)

    The admin context and httpx client are closed after the module finishes.
    """
    token = reset_db()                        # wipe DB, restart app, get token
    admin_session = await bootstrap_admin(
        browser,
        token=token,
        username=ADMIN_USERNAME,
        password=ADMIN_PASSWORD,
    )
    admin_client = AdminClient.from_session(admin_session)

    # Mark the first-run wizard as complete so any browser navigation to
    # #/admin lands on the admin panel rather than being redirected to #/setup.
    await admin_client.set_setting("first_run_completed", "1")

    env = {
        "admin_session": admin_session,
        "admin_client":  admin_client,
    }
    yield env

    await admin_client.aclose()
    await admin_session.ctx.close()


# ---------------------------------------------------------------------------
# Convenience fixtures derived from seeded_env
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def admin_session(seeded_env) -> UserSession:
    return seeded_env["admin_session"]


@pytest.fixture(scope="module")
def admin_client(seeded_env) -> AdminClient:
    return seeded_env["admin_client"]


# ---------------------------------------------------------------------------
# Helper: register a user via invite — used by multiple groups
# ---------------------------------------------------------------------------

async def register_test_user(
    browser,
    admin_client: AdminClient,
    username: str,
    password: str,
) -> UserSession:
    """
    Create an invite, register a new user via the browser, return their session.
    Convenience wrapper used across multiple test groups.
    """
    from tests.e2e.helpers.auth import register_via_invite
    invite_url = await admin_client.create_invite_url()
    return await register_via_invite(browser, invite_url, username, password)


# ---------------------------------------------------------------------------
# Per-test container log capture
#
# Records a timestamp before each test runs, then after the test fetches logs
# from all containers covering just that window.  On failure: all logs are
# shown.  On pass: only ERROR/CRITICAL/Traceback lines are shown (catches
# silent backend problems that didn't cause an assertion failure).
# ---------------------------------------------------------------------------

_COMPOSE_FILE    = "docker-compose.test.yml"
_PROJECT_NAME    = os.getenv("TEST_PROJECT_NAME", "tusshare_test")
_test_start: dict[str, str] = {}

_ERROR_KEYWORDS = ("ERROR", "CRITICAL", "Traceback", "Exception:", "panic:")
# All LDAP container lines are Dex/slapd healthcheck noise — filter the whole container
_LDAP_NOISE_PREFIXES = ("tusshare_test_ldap  |", "tusshare_test_ldap |")
# MinIO and its init container produce healthcheck/startup noise — filter both
_MINIO_NOISE_PREFIXES = (
    "tusshare_test_minio  |", "tusshare_test_minio |",
    "tusshare_test_minio_init  |", "tusshare_test_minio_init |",
)
# The bootstrap banner logs at CRITICAL level but is expected on every fresh DB
_BOOTSTRAP_MARKER = "TUSSHARE FIRST-RUN BOOTSTRAP"


def _fetch_logs_since(since: str) -> str:
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", _COMPOSE_FILE, "-p", _PROJECT_NAME,
             "logs", "--since", since],
            capture_output=True, text=True, timeout=15,
        )
        lines = [
            line for line in result.stdout.splitlines()
            if not any(line.startswith(p) for p in _LDAP_NOISE_PREFIXES)
            and not any(line.startswith(p) for p in _MINIO_NOISE_PREFIXES)
        ]
        return "\n".join(lines).strip()
    except Exception:
        return ""


def _extract_bootstrap_token(logs: str) -> str | None:
    """Return the one-time bootstrap token if the bootstrap banner appears in logs."""
    lines = logs.splitlines()
    for i, line in enumerate(lines):
        if _BOOTSTRAP_MARKER in line:
            for j in range(i + 1, min(i + 7, len(lines))):
                content = lines[j].split("|", 1)[-1].strip()
                if (content and "=" not in content
                        and "Register" not in content
                        and _BOOTSTRAP_MARKER not in content):
                    return content
    return None


def _extract_error_lines_with_context(logs: str, context: int = 5) -> list[str]:
    """Return lines matching error keywords plus `context` lines after each match.

    Bootstrap CRITICAL banners are excluded — they are expected on every fresh DB
    and are surfaced separately as notices.
    """
    all_lines = logs.splitlines()
    output: list[str] = []
    emit_until = -1
    for i, line in enumerate(all_lines):
        if any(kw in line for kw in _ERROR_KEYWORDS):
            # Don't treat the bootstrap CRITICAL banner as an error
            lookahead = " ".join(all_lines[i : i + 5])
            if _BOOTSTRAP_MARKER in lookahead:
                continue
            emit_until = i + context
        if i <= emit_until:
            output.append(line)
    return output


def pytest_runtest_setup(item: pytest.Item) -> None:
    _test_start[item.nodeid] = (
        datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.when not in ("call", "setup"):
        return

    since = _test_start.get(report.nodeid) if report.when == "setup" else \
            _test_start.pop(report.nodeid, None)
    if not since:
        return

    # For setup failures, clean up the stored timestamp
    if report.when == "setup" and report.failed:
        _test_start.pop(report.nodeid, None)

    if not report.failed and report.when == "setup":
        return  # only capture setup logs on failure

    logs = _fetch_logs_since(since)
    if not logs:
        return

    if report.failed:
        print(f"\n\n{'='*60}")
        print(f"Container logs during: {report.nodeid} [{report.when}]")
        print(f"{'='*60}")
        print(logs)
        print(f"{'='*60}\n")
    else:
        bootstrap_token = _extract_bootstrap_token(logs)
        error_lines = _extract_error_lines_with_context(logs)
        if bootstrap_token:
            print(f"\n[NOTICE] First-run bootstrap token: {bootstrap_token}")
        if error_lines:
            print(f"\n\n{'='*60}")
            print(f"Backend errors during (passing) test: {report.nodeid}")
            print(f"{'='*60}")
            print("\n".join(error_lines))
            print(f"{'='*60}\n")
