"""
Group 13 — MFA enforcement.

Tests the full MFA enforcement surface:
  - API-level enforcement via require_user_role (backend security gate)
  - Enrollment endpoints remain reachable when enforcement blocks file access
  - TOTP enrollment flow (start → finish with pyotp-generated code)
  - MFA status and admin MFA info endpoints
  - Admin step-up requirement on destructive MFA operations
  - Optional enforcement allows file access for unenrolled users
  - Browser: login under required enforcement redirects to #/mfa, not #/files

Tests
-----
13-01  Default enforcement is 'off'; folder list returns 200 for unenrolled user
13-02  Admin sets enforcement to 'required'
13-03  Unenrolled user: folder list returns 403 mfa_enrollment_required
13-04  Unenrolled user: MFA status endpoint returns 200 (enrollment gate reachable)
13-05  Unenrolled user: TOTP enroll/start returns totp_uri, secret_b32, cred_id
13-06  Unenrolled user: TOTP enroll/finish with valid code returns recovery codes
13-07  Enrolled user: folder list returns 200
13-08  Enrolled user: MFA status shows active_count=1
13-09  Admin: GET /admin/users/{id}/mfa returns credential list
13-10  Admin: DELETE /admin/users/{id}/mfa without step-up token returns 403
13-11  Second unenrolled user: folder list still returns 403
13-12  Second user enrolls TOTP; folder list returns 200
13-13  Browser: fresh login as unenrolled user under required enforcement → hash #/mfa
13-14  Admin sets enforcement to 'optional'; unenrolled user can access folders
"""

from __future__ import annotations

import pytest
import pyotp
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth  import register_via_invite
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# Module-level state: three users, all registered before enforcement changes
_alice:   dict = {}   # enrolls TOTP in 13-06
_bob:     dict = {}   # enrolls TOTP in 13-12
_charlie: dict = {}   # never enrolls; used for browser nav and optional-mode tests

# TOTP state carried between enroll/start and enroll/finish tests
_alice_totp:  dict = {}   # {secret_b32, cred_id}
_bob_totp:    dict = {}

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# auth.forbidden: 13-03 (unenrolled blocked from /folders), 13-03b (blocked
# from /uploads), 13-10 (admin MFA wipe without step-up → 403), 13-10b,
# 13-11 (second unenrolled user blocked).
# MFA enrollment (enroll/start + enroll/finish) does not emit SIEM events.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("auth.forbidden", outcome="failure", severity="warning", tier=2),
]


# ---------------------------------------------------------------------------
# Module fixture: register three users, restore enforcement on teardown
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup_users(seeded_env, browser: Browser):
    admin_client: AdminClient = seeded_env["admin_client"]

    # Register all three users
    for username, password, bucket in [
        ("mfa_alice_13",   "Al1ce!Mfa99", _alice),
        ("mfa_bob_13",     "B0b!Mfa99",   _bob),
        ("mfa_charlie_13", "Ch4rl!Mfa99", _charlie),
    ]:
        invite_url = await admin_client.create_invite_url()
        session    = await register_via_invite(browser, invite_url, username, password)
        bucket["session"]  = session
        bucket["client"]   = ApiClient.from_session(session)
        bucket["username"] = username
        bucket["password"] = password

    # Resolve user IDs from the admin user list
    users = await admin_client.list_users()
    by_name = {u["username"].lower(): u["id"] for u in users}
    _alice["id"]   = by_name["mfa_alice_13"]
    _bob["id"]     = by_name["mfa_bob_13"]
    _charlie["id"] = by_name["mfa_charlie_13"]

    yield

    # Restore enforcement to 'off' so later groups are unaffected
    await admin_client.set_setting("mfa_enforcement", "off")

    for bucket in (_alice, _bob, _charlie):
        if bucket.get("session"):
            await bucket["session"].ctx.close()


# ---------------------------------------------------------------------------
# 13-01  Default enforcement is 'off'
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_01_off_enforcement_allows_file_access():
    """GET /folders returns 200 when enforcement is 'off' (default)."""
    async with _alice["client"] as api:
        r = await api.get("/folders")
    assert r.status_code == 200, (
        f"Expected 200 with enforcement=off, got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# 13-02  Enable required enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_02_admin_enables_required_enforcement(admin_client: AdminClient):
    await admin_client.set_setting("mfa_enforcement", "required")
    settings = await admin_client.get_settings()
    assert settings.get("mfa_enforcement") == "required"


# ---------------------------------------------------------------------------
# 13-03  Unenrolled user blocked from file access
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_03_unenrolled_user_blocked_from_folders():
    """require_user_role enforcement gate: 403 with mfa_enrollment_required."""
    if not _alice.get("client"):
        pytest.skip("alice session not available")
    async with _alice["client"] as api:
        r = await api.get("/folders")
    assert r.status_code == 403, (
        f"Expected 403 for unenrolled user under required enforcement, got {r.status_code}"
    )
    body = r.json()
    assert body.get("detail", {}).get("error") == "mfa_enrollment_required", (
        f"Expected mfa_enrollment_required error, got: {body}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_13_03b_unenrolled_user_blocked_from_uploads():
    """Confirm enforcement covers other require_user_role-protected endpoints too."""
    if not _alice.get("client"):
        pytest.skip("alice session not available")
    async with _alice["client"] as api:
        # POST /uploads is a require_user_role endpoint; 403 expected before any validation
        r = await api.post("/uploads", json={"filename": "x.txt", "file_size": 1})
    assert r.status_code == 403, (
        f"Uploads endpoint should also be blocked, got {r.status_code}"
    )
    body = r.json()
    assert body.get("detail", {}).get("error") == "mfa_enrollment_required"


# ---------------------------------------------------------------------------
# 13-04  Enrollment endpoints remain reachable
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_04_mfa_status_reachable_while_blocked():
    """GET /auth/mfa/status uses get_current_user, not require_user_role — must not block."""
    if not _alice.get("client"):
        pytest.skip("alice session not available")
    async with _alice["client"] as api:
        r = await api.get("/auth/mfa/status")
    assert r.status_code == 200, (
        f"MFA status endpoint blocked unenrolled user — enrollment deadlock! "
        f"Got {r.status_code}: {r.text}"
    )
    body = r.json()
    assert body.get("active_count") == 0
    assert body.get("enforcement") == "required"


# ---------------------------------------------------------------------------
# 13-05  TOTP enrollment start
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_05_totp_enroll_start():
    """POST /auth/totp/enroll/start returns a provisioning URI and secret."""
    if not _alice.get("client"):
        pytest.skip("alice session not available")
    async with _alice["client"] as api:
        r = await api.post("/auth/totp/enroll/start", json={})
    assert r.status_code == 200, (
        f"totp/enroll/start failed: {r.status_code}: {r.text}"
    )
    body = r.json()
    assert "totp_uri"   in body, "Missing totp_uri"
    assert "secret_b32" in body, "Missing secret_b32"
    assert "cred_id"    in body, "Missing cred_id"
    assert body["totp_uri"].startswith("otpauth://"), "totp_uri should be an otpauth URI"

    _alice_totp["secret_b32"] = body["secret_b32"]
    _alice_totp["cred_id"]    = body["cred_id"]


# ---------------------------------------------------------------------------
# 13-06  TOTP enrollment finish — activate credential, get recovery codes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_06_totp_enroll_finish():
    """POST /auth/totp/enroll/finish with a valid code activates the credential."""
    if not _alice_totp.get("secret_b32"):
        pytest.skip("TOTP enroll/start did not complete successfully")

    totp_code = pyotp.TOTP(_alice_totp["secret_b32"]).now()

    async with _alice["client"] as api:
        r = await api.post("/auth/totp/enroll/finish", json={
            "cred_id":   _alice_totp["cred_id"],
            "totp_code": totp_code,
            "name":      "Test Authenticator",
        })
    assert r.status_code == 200, (
        f"totp/enroll/finish failed: {r.status_code}: {r.text}"
    )
    body = r.json()
    assert "recovery_codes" in body, "Expected recovery_codes in response"
    assert isinstance(body["recovery_codes"], list), "recovery_codes should be a list"
    assert len(body["recovery_codes"]) == 10, (
        f"Expected 10 recovery codes, got {len(body['recovery_codes'])}"
    )


# ---------------------------------------------------------------------------
# 13-07  Enrolled user can now access files
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_07_enrolled_user_can_access_folders():
    """After TOTP enrollment, folder list returns 200."""
    if not _alice.get("client"):
        pytest.skip("alice session not available")
    async with _alice["client"] as api:
        r = await api.get("/folders")
    assert r.status_code == 200, (
        f"Enrolled user still blocked: {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# 13-08  MFA status reflects enrolled credential
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_08_mfa_status_shows_one_credential():
    """After enrollment, active_count should be 1."""
    if not _alice.get("client"):
        pytest.skip("alice session not available")
    async with _alice["client"] as api:
        r = await api.get("/auth/mfa/status")
    assert r.status_code == 200
    body = r.json()
    assert body.get("active_count") == 1, (
        f"Expected active_count=1, got {body.get('active_count')}"
    )
    creds = body.get("credentials", [])
    assert len(creds) == 1
    assert creds[0]["method"] == "totp"
    assert creds[0]["name"]   == "Test Authenticator"


# ---------------------------------------------------------------------------
# 13-09  Admin can read per-user MFA info
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_09_admin_can_read_user_mfa_info(admin_client: AdminClient):
    """GET /admin/users/{id}/mfa returns credential list (no step-up required)."""
    if not _alice.get("id"):
        pytest.skip("alice user ID not available")
    r = await admin_client._client.get(f"{API}/admin/users/{_alice['id']}/mfa")
    assert r.status_code == 200, (
        f"Admin MFA info endpoint failed: {r.status_code}: {r.text}"
    )
    body = r.json()
    assert "credentials" in body
    assert len(body["credentials"]) == 1
    assert body["credentials"][0]["method"] == "totp"


# ---------------------------------------------------------------------------
# 13-10  Admin destructive MFA operations require step-up
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_10_admin_mfa_wipe_requires_step_up(admin_client: AdminClient):
    """DELETE /admin/users/{id}/mfa without X-Step-Up-Token returns 403."""
    if not _alice.get("id"):
        pytest.skip("alice user ID not available")
    # Deliberately omit the step-up token to confirm the gate is enforced
    r = await admin_client._client.delete(f"{API}/admin/users/{_alice['id']}/mfa")
    assert r.status_code == 403, (
        f"Expected 403 (step-up required) for admin MFA wipe without token, "
        f"got {r.status_code}: {r.text}"
    )
    body = r.json()
    assert body.get("detail", {}).get("error") == "step_up_required", (
        f"Expected step_up_required error, got: {body}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_13_10b_admin_mfa_reset_requires_step_up(admin_client: AdminClient):
    """POST /admin/users/{id}/mfa/reset without X-Step-Up-Token returns 403."""
    if not _alice.get("id"):
        pytest.skip("alice user ID not available")
    r = await admin_client._client.post(f"{API}/admin/users/{_alice['id']}/mfa/reset", json={})
    assert r.status_code == 403, (
        f"Expected 403 (step-up required) for admin MFA reset without token, "
        f"got {r.status_code}: {r.text}"
    )
    body = r.json()
    assert body.get("detail", {}).get("error") == "step_up_required"


# ---------------------------------------------------------------------------
# 13-11  Second unenrolled user is still blocked
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_11_second_unenrolled_user_blocked():
    """Bob (never enrolled) is still blocked — enrollment is per-user."""
    if not _bob.get("client"):
        pytest.skip("bob session not available")
    async with _bob["client"] as api:
        r = await api.get("/folders")
    assert r.status_code == 403
    assert r.json().get("detail", {}).get("error") == "mfa_enrollment_required"


# ---------------------------------------------------------------------------
# 13-12  Second user enrolls and regains access
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_12_second_user_enrolls_and_accesses_folders():
    """Bob completes TOTP enrollment; folder list returns 200."""
    if not _bob.get("client"):
        pytest.skip("bob session not available")

    # Enroll start
    async with _bob["client"] as api:
        r = await api.post("/auth/totp/enroll/start", json={})
    assert r.status_code == 200, f"bob enroll/start failed: {r.status_code}"
    body = r.json()
    _bob_totp["secret_b32"] = body["secret_b32"]
    _bob_totp["cred_id"]    = body["cred_id"]

    # Enroll finish
    totp_code = pyotp.TOTP(_bob_totp["secret_b32"]).now()
    async with _bob["client"] as api:
        r = await api.post("/auth/totp/enroll/finish", json={
            "cred_id":   _bob_totp["cred_id"],
            "totp_code": totp_code,
            "name":      "Bob Test Key",
        })
    assert r.status_code == 200, f"bob enroll/finish failed: {r.status_code}: {r.text}"

    # Folder access now works
    async with _bob["client"] as api:
        r = await api.get("/folders")
    assert r.status_code == 200, f"Bob still blocked after enrollment: {r.status_code}"


# ---------------------------------------------------------------------------
# 13-13  Browser: login as unenrolled user → hash becomes #/mfa
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_13_login_required_enforcement_redirects_to_mfa(browser: Browser):
    """After OPAQUE login with enforcement=required and no MFA, frontend navigates to #/mfa.

    This tests the data.mfa_enrollment_required branch in _handleLogin (auth.js),
    not just the init() gate — the browser stays on the page during the login flow.
    """
    if not _charlie.get("username"):
        pytest.skip("charlie session not available")

    # Charlie has no MFA enrolled; enforcement is still 'required' from 13-02.
    from tests.e2e.helpers.auth import NAV_TIMEOUT_MS, OPAQUE_TIMEOUT_MS

    ctx  = await browser.new_context(base_url=APP_URL)
    page = await ctx.new_page()
    try:
        await page.goto("/", wait_until="load", timeout=NAV_TIMEOUT_MS)

        # Should show the login form
        await page.wait_for_selector("#username", timeout=NAV_TIMEOUT_MS)
        await page.fill("#username", _charlie["username"])
        await page.fill("#password", _charlie["password"])
        await page.click("button[type='submit']")

        # Wait for OPAQUE + key derivation + mfa_enrollment_required → hash #/mfa
        await page.wait_for_function(
            "() => window.location.hash === '#/mfa'",
            timeout=OPAQUE_TIMEOUT_MS,
        )

        assert "#/mfa" in page.url, (
            f"Expected URL to contain #/mfa after login with required enforcement "
            f"and no MFA enrolled, got: {page.url}"
        )
    finally:
        await page.close()
        await ctx.close()


# ---------------------------------------------------------------------------
# 13-14  Optional enforcement does not block file access
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_14_optional_enforcement_allows_unenrolled_access(
    admin_client: AdminClient,
):
    """enforcement='optional' should not block file access for unenrolled users."""
    await admin_client.set_setting("mfa_enforcement", "optional")

    # Charlie is still unenrolled; should now get 200
    if not _charlie.get("client"):
        pytest.skip("charlie session not available")
    async with _charlie["client"] as api:
        r = await api.get("/folders")
    assert r.status_code == 200, (
        f"Optional enforcement should allow unenrolled access, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_13_14b_optional_enforcement_status_reports_optional(
    admin_client: AdminClient,
):
    """MFA status endpoint reports enforcement=optional when set."""
    if not _charlie.get("client"):
        pytest.skip("charlie session not available")
    async with _charlie["client"] as api:
        r = await api.get("/auth/mfa/status")
    assert r.status_code == 200
    body = r.json()
    assert body.get("enforcement") == "optional"
    assert body.get("active_count") == 0


# ---------------------------------------------------------------------------
# 13-15  Admin endpoints are not subject to user MFA enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_15_admin_endpoints_unaffected_by_mfa_enforcement(
    admin_client: AdminClient,
):
    """Admin routes use require_admin (not require_user_role) — never blocked by MFA policy.

    Re-enables required enforcement to verify admin API access is unaffected,
    then restores optional for cleanliness (teardown fixture resets to 'off').
    """
    await admin_client.set_setting("mfa_enforcement", "required")

    # Admin settings endpoint is require_admin, not require_user_role
    r = await admin_client._client.get(f"{API}/admin/settings")
    assert r.status_code == 200, (
        f"Admin settings blocked under required MFA enforcement: {r.status_code}"
    )

    # Admin user list also require_admin
    r = await admin_client._client.get(f"{API}/admin/users")
    assert r.status_code == 200, (
        f"Admin users endpoint blocked under required MFA enforcement: {r.status_code}"
    )

    # Restore optional so teardown fixture's 'off' reset is the only state change needed
    await admin_client.set_setting("mfa_enforcement", "optional")


# ---------------------------------------------------------------------------
# 13-16  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_13_16_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
