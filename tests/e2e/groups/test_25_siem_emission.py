"""
Group 25 — SIEM fan-out capture verification.

Verifies that security events reach the SIEM fan-out path with the correct
dot-namespaced taxonomy, covering both emission routes added in Phase 2.5:

  emit()            — persist to DB + fan-out (used by most route handlers)
  emit_fanout_only() — fan-out only, no second DB write (used by log_security_event
                       so events from step-up, MFA, LDAP/OIDC login reach SIEM
                       without duplicating the already-persisted DB row)

The app container writes every fanned-out event as a JSON line to
TUSSHARE_SIEM_CAPTURE_FILE (/data/siem_capture.jsonl), which is cleared on each
app startup.  The siem helper reads the file via docker exec.

Capture file is reset implicitly by reset_db() restarting the app container
before this module runs, so only events from this test group appear.

Tests
-----
25-01  emit() path: admin.siem.config_changed reaches capture file
25-02  emit() path: admin.emergency_revocation at severity=critical reaches capture
25-03  emit_fanout_only() path: failed LDAP login → auth.ldap.login (severity=warning)
25-04  Taxonomy guard: no legacy flat event_type strings appear in capture
"""

from __future__ import annotations

import asyncio
import socket

import httpx
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient
from tests.e2e.helpers.auth  import register_via_invite
from tests.e2e.helpers.siem  import find, read_all, wait_for
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# LDAP constants — must match docker-compose.test.yml + tests/fixtures/ldap/seed.ldif
_LDAP_PROVIDER_CONFIG = {
    "server_uri":    "ldap://ldap:389",
    "bind_dn":       "cn=admin,dc=test,dc=local",
    "bind_password": "ldap_admin_secret",
    "base_dn":       "ou=users,dc=test,dc=local",
    "user_filter":   "(uid={username})",
    "tls":           "skip_verify",
    "username_attr": "uid",
}

# Legacy flat event_type strings that should never appear in fan-out after Phase 2.5
_LEGACY_FLAT_TYPES = frozenset({
    "step_up_failed", "step_up_granted", "step_up_lockout",
    "ldap_login_failed", "oidc_login_failed", "oidc_login_success",
    "mfa_totp_verified", "mfa_webauthn_verified", "mfa_recovery_code_used",
    "session_unlock_webauthn", "mfa_credential_removed",
    "mfa_admin_removed", "mfa_admin_reset", "password_reset_via_recovery_key",
})

_state: dict = {}

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# This group explicitly exercises the fan-out paths:
#   admin.siem.config_changed: 25-01 (admin changes SIEM webhook config).
#   admin.emergency_revocation: 25-02 (emergency revoke of victim user).
#   auth.ldap.login (outcome=failure): 25-03 (failed LDAP login attempt).
# All three are tier=2 except admin.emergency_revocation which is tier=3.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("admin.siem.config_changed",   outcome="success", severity="info",     tier=2),
    ExpectedSiemEvent("admin.emergency_revocation",  outcome="success", severity="critical",  tier=3),
    ExpectedSiemEvent("auth.ldap.login",             outcome="failure", severity="warning",   tier=2),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ldap_reachable() -> bool:
    try:
        with socket.create_connection(("localhost", 389), timeout=3):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup_world(seeded_env, browser: Browser):
    """
    Provision a victim user (for emergency-revocation test) and, if the LDAP
    container is reachable, create a temporary LDAP identity provider.
    """
    global _state
    admin_client: AdminClient = seeded_env["admin_client"]

    # Victim user for test 25-02
    invite_url = await admin_client.create_invite_url()
    session    = await register_via_invite(
        browser, invite_url, "siem_victim_25", "V1ctim!Siem99"
    )
    users = await admin_client.list_users()
    uid   = next(u["id"] for u in users if u["username"].lower() == "siem_victim_25")
    _state["victim_id"]      = uid
    _state["victim_session"] = session

    # LDAP provider for test 25-03 (optional — skipped if LDAP not reachable)
    _state["ldap_available"] = _ldap_reachable()
    if _state["ldap_available"]:
        data = await admin_client.create_idp_provider(
            provider_type="ldap",
            name="25-ldap",
            config=_LDAP_PROVIDER_CONFIG,
        )
        _state["ldap_provider_id"] = data["id"]

    yield

    # Teardown
    try:
        await _state["victim_session"].ctx.close()
    except Exception:
        pass
    if _state.get("ldap_provider_id"):
        try:
            await admin_client.delete_idp_provider(_state["ldap_provider_id"])
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 25-01  emit() path: admin.siem.config_changed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_25_01_siem_config_change_reaches_capture(admin_client: AdminClient):
    """
    Creating a SIEM destination emits admin.siem.config_changed via emit()
    (persist + fan-out).  Verify it appears in the SIEM capture file.
    """
    dest = await admin_client.create_siem_destination(
        name="25-siem-probe",
        type="syslog",
        host="127.0.0.1",
        port=514,
        protocol="udp",
        syslog_format="rfc5424",
    )
    dest_id = dest["id"]

    ev = await wait_for("admin.siem.config_changed", max_wait=5.0)
    assert ev is not None, (
        "admin.siem.config_changed did not appear in SIEM capture file within 5 s.\n"
        f"Capture contents: {read_all()}"
    )
    assert ev["outcome"] == "success", f"Unexpected outcome: {ev['outcome']!r}"

    await admin_client.delete_siem_destination(dest_id)


# ---------------------------------------------------------------------------
# 25-02  emit() path: admin.emergency_revocation at severity=critical
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_25_02_emergency_revocation_reaches_capture(admin_client: AdminClient):
    """
    Emergency revocation emits admin.emergency_revocation via emit().
    Verify it appears in the capture file at severity=critical.
    """
    result = await admin_client.emergency_revoke(
        _state["victim_id"],
        reason="SIEM capture test 25-02",
        scope="owned_only",
    )
    assert result.get("ok"), f"Emergency revoke API call failed: {result}"

    ev = await wait_for("admin.emergency_revocation", max_wait=5.0, severity="critical")
    assert ev is not None, (
        "admin.emergency_revocation (severity=critical) not found in capture within 5 s.\n"
        f"Capture contents: {read_all()}"
    )
    assert ev["outcome"] == "success", f"Expected outcome=success, got: {ev['outcome']!r}"


# ---------------------------------------------------------------------------
# 25-03  emit_fanout_only() path: failed LDAP login
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_25_03_ldap_login_failure_reaches_capture():
    """
    A failed LDAP login calls log_security_event('ldap_login_failed') which
    calls event_bus.emit_fanout_only().  Verify the translated event
    auth.ldap.login (severity=warning, outcome=failure) reaches the capture file.

    This is the primary Phase 2.5 smoke test: it confirms that the
    emit_fanout_only() path actually delivers events to SIEM output paths.

    Skipped if the LDAP container is not reachable on localhost:389.
    """
    if not _state.get("ldap_available"):
        pytest.skip("LDAP container not reachable on localhost:389 — skipping")

    provider_id = _state["ldap_provider_id"]

    async with httpx.AsyncClient(base_url=APP_URL, timeout=10.0) as client:
        # Seed the CSRF cookie
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")

        # Attempt login with a username that does not exist in LDAP
        await client.post(
            f"{API}/auth/ldap/login",
            json={
                "provider_id":      provider_id,
                "username":         "nonexistent_user_25xz",
                "password":         "wrong_password",
                "is_public_device": False,
            },
            headers={"X-CSRF-Token": csrf},
        )
        # We expect 401/403; we don't assert the status — the event is what matters.

    ev = await wait_for("auth.ldap.login", max_wait=5.0, severity="warning")
    assert ev is not None, (
        "auth.ldap.login (severity=warning) did not appear in SIEM capture within 5 s "
        "after a failed LDAP login attempt.  This tests the emit_fanout_only() path "
        f"added in Phase 2.5.\nCapture contents: {read_all()}"
    )
    assert ev["outcome"] == "failure", (
        f"Expected outcome=failure for ldap login failure, got: {ev['outcome']!r}"
    )


# ---------------------------------------------------------------------------
# 25-04  Taxonomy guard: no legacy flat strings in capture
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_25_04_no_legacy_flat_event_types_in_capture():
    """
    All events in the capture file must use dot-namespaced event_type values
    (e.g. 'auth.ldap.login'), not the legacy flat strings that existed before
    Phase 2.5 (e.g. 'ldap_login_failed').  The _EVENT_MAP in stepup.py is
    responsible for this translation.
    """
    events = read_all()
    assert events, (
        "Capture file is empty — tests 25-01 through 25-03 should have populated it"
    )

    bad = [ev["event_type"] for ev in events if ev.get("event_type") in _LEGACY_FLAT_TYPES]
    assert not bad, (
        f"Found events with legacy flat event_type strings: {bad}.\n"
        "These should have been translated to dot-namespaced taxonomy by _EVENT_MAP "
        "in auth/stepup.py before being passed to emit_fanout_only()."
    )


# ---------------------------------------------------------------------------
# 25-05  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_25_05_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
