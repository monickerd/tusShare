"""
Group 35 — Security audit event emission.

Verifies SIEM events for sharing rule mutations and login failure attribution
that are not exercised by any existing test group.

Tests
-----
  35-01  Failed OPAQUE login finish emits auth.login.failure with username + reason
  35-02  Create sharing rule emits admin.sharing_rule.created
  35-03  Update sharing rule emits admin.sharing_rule.updated
  35-04  Delete sharing rule emits admin.sharing_rule.deleted
  35-05  SIEM manifest assertion

Notes
-----
Step-up tokens for sharing-rule mutations are minted directly against the test
JWT secret (TUSSHARE_JWT_SECRET in docker-compose.test.yml), following the same
pattern as test_26_service_accounts.py.

OPAQUE login failure is triggered by submitting a finish request with a
fabricated session_id that does not exist in the database.  The server emits
auth.login.failure with reason='session_not_found' before returning 401.
"""

from __future__ import annotations

import base64
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import jwt
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient
from tests.e2e.helpers.siem import wait_for
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# JWT secret from docker-compose.test.yml (TUSSHARE_JWT_SECRET in test container).
_TEST_JWT_SECRET  = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
_SHARING_ACTION   = "policy.sharing.*"

# ---------------------------------------------------------------------------
# SIEM manifest
# ---------------------------------------------------------------------------

_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    # G24: OPAQUE login failure — auth.* → tier=2
    ExpectedSiemEvent("auth.login.failure",            outcome="failure", severity="warning", tier=2),
    # G20: sharing rule mutations — admin.* → tier=2
    ExpectedSiemEvent("admin.sharing_rule.created",    outcome="success", severity="warning", tier=2),
    ExpectedSiemEvent("admin.sharing_rule.updated",    outcome="success", severity="warning", tier=2),
    ExpectedSiemEvent("admin.sharing_rule.deleted",    outcome="success", severity="warning", tier=2),
]

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_state: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _step_up(user_id: str, action: str = _SHARING_ACTION) -> str:
    """Mint a valid step-up JWT for the given action using the test JWT secret."""
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub":    user_id,
            "type":   "step_up",
            "action": action,
            "scope":  "*",
            "iat":    now,
            "exp":    now + timedelta(minutes=5),
        },
        _TEST_JWT_SECRET,
        algorithm="HS512",
    )


async def _get_csrf(client: httpx.AsyncClient) -> str:
    await client.get("/")
    return client.cookies.get("__Host-csrf_token", "")


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup_world(seeded_env, browser: Browser):
    global _state
    admin_client: AdminClient = seeded_env["admin_client"]

    me_r = await admin_client._client.get(f"{API}/auth/me")
    me_r.raise_for_status()
    _state["admin_id"]     = me_r.json()["user"]["id"]
    _state["admin_client"] = admin_client
    _state["rule_id"]      = None

    yield

    # Teardown: remove any lingering sharing rules created by this group
    rule_id = _state.get("rule_id")
    if rule_id:
        try:
            tok = _step_up(_state["admin_id"])
            await admin_client._client.delete(
                f"{API}/admin/sharing/rules/{rule_id}",
                headers={"X-Step-Up-Token": tok},
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 35-01  G24: Failed OPAQUE login emits auth.login.failure
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_35_01_failed_opaque_login_emits_failure_event():
    """
    Submitting login/finish with a fabricated session_id triggers the
    'session_not_found' failure path, which emits auth.login.failure
    (severity=warning, outcome=failure) before returning 401.
    """
    fake_session_id  = str(uuid.uuid4())
    fake_client_data = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    probe_username   = "nonexistent_35_probe"

    async with httpx.AsyncClient(base_url=APP_URL, timeout=10.0) as client:
        await client.get("/")
        csrf = client.cookies.get("__Host-csrf_token", "")
        r = await client.post(
            f"{API}/auth/opaque/login/finish",
            json={
                "username":            probe_username,
                "session_id":          fake_session_id,
                "client_login_finish": fake_client_data,
                "is_public_device":    False,
            },
            headers={"X-CSRF-Token": csrf},
        )

    assert r.status_code == 401, (
        f"Expected 401 for fabricated session, got {r.status_code}: {r.text}"
    )

    ev = await wait_for("auth.login.failure", max_wait=5.0, outcome="failure")
    assert ev is not None, (
        "auth.login.failure did not appear in SIEM capture within 5 s after a "
        "failed OPAQUE login/finish request.\nCapture note: event should carry "
        "detail.method='opaque' and detail.reason='session_not_found'."
    )
    assert ev.get("severity") == "warning", f"Expected severity=warning: {ev}"
    detail = ev.get("detail", {})
    assert detail.get("method") == "opaque", f"Expected detail.method='opaque': {detail}"


# ---------------------------------------------------------------------------
# 35-02  G20: Create sharing rule → admin.sharing_rule.created
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_35_02_create_sharing_rule_emits_event():
    """
    POST /admin/sharing/rules emits admin.sharing_rule.created (severity=warning).
    """
    admin_client: AdminClient = _state["admin_client"]
    tok = _step_up(_state["admin_id"])

    r = await admin_client._client.post(
        f"{API}/admin/sharing/rules",
        json={
            "name":     "35-test-rule",
            "subject":  "sender",
            "effect":   "deny",
            "priority": 9900,
            "is_active": False,
            "conditions": [],
        },
        headers={"X-Step-Up-Token": tok},
    )
    assert r.status_code == 200, f"Expected 200 creating rule, got {r.status_code}: {r.text}"
    rule = r.json()
    _state["rule_id"] = rule["id"]

    ev = await wait_for("admin.sharing_rule.created", max_wait=5.0, outcome="success")
    assert ev is not None, (
        "admin.sharing_rule.created did not appear in SIEM capture within 5 s."
    )
    assert ev.get("severity") == "warning", f"Expected severity=warning: {ev}"


# ---------------------------------------------------------------------------
# 35-03  G20: Update sharing rule → admin.sharing_rule.updated
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_35_03_update_sharing_rule_emits_event():
    """
    PUT /admin/sharing/rules/{id} emits admin.sharing_rule.updated (severity=warning).
    """
    rule_id = _state["rule_id"]
    assert rule_id, "rule_id not set — test_35_02 must have passed first"

    admin_client: AdminClient = _state["admin_client"]
    tok = _step_up(_state["admin_id"])

    r = await admin_client._client.put(
        f"{API}/admin/sharing/rules/{rule_id}",
        json={"name": "35-test-rule-updated"},
        headers={"X-Step-Up-Token": tok},
    )
    assert r.status_code == 200, f"Expected 200 updating rule, got {r.status_code}: {r.text}"

    ev = await wait_for("admin.sharing_rule.updated", max_wait=5.0, outcome="success")
    assert ev is not None, (
        "admin.sharing_rule.updated did not appear in SIEM capture within 5 s."
    )
    assert ev.get("severity") == "warning", f"Expected severity=warning: {ev}"


# ---------------------------------------------------------------------------
# 35-04  G20: Delete sharing rule → admin.sharing_rule.deleted
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_35_04_delete_sharing_rule_emits_event():
    """
    DELETE /admin/sharing/rules/{id} emits admin.sharing_rule.deleted (severity=warning).
    """
    rule_id = _state["rule_id"]
    assert rule_id, "rule_id not set — test_35_02 must have passed first"

    admin_client: AdminClient = _state["admin_client"]
    tok = _step_up(_state["admin_id"])

    r = await admin_client._client.delete(
        f"{API}/admin/sharing/rules/{rule_id}",
        headers={"X-Step-Up-Token": tok},
    )
    assert r.status_code == 200, f"Expected 200 deleting rule, got {r.status_code}: {r.text}"
    _state["rule_id"] = None  # Cleared — teardown no-op

    ev = await wait_for("admin.sharing_rule.deleted", max_wait=5.0, outcome="success")
    assert ev is not None, (
        "admin.sharing_rule.deleted did not appear in SIEM capture within 5 s."
    )
    assert ev.get("severity") == "warning", f"Expected severity=warning: {ev}"


# ---------------------------------------------------------------------------
# 35-05  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_35_05_siem_manifest():
    """Verify all expected SIEM events appeared during this test group."""
    assert_manifest(_SIEM_MANIFEST)
