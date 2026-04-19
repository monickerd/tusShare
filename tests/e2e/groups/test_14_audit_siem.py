"""
Group 14 — Audit trail + SIEM.

Structural tests for the E7 audit subsystem.  All tests run against the live
application via the API; no browser is needed here.

World layout
------------
A single victim user (audit_victim_14) is registered, then emergency-revoked
to generate a real admin.emergency_revocation event for the emission tests.
The SIEM destination tests create and delete their own destinations, leaving
the DB clean for teardown.

Tests
-----
14-01  Pull API returns 200 with expected shape
14-02  Pull API event objects contain all required fields
14-03  Event-type glob filter: auth.* matches auth events, not file events
14-04  Severity filter: requesting 'warning' minimum excludes info events
14-05  CSV export returns 200 with text/csv content-type and correct headers
14-06  Non-admin cannot query audit logs (403)
14-07  SSE stream endpoint returns 200 with text/event-stream content-type
14-08  SSE stream delivers an event emitted after the connection opens
14-09  Emergency revocation emits admin.emergency_revocation at severity=critical
14-10  SIEM: create syslog destination — appears in list with correct fields
14-11  SIEM: webhook destination rejects non-HTTPS URL (400)
14-12  SIEM: update destination name
14-13  SIEM: delete destination — gone from list
14-14  SIEM: admin.siem.config_changed event emitted on destination create
14-15  Retention setting is readable via GET /admin/settings
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin import AdminClient, ApiClient
from tests.e2e.helpers.auth  import register_via_invite
from tests.e2e.helpers.audit import get_recent_event

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

# Module-level state shared across tests
_victim: dict = {}       # {id, session} — the user who will be revoked
_dest_id: str = ""       # created syslog destination id (cleaned up in 14-13)


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup_world(seeded_env, browser: Browser):
    """Register the victim user; clean up siem destinations on teardown."""
    global _victim, _dest_id
    admin_client: AdminClient = seeded_env["admin_client"]

    invite_url = await admin_client.create_invite_url()
    session    = await register_via_invite(browser, invite_url, "audit_victim_14", "V1ctim!Pwd99")
    users      = await admin_client.list_users()
    uid        = next(u["id"] for u in users if u["username"].lower() == "audit_victim_14")
    _victim    = {"id": uid, "session": session}

    # Seed at least one security event so test_14_02's field check always has data.
    seed = await admin_client.create_siem_destination(
        name="14-world-seed",
        type="syslog",
        host="127.0.0.1",
        port=514,
        protocol="udp",
        syslog_format="rfc5424",
    )
    await admin_client.delete_siem_destination(seed["id"])

    yield

    # Best-effort cleanup: remove any leftover SIEM destinations from this run
    try:
        dests = await admin_client.list_siem_destinations()
        for d in dests:
            if "14" in d.get("name", ""):
                await admin_client.delete_siem_destination(d["id"])
    except Exception:
        pass

    if _victim.get("session"):
        await _victim["session"].ctx.close()


# ---------------------------------------------------------------------------
# 14-01  Pull API shape
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_01_pull_api_returns_200(admin_client: AdminClient):
    data = await admin_client.query_audit_logs(limit=10)
    assert "events" in data, f"Expected 'events' key in response: {data}"
    assert "count"  in data, f"Expected 'count' key in response: {data}"
    assert isinstance(data["events"], list)


# ---------------------------------------------------------------------------
# 14-02  Required event fields
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_02_event_objects_have_required_fields(admin_client: AdminClient):
    data = await admin_client.query_audit_logs(limit=20)
    events = data["events"]
    assert events, "Expected events in audit log (setup_world seeds at least one)"

    required = {"event_id", "timestamp", "event_type", "severity"}
    for ev in events[:5]:
        missing = required - set(ev.keys())
        assert not missing, f"Event missing fields {missing}: {ev}"


# ---------------------------------------------------------------------------
# 14-03  Event-type glob filter
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_03_glob_filter_matches_correctly(admin_client: AdminClient):
    # Seed at least one auth event by triggering a SIEM config change first,
    # then filter — auth.* should not return admin.siem.* events.
    # Create and delete a throwaway destination to seed admin.siem.config_changed.
    dest = await admin_client.create_siem_destination(
        name="14-glob-seed",
        type="syslog",
        host="127.0.0.1",
        port=514,
        protocol="udp",
        syslog_format="rfc5424",
    )
    await admin_client.delete_siem_destination(dest["id"])

    # Filter for auth.* only
    data = await admin_client.query_audit_logs(event_types="auth.*", limit=50)
    for ev in data["events"]:
        assert ev["event_type"].startswith("auth."), (
            f"Glob 'auth.*' returned non-auth event: {ev['event_type']}"
        )

    # Filter for admin.siem.* only — should include our seeded events
    data2 = await admin_client.query_audit_logs(event_types="admin.siem.*", limit=50)
    types = {ev["event_type"] for ev in data2["events"]}
    assert any(t.startswith("admin.siem.") for t in types), (
        f"admin.siem.* filter returned no matching events; got types: {types}"
    )
    for ev in data2["events"]:
        assert ev["event_type"].startswith("admin.siem."), (
            f"admin.siem.* filter returned unexpected event: {ev['event_type']}"
        )


# ---------------------------------------------------------------------------
# 14-04  Severity filter
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_04_severity_filter_excludes_info(admin_client: AdminClient):
    data = await admin_client.query_audit_logs(severity="warning", limit=100)
    for ev in data["events"]:
        assert ev["severity"] in ("warning", "critical"), (
            f"Severity filter 'warning' returned info event: {ev}"
        )


# ---------------------------------------------------------------------------
# 14-05  CSV export
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_05_csv_export_returns_correct_content_type(admin_client: AdminClient):
    resp = await admin_client.export_audit_logs_raw(limit=10)
    ct = resp.headers.get("content-type", "")
    assert "text/csv" in ct, f"Expected text/csv content-type, got: {ct!r}"


@pytest.mark.asyncio(loop_scope="session")
async def test_14_05b_csv_export_has_correct_headers(admin_client: AdminClient):
    resp = await admin_client.export_audit_logs_raw()
    text = resp.text
    first_line = text.splitlines()[0] if text else ""
    expected_cols = {"event_id", "timestamp", "event_type", "severity", "outcome", "actor_user_id"}
    actual_cols   = set(first_line.split(","))
    missing = expected_cols - actual_cols
    assert not missing, f"CSV missing columns: {missing}; first line: {first_line!r}"


# ---------------------------------------------------------------------------
# 14-06  Non-admin access denied
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_06_non_admin_cannot_query_audit_logs():
    victim_api = ApiClient.from_session(_victim["session"])
    async with victim_api:
        r = await victim_api.get("/admin/audit/logs")
    assert r.status_code == 403, (
        f"Regular user should be denied audit log access, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# 14-07  SSE content-type header
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_07_sse_endpoint_returns_event_stream_content_type(
    admin_client: AdminClient,
):
    """Open the SSE stream and verify status + content-type header.

    We do NOT read any body bytes — SSE streams stay open indefinitely and
    the first keepalive comment arrives after 25 s, which would exceed any
    reasonable read timeout.  The status code and content-type header are
    available as soon as the connection is established.
    """
    cookies = admin_client._cookies
    # No read timeout — the stream never finishes; we close as soon as we have headers.
    timeout = httpx.Timeout(connect=5.0, read=None, write=5.0, pool=5.0)

    async with httpx.AsyncClient(cookies=cookies, timeout=timeout) as client:
        async with client.stream("GET", f"{API}/admin/audit/logs/stream") as resp:
            assert resp.status_code == 200, (
                f"SSE stream returned {resp.status_code}"
            )
            ct = resp.headers.get("content-type", "")
            assert "text/event-stream" in ct, (
                f"Expected text/event-stream, got: {ct!r}"
            )
            # Headers confirmed — close without reading body.


# ---------------------------------------------------------------------------
# 14-08  SSE stream delivers live events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_08_sse_stream_delivers_events(admin_client: AdminClient):
    """
    Connect to the SSE stream, trigger a SIEM config-change event by creating
    a throwaway destination, then assert the event arrives on the stream within
    five seconds.
    """
    cookies = admin_client._cookies
    received: list[str] = []
    stream_opened = asyncio.Event()

    async def _consume():
        async with httpx.AsyncClient(cookies=cookies, timeout=10) as client:
            async with client.stream("GET", f"{API}/admin/audit/logs/stream") as resp:
                stream_opened.set()
                async for line in resp.aiter_lines():
                    if line.startswith("event:"):
                        received.append(line)
                    if any("admin.siem" in s for s in received):
                        return

    consumer = asyncio.create_task(_consume())

    # Wait for the stream to open before triggering the event
    await asyncio.wait_for(stream_opened.wait(), timeout=3)

    dest = await admin_client.create_siem_destination(
        name="14-sse-seed",
        type="syslog",
        host="127.0.0.1",
        port=514,
        protocol="udp",
        syslog_format="rfc5424",
    )
    await admin_client.delete_siem_destination(dest["id"])

    # Give the stream up to five seconds to deliver the event
    try:
        await asyncio.wait_for(asyncio.shield(consumer), timeout=5)
    except asyncio.TimeoutError:
        pass
    finally:
        consumer.cancel()
        try:
            await consumer
        except (asyncio.CancelledError, Exception):
            pass

    assert any("admin.siem" in s for s in received), (
        f"SSE stream did not deliver expected admin.siem event within 5s. "
        f"Received lines: {received}"
    )


# ---------------------------------------------------------------------------
# 14-09  Emergency revocation emits the right event
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_09_emergency_revocation_emits_critical_event(admin_client: AdminClient):
    """
    Emergency-revoke the victim user and verify that an
    admin.emergency_revocation event at severity=critical appears in the
    audit log with the correct target_id.
    """
    result = await admin_client.emergency_revoke(
        _victim["id"],
        reason="Test revocation for audit log verification",
        scope="owned_only",
    )
    assert result.get("ok"), f"Emergency revoke failed: {result}"

    ev = await get_recent_event(
        admin_client,
        "admin.emergency_revocation",
        target_id=_victim["id"],
    )
    assert ev is not None, (
        "admin.emergency_revocation event did not appear in audit log within timeout"
    )
    assert ev["severity"] == "critical", (
        f"Expected severity=critical for emergency revocation, got: {ev['severity']!r}"
    )
    assert ev["outcome"] == "success", (
        f"Expected outcome=success, got: {ev['outcome']!r}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_14_09b_revoked_user_cannot_make_requests():
    """Verify the revoked user is actually blocked (not just event-emission check)."""
    victim_api = ApiClient.from_session(_victim["session"])
    async with victim_api:
        r = await victim_api.get("/folders")
    assert r.status_code in (401, 403), (
        f"Revoked user should be blocked, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# 14-10  SIEM destination: create syslog
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_10_create_syslog_destination(admin_client: AdminClient):
    global _dest_id
    resp = await admin_client.create_siem_destination(
        name="14-syslog-dest",
        type="syslog",
        host="siem.corp.example.com",
        port=514,
        protocol="udp",
        syslog_format="rfc5424",
    )
    assert resp.get("ok"), f"Create destination failed: {resp}"
    _dest_id = resp["id"]

    dests = await admin_client.list_siem_destinations()
    match = next((d for d in dests if d["id"] == _dest_id), None)
    assert match is not None, "Newly created syslog destination not found in list"
    assert match["type"] == "syslog"
    assert match["host"] == "siem.corp.example.com"
    assert match["syslog_format"] == "rfc5424"
    assert match["is_active"] is True


# ---------------------------------------------------------------------------
# 14-11  Webhook rejects non-HTTPS URL
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_11_webhook_rejects_http_url(admin_client: AdminClient):
    r = await admin_client._client.post(
        f"{API}/admin/audit/siem",
        json={
            "name": "14-bad-webhook",
            "type": "webhook",
            "url": "http://not-secure.example.com/ingest",  # HTTP, not HTTPS
        },
    )
    assert r.status_code == 400, (
        f"Expected 400 for non-HTTPS webhook URL, got {r.status_code}: {r.text}"
    )


# ---------------------------------------------------------------------------
# 14-12  Update destination name
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_12_update_destination_name(admin_client: AdminClient):
    assert _dest_id, "Depends on test_14_10 creating a destination"
    resp = await admin_client.update_siem_destination(
        _dest_id,
        name="14-syslog-dest-renamed",
        type="syslog",
        host="siem.corp.example.com",
        port=514,
        protocol="udp",
        syslog_format="rfc5424",
    )
    assert resp.get("ok"), f"Update failed: {resp}"

    dests = await admin_client.list_siem_destinations()
    match = next((d for d in dests if d["id"] == _dest_id), None)
    assert match is not None
    assert match["name"] == "14-syslog-dest-renamed", (
        f"Name was not updated; got: {match['name']!r}"
    )


# ---------------------------------------------------------------------------
# 14-13  Delete destination
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_13_delete_destination(admin_client: AdminClient):
    assert _dest_id, "Depends on test_14_10 creating a destination"
    await admin_client.delete_siem_destination(_dest_id)

    dests = await admin_client.list_siem_destinations()
    assert not any(d["id"] == _dest_id for d in dests), (
        "Deleted destination still appears in the list"
    )


# ---------------------------------------------------------------------------
# 14-14  admin.siem.config_changed emitted on create
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_14_siem_config_changed_event_emitted(admin_client: AdminClient):
    dest = await admin_client.create_siem_destination(
        name="14-event-check",
        type="syslog",
        host="127.0.0.1",
        port=514,
        protocol="udp",
        syslog_format="rfc5424",
    )
    dest_id = dest["id"]

    ev = await get_recent_event(admin_client, "admin.siem.config_changed")
    assert ev is not None, (
        "admin.siem.config_changed event did not appear in audit log"
    )
    assert ev["outcome"] == "success"

    # Cleanup
    await admin_client.delete_siem_destination(dest_id)


# ---------------------------------------------------------------------------
# 14-15  Retention setting is readable and writable
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_14_15_retention_setting_readable_and_writable(admin_client: AdminClient):
    settings = await admin_client.get_settings()
    assert "audit_retention_days" in settings, (
        f"audit_retention_days missing from settings: {set(settings.keys())}"
    )

    original = settings["audit_retention_days"]
    await admin_client.set_setting("audit_retention_days", "730")
    updated = await admin_client.get_settings()
    assert updated["audit_retention_days"] == "730"

    # Restore
    await admin_client.set_setting("audit_retention_days", original)
