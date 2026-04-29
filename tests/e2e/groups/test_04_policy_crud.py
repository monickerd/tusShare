"""
Group 04 — Policy engine CRUD.

Tests the full policy lifecycle: field definitions → policies → conditions →
effects (folder grants) → revocation.

Tests
-----
04-01  Built-in policy fields exist (totp_enabled, auth_provider, identity_provider)
04-02  Admin can create a custom internal policy field
04-03  Custom field appears in field list
04-04  Admin can create a policy (org scope)
04-05  Policy appears in policy list
04-06  Admin can add a condition to a policy
04-07  Condition is listed under the policy
04-08  Admin can update a policy condition
04-09  Admin can delete a policy condition
04-10  Admin can delete a policy
04-11  Deleted policy is gone from the list
04-12  Admin can create a team-scoped policy
04-13  Deleting a policy field that is in use is rejected
"""

from __future__ import annotations

import pytest

from tests.e2e.helpers.admin   import AdminClient, ApiClient
from tests.e2e.helpers.policies import create_policy_with_conditions
from tests.e2e.helpers.teams   import create_team, delete_team
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

_field:         dict = {}
_policy:        dict = {}
_condition:     dict = {}
_team_policy:   dict = {}

# ---------------------------------------------------------------------------
# SIEM manifest — events this group's actions must produce
#
# Policy and policy-field CRUD routes do not emit SIEM events.
# Team creation does not emit SIEM events.
# No 401/403 responses expected from the happy-path policy tests.
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = []


@pytest.mark.asyncio(loop_scope="session")
async def test_04_01_builtin_policy_fields_exist(admin_client: AdminClient):
    fields = await admin_client.list_policy_fields()
    names = {f["name"] for f in fields}
    for expected in ("totp_enabled", "auth_provider", "identity_provider"):
        assert expected in names, f"Built-in field '{expected}' missing: {names}"


@pytest.mark.asyncio(loop_scope="session")
async def test_04_02_admin_creates_policy_field(admin_client: AdminClient):
    global _field
    _field = await admin_client.create_policy_field(
        name="department",
        display_label="Department",
        source="ldap",
        data_type="string",
        claim_path="department",
    )
    assert _field["name"] == "department"


@pytest.mark.asyncio(loop_scope="session")
async def test_04_03_custom_field_in_list(admin_client: AdminClient):
    fields = await admin_client.list_policy_fields()
    names = {f["name"] for f in fields}
    assert "department" in names


@pytest.mark.asyncio(loop_scope="session")
async def test_04_04_admin_creates_policy(admin_client: AdminClient):
    global _policy
    _policy = await admin_client.create_policy(
        name="Engineering Access",
        scope_type="org",
    )
    assert _policy["name"] == "Engineering Access"
    assert "id" in _policy


@pytest.mark.asyncio(loop_scope="session")
async def test_04_05_policy_in_list(admin_client: AdminClient):
    policies = await admin_client.list_policies()
    ids = [p["id"] for p in policies]
    assert _policy["id"] in ids


@pytest.mark.asyncio(loop_scope="session")
async def test_04_06_admin_adds_condition(admin_client: AdminClient):
    global _condition
    _condition = await admin_client.add_policy_condition(
        _policy["id"],
        field="department",
        operator="=",
        value="engineering",
    )
    assert _condition.get("field")    == "department"
    assert _condition.get("operator") == "="
    assert _condition.get("value")    == "engineering"


@pytest.mark.asyncio(loop_scope="session")
async def test_04_07_condition_listed_under_policy(admin_client: AdminClient):
    policy = await admin_client.get_policy(_policy["id"])
    # The full policy object should include its conditions
    cond_ids = [c["id"] for c in policy.get("conditions", [])]
    assert _condition["id"] in cond_ids, (
        f"Condition {_condition['id']} not found in policy conditions: {cond_ids}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_04_08_admin_updates_condition(admin_client: AdminClient):
    r = await admin_client._client.patch(
        f"/api/v1/admin/policies/{_policy['id']}/conditions/{_condition['id']}",
        json={"value": "product"},
    )
    assert r.status_code == 200
    updated = r.json()
    assert updated.get("value") == "product"
    # Restore original value
    await admin_client._client.patch(
        f"/api/v1/admin/policies/{_policy['id']}/conditions/{_condition['id']}",
        json={"value": "engineering"},
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_04_09_admin_deletes_condition(admin_client: AdminClient):
    # Add a second condition to delete
    cond = await admin_client.add_policy_condition(
        _policy["id"],
        field="auth_provider",
        operator="=",
        value="local",
    )
    await admin_client.delete_policy_condition(_policy["id"], cond["id"])

    policy = await admin_client.get_policy(_policy["id"])
    cond_ids = [c["id"] for c in policy.get("conditions", [])]
    assert cond["id"] not in cond_ids


@pytest.mark.asyncio(loop_scope="session")
async def test_04_10_admin_deletes_policy(admin_client: AdminClient):
    disposable = await admin_client.create_policy(name="To Be Deleted")
    await admin_client.delete_policy(disposable["id"])


@pytest.mark.asyncio(loop_scope="session")
async def test_04_11_deleted_policy_gone(admin_client: AdminClient):
    policies = await admin_client.list_policies()
    names = [p["name"] for p in policies]
    assert "To Be Deleted" not in names


@pytest.mark.asyncio(loop_scope="session")
async def test_04_12_team_scoped_policy(admin_client: AdminClient, seeded_env):
    """Team-scoped policy requires a scope_id (team_id). Verify it's created."""
    global _team_policy
    # Create a team using the fake-crypto helper (no browser needed).
    admin_api = ApiClient.from_session(seeded_env["admin_session"])
    team = await create_team(admin_api, "04 Policy Test Team")
    team_id = team["id"]

    try:
        _team_policy = await admin_client.create_policy(
            name="Team-Scoped Policy",
            scope_type="team",
            scope_id=team_id,
        )
        assert _team_policy["scope_type"] == "team"
        assert _team_policy["scope_id"]   == team_id
    finally:
        await delete_team(admin_api, team_id)


@pytest.mark.asyncio(loop_scope="session")
async def test_04_13_cannot_delete_field_in_use(admin_client: AdminClient):
    """Deleting a policy field that is referenced by a condition should fail."""
    # 'department' field is used by the condition in _policy
    r = await admin_client._client.delete("/api/v1/admin/policy-fields/department")
    # Expect 409 Conflict or 400 Bad Request
    assert r.status_code in (400, 409), (
        f"Expected rejection when deleting a field in use, got {r.status_code}: {r.text}"
    )

    # Cleanup: delete the policy (and its conditions) first, then the field
    await admin_client.delete_policy(_policy["id"])
    await admin_client.delete_policy_field("department")


# ---------------------------------------------------------------------------
# 04-14  SIEM manifest
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_04_14_siem_manifest():
    """Verify expected SIEM events appeared in the capture file during this test group."""
    assert_manifest(_SIEM_MANIFEST)
