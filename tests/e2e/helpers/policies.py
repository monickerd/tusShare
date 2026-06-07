"""
Policy engine helpers.

Thin wrappers around the policy-related admin API endpoints. Most of the
policy logic is server-side, so these helpers just drive the HTTP layer.
"""

from __future__ import annotations

import os
from typing import Optional

from tests.e2e.helpers.admin import AdminClient, ApiClient

APP_URL = os.getenv("TEST_APP_URL", "http://localhost:8001")


# ---------------------------------------------------------------------------
# Convenience: build a complete policy in one call
# ---------------------------------------------------------------------------


async def create_policy_with_conditions(
    admin:      AdminClient,
    name:       str,
    conditions: list[dict],    # [{"field": ..., "operator": ..., "value": ...}]
    scope_type: str = "org",
    scope_id:   Optional[str] = None,
) -> dict:
    """
    Create a policy and attach all conditions in a single helper call.

    Returns the policy dict with an added "conditions" key containing the
    created condition objects.

    Example:
        policy = await create_policy_with_conditions(
            admin,
            name="Engineering only",
            conditions=[
                {"field": "department", "operator": "=", "value": "engineering"},
            ],
        )
    """
    policy = await admin.create_policy(name, scope_type=scope_type, scope_id=scope_id)
    policy_id = policy["id"]
    created_conditions = []
    for cond in conditions:
        c = await admin.add_policy_condition(
            policy_id,
            field=cond["field"],
            operator=cond["operator"],
            value=cond["value"],
        )
        created_conditions.append(c)

    policy["conditions"] = created_conditions
    return policy


# ---------------------------------------------------------------------------
# Effect / grant inspection
# ---------------------------------------------------------------------------


async def wait_for_policy_grant(
    admin:     AdminClient,
    policy_id: str,
    user_id:   str,
    folder_id: str,
    timeout_s: int = 10,
) -> bool:
    """
    Poll policy effects until a grant appears for (user_id, folder_id),
    or the timeout is reached.

    Policy evaluation may be async/debounced on the server, so a brief wait
    is sometimes needed after the trigger.  Returns True if the grant was
    found, False on timeout.
    """
    import asyncio
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        effects = await admin.list_policy_effects(policy_id)
        if any(
            e.get("user_id") == user_id and e.get("folder_id") == folder_id
            for e in effects
        ):
            return True
        await asyncio.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Admin scope conditions
# ---------------------------------------------------------------------------


async def create_admin_scope(
    client:      ApiClient,
    holder_type: str,          # "user" | "role"
    holder_id:   str,
    field:       str,
    operator:    str,
    value:       str,
) -> dict:
    r = await client.post(
        "/admin/scopes",
        json={
            "holder_type": holder_type,
            "holder_id":   holder_id,
            "field":       field,
            "operator":    operator,
            "value":       value,
        },
    )
    r.raise_for_status()
    return r.json()


async def list_admin_scopes(client: ApiClient) -> list[dict]:
    r = await client.get("/admin/scopes")
    r.raise_for_status()
    return r.json()


async def delete_admin_scope_condition(client: ApiClient, cond_id: str) -> None:
    r = await client.delete(f"/admin/scopes/conditions/{cond_id}")
    r.raise_for_status()
