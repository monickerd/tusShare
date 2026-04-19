"""
Audit log helpers for e2e tests.

Provides a polling helper that waits for a specific security event to appear
in the pull API, with a configurable timeout.  Use this when a test performs
an action and then needs to verify the event was emitted — the event bus is
asynchronous, so the DB row may appear a moment after the HTTP response.

Usage
-----
    from tests.e2e.helpers.audit import get_recent_event

    ev = await get_recent_event(admin_client, "admin.emergency_revocation",
                                target_id=revoked_user_id)
    assert ev is not None, "Expected emergency_revocation event to be logged"
    assert ev["outcome"] == "success"
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

from tests.e2e.helpers.admin import AdminClient, API


async def get_recent_event(
    admin_client: AdminClient,
    event_type: str,
    *,
    max_wait: float = 4.0,
    poll_interval: float = 0.25,
    **match_fields: Any,
) -> Optional[dict]:
    """
    Poll the audit log pull API until an event of ``event_type`` matching all
    ``match_fields`` appears, or ``max_wait`` seconds elapse.

    ``match_fields`` are checked against the top-level event dict keys returned
    by the pull API.  Pass ``target_id=<id>`` to filter by target, for example.

    Returns the matching event dict, or None if not found within the timeout.
    """
    deadline = asyncio.get_event_loop().time() + max_wait
    while asyncio.get_event_loop().time() < deadline:
        data = await admin_client.query_audit_logs(
            event_types=event_type,
            limit=50,
        )
        for ev in data.get("events", []):
            if ev.get("event_type") != event_type:
                continue
            if all(ev.get(k) == v for k, v in match_fields.items()):
                return ev
        await asyncio.sleep(poll_interval)
    return None
