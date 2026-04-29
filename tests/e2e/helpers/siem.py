"""SIEM capture helper for e2e tests.

Reads events written by the app container to TUSSHARE_SIEM_CAPTURE_FILE
(/data/siem_capture.jsonl in the test container, set in docker-compose.test.yml).
The capture file is cleared at app startup, so each reset_db() / app restart
starts with an empty file.

Uses docker exec to access the file — no bind-mount needed.

Usage
-----
    from tests.e2e.helpers.siem import read_all, find, wait_for

    # Block until the event appears (or timeout)
    ev = await wait_for("auth.ldap.login", severity="warning")
    assert ev is not None, "Expected ldap login failure event in capture"

    # One-shot read + search (no polling)
    events = read_all()
    ev = find("admin.siem.config_changed", events=events, outcome="success")
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
from typing import Any, Optional

_PROJECT       = os.getenv("TEST_PROJECT_NAME", "tusshare_test")
_CONTAINER_APP = f"{_PROJECT}_app"
_CAPTURE_PATH  = "/data/siem_capture.jsonl"


# ---------------------------------------------------------------------------
# Low-level I/O — all blocking; wrap in asyncio.to_thread for async callers
# ---------------------------------------------------------------------------

def read_all() -> list[dict]:
    """Return all events currently in the capture file (docker exec cat)."""
    result = subprocess.run(
        ["docker", "exec", _CONTAINER_APP, "cat", _CAPTURE_PATH],
        capture_output=True,
        text=True,
    )
    events: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return events


def find(
    event_type: str,
    *,
    events: list[dict] | None = None,
    **match_fields: Any,
) -> Optional[dict]:
    """Return the first event matching event_type and all match_fields, or None.

    Pass ``events=read_all()`` to avoid re-reading the file on each call.
    """
    if events is None:
        events = read_all()
    for ev in events:
        if ev.get("event_type") != event_type:
            continue
        if all(ev.get(k) == v for k, v in match_fields.items()):
            return ev
    return None


# ---------------------------------------------------------------------------
# Async polling helper
# ---------------------------------------------------------------------------

async def wait_for(
    event_type: str,
    *,
    max_wait: float = 5.0,
    poll_interval: float = 0.35,
    **match_fields: Any,
) -> Optional[dict]:
    """Poll the capture file until a matching event appears or max_wait elapses.

    The file read runs in a thread (asyncio.to_thread) so the event loop is
    not blocked during the subprocess call.

    Returns the matching event dict, or None on timeout.
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + max_wait
    while loop.time() < deadline:
        events = await asyncio.to_thread(read_all)
        ev = find(event_type, events=events, **match_fields)
        if ev is not None:
            return ev
        await asyncio.sleep(poll_interval)
    return None
