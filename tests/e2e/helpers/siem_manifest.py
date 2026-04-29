"""SIEM manifest helpers for per-group emission verification.

Each test group declares a manifest — a list of ExpectedSiemEvent objects — and
calls assert_manifest() as a final test (e.g. test_NN_99_siem_manifest).  The
manifest states which events the group's actions should produce, and each event
is annotated with the highest (most relaxed) profile tier that still captures it.

Tier semantics
--------------
Profiles (from siem_filters.py, high_security → relaxed):

  Tier 1  high_security   All event types, all severities (min_severity=info).
  Tier 2  recommended     auth.*, admin.*, policy.*, file.delete, file.move,
                          share.*, team.* — all severities.
  Tier 3  relaxed         All event types, but critical severity only.

Labelling rule — derive the tier for any expected event:

  • severity == "critical"                    → tier=3  (critical always reaches relaxed)
  • event_type matches recommended globs      → tier=2  (reaches recommended + high_security)
  • everything else (file.upload, etc.)       → tier=1  (high_security only)

Assertion rule — an event with label L is asserted present when active_tier ≤ L:

  Event tier=2, active_tier=1 → 1 ≤ 2 → assert present  ✓ (high_security sees it)
  Event tier=2, active_tier=2 → 2 ≤ 2 → assert present  ✓ (recommended sees it)
  Event tier=2, active_tier=3 → 3 ≤ 2 → skip            ✓ (relaxed does not see it)

Active tier
-----------
Set the SIEM_TEST_TIER env var before running pytest to simulate a profile:

  SIEM_TEST_TIER=1  (default) — assert all tier-1, 2, and 3 events present
  SIEM_TEST_TIER=2            — assert tier-2 and 3 events; skip tier-1
  SIEM_TEST_TIER=3            — assert only tier-3 (critical) events

Important: the capture file always receives all emitted events regardless of
profile — it is captured pre-filter.  These manifests verify emission completeness
("did the right events fire?"), not destination delivery ("did they reach the SIEM
after filtering?").  Profile-filter correctness belongs in siem_filters unit tests.

Usage
-----
    from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

    _SIEM_MANIFEST = [
        ExpectedSiemEvent("admin.emergency_revocation", outcome="success",
                          severity="critical", tier=3),
        ExpectedSiemEvent("admin.siem.config_changed", outcome="success",
                          severity="info", tier=2),
    ]

    @pytest.mark.asyncio(loop_scope="session")
    async def test_NN_99_siem_manifest():
        assert_manifest(_SIEM_MANIFEST)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from tests.e2e.helpers.siem import find, read_all


@dataclass
class ExpectedSiemEvent:
    """One expected entry in a per-group SIEM manifest.

    Parameters
    ----------
    event_type:
        Dot-namespaced event type, e.g. "auth.ldap.login".
    outcome:
        Expected value of the "outcome" field, or None to skip checking.
    severity:
        Expected value of the "severity" field, or None to skip checking.
    tier:
        The highest (most relaxed) profile tier that still captures this event.
        1 = high_security only, 2 = recommended+, 3 = all profiles.
        Derive from event type and severity using the labelling rule in the
        module docstring.
    extra:
        Additional fields to match (e.g. {"detail": {...}}).  Checked with
        exact equality against the captured event dict.
    """
    event_type: str
    outcome:    str | None = None
    severity:   str | None = None
    tier:       int        = 3
    extra:      dict       = field(default_factory=dict)


def active_tier() -> int:
    """Return the current test tier from SIEM_TEST_TIER (default 1 = strictest)."""
    raw = os.getenv("SIEM_TEST_TIER", "1")
    try:
        t = int(raw)
        return t if t in (1, 2, 3) else 1
    except ValueError:
        return 1


def assert_manifest(
    manifest: list[ExpectedSiemEvent],
    *,
    tier: int | None = None,
    events: list[dict] | None = None,
) -> None:
    """Assert that all manifest events expected at the current tier are present.

    Events with event.tier >= active_tier are asserted present in the capture
    file.  Events below the threshold are silently skipped (they would not reach
    a SIEM destination at the active profile level).

    Parameters
    ----------
    manifest:
        List of ExpectedSiemEvent for this test group.
    tier:
        Override the active tier (default: read from SIEM_TEST_TIER env var).
    events:
        Pre-read capture file contents.  Pass a cached list to avoid re-reading
        the file when you need multiple assertions.  If None, reads once.
    """
    t = tier if tier is not None else active_tier()
    if events is None:
        events = read_all()

    missing: list[ExpectedSiemEvent] = []
    for exp in manifest:
        if exp.tier < t:
            continue  # this event is not expected to reach a tier-t profile

        match_fields: dict[str, Any] = {}
        if exp.outcome is not None:
            match_fields["outcome"] = exp.outcome
        if exp.severity is not None:
            match_fields["severity"] = exp.severity
        match_fields.update(exp.extra)

        if find(exp.event_type, events=events, **match_fields) is None:
            missing.append(exp)

    if missing:
        seen_types = sorted({e.get("event_type", "") for e in events})
        lines = [
            f"  - {e.event_type!r}  "
            f"outcome={e.outcome!r}  severity={e.severity!r}  tier={e.tier}"
            for e in missing
        ]
        raise AssertionError(
            f"SIEM manifest check failed (active_tier={t}): "
            f"{len(missing)} expected event(s) not found in capture file:\n"
            + "\n".join(lines)
            + f"\n\nEvent types present in capture: {seen_types}"
        )
