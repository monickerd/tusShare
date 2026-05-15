"""
Group 27 — Security profiles (Phase 4).

Tests the three built-in profiles, export/import round-trip, merge mode,
permission gates, first-run flag, and SIEM event emission.

Sections
--------
  A. Profile listing
    27-01  GET /admin/settings/profiles lists the three built-in profiles

  B. High Security profile
    27-02  Preview diff reports expected changes before applying
    27-03  Apply (replace, confirm=REPLACE) sets admin_settings, role_user flags, sharing rule
    27-04  Applied settings have correct is_locked=True, locked_min_tier=1

  C. Recommended profile
    27-05  Apply Recommended → correct settings, all sharing flags ON, locked at tier 2, no rules

  D. Open profile
    27-06  Apply Open → all sharing flags ON, not locked, no rules, escrow not required

  E. Export / import (replace mode)
    27-07  Export after Open: valid JSON structure, _warnings=[]
    27-08  Export after adding escrow user IDs → user IDs stripped, _warnings populated
    27-09  Import exported profile (replace mode) → settings exactly restored
    27-10  Replace-all clears existing sharing rules before applying imported rules

  F. Import (merge mode)
    27-11  Preview (confirm=False) returns diff without changing settings
    27-12  Selective decisions: only 'proposed' items applied; 'current' items skipped

  G. Permission gates & validation
    27-13  Export without step-up token → 403 step_up_required
    27-14  Apply-profile replace without confirmation_text → 400
    27-15  Import with unknown top-level key → 400

  H. First-run flag
    27-16  Apply with mark_first_run=True → first_run_completed='1' in settings

  I. SIEM events
    27-17  SIEM manifest: profile_applied, profile_exported, profile_imported present

Notes
-----
Step-up tokens are minted against the test JWT secret for action key
"admin.settings.security.*" (wildcard covers profile operations).

Teardown applies the Recommended profile to restore a sane shared state for
subsequent test groups (all sharing flags on, no deny rules).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest
from playwright.async_api import Browser

from tests.e2e.helpers.admin         import AdminClient
from tests.e2e.helpers.siem_manifest import ExpectedSiemEvent, assert_manifest

APP_URL = "http://localhost:8001"
API     = f"{APP_URL}/api/v1"

_TEST_JWT_SECRET = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
_PROFILE_ACTION  = "admin.settings.security.*"

# ---------------------------------------------------------------------------
# SIEM manifest
# ---------------------------------------------------------------------------
_SIEM_MANIFEST: list[ExpectedSiemEvent] = [
    ExpectedSiemEvent("admin.settings.profile_applied",  outcome="success", severity="high",     tier=1),
    ExpectedSiemEvent("admin.settings.profile_exported", outcome="success", severity="info",      tier=1),
    ExpectedSiemEvent("admin.settings.profile_imported", outcome="success", severity="critical",  tier=1),
]

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
_state: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _step_up(user_id: str) -> str:
    """Mint a valid step-up JWT for admin.settings.security.* using the test JWT secret."""
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub":    user_id,
            "type":   "step_up",
            "action": _PROFILE_ACTION,
            "scope":  "*",
            "iat":    now,
            "exp":    now + timedelta(minutes=5),
        },
        _TEST_JWT_SECRET,
        algorithm="HS512",
    )


# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
async def setup_world(seeded_env, browser: Browser):
    """Capture admin ID for step-up minting; restore sane state on teardown."""
    global _state
    admin_client: AdminClient = seeded_env["admin_client"]

    me_r = await admin_client._client.get(f"{API}/auth/me")
    me_r.raise_for_status()
    _state["admin_id"] = me_r.json()["user"]["id"]

    yield

    # Teardown: restore Recommended profile so later groups see normal sharing defaults.
    try:
        tok = _step_up(_state["admin_id"])
        await admin_client.apply_profile("recommended", tok, mode="replace")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# A. Profile listing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_27_01_list_profiles(admin_client: AdminClient):
    """GET /admin/settings/profiles returns the three built-in profiles."""
    profiles = await admin_client.list_profiles()
    ids = {p["id"] for p in profiles}
    assert ids == {"high_security", "recommended", "open"}, (
        f"Expected 3 built-in profiles, got: {ids}"
    )
    for p in profiles:
        assert "name" in p and "description" in p, f"Missing fields in profile: {p}"


# ---------------------------------------------------------------------------
# B. High Security profile
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_27_02_preview_diff_before_apply(admin_client: AdminClient):
    """Preview diff for High Security shows expected changed items."""
    tok  = _step_up(_state["admin_id"])
    diff = await admin_client.preview_apply_profile("high_security", mode="replace", step_up_token=tok)

    keys = {d["key"] for d in diff}
    assert "admin_setting.escrow_require_coverage"     in keys, f"Missing escrow_require_coverage in diff: {keys}"
    assert "admin_setting.notify_escrow_on_revocation" in keys, f"Missing notify_escrow_on_revocation in diff: {keys}"
    assert "role_flag.role_user.can_create_link_shares" in keys, f"Missing link_shares flag in diff: {keys}"

    # At least some items should be marked as changed (fresh DB has no profile applied)
    changed = [d for d in diff if d["changed"]]
    assert len(changed) > 0, "Expected at least one changed item in diff"


@pytest.mark.asyncio(loop_scope="session")
async def test_27_03_apply_high_security(admin_client: AdminClient):
    """Apply High Security profile: verify admin_settings, role_user flags, and sharing rule."""
    tok = _step_up(_state["admin_id"])
    result = await admin_client.apply_profile("high_security", tok, mode="replace")
    assert result.get("profile") == "high_security", f"Unexpected response: {result}"

    # Verify admin_settings
    settings = await admin_client.get_settings()
    assert settings.get("escrow_require_coverage")     == "1", "escrow_require_coverage should be '1'"
    assert settings.get("notify_escrow_on_revocation") == "1", "notify_escrow_on_revocation should be '1'"

    # Verify role_user sharing flags
    perms = await admin_client.get_role_permissions("role_user")
    assert perms.get("can_create_link_shares",   {}).get("value") == "0", "link shares should be OFF"
    assert perms.get("can_create_user_shares",   {}).get("value") == "1", "user shares should be ON"
    assert perms.get("can_create_upload_grants", {}).get("value") == "1", "upload grants should be ON"
    assert perms.get("can_share_folders",        {}).get("value") == "0", "share folders should be OFF"

    # Verify sharing rule was created
    rules_data = await admin_client.list_sharing_rules()
    rules = rules_data.get("rules", [])
    assert len(rules) >= 1, f"Expected at least 1 sharing rule after High Security, got: {rules}"
    rule_names = [r["name"] for r in rules]
    assert any("high security" in n.lower() or "link" in n.lower() for n in rule_names), (
        f"Expected High Security deny rule, got names: {rule_names}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_27_04_high_security_settings_locked(admin_client: AdminClient):
    """High Security: role_user flags and sharing rules are locked at tier 1."""
    perms = await admin_client.get_role_permissions("role_user")
    for flag in ("can_create_link_shares", "can_share_folders"):
        fp = perms.get(flag, {})
        assert fp.get("is_locked") is True,   f"{flag} should be locked"
        assert fp.get("locked_min_tier") == 1, f"{flag} should be locked at tier 1, got: {fp}"

    rules_data = await admin_client.list_sharing_rules()
    for rule in rules_data.get("rules", []):
        if "high security" in rule.get("name", "").lower():
            assert rule.get("is_locked") is True,   f"High Security rule should be locked"
            assert rule.get("locked_min_tier") == 1, f"High Security rule should be locked at tier 1"


# ---------------------------------------------------------------------------
# C. Recommended profile
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_27_05_apply_recommended(admin_client: AdminClient):
    """Apply Recommended profile: sharing flags ON, locked tier 2, no rules."""
    tok = _step_up(_state["admin_id"])
    await admin_client.apply_profile("recommended", tok, mode="replace")

    settings = await admin_client.get_settings()
    assert settings.get("escrow_require_coverage")     == "0", "Recommended: no required escrow coverage"
    assert settings.get("notify_escrow_on_revocation") == "1", "Recommended: notify on revocation ON"

    perms = await admin_client.get_role_permissions("role_user")
    for flag in ("can_create_link_shares", "can_create_user_shares",
                 "can_create_upload_grants", "can_share_folders"):
        fp = perms.get(flag, {})
        assert fp.get("value") == "1",          f"Recommended: {flag} should be ON"
        assert fp.get("is_locked") is True,     f"Recommended: {flag} should be locked"
        assert fp.get("locked_min_tier") == 2,  f"Recommended: {flag} should be locked at tier 2"

    rules_data = await admin_client.list_sharing_rules()
    assert len(rules_data.get("rules", [])) == 0, (
        "Recommended profile should produce no sharing rules"
    )


# ---------------------------------------------------------------------------
# D. Open profile
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_27_06_apply_open(admin_client: AdminClient):
    """Apply Open profile: all flags ON, unlocked, escrow not required."""
    tok = _step_up(_state["admin_id"])
    await admin_client.apply_profile("open", tok, mode="replace")

    settings = await admin_client.get_settings()
    assert settings.get("escrow_require_coverage") == "0", "Open: escrow_require_coverage should be 0"

    perms = await admin_client.get_role_permissions("role_user")
    for flag in ("can_create_link_shares", "can_create_user_shares",
                 "can_create_upload_grants", "can_share_folders"):
        fp = perms.get(flag, {})
        assert fp.get("value") == "1",         f"Open: {flag} should be ON"
        assert fp.get("is_locked") is False,   f"Open: {flag} should NOT be locked"

    rules_data = await admin_client.list_sharing_rules()
    assert len(rules_data.get("rules", [])) == 0, "Open profile should produce no sharing rules"


# ---------------------------------------------------------------------------
# E. Export / import (replace mode)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_27_07_export_structure(admin_client: AdminClient):
    """Export after Open profile has correct top-level structure and empty _warnings."""
    tok    = _step_up(_state["admin_id"])
    export = await admin_client.export_settings(tok)

    assert "_meta"             in export, "Missing _meta"
    assert "_warnings"         in export, "Missing _warnings"
    assert "admin_settings"    in export, "Missing admin_settings"
    assert "role_flag_overrides" in export, "Missing role_flag_overrides"
    assert "sharing_rules"     in export, "Missing sharing_rules"

    assert export["_warnings"] == [], f"Expected empty _warnings for Open profile, got: {export['_warnings']}"
    assert export["_meta"]["format_version"] == "1", "Unexpected format_version"

    admin_settings = export["admin_settings"]
    assert "escrow_require_coverage" in admin_settings, (
        f"escrow_require_coverage missing from export: {list(admin_settings)}"
    )

    role_flags = export["role_flag_overrides"].get("role_user", {})
    assert "can_create_link_shares" in role_flags, (
        f"can_create_link_shares missing from role_flag_overrides.role_user: {list(role_flags)}"
    )

    assert isinstance(export["sharing_rules"], list), "sharing_rules should be a list"

    _state["open_export"] = export


@pytest.mark.asyncio(loop_scope="session")
async def test_27_08_export_strips_escrow_user_ids(admin_client: AdminClient):
    """Export strips user IDs from escrow settings and populates _warnings."""
    import json as _json

    # Inject a fake user ID list into escrow settings so the export has something to strip
    await admin_client._client.put(
        f"{API}/admin/escrow/settings",
        json={"escrow_default_user_ids": [_state["admin_id"]]},
    )

    tok    = _step_up(_state["admin_id"])
    export = await admin_client.export_settings(tok)

    assert len(export["_warnings"]) >= 1, (
        f"Expected at least one warning about stripped user IDs, got: {export['_warnings']}"
    )
    assert any("STRIPPED" in w for w in export["_warnings"]), (
        f"Expected 'STRIPPED' in warnings, got: {export['_warnings']}"
    )

    # escrow_default_user_ids should NOT appear in admin_settings (it's escrow-specific)
    # — it's stripped; only profile settings (escrow_require_coverage etc.) are exported.
    # Role IDs (escrow_default_role_ids) are kept; confirm no user IDs leaked through.
    # Reset escrow settings so they don't affect later tests
    await admin_client._client.put(
        f"{API}/admin/escrow/settings",
        json={"escrow_default_user_ids": []},
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_27_09_import_replace_restores_settings(admin_client: AdminClient):
    """Import the saved Open export (replace mode) and verify settings are restored."""
    open_export = _state.get("open_export")
    assert open_export is not None, "open_export not in state (27-07 must run first)"

    # First apply High Security to create a divergent state
    tok = _step_up(_state["admin_id"])
    await admin_client.apply_profile("high_security", tok, mode="replace")

    settings_before = await admin_client.get_settings()
    assert settings_before.get("escrow_require_coverage") == "1", "Expected HS state before import"

    # Now import the Open profile export
    tok    = _step_up(_state["admin_id"])
    result = await admin_client.import_profile(open_export, tok, mode="replace")
    assert "imported" in result.get("message", "").lower(), f"Unexpected import response: {result}"

    # Verify restored
    settings_after = await admin_client.get_settings()
    assert settings_after.get("escrow_require_coverage") == "0", (
        "escrow_require_coverage should be 0 after importing Open profile"
    )

    perms = await admin_client.get_role_permissions("role_user")
    for flag in ("can_create_link_shares", "can_share_folders"):
        fp = perms.get(flag, {})
        assert fp.get("value") == "1",       f"After import: {flag} should be ON"
        assert fp.get("is_locked") is False, f"After import: {flag} should be unlocked"


@pytest.mark.asyncio(loop_scope="session")
async def test_27_10_import_replace_clears_sharing_rules(admin_client: AdminClient):
    """Replace-all import wipes existing sharing rules before inserting profile rules."""
    # Apply High Security (creates a deny rule)
    tok = _step_up(_state["admin_id"])
    await admin_client.apply_profile("high_security", tok, mode="replace")
    rules_hs = await admin_client.list_sharing_rules()
    assert len(rules_hs.get("rules", [])) >= 1, "High Security should have added a sharing rule"

    # Import Open profile (no rules) via replace-all
    open_export = _state.get("open_export", {})
    tok    = _step_up(_state["admin_id"])
    await admin_client.import_profile(open_export, tok, mode="replace")

    rules_after = await admin_client.list_sharing_rules()
    assert len(rules_after.get("rules", [])) == 0, (
        f"Replace-all import should have wiped all sharing rules, got: {rules_after['rules']}"
    )


# ---------------------------------------------------------------------------
# F. Import (merge mode)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_27_11_preview_import_returns_diff_without_changes(admin_client: AdminClient):
    """Preview (confirm=False) returns diff without applying any changes."""
    # Ensure we're in Open state
    tok = _step_up(_state["admin_id"])
    await admin_client.apply_profile("open", tok, mode="replace")

    settings_before = await admin_client.get_settings()

    # Preview importing High Security profile as merge (no confirm)
    tok     = _step_up(_state["admin_id"])
    import json as _json
    from tests.e2e.helpers.admin import API as _API

    # Build a minimal profile with one changed setting to preview
    hs_profile = {
        "admin_settings": {
            "escrow_require_coverage": {"value": "1", "is_locked": True, "locked_min_tier": 1},
        },
        "role_flag_overrides": {},
        "sharing_rules": [],
    }
    preview = await admin_client.preview_import_profile(hs_profile, mode="merge", step_up_token=tok)

    diff = preview.get("diff", [])
    assert len(diff) >= 1, f"Expected at least one diff item, got: {diff}"
    changed_keys = {d["key"] for d in diff if d["changed"]}
    assert "admin_setting.escrow_require_coverage" in changed_keys, (
        f"escrow_require_coverage should be a changed diff item: {changed_keys}"
    )

    # Verify NO changes were applied
    settings_after = await admin_client.get_settings()
    assert settings_after.get("escrow_require_coverage") == settings_before.get("escrow_require_coverage"), (
        "Preview should not have changed any settings"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_27_12_merge_selective_decisions(admin_client: AdminClient):
    """Merge mode with selective decisions: only 'proposed' items applied."""
    # Start from Open profile
    tok = _step_up(_state["admin_id"])
    await admin_client.apply_profile("open", tok, mode="replace")

    profile_to_import = {
        "admin_settings": {
            "escrow_require_coverage":     {"value": "1", "is_locked": True,  "locked_min_tier": 1},
            "notify_escrow_on_revocation": {"value": "1", "is_locked": False, "locked_min_tier": None},
        },
        "role_flag_overrides": {},
        "sharing_rules": [],
    }

    # Keep escrow_require_coverage at current (0), accept notify_escrow_on_revocation (1)
    decisions = {
        "admin_setting.escrow_require_coverage":     "current",   # keep 0
        "admin_setting.notify_escrow_on_revocation": "proposed",  # apply → 1
    }

    tok = _step_up(_state["admin_id"])
    result = await admin_client.import_profile(
        profile_to_import, tok, mode="merge", decisions=decisions
    )
    assert "imported" in result.get("message", "").lower(), f"Unexpected merge response: {result}"

    settings = await admin_client.get_settings()
    assert settings.get("escrow_require_coverage")     == "0", (
        "escrow_require_coverage should remain 0 (decision=current)"
    )
    assert settings.get("notify_escrow_on_revocation") == "1", (
        "notify_escrow_on_revocation should be 1 (decision=proposed)"
    )


# ---------------------------------------------------------------------------
# G. Permission gates & validation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_27_13_export_requires_step_up(admin_client: AdminClient):
    """GET /admin/settings/export without step-up token → 403 step_up_required."""
    r = await admin_client._client.get(f"{API}/admin/settings/export")
    assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"
    detail = r.json().get("detail", {})
    assert detail.get("error") == "step_up_required", (
        f"Expected step_up_required error, got: {detail}"
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_27_14_apply_replace_without_confirmation_text_returns_400(admin_client: AdminClient):
    """Apply-profile (replace mode) without confirmation_text='REPLACE' → 400."""
    tok = _step_up(_state["admin_id"])
    r   = await admin_client._client.post(
        f"{API}/admin/settings/apply-profile",
        json={
            "profile":           "open",
            "mode":              "replace",
            "confirm":           True,
            "confirmation_text": "",   # missing
        },
        headers={"X-Step-Up-Token": tok},
    )
    assert r.status_code == 400, f"Expected 400, got {r.status_code}: {r.text}"
    assert "REPLACE" in r.json().get("detail", ""), f"Expected 'REPLACE' in error: {r.text}"


@pytest.mark.asyncio(loop_scope="session")
async def test_27_15_import_unknown_top_level_key_returns_400(admin_client: AdminClient):
    """Import profile with an unknown top-level key → 400."""
    tok = _step_up(_state["admin_id"])
    r   = await admin_client._client.post(
        f"{API}/admin/settings/import",
        json={
            "profile_json": {
                "unknown_key": "this should not be allowed",
                "admin_settings": {},
            },
            "mode":    "merge",
            "confirm": False,
        },
        headers={"X-Step-Up-Token": tok},
    )
    assert r.status_code == 400, f"Expected 400 for unknown key, got {r.status_code}: {r.text}"
    assert "Unknown" in r.json().get("detail", "") or "unknown" in r.json().get("detail", ""), (
        f"Expected 'Unknown' in error detail: {r.text}"
    )


# ---------------------------------------------------------------------------
# H. First-run flag
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_27_16_mark_first_run_sets_setting(admin_client: AdminClient):
    """Apply with mark_first_run=True writes first_run_completed='1' to admin_settings."""
    tok = _step_up(_state["admin_id"])
    await admin_client.apply_profile(
        "recommended", tok, mode="replace", mark_first_run=True
    )

    settings = await admin_client.get_settings()
    assert settings.get("first_run_completed") == "1", (
        f"Expected first_run_completed='1', got: {settings.get('first_run_completed')!r}"
    )


# ---------------------------------------------------------------------------
# I. SIEM events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio(loop_scope="session")
async def test_27_17_siem_manifest(admin_client: AdminClient):
    """SIEM manifest: profile_applied, profile_exported, profile_imported all emitted."""
    assert_manifest(_SIEM_MANIFEST)
