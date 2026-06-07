"""
Unit tests for SIEM output formatters and HMAC signing.

These tests are purely synchronous and require no running server, database,
or Docker container.  They verify that the three syslog output formats
(RFC 5424, CEF, LEEF) and the webhook HMAC signer produce correct output
for a known input SecurityEvent.

Run with: pytest tests/unit/
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from app.schemas.security_event import EventActor, EventTarget, SecurityEvent
from app.services.siem_syslog import (
    _format_cef,
    _format_leef,
    _format_rfc5424,
    _syslog_pri,
)
from app.util.crypto import hmac_sha256_hex as _sign

# ---------------------------------------------------------------------------
# Fixtures / shared test data
# ---------------------------------------------------------------------------

_FIXED_TS = datetime(2026, 4, 18, 12, 0, 0, 123000, tzinfo=timezone.utc)

_DEST_SYSLOG = {
    "id": "test-dest-01",
    "type": "syslog",
    "facility": 16,          # LOCAL0
    "protocol": "udp",
    "syslog_format": "rfc5424",
}

_DEST_CEF = {**_DEST_SYSLOG, "syslog_format": "cef"}
_DEST_LEEF = {**_DEST_SYSLOG, "syslog_format": "leef"}


def _make_event(
    event_type: str = "auth.login.failure",
    severity: str = "warning",
    outcome: str = "failure",
    username: str = "testuser",
    ip: str = "10.0.0.1",
    with_target: bool = False,
) -> SecurityEvent:
    return SecurityEvent(
        event_id="aaaaaaaa-0000-0000-0000-000000000001",
        timestamp=_FIXED_TS,
        event_type=event_type,
        severity=severity,
        outcome=outcome,
        actor=EventActor(user_id="uid-01", username=username, ip=ip, session_id="sid-01"),
        target=EventTarget(type="file", id="fid-01", name="secret.pdf") if with_target else None,
    )


# ---------------------------------------------------------------------------
# _syslog_pri
# ---------------------------------------------------------------------------

class TestSyslogPri:
    def test_info_local0(self):
        # LOCAL0 (16) * 8 + info (6) = 134
        assert _syslog_pri(16, "info") == 134

    def test_warning_local0(self):
        # LOCAL0 (16) * 8 + warning (4) = 132
        assert _syslog_pri(16, "warning") == 132

    def test_critical_local0(self):
        # LOCAL0 (16) * 8 + critical (2) = 130
        assert _syslog_pri(16, "critical") == 130

    def test_local1_info(self):
        # LOCAL1 (17) * 8 + info (6) = 142
        assert _syslog_pri(17, "info") == 142

    def test_unknown_severity_defaults_to_info(self):
        assert _syslog_pri(16, "unknown_sev") == _syslog_pri(16, "info")


# ---------------------------------------------------------------------------
# RFC 5424 format
# ---------------------------------------------------------------------------

class TestRfc5424Format:
    def test_returns_bytes(self):
        ev = _make_event()
        result = _format_rfc5424(_DEST_SYSLOG, ev)
        assert isinstance(result, bytes)

    def test_starts_with_pri(self):
        ev = _make_event(severity="warning")
        result = _format_rfc5424(_DEST_SYSLOG, ev).decode()
        # PRI = LOCAL0 * 8 + warning(4) = 132; RFC5424 version = 1
        assert result.startswith("<132>1 ")

    def test_contains_event_type(self):
        ev = _make_event(event_type="file.download.started")
        result = _format_rfc5424(_DEST_SYSLOG, ev).decode()
        assert "file_download_started" in result   # dots replaced with underscores in MSGID

    def test_contains_actor_ip(self):
        ev = _make_event(ip="192.168.99.1")
        result = _format_rfc5424(_DEST_SYSLOG, ev).decode()
        assert "192.168.99.1" in result

    def test_contains_severity(self):
        ev = _make_event(severity="critical")
        result = _format_rfc5424(_DEST_SYSLOG, ev).decode()
        assert 'severity="critical"' in result

    def test_contains_outcome(self):
        ev = _make_event(outcome="failure")
        result = _format_rfc5424(_DEST_SYSLOG, ev).decode()
        assert 'outcome="failure"' in result

    def test_timestamp_format(self):
        # RFC 5424 requires ISO 8601 with a trailing Z
        ev = _make_event()
        result = _format_rfc5424(_DEST_SYSLOG, ev).decode()
        assert "2026-04-18T12:00:00.123Z" in result

    def test_app_name_is_tusshare(self):
        ev = _make_event()
        result = _format_rfc5424(_DEST_SYSLOG, ev).decode()
        assert "tusShare" in result

    def test_critical_event_has_lower_pri(self):
        """Critical events must have a lower PRI number than info (syslog convention)."""
        ev_info     = _make_event(severity="info")
        ev_critical = _make_event(severity="critical")
        pri_info     = int(_format_rfc5424(_DEST_SYSLOG, ev_info).decode().split(">")[0][1:])
        pri_critical = int(_format_rfc5424(_DEST_SYSLOG, ev_critical).decode().split(">")[0][1:])
        assert pri_critical < pri_info


# ---------------------------------------------------------------------------
# CEF format
# ---------------------------------------------------------------------------

class TestCefFormat:
    def test_returns_bytes(self):
        ev = _make_event()
        assert isinstance(_format_cef(_DEST_CEF, ev), bytes)

    def test_cef_header_present(self):
        ev = _make_event(event_type="admin.emergency_revocation")
        result = _format_cef(_DEST_CEF, ev).decode()
        assert "CEF:0|tusShare|tusShare|" in result

    def test_event_type_in_signature(self):
        ev = _make_event(event_type="admin.emergency_revocation")
        result = _format_cef(_DEST_CEF, ev).decode()
        assert "admin.emergency_revocation" in result

    def test_severity_mapped_to_numeric(self):
        # CEF severity: info→3, warning→6, critical→9
        for sev, expected in [("info", "3"), ("warning", "6"), ("critical", "9")]:
            ev = _make_event(severity=sev)
            result = _format_cef(_DEST_CEF, ev).decode()
            # The numeric sev appears as the last pipe-separated header field
            cef_header = result.split("|")
            assert cef_header[6] == expected, (
                f"CEF severity for '{sev}' should be {expected}, got {cef_header[6]!r}"
            )

    def test_actor_username_in_extension(self):
        ev = _make_event(username="alice")
        result = _format_cef(_DEST_CEF, ev).decode()
        assert "suser=alice" in result

    def test_actor_ip_in_extension(self):
        ev = _make_event(ip="10.20.30.40")
        result = _format_cef(_DEST_CEF, ev).decode()
        assert "src=10.20.30.40" in result

    def test_target_name_in_extension(self):
        ev = _make_event(with_target=True)
        result = _format_cef(_DEST_CEF, ev).decode()
        assert "fname=secret.pdf" in result


# ---------------------------------------------------------------------------
# LEEF format
# ---------------------------------------------------------------------------

class TestLeefFormat:
    def test_returns_bytes(self):
        ev = _make_event()
        assert isinstance(_format_leef(_DEST_LEEF, ev), bytes)

    def test_leef_header_present(self):
        ev = _make_event()
        result = _format_leef(_DEST_LEEF, ev).decode()
        assert "LEEF:1.0|tusShare|tusShare|" in result

    def test_event_type_in_header(self):
        ev = _make_event(event_type="file.delete")
        result = _format_leef(_DEST_LEEF, ev).decode()
        assert "file.delete" in result

    def test_attributes_tab_separated(self):
        ev = _make_event()
        result = _format_leef(_DEST_LEEF, ev).decode()
        # The attribute block after the LEEF header should be tab-separated key=value pairs
        # Split off the pipe-delimited header (5 pipes) and check the attribute block
        parts = result.split("|")
        assert len(parts) >= 6, f"Expected at least 6 pipe segments, got: {result!r}"
        attr_block = parts[5]
        assert "\t" in attr_block, "LEEF attribute block must be tab-separated"

    def test_severity_attribute(self):
        ev = _make_event(severity="critical")
        result = _format_leef(_DEST_LEEF, ev).decode()
        assert "sev=critical" in result

    def test_category_attribute(self):
        ev = _make_event(event_type="auth.login.success")
        result = _format_leef(_DEST_LEEF, ev).decode()
        assert "cat=auth.login.success" in result

    def test_timestamp_attribute_present(self):
        ev = _make_event()
        result = _format_leef(_DEST_LEEF, ev).decode()
        assert "devTime=" in result


# ---------------------------------------------------------------------------
# HMAC signing (_sign from siem_webhook)
# ---------------------------------------------------------------------------

class TestWebhookSigning:
    def test_returns_hex_string(self):
        sig = _sign("mysecret", b'{"events":[]}')
        assert isinstance(sig, str)
        # HMAC-SHA256 produces 64 hex characters
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)

    def test_is_deterministic(self):
        body = b'{"events":[{"event_type":"auth.login.success"}]}'
        assert _sign("key", body) == _sign("key", body)

    def test_different_secrets_produce_different_signatures(self):
        body = b'{"events":[]}'
        assert _sign("secret-a", body) != _sign("secret-b", body)

    def test_different_bodies_produce_different_signatures(self):
        assert _sign("key", b"body-a") != _sign("key", b"body-b")

    def test_matches_stdlib_hmac(self):
        secret = "correct-horse-battery-staple"
        body   = b'{"events":[{"event_type":"file.delete"}]}'
        expected = hmac.new(
            secret.encode(), body, hashlib.sha256
        ).hexdigest()
        assert _sign(secret, body) == expected

    def test_empty_secret_returns_empty_string(self):
        assert _sign("", b'{"events":[]}') == ""

    def test_empty_body(self):
        sig = _sign("key", b"")
        assert len(sig) == 64
