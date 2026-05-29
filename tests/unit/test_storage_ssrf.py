"""
Unit tests for the SSRF validation in admin_storage.py.

These tests exercise _validate_endpoint_url() directly — no running server,
database, or Docker container required.  They verify that private/reserved
IP ranges and plain-HTTP endpoints are rejected before any outbound
connection is ever attempted.

Run with: pytest tests/unit/
"""

from __future__ import annotations

import asyncio
import os

import pytest
from fastapi import HTTPException

# Ensure settings can be imported with minimal env (JWT_SECRET has a default of "")
# No other vars are needed for _validate_endpoint_url.
from app.util.ssrf import validate_endpoint_url as _validate_endpoint_url


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run(coro):
    """Run an async function synchronously — keeps unit tests purely sync."""
    return asyncio.run(coro)


def _assert_422(coro, expected_fragment: str = "") -> None:
    with pytest.raises(HTTPException) as exc_info:
        _run(coro)
    assert exc_info.value.status_code == 422, (
        f"Expected 422 but got {exc_info.value.status_code}: {exc_info.value.detail}"
    )
    if expected_fragment:
        assert expected_fragment in exc_info.value.detail, (
            f"Expected {expected_fragment!r} in detail: {exc_info.value.detail!r}"
        )


# ---------------------------------------------------------------------------
# Scheme validation
# ---------------------------------------------------------------------------

def test_http_rejected_in_non_debug_mode():
    """Plain HTTP endpoints must be rejected when DEBUG=false (default)."""
    _assert_422(
        _validate_endpoint_url("http://s3.example.com/bucket"),
        expected_fragment="https",
    )


def test_unsupported_scheme_rejected():
    """Non-http/https schemes must be rejected."""
    _assert_422(
        _validate_endpoint_url("ftp://s3.example.com"),
        expected_fragment="http or https",
    )


def test_no_hostname_rejected():
    """URLs with no resolvable hostname must be rejected."""
    _assert_422(
        _validate_endpoint_url("https://"),
        expected_fragment="hostname",
    )


# ---------------------------------------------------------------------------
# RFC 1918 private ranges
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://10.0.0.1",
    "https://10.255.255.255",
    "https://172.16.0.1",
    "https://172.31.255.255",
    "https://192.168.0.1",
    "https://192.168.255.255",
])
def test_rfc1918_addresses_blocked(url: str):
    """RFC 1918 private addresses must be rejected regardless of scheme."""
    _assert_422(
        _validate_endpoint_url(url),
        expected_fragment="private or reserved",
    )


# ---------------------------------------------------------------------------
# Loopback
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://127.0.0.1",
    "https://127.0.0.1:9000",
    "https://127.1.2.3",
])
def test_loopback_addresses_blocked(url: str):
    """IPv4 loopback (127.0.0.0/8) must be rejected."""
    _assert_422(
        _validate_endpoint_url(url),
        expected_fragment="private or reserved",
    )


# ---------------------------------------------------------------------------
# Link-local / metadata endpoint
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://169.254.169.254",           # AWS/GCP/Azure IMDS
    "https://169.254.169.254/latest",    # AWS metadata path
    "https://169.254.0.1",
])
def test_link_local_addresses_blocked(url: str):
    """Link-local range (169.254.0.0/16) must be rejected — includes cloud metadata IPs."""
    _assert_422(
        _validate_endpoint_url(url),
        expected_fragment="private or reserved",
    )


# ---------------------------------------------------------------------------
# CGNAT shared space
# ---------------------------------------------------------------------------

def test_cgnat_range_blocked():
    """CGNAT shared space (100.64.0.0/10) must be rejected."""
    _assert_422(
        _validate_endpoint_url("https://100.64.0.1"),
        expected_fragment="private or reserved",
    )


# ---------------------------------------------------------------------------
# IPv6 reserved ranges
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://[::1]",                     # IPv6 loopback
    "https://[fc00::1]",                 # IPv6 ULA
    "https://[fe80::1]",                 # IPv6 link-local
])
def test_ipv6_reserved_blocked(url: str):
    """IPv6 loopback, ULA, and link-local addresses must be rejected."""
    _assert_422(
        _validate_endpoint_url(url),
        expected_fragment="private or reserved",
    )
