"""Egress connection monitor — Python audit hook for supply-chain detection.

Installs a sys.addaudithook listener that fires on every socket.connect() call
within the process (including from third-party libraries). Any connection whose
(ip, port) pair is not in the allowlist is logged to stderr immediately and
emitted as a ``supply_chain.unexpected_egress`` security event once the event
bus is running.

Design notes
------------
- Detection only — no blocking. The iptables egress rules handle enforcement;
  this layer adds in-process visibility and first-class security event logging.
- The hook cannot be removed once installed (sys.addaudithook is one-way by
  design). It must never raise; all exceptions are silently swallowed.
- Thread-safe: all shared state is protected by a threading.Lock, since the
  hook can fire from any thread (asyncio loop, background tasks, library code).

Allowlist lifecycle
-------------------
Phase 1 (call build_initial_allowlist from main.py after settings are loaded):
  Seeds the allowlist from env-var settings: postgres, redis.
  The hook is installed at import time and begins monitoring immediately.

Phase 2 (call update_allowlist_from_db from lifespan after storage.init()):
  Extends the allowlist with all DB-configured endpoints: LDAP/OIDC identity
  providers, notification channel webhooks, AV scanner, storage volumes.

Call mark_event_bus_ready() after event_bus.start() so that detected events
can be persisted and fanned out to SIEM subscribers.
"""

from __future__ import annotations

import logging
import socket
import sys
import threading
import time
import traceback
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared state — all access under _lock
# ---------------------------------------------------------------------------

_lock = threading.Lock()

# (ip_str, port) pairs that are explicitly allowed.
_allowed: set[tuple[str, int]] = set()

# Rate-limit: last alert time per (ip, port) — suppress repeats within window.
_alert_times: dict[tuple[str, int], float] = {}
_ALERT_DEDUPE_SECONDS = 60.0

# Set by mark_event_bus_ready() once the event bus drainer is running.
_event_bus_ready = False

# IPs that are always allowed regardless of port (loopback + Docker DNS).
_ALWAYS_ALLOWED_IPS = frozenset({"127.0.0.1", "::1", "0.0.0.0", "127.0.0.11"})

# Ports that are always allowed (DNS — resolved before the connect() call).
_ALWAYS_ALLOWED_PORTS = frozenset({53})


# ---------------------------------------------------------------------------
# Public API — called from main.py
# ---------------------------------------------------------------------------


def build_initial_allowlist(settings) -> None:
    """Phase 1: seed allowlist from env-var settings.

    Call this once from main.py after `from app.config import settings`.
    Covers postgres and redis (the only connections made before lifespan runs).
    """
    for url in (settings.DATABASE_URL, settings.SUPERUSER_URL, settings.REDIS_URL):
        if url:
            _add_url(url)


async def update_allowlist_from_db(db) -> None:
    """Phase 2: extend allowlist from DB-stored endpoint configuration.

    Call from the lifespan function after storage.init() and
    sensitive_config.load(). Covers LDAP/OIDC providers, notification
    channel webhooks, AV scanner endpoint, and storage volume endpoints.
    """
    # Notification channel webhook endpoints.
    try:
        cur = await db.execute(
            "SELECT endpoint_url FROM notification_channels WHERE enabled = 1"
        )
        for row in await cur.fetchall():
            _add_url(row["endpoint_url"])
    except Exception:
        logger.warning("egress_monitor: could not query notification_channels")

    # AV scanner endpoint (stored in admin_settings, may be empty string).
    try:
        cur = await db.execute(
            "SELECT value FROM admin_settings WHERE key = 'av_scan_endpoint'"
        )
        row = await cur.fetchone()
        if row and row["value"]:
            _add_url(row["value"])
    except Exception:
        logger.warning("egress_monitor: could not query av_scan_endpoint")

    # LDAP / OIDC identity providers (config blobs are encrypted — decrypt here).
    try:
        cur = await db.execute(
            "SELECT provider_type, config_enc FROM identity_providers WHERE is_active = 1"
        )
        rows = await cur.fetchall()
        if rows:
            from app.auth.idp_crypto import decrypt_idp_config

            for row in rows:
                try:
                    cfg = decrypt_idp_config(row["config_enc"])
                    if row["provider_type"] == "ldap":
                        _add_url(cfg.get("server_uri", ""))
                    elif row["provider_type"] == "oidc":
                        _add_url(cfg.get("issuer_url", ""))
                except Exception:
                    logger.warning("egress_monitor: could not decrypt IdP config")
    except Exception:
        logger.warning("egress_monitor: could not query identity_providers")

    # Storage volume endpoints (already decrypted by the storage manager).
    _add_storage_endpoints()


def mark_event_bus_ready() -> None:
    """Signal that the event bus drainer is running and events can be queued.

    Call from main.py lifespan after event_bus.start().
    """
    global _event_bus_ready
    _event_bus_ready = True


def extend(host: str, port: int) -> None:
    """Manually add a single host:port to the allowlist.

    Use this from any code path that establishes a connection to a destination
    that wasn't known at startup (e.g. a dynamically configured integration).
    """
    _add_host(host, port)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve(host: str) -> list[str]:
    """Resolve hostname to all IPv4/IPv6 addresses. Returns [] on failure."""
    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return list({r[4][0] for r in results})
    except Exception:
        return []


def _add_host(host: str, port: int) -> None:
    ips = _resolve(host)
    if not ips:
        logger.debug("egress_monitor: could not resolve %s", host)
        return
    with _lock:
        for ip in ips:
            _allowed.add((ip, port))


def _add_url(url: str) -> None:
    """Parse url and add all resolved IPs + the implied port to the allowlist."""
    if not url or not url.strip():
        return
    try:
        p = urlparse(url.strip())
        host = p.hostname
        if not host:
            return
        scheme_defaults = {"https": 443, "http": 80, "ldap": 389, "ldaps": 636,
                           "postgresql": 5432, "postgres": 5432, "redis": 6379,
                           "rediss": 6379}
        port = p.port or scheme_defaults.get(p.scheme, 443)
        _add_host(host, int(port))
    except Exception:
        pass


def _add_storage_endpoints() -> None:
    """Allowlist storage volume endpoints from the already-initialised manager."""
    try:
        from app.storage.manager import get_manager

        mgr = get_manager()
        has_cloud = False

        for vol in mgr._volumes.values():
            if vol.provider == "local":
                continue
            has_cloud = True
            cfg = vol.config

            if vol.provider in ("s3", "b2"):
                ep = cfg.get("endpoint_url")
                if ep:
                    _add_url(ep)
                else:
                    # AWS S3 — regional endpoints; add canonical hostnames.
                    region = cfg.get("region", "us-east-1")
                    _add_host(f"s3.{region}.amazonaws.com", 443)
                    _add_host("s3.amazonaws.com", 443)
                    # STS / auth
                    _add_host(f"sts.{region}.amazonaws.com", 443)

            elif vol.provider == "azure":
                account = cfg.get("account_name", "")
                if account:
                    _add_host(f"{account}.blob.core.windows.net", 443)
                # Azure auth endpoint
                _add_host("login.microsoftonline.com", 443)

            elif vol.provider == "gcs":
                _add_host("storage.googleapis.com", 443)
                _add_host("oauth2.googleapis.com", 443)

        if has_cloud:
            # Cloud provider instance metadata service (169.254.169.254:80).
            # AWS, Azure, and GCP SDKs all probe this for credential discovery
            # on startup, even when credentials are explicitly configured.
            with _lock:
                _allowed.add(("169.254.169.254", 80))
                _allowed.add(("169.254.169.254", 443))

    except Exception:
        logger.warning("egress_monitor: could not read storage manager volumes")


def _is_allowed(host: str, port: int) -> bool:
    if host in _ALWAYS_ALLOWED_IPS:
        return True
    if port in _ALWAYS_ALLOWED_PORTS:
        return True
    with _lock:
        return (host, port) in _allowed


def _should_alert(host: str, port: int) -> bool:
    """Return True if this (host, port) hasn't been alerted on recently."""
    key = (host, port)
    now = time.monotonic()
    with _lock:
        if now - _alert_times.get(key, 0.0) < _ALERT_DEDUPE_SECONDS:
            return False
        _alert_times[key] = now
    return True


def _format_stack() -> list[str]:
    """Capture the current call stack and format it for the security event.

    Frames from this module are stripped (they're noise). Frames from
    third-party site-packages are annotated with [LIB] so they stand out
    when reviewing the trace for a suspicious library.
    """
    raw = traceback.extract_stack()

    # Drop frames from this file — they add no investigative value.
    frames = [f for f in raw if not f.filename.endswith("egress_monitor.py")]

    # Limit depth: keep the 25 most recent frames (closest to the connect call).
    omitted = max(0, len(frames) - 25)
    frames = frames[-25:]

    lines: list[str] = []
    if omitted:
        lines.append(f"  ... {omitted} older frame(s) omitted ...\n")

    for f in frames:
        tag = "[LIB] " if "site-packages" in f.filename else ""
        lines.append(f"  {tag}File \"{f.filename}\", line {f.lineno}, in {f.name}\n")
        if f.line:
            lines.append(f"    {f.line.strip()}\n")

    return lines


def _emit_alert(host: str, port: int, stack_lines: list[str]) -> None:
    """Log the suspicious connection to stderr and queue a security event."""
    header = (
        f"[EGRESS MONITOR] Unexpected outbound connection to {host}:{port} "
        f"— destination is not in the egress allowlist\n"
        f"Stack trace (most recent call last):\n"
    )
    print(header + "".join(stack_lines), file=sys.stderr, flush=True)

    if not _event_bus_ready:
        return

    try:
        from app.schemas.security_event import SecurityEvent
        from app.services import event_bus

        event_bus.emit(
            SecurityEvent(
                event_type="supply_chain.unexpected_egress",
                severity="critical",
                outcome="blocked",
                detail={
                    "destination_host": host,
                    "destination_port": port,
                    "note": (
                        "Connection attempt detected by in-process audit hook. "
                        "Network-level egress rules provide the actual block."
                    ),
                    "stack_trace": stack_lines,
                },
            )
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# The audit hook — installed immediately on module import
# ---------------------------------------------------------------------------


def _audit_hook(event: str, args) -> None:
    """sys.addaudithook callback. Must never raise."""
    if event != "socket.connect":
        return
    try:
        if len(args) < 2:
            return
        addr = args[1]
        # TCP/UDP: (host, port) — ignore AF_UNIX (str) and other non-tuple addrs.
        if not isinstance(addr, (tuple, list)) or len(addr) < 2:
            return

        host = str(addr[0])
        port = int(addr[1])

        if _is_allowed(host, port):
            return

        if not _should_alert(host, port):
            return

        stack_lines = _format_stack()
        _emit_alert(host, port, stack_lines)
    except Exception:
        pass


sys.addaudithook(_audit_hook)
