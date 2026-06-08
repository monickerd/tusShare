"""Shared IP allowlist check for credential-level source IP restrictions.

Used by api_key.py and service_account.py to gate requests from unexpected
source IPs.  Stored on-disk as a JSON array of CIDR ranges or exact IPs.

Fail-open by design: if the client IP cannot be parsed or the stored list is
malformed we let the request through rather than locking out legitimate traffic.
The allowlist is advisory hardening, not the primary auth control.
"""

from __future__ import annotations

import ipaddress
import json
import logging

logger = logging.getLogger(__name__)


def is_allowed(client_ip: str | None, allowed_ips_json: str | None) -> bool:
    """Return True if *client_ip* passes the allowlist stored in *allowed_ips_json*.

    allowed_ips_json: JSON-encoded list of CIDR strings or exact IPs, e.g.
        '["10.0.0.0/8", "192.168.1.42"]'
    Returns True (unrestricted) when:
      - allowed_ips_json is None / empty / empty list
      - client_ip is None or unparseable
      - the JSON is malformed
    """
    if not allowed_ips_json:
        return True
    try:
        allowed: list = json.loads(allowed_ips_json)
    except (json.JSONDecodeError, TypeError):
        return True
    if not allowed:
        return True
    if not client_ip:
        return True

    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        logger.warning("ip_restrict: unparseable client IP %r — allowing", client_ip)
        return True

    for entry in allowed:
        try:
            if "/" in str(entry):
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            logger.warning("ip_restrict: invalid allowlist entry %r — skipping", entry)
    return False


def validate_list(entries: list[str]) -> list[str]:
    """Validate and normalise a list of IP/CIDR strings; raises ValueError on bad input."""
    out: list[str] = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                out.append(str(net))
            else:
                addr = ipaddress.ip_address(entry)
                out.append(str(addr))
        except ValueError:
            raise ValueError(f"Invalid IP address or CIDR range: {entry!r}")
    return out
