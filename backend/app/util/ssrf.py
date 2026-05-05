"""SSRF-prevention helpers shared by admin_storage and admin_notifications."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import urllib.parse

from fastapi import HTTPException

from app.config import settings

# Networks that must never be targets of server-side outbound connections.
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("10.0.0.0/8"),     # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"), # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"), # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT shared space
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),        # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
]


async def validate_endpoint_url(url: str, *, allowed_schemes: tuple[str, ...] = ("http", "https")) -> None:
    """Reject URLs that point to private/internal networks (SSRF prevention).

    Enforces HTTPS in non-debug mode and resolves the hostname to verify it
    does not fall within RFC 1918, link-local, loopback, or other reserved
    ranges.  Raises HTTPException(422) on any violation.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise HTTPException(status_code=422, detail="endpoint_url is not a valid URL")

    if parsed.scheme not in allowed_schemes:
        schemes = " or ".join(allowed_schemes)
        raise HTTPException(status_code=422, detail=f"endpoint_url must use {schemes} scheme")

    if parsed.scheme == "http" and not settings.DEBUG:
        raise HTTPException(
            status_code=422,
            detail="endpoint_url must use https in production (set DEBUG=true to allow plain http)",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=422, detail="endpoint_url must include a hostname")

    try:
        addr_infos = await asyncio.to_thread(socket.getaddrinfo, hostname, None)
    except socket.gaierror:
        raise HTTPException(status_code=422, detail="Cannot resolve the hostname in endpoint_url")

    for _, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for net in BLOCKED_NETWORKS:
            try:
                if ip in net:
                    raise HTTPException(
                        status_code=422,
                        detail=(
                            "endpoint_url resolves to a private or reserved address. "
                            "Direct access to internal networks is not permitted."
                        ),
                    )
            except TypeError:
                pass  # IPv4 address checked against IPv6 network (or vice-versa) — skip
