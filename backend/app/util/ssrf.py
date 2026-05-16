"""SSRF-prevention helpers shared by admin_storage, admin_notifications, OIDC, and AV scanner."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import urllib.parse
from typing import Optional

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


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for net in BLOCKED_NETWORKS:
        try:
            if ip in net:
                return True
        except TypeError:
            pass  # IPv4/IPv6 type mismatch — skip
    return False


async def validate_endpoint_url(
    url: str,
    *,
    allowed_schemes: tuple[str, ...] = ("http", "https"),
    allow_http: bool | None = None,
    allow_private: bool = False,
) -> None:
    """Reject URLs that point to private/internal networks (SSRF prevention).

    Resolves the hostname and verifies it does not fall within RFC 1918,
    link-local, loopback, or other reserved ranges.
    Raises HTTPException(422) on any violation.

    allow_http: override the HTTP-in-production check.
      None  → use settings.DEBUG (default: block HTTP in production)
      True  → allow HTTP (e.g. when ALLOW_HTTP_IDP=true for OIDC)
      False → always block HTTP

    allow_private: when True, skip the private/reserved-network check.
      Set only for deployments that explicitly configure an internal IdP
      (ALLOW_HTTP_IDP=true implies an on-premises deployment where the IdP
      may resolve to a RFC 1918 address).
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise HTTPException(status_code=422, detail="endpoint_url is not a valid URL")

    if parsed.scheme not in allowed_schemes:
        schemes = " or ".join(allowed_schemes)
        raise HTTPException(status_code=422, detail=f"endpoint_url must use {schemes} scheme")

    http_ok = settings.DEBUG if allow_http is None else allow_http
    if parsed.scheme == "http" and not http_ok:
        raise HTTPException(
            status_code=422,
            detail="endpoint_url must use https in production (set DEBUG=true to allow plain http)",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=422, detail="endpoint_url must include a hostname")

    if allow_private:
        return

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
        if _is_blocked(ip):
            raise HTTPException(
                status_code=422,
                detail=(
                    "endpoint_url resolves to a private or reserved address. "
                    "Direct access to internal networks is not permitted."
                ),
            )


async def resolve_validated_endpoint(
    url: str,
    *,
    allowed_schemes: tuple[str, ...] = ("http", "https"),
    allow_http: Optional[bool] = None,
) -> tuple[str, str]:
    """Validate url for SSRF and return (hostname, pinned_ip_str).

    The returned IP is the validated resolved address; callers should use it as
    a pinned DNS target so that the validation and connection use the same address
    (prevents DNS rebinding TOCTOU attacks).
    Raises HTTPException(422) on any violation.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise HTTPException(status_code=422, detail="endpoint_url is not a valid URL")

    if parsed.scheme not in allowed_schemes:
        schemes = " or ".join(allowed_schemes)
        raise HTTPException(status_code=422, detail=f"endpoint_url must use {schemes} scheme")

    http_ok = settings.DEBUG if allow_http is None else allow_http
    if parsed.scheme == "http" and not http_ok:
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

    pinned_ip: Optional[str] = None
    for _, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked(ip):
            raise HTTPException(
                status_code=422,
                detail=(
                    "endpoint_url resolves to a private or reserved address. "
                    "Direct access to internal networks is not permitted."
                ),
            )
        if pinned_ip is None:
            pinned_ip = ip_str

    if pinned_ip is None:
        raise HTTPException(status_code=422, detail="Cannot resolve a usable address for endpoint_url")

    return hostname, pinned_ip
