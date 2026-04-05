"""HTTPS redirect middleware.

When TUSSHARE_FORCE_HTTPS=true, any request that arrived over plain HTTP
(reported by the reverse proxy via X-Forwarded-Proto: http) is permanently
redirected to the HTTPS equivalent.

IMPORTANT: Only enable FORCE_HTTPS when the application is not directly
internet-accessible — i.e. the app port is not published in docker-compose
and all traffic is routed through the TLS-terminating reverse proxy (nginx,
Cloudflare, etc.). If the app were directly reachable, clients could spoof
X-Forwarded-Proto: https to bypass this check. Network-level isolation is
the primary control; this redirect is the application-layer enforcement layer.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse


class HttpsRedirectMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        proto = request.headers.get("X-Forwarded-Proto", "https").lower()
        if proto != "http":
            return await call_next(request)

        # Reconstruct the URL with https scheme, preserving path + query string.
        # Drop the port — standard HTTPS is 443, which nginx/Cloudflare handles.
        host = request.headers.get("X-Forwarded-Host") or request.url.hostname
        location = f"https://{host}{request.url.path}"
        if request.url.query:
            location += f"?{request.url.query}"

        return RedirectResponse(url=location, status_code=301)
