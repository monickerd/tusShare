"""Security response headers middleware.

Sets standard security headers on all responses to mitigate
XSS, clickjacking, MIME-sniffing, and information leakage.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.conf.middleware import (
    CACHE_CONTROL_NO_STORE,
    CACHE_CONTROL_REVALIDATE,
    CONTENT_SECURITY_POLICY,
    SECURITY_HEADERS,
)

_HTML_EXTENSIONS = (".html",)
_REVALIDATE_EXTENSIONS = (".js", ".css", ".woff", ".woff2", ".ttf", ".ico", ".png", ".svg", ".webp")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value

        path = request.url.path

        if not path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY

            # Strip query string for extension matching (e.g. file.js?v=3)
            clean_path = path.split("?")[0]
            if clean_path.endswith(_HTML_EXTENSIONS) or clean_path == "/" or "." not in clean_path.rsplit("/", 1)[-1]:
                response.headers["Cache-Control"] = CACHE_CONTROL_NO_STORE
            elif clean_path.endswith(_REVALIDATE_EXTENSIONS):
                response.headers["Cache-Control"] = CACHE_CONTROL_REVALIDATE

        return response
