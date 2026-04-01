"""CSRF protection via double-submit cookie pattern.

On login, the server sets a readable `csrf_token` cookie.
On every state-changing request (POST/PUT/DELETE/PATCH), the middleware
compares the `X-CSRF-Token` header against the `csrf_token` cookie value
using constant-time comparison.

Exempt paths: login, refresh, and all public share endpoints.
"""

import hmac
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.conf.middleware import CSRF_EXEMPT_PREFIXES, CSRF_STATE_CHANGING_METHODS

logger = logging.getLogger(__name__)


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method not in CSRF_STATE_CHANGING_METHODS:
            return await call_next(request)

        path = request.url.path
        if any(path.startswith(prefix) for prefix in CSRF_EXEMPT_PREFIXES):
            return await call_next(request)

        cookie_token = request.cookies.get("csrf_token", "")
        header_token = request.headers.get("X-CSRF-Token", "")

        if not cookie_token or not header_token:
            logger.warning("CSRF: missing token (path=%s, ip=%s)", path, request.client.host if request.client else "unknown")
            return JSONResponse(
                status_code=403,
                content={"error": {"code": "CSRF_ERROR", "message": "CSRF token missing"}},
            )

        if not hmac.compare_digest(cookie_token, header_token):
            logger.warning("CSRF: token mismatch (path=%s)", path)
            return JSONResponse(
                status_code=403,
                content={"error": {"code": "CSRF_ERROR", "message": "CSRF token invalid"}},
            )

        return await call_next(request)
