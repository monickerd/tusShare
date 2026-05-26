"""Input sanitization middleware.

Strips or rejects dangerous content from request headers and query
parameters before they reach route handlers. This is a defense-in-depth
layer — individual routes still validate their own inputs.
"""

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.conf.middleware import (
    CONTROL_CHAR_CHECKED_HEADERS,
    HEADER_MAX_LENGTHS,
    QUERY_PARAM_MAX_LENGTH,
)
from app.conf.validation import CONTROL_CHAR_PATTERN, ENCODED_CONTROL_PATTERN

logger = logging.getLogger(__name__)


class InputSanitizationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Check consumed header lengths
        for header_name, max_len in HEADER_MAX_LENGTHS.items():
            value = request.headers.get(header_name, "")
            if len(value) > max_len:
                logger.warning("Header too long: %s (%d > %d)", header_name, len(value), max_len)
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": f"Header '{header_name}' exceeds maximum length",
                        }
                    },
                )

        # Check for control characters in consumed headers
        for header_name in CONTROL_CHAR_CHECKED_HEADERS:
            value = request.headers.get(header_name, "")
            if value and CONTROL_CHAR_PATTERN.search(value):
                logger.warning("Control chars in header: %s", header_name)
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": f"Header '{header_name}' contains invalid characters",
                        }
                    },
                )

        # Check for percent-encoded control characters in the raw URL path
        # before Starlette decodes it. Catches CRLF/null injection via the URL.
        raw_path = request.url.path
        if ENCODED_CONTROL_PATTERN.search(raw_path):
            logger.warning("Encoded control chars in URL path: %s", raw_path)
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "URL path contains invalid encoded characters",
                    }
                },
            )

        # Check query parameter lengths and control characters.
        # Starlette URL-decodes query params before we see them, so control
        # chars that survive the raw-path check above are caught here.
        for param, value in request.query_params.items():
            if len(value) > QUERY_PARAM_MAX_LENGTH:
                logger.warning("Query param too long: %s (%d chars)", param, len(value))
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": f"Query parameter '{param}' exceeds maximum length",
                        }
                    },
                )
            if CONTROL_CHAR_PATTERN.search(value):
                logger.warning("Control chars in query param: %s", param)
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": f"Query parameter '{param}' contains invalid characters",
                        }
                    },
                )

        return await call_next(request)
