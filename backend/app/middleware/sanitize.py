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
from app.conf.validation import CONTROL_CHAR_PATTERN

logger = logging.getLogger(__name__)


class InputSanitizationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Check consumed header lengths
        for header_name, max_len in HEADER_MAX_LENGTHS.items():
            value = request.headers.get(header_name, "")
            if len(value) > max_len:
                logger.warning(
                    "Header too long: %s (%d > %d)", header_name, len(value), max_len
                )
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

        # Check query parameter lengths
        for param, value in request.query_params.items():
            if len(value) > QUERY_PARAM_MAX_LENGTH:
                logger.warning(
                    "Query param too long: %s (%d chars)", param, len(value)
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": f"Query parameter '{param}' exceeds maximum length",
                        }
                    },
                )

        return await call_next(request)
