"""HTTP protocol helpers shared across route files."""

from __future__ import annotations

import urllib.parse

from fastapi import HTTPException
from starlette.responses import Response


def parse_range_header(range_header: str, total_size: int) -> tuple[int, int] | Response:
    """Parse an HTTP Range header against a known total size.

    Returns (start, end) on success, or a 416 Response object when the
    requested range is not satisfiable.  Raises HTTPException(400) for
    syntactically invalid headers.

    The caller is responsible for setting status_code=206 and the
    Content-Range response header when a range was satisfied.
    """
    if not range_header.startswith("bytes="):
        raise HTTPException(status_code=400, detail="Only bytes ranges are supported")

    spec = range_header[6:]  # strip "bytes="
    parts = spec.split("-", 1)
    try:
        if parts[0] == "" and len(parts) == 2 and parts[1]:
            # Suffix range: bytes=-N  →  last N bytes
            suffix = int(parts[1])
            start = max(0, total_size - suffix)
            end = total_size - 1
        else:
            start = int(parts[0]) if parts[0] else 0
            end = int(parts[1]) if (len(parts) > 1 and parts[1]) else total_size - 1
    except (ValueError, OverflowError):
        raise HTTPException(status_code=400, detail="Invalid Range header")

    if start < 0 or end < start or start >= total_size:
        return Response(
            status_code=416,
            headers={"Content-Range": f"bytes */{total_size}"},
        )

    end = min(end, total_size - 1)
    return start, end


def content_disposition(filename: str) -> str:
    """Return an RFC 5987 Content-Disposition value for *filename*.

    Uses the ``filename*=UTF-8''<encoded>`` form so that non-ASCII characters
    survive transmission without mangling.
    """
    encoded = urllib.parse.quote(filename, safe="")
    return f"attachment; filename*=UTF-8''{encoded}"
