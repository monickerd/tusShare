"""Request-level validators for common patterns (pagination, Range headers, etc.)."""

from dataclasses import dataclass

from app.conf.validation import (
    PAGINATION_DEFAULT_LIMIT,
    PAGINATION_DEFAULT_PAGE,
    PAGINATION_MAX_LIMIT,
    PAGINATION_MAX_PAGE,
    RANGE_HEADER_PATTERN,
)


@dataclass
class PaginationParams:
    page: int
    limit: int
    offset: int


def validate_pagination(
    page: int = PAGINATION_DEFAULT_PAGE,
    limit: int = PAGINATION_DEFAULT_LIMIT,
) -> PaginationParams:
    """Validate and clamp pagination parameters."""
    page = max(1, min(page, PAGINATION_MAX_PAGE))
    limit = max(1, min(limit, PAGINATION_MAX_LIMIT))
    offset = (page - 1) * limit
    return PaginationParams(page=page, limit=limit, offset=offset)


@dataclass
class RangeRequest:
    start: int
    end: int | None


def parse_range_header(value: str | None, total_size: int) -> RangeRequest | None:
    """Parse an HTTP Range header.

    Returns None if no Range header is present.
    Raises ValueError for malformed or unsatisfiable ranges.
    """
    if not value:
        return None

    match = RANGE_HEADER_PATTERN.match(value.strip())
    if not match:
        raise ValueError("Malformed Range header")

    start = int(match.group(1))
    end_str = match.group(2)
    end = int(end_str) if end_str else None

    if start >= total_size:
        raise ValueError("Range not satisfiable")

    if end is not None:
        if end >= total_size:
            end = total_size - 1
        if end < start:
            raise ValueError("Range end must be >= start")

    return RangeRequest(start=start, end=end)


def validate_upload_offset(value: str) -> int:
    """Validate an Upload-Offset header value."""
    try:
        offset = int(value)
    except (TypeError, ValueError):
        raise ValueError("Upload-Offset must be a non-negative integer")
    if offset < 0:
        raise ValueError("Upload-Offset must be non-negative")
    return offset


def validate_upload_length(value: str, max_size: int) -> int:
    """Validate an Upload-Length header value against max file size."""
    try:
        length = int(value)
    except (TypeError, ValueError):
        raise ValueError("Upload-Length must be a positive integer")
    if length <= 0:
        raise ValueError("Upload-Length must be positive")
    if length > max_size:
        raise ValueError(f"Upload-Length exceeds maximum file size ({max_size} bytes)")
    return length
