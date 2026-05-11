"""Input sanitization functions.

Whitelists for structured inputs (usernames, folder names, UUIDs).
Blacklist for filenames (strips OS-forbidden characters, preserves Unicode).
Every function either returns a cleaned value or raises ValueError.
"""

import base64
import unicodedata
import urllib.parse

from app.conf.validation import (
    BASE64_MAX_LENGTH,
    BASE64_PATTERN,
    CONTROL_CHAR_PATTERN,
    ENCODED_CONTROL_PATTERN,
    FILENAME_BLACKLIST_CHARS,
    FILENAME_MAX_LENGTH,
    FILENAME_RESERVED_NAMES,
    FOLDER_NAME_PATTERN,
    IP_MAX_LENGTH,
    IP_PATTERN,
    MAX_URL_DECODE_ROUNDS,
    SHARE_TOKEN_PATTERN,
    SHORT_SLUG_PATTERN,
    TEAM_NAME_PATTERN,
    USER_AGENT_MAX_LENGTH,
    USERNAME_PATTERN,
    UUID_PATTERN,
)
from app.conf.teams import G1_COMPRESSED_BYTES, G1_BASE64_MAX_LENGTH, G2_COMPRESSED_BYTES, G2_BASE64_MAX_LENGTH


def sanitize_username(value: str) -> str:
    """Validate and return a username. Raises ValueError if invalid.

    Accepts plain usernames (alice) and email-style (alice+tag@example.com).
    Structural rules match major providers (Gmail, Outlook, Yahoo):
    - No leading/trailing dots, hyphens, or plus signs
    - No consecutive dots
    - At most one @
    """
    value = value.strip()
    if not USERNAME_PATTERN.match(value):
        raise ValueError(
            "Username must be 1-64 characters: letters, digits, . _ + - @"
        )
    if value.startswith((".", "-", "+")) or value.endswith((".", "-", "+")):
        raise ValueError("Username must not start or end with . - or +")
    if ".." in value:
        raise ValueError("Username must not contain consecutive dots")
    if value.count("@") > 1:
        raise ValueError("Username must contain at most one @")
    return value


def sanitize_folder_name(value: str) -> str:
    """Validate and return a folder name. Raises ValueError if invalid."""
    value = value.strip()
    if not FOLDER_NAME_PATTERN.match(value):
        raise ValueError(
            "Folder name must be 1-255 characters: letters, digits, spaces, or _ - . ' ! ( ) &"
        )
    if value.replace(".", "") == "":
        raise ValueError("Folder name cannot be only dots")
    return value


class SanitizedFilename:
    """Result of filename sanitization, carrying both the cleaned name and any removed characters."""

    __slots__ = ("name", "removed_chars")

    def __init__(self, name: str, removed_chars: list[str]):
        self.name = name
        self.removed_chars = removed_chars

    def __str__(self) -> str:
        return self.name


def sanitize_filename(value: str) -> SanitizedFilename:
    """Sanitize a user-provided filename for cross-platform safety.

    Uses a blacklist approach: removes characters forbidden by Windows (NTFS)
    and Linux (ext4), control characters, and null bytes. Everything else —
    including full Unicode — is preserved.

    Returns a SanitizedFilename with the cleaned name and a list of unique
    characters that were removed (for frontend warning display).

    Raises ValueError if the result is empty or exceeds the length limit.
    """
    if not value:
        raise ValueError("Filename must not be empty")

    # Track which characters we strip (unique, preserving first-seen order)
    removed: dict[str, None] = {}  # ordered set via dict keys

    # Pass 1: strip control characters
    cleaned_chars: list[str] = []
    for ch in value:
        if CONTROL_CHAR_PATTERN.match(ch) or ch == "\x00":
            removed[ch] = None
        elif ch in FILENAME_BLACKLIST_CHARS:
            removed[ch] = None
        else:
            cleaned_chars.append(ch)

    cleaned = "".join(cleaned_chars)

    # Collapse consecutive dots (prevent ".." path traversal and dots-only names)
    while ".." in cleaned:
        cleaned = cleaned.replace("..", ".")

    # Strip leading/trailing whitespace and dots
    cleaned = cleaned.strip().strip(".")

    # Normalize Unicode to NFC (canonical composed form)
    cleaned = unicodedata.normalize("NFC", cleaned)

    # Reject Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    stem = cleaned.split(".")[0].upper()
    if stem in FILENAME_RESERVED_NAMES:
        cleaned = f"_{cleaned}"

    # Enforce cross-platform component length limit
    if len(cleaned) > FILENAME_MAX_LENGTH:
        # Truncate but preserve extension
        name_part, _, ext = cleaned.rpartition(".")
        if ext and name_part:
            max_name = FILENAME_MAX_LENGTH - len(ext) - 1
            cleaned = f"{name_part[:max_name]}.{ext}"
        else:
            cleaned = cleaned[:FILENAME_MAX_LENGTH]

    # Strip trailing dots/spaces again (Windows silently strips these)
    cleaned = cleaned.rstrip(". ")

    if not cleaned:
        raise ValueError("Filename is empty after sanitization")

    return SanitizedFilename(name=cleaned, removed_chars=list(removed.keys()))


def validate_uuid(value: str) -> str:
    """Validate a UUID string. Raises ValueError if invalid."""
    value = value.strip().lower()
    if not UUID_PATTERN.match(value):
        raise ValueError("Invalid UUID format")
    return value


def validate_share_token(value: str) -> str:
    """Validate a share token. Raises ValueError if invalid."""
    if not SHARE_TOKEN_PATTERN.match(value):
        raise ValueError("Invalid share token format")
    return value


def validate_short_slug(value: str) -> str:
    """Validate a short link slug. Raises ValueError if invalid."""
    if not SHORT_SLUG_PATTERN.match(value):
        raise ValueError("Invalid short link slug format")
    return value


def validate_base64(value: str, max_length: int = BASE64_MAX_LENGTH) -> str:
    """Validate a base64/base64url string. Raises ValueError if invalid."""
    if not value or len(value) > max_length:
        raise ValueError(f"Base64 value must be 1-{max_length} characters")
    if not BASE64_PATTERN.match(value):
        raise ValueError("Invalid base64 encoding")
    return value


def sanitize_ip(value: str) -> str:
    """Sanitize an IP address string for logging."""
    value = value.strip()
    if not IP_PATTERN.match(value):
        return "invalid"
    return value[:IP_MAX_LENGTH]


def sanitize_user_agent(value: str) -> str:
    """Sanitize User-Agent for safe logging. Truncate and strip control chars."""
    if not value:
        return ""
    cleaned = CONTROL_CHAR_PATTERN.sub("", value)
    return cleaned[:USER_AGENT_MAX_LENGTH]


def sanitize_sort_field(value: str, allowed: set[str]) -> str:
    """Validate a sort field against an explicit allowlist."""
    value = value.strip().lower()
    if value not in allowed:
        raise ValueError(f"Sort field must be one of: {', '.join(sorted(allowed))}")
    return value


def sanitize_sort_order(value: str) -> str:
    """Validate sort order is 'asc' or 'desc'."""
    value = value.strip().lower()
    if value not in ("asc", "desc"):
        raise ValueError("Sort order must be 'asc' or 'desc'")
    return value


def sanitize_team_name(value: str) -> str:
    """Validate and return a team name. Raises ValueError if invalid."""
    value = value.strip()
    if not TEAM_NAME_PATTERN.match(value):
        raise ValueError(
            "Team name must be 1-64 characters: letters, digits, space, underscore, hyphen, dot"
        )
    if value.replace(".", "") == "":
        raise ValueError("Team name cannot be only dots")
    return value


def check_encode_depth(value: str, max_rounds: int = MAX_URL_DECODE_ROUNDS) -> None:
    """Detect nested/recursive URL encoding in a string.

    Repeatedly URL-decodes the value up to max_rounds times.  If the string
    still contains percent-encoded sequences after max_rounds it suggests a
    deliberate evasion attempt; raises ValueError in that case.

    Also raises ValueError immediately if any decode round produces a string
    containing encoded control characters (%0a, %0d, %00) — these are a sign
    of CRLF- or null-injection via multi-level encoding.

    Intended for inputs that pass through multiple decode layers (e.g. values
    that are URL-decoded by FastAPI and then again by a downstream subsystem).
    Not needed for inputs validated against strict whitelists — use it for
    free-form text that flows into log sinks, filenames derived from URLs, or
    response headers.
    """
    current = value
    for _ in range(max_rounds):
        if "%" not in current:
            return  # nothing left to decode — clean
        if ENCODED_CONTROL_PATTERN.search(current):
            raise ValueError("Input contains encoded control characters (possible injection attempt)")
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            return  # no change — percent sign is a literal, not encoding
        current = decoded

    # After max_rounds the string still has percent-encoding — suspicious
    if "%" in current:
        raise ValueError(
            f"Input still contains percent-encoded sequences after {max_rounds} decode rounds"
        )


def validate_g1_point(value: str) -> str:
    """Validate a base64-encoded BLS12-381 G1 compressed point (48 bytes).

    Only checks size and the compression flag (MSB of first byte).
    Full curve-point validity is enforced by the client library.
    """
    validate_base64(value, max_length=G1_BASE64_MAX_LENGTH)
    try:
        data = base64.b64decode(value + "==")  # tolerate missing padding
    except Exception:
        raise ValueError("G1 point is not valid base64")
    if len(data) != G1_COMPRESSED_BYTES:
        raise ValueError(f"G1 point must be {G1_COMPRESSED_BYTES} bytes (got {len(data)})")
    if not (data[0] & 0x80):
        raise ValueError("G1 point must be in compressed form (MSB flag not set)")
    return value


def validate_g2_point(value: str) -> str:
    """Validate a base64-encoded BLS12-381 G2 compressed point (96 bytes).

    Only checks size and the compression flag (MSB of first byte).
    Full curve-point validity is enforced by the client library.
    """
    validate_base64(value, max_length=G2_BASE64_MAX_LENGTH)
    try:
        data = base64.b64decode(value + "==")
    except Exception:
        raise ValueError("G2 point is not valid base64")
    if len(data) != G2_COMPRESSED_BYTES:
        raise ValueError(f"G2 point must be {G2_COMPRESSED_BYTES} bytes (got {len(data)})")
    if not (data[0] & 0x80):
        raise ValueError("G2 point must be in compressed form (MSB flag not set)")
    return value
