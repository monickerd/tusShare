"""Input validation constants — field lengths, regex patterns, pagination."""

import re

# --- Username ---
USERNAME_MIN_LENGTH = 1
USERNAME_MAX_LENGTH = 64
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._+@-]{1,64}$")

# --- Folder names ---
FOLDER_NAME_MIN_LENGTH = 1
FOLDER_NAME_MAX_LENGTH = 255
FOLDER_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9 _\-.'!()&,]{1,255}$")

# --- File names ---
# Cross-platform max: 255 chars (NTFS/ext4 component limit).
# Windows full path limit is 260 by default, but we only control the name
# component — 255 is the safe per-component ceiling on both OSes.
FILENAME_MAX_LENGTH = 255

# Characters forbidden by Windows (NTFS) and/or Linux (ext4):
#   < > : " / \ | ? *        — Windows reserved
#   /                         — Linux path separator (already in Windows set)
#   \x00                      — null byte (both OSes)
# Control chars (0x00-0x1F, 0x7F-0x9F) are handled separately by CONTROL_CHAR_PATTERN.
FILENAME_BLACKLIST_CHARS = set('<>:"/\\|?*')

# Windows reserved device names — cannot be used as filenames (with or without extension).
FILENAME_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)

# --- UUIDs ---
UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# --- Share tokens ---
SHARE_TOKEN_LENGTH = 43  # base64url of 32 bytes
SHARE_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")

# --- Short link slugs ---
# Each word: 1 uppercase + 2–11 lowercase (accommodates "Genderfluid" = 11 chars)
SHORT_SLUG_PATTERN = re.compile(r"^[A-Z][a-z]{2,11}[A-Z][a-z]{2,11}[A-Z][a-z]{2,11}$")

# --- Base64 ---
BASE64_MAX_LENGTH = 4096
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=_-]+$")

# --- IP addresses ---
IP_MAX_LENGTH = 45
IP_PATTERN = re.compile(r"^[0-9a-fA-F.:]{1,45}$")

# --- User-Agent ---
USER_AGENT_MAX_LENGTH = 512

# --- BLS12-381 compressed point sizes (cross-referenced by sanitizers) ---
# Imported from conf/teams.py at use-site to avoid circular imports.
# Listed here as documentation only.
# G1: 48 bytes compressed, G2: 96 bytes compressed.

# --- Team name ---
TEAM_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9 _\-.]{1,64}$")

# --- Pagination ---
PAGINATION_DEFAULT_PAGE = 1
PAGINATION_DEFAULT_LIMIT = 20
PAGINATION_MAX_PAGE = 10000
PAGINATION_MAX_LIMIT = 100

# --- Range header ---
RANGE_HEADER_PATTERN = re.compile(r"^bytes=(\d+)-(\d*)$")

# --- Control characters ---
# Full C0 (0x00-0x1f) including TAB (0x09), plus DEL (0x7f) and C1 (0x80-0x9f).
# TAB is not a valid character in filenames, usernames, or header values on any
# supported platform; permitting it was an oversight.
# CR (0x0d) and LF (0x0a) are included — they are header/log delimiters.
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Detects any percent-encoded control character (U+0000–U+001F, U+007F, U+0080–U+009F).
ENCODED_CONTROL_PATTERN = re.compile(
    r"%(?:0[0-9a-f]|1[0-9a-f]|7f|[89a-f][0-9a-f])",
    re.IGNORECASE,
)

# Maximum number of URL-decode rounds to attempt when checking for nested encoding.
MAX_URL_DECODE_ROUNDS = 3
