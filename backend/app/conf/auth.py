"""Authentication and security constants."""

# --- Password rules ---
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
PASSWORD_LOGIN_MIN_LENGTH = 1  # Login accepts any non-empty string; bcrypt rejects wrong passwords regardless. Early rejection of short strings would leak valid password length ranges via 422.

# --- Token generation ---
REFRESH_TOKEN_BYTES = 48       # secrets.token_urlsafe length
ENCRYPTION_SALT_BYTES = 32     # hex-encoded = 64 chars
CSRF_TOKEN_BYTES = 32          # secrets.token_hex length

# --- bcrypt ---
BCRYPT_ROUNDS = 12

# --- Share session tokens ---
SHARE_SESSION_EXPIRE_HOURS = 2   # short-lived IP-bound token for public share access

# --- Cookie paths ---
REFRESH_TOKEN_COOKIE_PATH = "/api/v1/auth/refresh"
