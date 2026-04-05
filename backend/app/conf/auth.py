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

# --- Cookie names and paths ---
# __Host- prefix: browser enforces Secure + no Domain + Path=/ — prevents subdomain injection.
# __Secure- prefix: browser enforces Secure only — used for refresh_token which has a narrow path.
COOKIE_ACCESS  = "__Host-access_token"
COOKIE_CSRF    = "__Host-csrf_token"
COOKIE_REFRESH = "__Secure-refresh_token"
REFRESH_TOKEN_COOKIE_PATH = "/api/v1/auth/refresh"

# --- Key derivation ---
# Must match frontend Config.crypto.pbkdf2Iterations exactly.
# The server re-derives the KEK during step-up auth to verify the HMAC.
PBKDF2_ITERATIONS = 600_000

# --- Step-up authentication ---
# Maximum clock skew (seconds) tolerated between client and server timestamps
# during step-up HMAC verification.
STEP_UP_TIMESTAMP_TOLERANCE = 30
