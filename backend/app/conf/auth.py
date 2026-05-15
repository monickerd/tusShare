"""Authentication and security constants."""

# --- Password rules ---
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

# --- Token generation ---
REFRESH_TOKEN_BYTES = 48       # secrets.token_urlsafe length
CSRF_TOKEN_BYTES = 32          # secrets.token_hex length

# --- Share session tokens ---
SHARE_SESSION_EXPIRE_HOURS = 2   # short-lived IP-bound token for public share access

# --- Cookie names and paths ---
# __Host- prefix: browser enforces Secure + no Domain + Path=/ — prevents subdomain injection.
# __Secure- prefix: browser enforces Secure only — used for refresh_token which has a narrow path.
COOKIE_ACCESS  = "__Host-access_token"
COOKIE_CSRF    = "__Host-csrf_token"
# __Host- prefix: enforces Secure + no Domain + Path=/ at the browser level — prevents subdomain injection.
# Path narrowing for the refresh cookie is application-layer only (only /auth/refresh reads it).
COOKIE_REFRESH = "__Host-refresh_token"
REFRESH_TOKEN_COOKIE_PATH = "/"

# --- JWT algorithm policy ---
# Only HMAC algorithms are permitted for the app's own JWTs.  These tokens are
# signed and verified exclusively by the server; clients treat them as opaque
# strings, so there are no client-side compatibility constraints.
# HS384 is excluded: on 64-bit hardware SHA-384 costs the same as SHA-512
# (it is SHA-512 truncated after fewer rounds) but produces a smaller output
# with no security benefit.
ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS512"})

# --- Step-up authentication ---
# Maximum clock skew (seconds) tolerated between client and server timestamps
# during step-up HMAC verification.
STEP_UP_TIMESTAMP_TOLERANCE = 30
