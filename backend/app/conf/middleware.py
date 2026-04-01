"""Middleware constants — header limits, security headers, rate limit windows."""

# --- Header max lengths (bytes) ---
HEADER_MAX_LENGTHS = {
    "user-agent": 512,
    "x-csrf-token": 128,
    "x-chunk-iv": 64,
    "x-chunk-hash": 71,         # "sha256:" (7) + 64 hex chars
    "authorization": 2048,
    "upload-metadata": 4096,
    "upload-length": 24,    # max 20-digit integer
    "upload-offset": 24,    # max 20-digit integer
    "tus-resumable": 16,    # e.g. "1.0.0"
    "content-type": 256,
    "range": 128,
}

# --- Query parameter limits ---
QUERY_PARAM_MAX_LENGTH = 1024

# --- Headers checked for control characters ---
CONTROL_CHAR_CHECKED_HEADERS = (
    "x-csrf-token",
    "x-chunk-iv",
    "x-chunk-hash",
    "authorization",
    "range",
)

# --- CSRF ---
CSRF_STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
CSRF_EXEMPT_PREFIXES = (
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    # Registration and invite validation are unauthenticated — no session cookie
    # exists yet so the double-submit CSRF pattern doesn't apply.
    "/api/v1/auth/register",
    "/api/v1/auth/invite/",
    "/s/",
    "/l/",
)

# --- Rate limiting ---
RATE_LIMIT_CLEANUP_MAX_AGE = 3600.0      # seconds (1 hour)
RATE_LIMIT_LOGIN_WINDOW = 900            # seconds (15 minutes)
RATE_LIMIT_MANAGEMENT_WINDOW = 60        # seconds (1 minute)

# --- Security response headers ---
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

# --- Cache-Control headers for static assets ---
# index.html must never be cached (browser or CDN) so JS/CSS changes are
# picked up immediately without manual cache-busting query strings.
# JS/CSS/fonts/images use no-cache (ETag revalidation) — the browser keeps
# them locally but asks the server on each load; a changed file gets a new
# ETag and is re-fetched automatically.
CACHE_CONTROL_NO_STORE = "no-store"
CACHE_CONTROL_REVALIDATE = "no-cache"

# --- CSP applied to non-API responses ---
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)
