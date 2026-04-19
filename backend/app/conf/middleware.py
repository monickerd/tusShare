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
    # OPAQUE pre-auth endpoints — unauthenticated, no session cookie exists.
    # step-up is intentionally excluded (it requires an active session).
    "/api/v1/auth/opaque/login/",
    "/api/v1/auth/opaque/register/",
    "/api/v1/auth/opaque/bootstrap/",
    "/api/v1/auth/opaque/migrate/",
    "/api/v1/auth/opaque/recover/",
    # LDAP login is an unauthenticated pre-session endpoint — no CSRF cookie
    # exists before the first login completes, so the double-submit pattern
    # cannot be applied.  Login-CSRF risk is low: credentials must be valid
    # and the attacker gains no access to the victim's data.
    "/api/v1/auth/ldap/login",
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
    # Explicitly disable the legacy XSS auditor — it can introduce XSS vulnerabilities of its own.
    "X-XSS-Protection": "0",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()",
    # HSTS: tell browsers to always use HTTPS for this origin for 1 year.
    # includeSubDomains covers any subdomain. Do NOT add 'preload' unless you intend
    # to submit the domain to the HSTS preload list — that decision is permanent.
    # Note: Cloudflare can also enforce this, but setting it here ensures coverage
    # regardless of proxy configuration.
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    # Cross-origin isolation headers — prevent cross-origin attacks (Spectre, XS-Leaks).
    # COOP: restricts which pages can share a browsing context group with this page.
    # COEP: requires all subresources to be same-origin or explicitly opt in via CORP.
    # CORP: prevents other origins from loading this site's resources via no-cors fetch/img/script.
    # Safe here because all assets are self-hosted (script-src/style-src/connect-src 'self').
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    # Blocks Flash and PDF plugin cross-domain policy requests (legacy tech, still flagged by scanners).
    "X-Permitted-Cross-Domain-Policies": "none",
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
# Phase C (SRI+CSP): SRI integrity hashes are injected into index.html at startup
# (see app/util/sri.py), so every <script> and <link> tag is covered.
#
# 'unsafe-inline' in style-src remains intentional: several JS modules set
# element.style.* to computed pixel values at runtime (context-menu positioning,
# progress-bar widths) that cannot be expressed as static CSS classes.  Replacing
# them would require CSS custom properties or a nonce-based <style> pipeline —
# a non-trivial refactor tracked for a future hardening pass.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'wasm-unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "media-src 'none'; "
    "object-src 'none'; "
    "worker-src 'none'; "
    "frame-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "upgrade-insecure-requests"
)
