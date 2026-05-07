// Framejacking protection: break out of any frame immediately.
// Runs before any app code. Server-side X-Frame-Options: DENY and
// CSP frame-ancestors 'none' are the primary controls; this is a
// defence-in-depth fallback for legacy browsers or cached responses.
if (window !== window.top) {
    try {
        const _target = window.location.pathname + window.location.search + window.location.hash;
        if (_target.startsWith('/') && !_target.startsWith('//')) {
            window.top.location.replace(_target);
        }
    } catch (_) { document.documentElement.innerHTML = ''; }
}

/**
 * tusShare — Frontend configuration.
 *
 * All hardcoded values extracted here for central management.
 * Grouped by concern for easy navigation.
 */
const Config = Object.freeze({
    /* --- Application --- */
    app: Object.freeze({
        name: 'tusShare',
        apiPrefix: '/api/v1',
    }),

    /* --- Authentication --- */
    auth: Object.freeze({
        usernameMaxLength: 64,
        usernamePattern: '[a-zA-Z0-9._+@\\-]+',
        passwordMinLength: 1,      // login (server validates strength)
        passwordMaxLength: 128,
        sessionStorageKey: 'masterKey',
        cookieCsrfName: '__Host-csrf_token',
        cookieAccessName: '__Host-access_token',
        // How long (ms) the cached master key is trusted without re-entering the password.
        // Rolling window: resets on each page load that successfully restores the key.
        // NOTE: the raw key bytes are stored in sessionStorage (same-origin only, cleared
        // on tab close) for this duration. Acceptable trade-off for long upload sessions.
        keyGracePeriodMs: 30 * 60 * 1000,  // 30 minutes
        // Step-up sudo window (seconds). Must match TUSSHARE_STEP_UP_WINDOW_SECONDS on the server.
        // The step-up token cache uses 90% of this value to avoid racing server expiry.
        // Set to 0 to disable caching (single-use mode).
        stepUpWindowSeconds: 300,
    }),

    /* --- Cryptography --- */
    crypto: Object.freeze({
        aesKeyLength: 256,          // bits
        ivLength: 12,               // bytes
        algorithm: 'AES-GCM',
    }),

    /* --- Upload --- */
    upload: Object.freeze({
        defaultChunkSize: 5 * 1024 * 1024,  // 5 MB
        maxRetries: 3,
        retryBaseDelay: 1000,       // ms, doubles each retry
        // Integrity failure thresholds — abort if either is exceeded.
        // A single chunk repeatedly failing points to a corrupted network path or
        // hardware problem rather than a transient glitch.
        maxHashFailuresPerChunk: 2, // abort if the same chunk fails this many times (absolute)
        maxHashFailureRate: 0.02,   // abort if this fraction of all chunks have failures
        maxHashFailuresMin: 2,      // floor for the rate threshold (prevents a near-zero
                                    // threshold on very small files, e.g. 5 chunks × 2% = 0)
    }),

    /* --- File validation --- */
    file: Object.freeze({
        nameMaxLength: 255,         // cross-platform NTFS/ext4 component limit
        // Characters forbidden by Windows and/or Linux
        nameBlacklistChars: new Set('<>:"/\\|?*'),
        reservedNames: new Set([
            'CON','PRN','AUX','NUL',
            ...[1,2,3,4,5,6,7,8,9].map(i => `COM${i}`),
            ...[1,2,3,4,5,6,7,8,9].map(i => `LPT${i}`),
        ]),
    }),

    /* --- UI --- */
    ui: Object.freeze({
        toastFadeOutMs: 300,
        toastAutoHideMs: 5000,
        paginationDefaultLimit: 20,
        paginationMaxLimit: 100,
        fileNameMaxDisplay: 60,     // truncate long names in UI
    }),

    /* --- Time formatting thresholds (seconds) --- */
    time: Object.freeze({
        minute: 60,
        hour: 3600,
        day: 86400,
        week: 604800,
    }),

    /* --- Theme --- */
    theme: Object.freeze({
        current: 'default',         // folder name under /themes/
        storageKey: 'tusshare_theme',
    }),

    /* --- Sharing --- */
    share: Object.freeze({
        maxItems: 100,              // max files per share (mirrors backend limit)
        keyStoragePrefix: 'sk_',   // sessionStorage prefix for shareKeys, keyed by share_id
        defaultExpiryDays: 7,      // default link expiry when creating a share
    }),

    /* --- Public / shared device mode --- */
    // TODO: migrate bannerVisible and bannerText into theme.json so
    // admins can customise them without touching source files.
    publicDevice: Object.freeze({
        sessionStorageKey: 'publicDevice',
        bannerVisible: true,
        bannerText: 'Public Device: Consider avoiding transferring particularly sensitive files. Remember to log out or close the tab when finished.',
    }),

    /* --- Admin --- */
    admin: Object.freeze({
        inviteExpireHours:          24,
        // Bandwidth and file sizes stored as bytes in admin_settings;
        // displayed in the UI as MB or MB/s respectively.
        bytesPerMb:                 1048576,
        diskWarningDefaultPct:      65,
    }),

    /* --- Teams --- */
    teams: Object.freeze({
        // Maximum file keys to submit in a single batch (mirrors backend limit)
        fileKeyBatchMax: 500,
        // Maximum files to PRE-rotate in one go before warning user
        rotationWarnThreshold: 1000,
        // BLS12-381 compressed point sizes in bytes
        g1Bytes: 48,
        g2Bytes: 96,
        // HKDF domain separator for team key wrapping
        hkdfInfo: 'tusShare-teamkey-v1',
    }),
});
