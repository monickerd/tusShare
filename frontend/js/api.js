/**
 * tusShare — HTTP client with CSRF and auto-refresh.
 *
 * All state-changing requests include the X-CSRF-Token header.
 * On 401, attempts a token refresh once before redirecting to login.
 */
const Api = (() => {
    let _refreshing = null;

    function _csrfToken() {
        return Utils.parseCookie(Config.auth.cookieCsrfName) || '';
    }

    async function _handle403(resp, path, method, headers, bodyString) {
        let data;
        try { data = await resp.json(); } catch { data = null; }

        if (data?.detail?.error === 'mfa_enrollment_required') {
            globalThis.location.hash = '#/mfa';
            const err = new Error('MFA enrollment required');
            err.status = 403;
            err.mfaEnrollmentRequired = true;
            throw err;
        }

        if (data?.detail?.error === 'step_up_required') {
            const actionKey     = data.detail.action;
            const challengeType = data.detail.challenge_type || 'password';
            const rawBody       = typeof bodyString === 'string' ? bodyString : '';
            const payloadHash   = await hashPayload(rawBody);
            const stepUpToken   = await StepUp.challenge(actionKey, payloadHash, challengeType);
            const retryHeaders  = { ...headers, 'X-Step-Up-Token': stepUpToken };
            if (retryHeaders['X-CSRF-Token']) retryHeaders['X-CSRF-Token'] = _csrfToken();
            const retryResp = await fetch(path, { method, headers: retryHeaders, body: bodyString, credentials: 'same-origin' });
            return _handleResponse(retryResp);
        }

        const errMsg = data?.error?.message || data?.detail || 'HTTP 403';
        const err = new Error(errMsg);
        err.status = 403;
        throw err;
    }

    async function _fetch(method, path, body = null, extraHeaders = {}) {
        const headers = { ...extraHeaders };

        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
            headers['X-CSRF-Token'] = _csrfToken();
        }

        // Stringify body early so we can hash it for step-up if needed
        let bodyString = body;
        if (body && !(body instanceof ArrayBuffer) && !(body instanceof Blob)) {
            headers['Content-Type'] = 'application/json';
            bodyString = JSON.stringify(body);
        }

        const resp = await fetch(path, {
            method,
            headers,
            body: bodyString,
            credentials: 'same-origin',
        });

        // 401 → attempt token refresh then retry
        if (resp.status === 401 && !path.includes('/auth/refresh') && !path.includes('/auth/login')) {
            const refreshed = await _tryRefresh();
            if (refreshed) {
                if (headers['X-CSRF-Token']) {
                    headers['X-CSRF-Token'] = _csrfToken();
                }
                const retry = await fetch(path, {
                    method,
                    headers,
                    body: bodyString,
                    credentials: 'same-origin',
                });
                return _handleResponse(retry);
            }
            sessionStorage.removeItem(Config.auth.sessionStorageKey);
            globalThis.location.hash = '#/login';
            throw new Error('Session expired');
        }

        // 403 → check for step-up requirement before generic error handling
        if (resp.status === 403 && !path.includes('/auth/step-up')) {
            return _handle403(resp, path, method, headers, bodyString);
        }

        return _handleResponse(resp);
    }

    async function _handleResponse(resp) {
        if (resp.ok) Auth.touchKeyCache();
        if (!resp.ok) {
            let detail = `HTTP ${resp.status}`;
            let existingFolderId = null;
            try {
                const data = await resp.json();
                if (Array.isArray(data.detail) && data.detail.length > 0) {
                    detail = data.detail.map(e => (e.msg || String(e)).replace(/^Value error,\s*/i, '')).join('; ');
                } else {
                    const detailObj = (data.detail && typeof data.detail === 'object') ? data.detail : null;
                    detail = data.error?.message || detailObj?.message || (typeof data.detail === 'string' ? data.detail : null) || detail;
                    existingFolderId = detailObj?.existing_folder_id ?? null;
                }
            } catch {}
            const err = new Error(detail);
            err.status = resp.status;
            err.existingFolderId = existingFolderId;
            throw err;
        }

        if (resp.status === 204 || resp.status === 205) return null;

        const ct = resp.headers.get('content-type') || '';
        if (ct.includes('application/json')) {
            return resp.json();
        }
        return resp;
    }

    async function _tryRefresh() {
        if (_refreshing) return _refreshing;
        _refreshing = (async () => {
            try {
                const resp = await fetch(`${Config.app.apiPrefix}/auth/refresh`, {
                    method: 'POST',
                    credentials: 'same-origin',
                });
                return resp.ok;
            } catch {
                return false;
            } finally {
                _refreshing = null;
            }
        })();
        return _refreshing;
    }

    return {
        get:    (path) => _fetch('GET', path),
        post:   (path, body) => _fetch('POST', path, body),
        put:    (path, body) => _fetch('PUT', path, body),
        del:    (path) => _fetch('DELETE', path),
        patch:  (path, body, headers) => _fetch('PATCH', path, body, headers),
        getCsrfToken: _csrfToken,
        refreshTokens: _tryRefresh,

        streamGet: (path, headers = {}) =>
            fetch(path, { method: 'GET', headers, credentials: 'same-origin' }),

        streamPatch: (path, body, headers = {}) => {
            headers['X-CSRF-Token'] = _csrfToken();
            return fetch(path, { method: 'PATCH', headers, body, credentials: 'same-origin' });
        },
    };
})();
