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

    async function _fetch(method, path, body = null, extraHeaders = {}) {
        const headers = { ...extraHeaders };

        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
            headers['X-CSRF-Token'] = _csrfToken();
        }

        if (body && !(body instanceof ArrayBuffer) && !(body instanceof Blob)) {
            headers['Content-Type'] = 'application/json';
            body = JSON.stringify(body);
        }

        const resp = await fetch(path, {
            method,
            headers,
            body,
            credentials: 'same-origin',
        });

        if (resp.status === 401 && !path.includes('/auth/refresh') && !path.includes('/auth/login')) {
            const refreshed = await _tryRefresh();
            if (refreshed) {
                if (headers['X-CSRF-Token']) {
                    headers['X-CSRF-Token'] = _csrfToken();
                }
                const retry = await fetch(path, {
                    method,
                    headers,
                    body,
                    credentials: 'same-origin',
                });
                return _handleResponse(retry);
            }
            sessionStorage.removeItem(Config.auth.sessionStorageKey);
            window.location.hash = '#/login';
            throw new Error('Session expired');
        }

        return _handleResponse(resp);
    }

    async function _handleResponse(resp) {
        if (resp.ok) Auth.touchKeyCache();
        if (!resp.ok) {
            let detail = `HTTP ${resp.status}`;
            try {
                const data = await resp.json();
                detail = data.error?.message || data.detail || detail;
            } catch {}
            const err = new Error(detail);
            err.status = resp.status;
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
        refreshTokens: _tryRefresh,

        streamGet: (path, headers = {}) =>
            fetch(path, { method: 'GET', headers, credentials: 'same-origin' }),

        streamPatch: (path, body, headers = {}) => {
            headers['X-CSRF-Token'] = _csrfToken();
            return fetch(path, { method: 'PATCH', headers, body, credentials: 'same-origin' });
        },
    };
})();
