/**
 * OPAQUE module loader — singleton that initialises the @serenity-kit/opaque WASM once
 * and caches it for the lifetime of the page.  Used by Auth and StepUp.
 */
let _opaqueModule = null;
// Kick off WASM load immediately on script parse so it's warm by the time
// the user reaches the login form. Prevents autofill confusion from a
// visible load blip triggered on first password-field focus.
const _opaqueReady = (async () => {
    const mod = await import('/js/lib/opaque.js'); // NOSONAR — web-root-relative URL, not a filesystem path
    await mod.ready;
    _opaqueModule = mod;
    return mod;
})();

async function _loadOpaque() {
    if (_opaqueModule) return _opaqueModule;
    return _opaqueReady;
}


/**
 * tusShare — Authentication UI and session management.
 *
 * Key wrapping model:
 *   Login:           password → KEK → unwrap wrappedMasterKey → masterKey
 *   Key prompt:      same as login (page refresh, session still valid)
 *   Password change: old KEK unwraps → new KEK re-wraps → server stores new blob
 *   Recovery:        recovery key → unwrap recoveryKeyWrapped → masterKey
 */
const Auth = (() => {
    let _currentUser = null;
    let _masterKeyObj = null;
    // Asymmetric keys in memory: { x25519PrivateKey: CryptoKey, mlkem768SecretKey: Uint8Array }
    // Set after login + key derivation. Null until keys are set up.
    // Failed unlock attempts — reset on success, triggers auto-logout at the limit.
    let _unlockFailures = 0;
    const _UNLOCK_MAX_FAILURES = 3;
    let _asymmetricKeys = null;

    function getCurrentUser() {
        return _currentUser;
    }

    function getMasterKeyObj() {
        return _masterKeyObj;
    }

    function getAsymmetricKeys() {
        return _asymmetricKeys;
    }

    // ------------------------------------------------------------------
    // Session key caching (grace period)
    //
    // The master key is exported to raw bytes and stored alongside the salt in
    // sessionStorage with a timestamp. On page reload, if the timestamp is within
    // the grace period (Config.auth.keyGracePeriodMs), the key is re-imported
    // without prompting the user for their password again. The timestamp rolls
    // forward on every successful restore so the window stays open during an
    // active session (e.g. long-running uploads). sessionStorage is cleared when
    // the tab closes, and we clear it explicitly on logout.
    //
    // Security trade-off (T1-H1): storing the master key in sessionStorage means
    // an XSS vulnerability with an active session yields immediate full key
    // compromise. This is an accepted trade-off: the OPFS download pipeline
    // requires access to raw key bytes during the session, and WebAuthn PRF
    // binding (which would eliminate the sessionStorage exposure) is deferred.
    // Mitigations in place: strict CSP, all innerHTML paths removed, SRI on all
    // scripts, sessionStorage scoped to tab lifetime.
    // ------------------------------------------------------------------

    async function _saveSessionKeyData(key, salt) {
        try {
            const keyB64url = await Crypto.exportKeyToBase64url(key);
            sessionStorage.setItem(Config.auth.sessionStorageKey, JSON.stringify({
                salt,
                keyB64url,
                cachedAt: Date.now(),
            }));
        } catch (err) {
            console.warn('[tusShare] Failed to cache master key:', err);
            // Fall back to storing salt only so the key prompt still works
            sessionStorage.setItem(Config.auth.sessionStorageKey, JSON.stringify({ salt }));
        }
    }

    async function _restoreCachedMasterKey() {
        try {
            const stored = JSON.parse(sessionStorage.getItem(Config.auth.sessionStorageKey) || '{}');
            if (!stored.keyB64url || !stored.cachedAt) return false;
            if (Date.now() - stored.cachedAt > Config.auth.keyGracePeriodMs) return false;
            _masterKeyObj = await Crypto.importKeyFromBase64url(stored.keyB64url);
            // Roll the window forward on restore
            stored.cachedAt = Date.now();
            sessionStorage.setItem(Config.auth.sessionStorageKey, JSON.stringify(stored));
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Update the cached-at timestamp so the grace period rolls forward on activity.
     * Called by Api._handleResponse and the upload loop on each successful request.
     * No-ops gracefully if there's no cached key.
     */
    function touchKeyCache() {
        try {
            const raw = sessionStorage.getItem(Config.auth.sessionStorageKey);
            if (!raw) return;
            const stored = JSON.parse(raw);
            if (!stored.keyB64url) return;
            stored.cachedAt = Date.now();
            sessionStorage.setItem(Config.auth.sessionStorageKey, JSON.stringify(stored));
        } catch {
            // Non-critical — silently ignore
        }
    }

    // ------------------------------------------------------------------
    // OPAQUE login helper — two-round-trip OPAQUE exchange.
    // Returns { data, exportKey } where data is the /login/finish JSON response.
    // is_public_device is forwarded to the server so it can issue a shorter token.
    // ------------------------------------------------------------------

    async function _runOpaqueLogin(username, password, isPublicDevice = false) {
        const opaque = await _loadOpaque();

        // Round 1: client generates blinded credential request
        const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });

        const round1 = await Api.post(`${Config.app.apiPrefix}/auth/opaque/login/start`, {
            username,
            client_login_start: startLoginRequest,
        });

        // Use the canonical username returned by the server (original casing from
        // registration) as the OPAQUE identifier.  This ensures case-insensitive
        // login works: a user registered as "GroupFolder" can log in as "groupfolder".
        const canonicalUsername = round1.username || username;

        // Client processes server OPRF response and generates KE3 MAC
        const loginResult = opaque.client.finishLogin({
            clientLoginState,
            loginResponse: round1.login_response,
            password,
            identifiers: { client: canonicalUsername, server: 'tusshare' },
        });
        if (!loginResult) throw new Error('Invalid credentials');

        const { finishLoginRequest, exportKey } = loginResult;

        // Round 2: server verifies MAC, issues auth cookies
        const data = await Api.post(`${Config.app.apiPrefix}/auth/opaque/login/finish`, {
            username: canonicalUsername,
            session_id: round1.session_id,
            client_login_finish: finishLoginRequest,
            is_public_device: isPublicDevice,
        });

        return { data, exportKey };
    }

    // ------------------------------------------------------------------
    // Login
    // ------------------------------------------------------------------

    let _loginRenderGen = 0;

    async function renderLogin(container) {
        const gen = ++_loginRenderGen;
        while (container.firstChild) container.firstChild.remove();

        // Fetch active IdP providers (non-blocking — show form even if this fails)
        let idpProviders = [];
        try {
            const idpData = await Api.get(`${Config.app.apiPrefix}/auth/idp/providers`);
            idpProviders = idpData.providers || [];
        } catch { /* server may not have any providers */ }

        // Abort if a newer renderLogin call has taken over (race between hashchange + direct call)
        if (gen !== _loginRenderGen) return;
        while (container.firstChild) container.firstChild.remove();

        const form = Utils.el('form', { className: 'auth-form', onSubmit: _handleLogin }, [
            Utils.el('h1', { textContent: Config.app.name }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'username', textContent: 'Username' }),
                Utils.el('input', {
                    type: 'text', id: 'username', name: 'username',
                    autocomplete: 'username', required: 'true',
                    maxlength: String(Config.auth.usernameMaxLength),
                    pattern: Config.auth.usernamePattern,
                    title: 'Letters, digits, . _ + - @',
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'password', textContent: 'Password' }),
                Utils.el('input', {
                    type: 'password', id: 'password', name: 'password',
                    autocomplete: 'current-password', required: 'true',
                    maxlength: String(Config.auth.passwordMaxLength),
                }),
            ]),
            Utils.el('div', { className: 'form-group public-device-row' }, [
                Utils.el('label', { className: 'checkbox-label' }, [
                    Utils.el('input', { type: 'checkbox', id: 'public-device', name: 'public-device' }),
                    Utils.el('span', { textContent: 'Public / shared device' }),
                ]),
            ]),
            Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Log In' }),
            Utils.el('div', { style: 'text-align:center;margin-top:12px' }, [
                Utils.el('a', {
                    href: '#',
                    className: 'text-muted',
                    textContent: 'Forgot password?',
                    onClick: (ev) => {
                        ev.preventDefault();
                        const prefill = document.getElementById('username')?.value?.trim() || '';
                        renderForgotPassword(container, prefill);
                    },
                }),
            ]),
            Utils.el('p', { id: 'login-status', className: 'auth-status' }),
        ]);
        container.appendChild(form);

        // Render IdP provider buttons if any are configured
        if (idpProviders.length > 0) {
            const divider = Utils.el('div', { className: 'idp-divider' }, [
                Utils.el('span', { textContent: 'or' }),
            ]);
            form.appendChild(divider);

            for (const provider of idpProviders) {
                if (provider.provider_type === 'oidc') {
                    const oidcBtn = Utils.el('button', {
                        type: 'button',
                        className: 'btn btn-secondary btn-full idp-btn',
                        textContent: `Sign in with ${provider.name}`,
                        onClick: () => _startOidcLogin(provider.id, provider.name),
                    });
                    oidcBtn.dataset.providerId = provider.id;
                    form.appendChild(oidcBtn);
                } else if (provider.provider_type === 'ldap') {
                    form.appendChild(Utils.el('button', {
                        type: 'button',
                        className: 'btn btn-secondary btn-full idp-btn',
                        textContent: `Sign in via ${provider.name}`,
                        onClick: () => _renderLdapLoginForm(container, provider),
                    }));
                }
            }
        }
    }

    async function _startOidcLogin(providerId, providerName) {
        try {
            const data = await Api.get(
                `${Config.app.apiPrefix}/auth/oidc/${providerId}/begin`,
            );
            if (data.redirect_url && /^https:\/\//i.test(data.redirect_url)) {
                globalThis.location.href = data.redirect_url;
            }
        } catch (err) {
            Utils.showToast(`Failed to start ${providerName} login: ${err.message}`, 'error');
        }
    }

    function _renderLdapLoginForm(container, provider) {
        while (container.firstChild) container.firstChild.remove();
        const form = Utils.el('form', {
            className: 'auth-form',
            onSubmit: (e) => _handleLdapLogin(e, provider, container),
        }, [
            Utils.el('h1', { textContent: provider.name }),
            Utils.el('p', { className: 'text-muted', textContent: 'Sign in with your directory credentials.' }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'ldap-username', textContent: 'Username' }),
                Utils.el('input', {
                    type: 'text', id: 'ldap-username', name: 'username',
                    autocomplete: 'username', required: 'true',
                    maxlength: '64',
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'ldap-password', textContent: 'Password' }),
                Utils.el('input', {
                    type: 'password', id: 'ldap-password', name: 'password',
                    autocomplete: 'current-password', required: 'true',
                    maxlength: String(Config.auth.passwordMaxLength),
                }),
            ]),
            Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Sign In' }),
            Utils.el('div', { style: 'text-align:center;margin-top:12px' }, [
                Utils.el('a', {
                    href: '#',
                    className: 'text-muted',
                    textContent: '← Back to login',
                    onClick: (ev) => { ev.preventDefault(); renderLogin(container); },
                }),
            ]),
            Utils.el('p', { id: 'ldap-status', className: 'auth-status' }),
        ]);
        container.appendChild(form);
        document.getElementById('ldap-username')?.focus();
    }

    async function _handleLdapLogin(e, provider, container) {
        e.preventDefault();
        const username = document.getElementById('ldap-username').value.trim();
        const password = document.getElementById('ldap-password').value;
        const status = document.getElementById('ldap-status');
        const btn = e.target.querySelector('button[type="submit"]');

        btn.disabled = true;
        if (status) status.textContent = 'Authenticating…';

        try {
            const data = await Api.post(`${Config.app.apiPrefix}/auth/ldap/login`, {
                provider_id: provider.id,
                username,
                password,
            });

            if (data.mfa_required) {
                if (status) status.textContent = '';
                btn.disabled = false;
                _renderMfaChallenge(container, data, null, username, false);
                return;
            }

            await _finishIdpSession(data, container);
        } catch (err) {
            if (status) status.textContent = err.message || 'Authentication failed.';
            btn.disabled = false;
        }
    }

    // Finalise an IdP session (LDAP or OIDC) — no KEK derivation needed.
    async function _finishIdpSession(data, _container) {
        _currentUser = data.user;
        if (_currentUser.is_admin) {
            globalThis.location.hash = '#/admin';
            return;
        }
        if (data.mfa_enrollment_required) {
            globalThis.location.hash = '#/mfa';
            return;
        }
        // IdP users have no personal encryption key (wrapped_master_key is null).
        // Navigate directly to files; personal file upload will be disabled client-side.
        globalThis.location.hash = '#/files';
    }

    // Called by app.js when ?mfa_pending=<token> is detected in the URL after OIDC callback.
    function renderOidcMfaChallenge(container, pendingToken, methods) {
        const mfaData = { pending_token: pendingToken, methods, reset_required: false };
        _renderMfaChallenge(container, mfaData, null, null, false);
    }

    async function _handleLogin(e) {
        e.preventDefault();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const isPublicDevice = document.getElementById('public-device')?.checked || false;
        const status = document.getElementById('login-status');
        const btn = e.target.querySelector('button[type="submit"]');

        btn.disabled = true;
        status.textContent = 'Authenticating…';

        try {
            status.textContent = 'Running zero-knowledge auth…';
            const { data, exportKey } = await _runOpaqueLogin(username, password, isPublicDevice);

            // MFA gate — server returns pending_token instead of user+cookies
            if (data.mfa_required) {
                status.textContent = '';
                btn.disabled = false;
                const container = e.target.closest('#app') || document.getElementById('app');
                _renderMfaChallenge(container, data, exportKey, username, isPublicDevice);
                return;
            }

            _currentUser = data.user;

            // Admin accounts have no encryption keys — go straight to the admin panel
            if (data.user.is_admin) {
                status.textContent = '';
                startIdentityWatch();
                globalThis.location.hash = '#/admin';
                return;
            }

            status.textContent = 'Deriving encryption key…';
            const kek = await Crypto.deriveOpaqueKEK(exportKey);


            _masterKeyObj = await Crypto.unwrapMasterKey(
                data.user.wrapped_master_key,
                data.user.wrapped_master_key_iv,
                kek
            );

            // Public device mode: key material lives in sessionStorage only (already the
            // case — sessionStorage is cleared on tab close).  We also store a flag so the
            // app shell can show the dismissable public-device banner.
            if (isPublicDevice) {
                sessionStorage.setItem(Config.publicDevice.sessionStorageKey, '1');
            } else {
                sessionStorage.removeItem(Config.publicDevice.sessionStorageKey);
            }

            await _saveSessionKeyData(_masterKeyObj, null);

            // Set up asymmetric PQ keys (generate + register if first login),
            // then process pending team operations once private keys are in memory.
            _setupAsymmetricKeys(data.user, _masterKeyObj)
                .then(() => Teams.processPendingTeamOperations().catch((err) => {
                    console.warn('Pending team operations check failed:', err.message);
                }))
                .catch((err) => {
                    console.error('Asymmetric key setup failed:', err);
                    Utils.showToast('Sharing keys could not be set up. User shares will not work this session.', 'warning');
                });

            status.textContent = '';
            startIdentityWatch();
            if (data.mfa_enrollment_required) {
                globalThis.location.hash = '#/mfa';
            } else {
                const pendingJoin = sessionStorage.getItem('pendingJoinHash');
                if (pendingJoin) {
                    sessionStorage.removeItem('pendingJoinHash');
                    globalThis.location.hash = pendingJoin;
                } else {
                    globalThis.location.hash = '#/files';
                }
            }
        } catch (err) {
            status.textContent = err.message;
            btn.disabled = false;
        }
    }

    // ------------------------------------------------------------------
    // Key prompt (page refresh — session valid but masterKey lost)
    // ------------------------------------------------------------------

    function renderKeyPrompt(container) {
        while (container.firstChild) container.firstChild.remove();

        const passwordForm = Utils.el('form', { className: 'auth-form', onSubmit: _handleKeyDerive }, [
            Utils.el('h2', { textContent: 'Encryption Key Required' }),
            Utils.el('p', { className: 'text-muted', textContent: 'Enter your password to unlock your encryption key.' }),
            Utils.el('div', { id: 'webauthn-unlock-area' }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'key-password', textContent: 'Password' }),
                Utils.el('input', {
                    type: 'password', id: 'key-password', name: 'password',
                    autocomplete: 'current-password', required: 'true',
                }),
            ]),
            Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Unlock' }),
            Utils.el('div', { style: 'text-align:center;margin-top:12px' }, [
                Utils.el('a', {
                    href: '#',
                    className: 'text-muted',
                    textContent: 'Use recovery key instead',
                    onClick: (ev) => {
                        ev.preventDefault();
                        renderRecoveryPrompt(container);
                    },
                }),
            ]),
            Utils.el('p', { id: 'key-status', className: 'auth-status' }),
        ]);
        container.appendChild(passwordForm);

        // Async: if sessionStorage key is present and user has WebAuthn, show unlock button
        _tryInjectWebAuthnUnlock(container);
    }

    async function _tryInjectWebAuthnUnlock(container) {
        try {
            const stored = JSON.parse(sessionStorage.getItem(Config.auth.sessionStorageKey) || '{}');
            if (!stored.keyB64url) return;

            const data = await Api.get(`${Config.app.apiPrefix}/auth/mfa/credentials`);
            const hasWebAuthn = (data.credentials || []).some(c => c.method === 'webauthn');
            if (!hasWebAuthn) return;

            const area = document.getElementById('webauthn-unlock-area');
            if (!area) return;

            const btn = Utils.el('button', {
                type: 'button', className: 'btn btn-secondary btn-full',
                style: 'margin-bottom:16px',
                textContent: 'Unlock with Security Key / Biometrics',
                onClick: () => _handleWebAuthnUnlock(container, stored.keyB64url),
            });
            area.appendChild(btn);
            area.appendChild(Utils.el('p', {
                className: 'text-muted', style: 'text-align:center;margin-bottom:8px;font-size:0.85em',
                textContent: '— or enter password below —',
            }));
        } catch {
            // Non-critical — password form is always shown as fallback
        }
    }

    async function _handleWebAuthnUnlock(container, keyB64url) {
        const status = document.getElementById('key-status');
        if (status) status.textContent = 'Waiting for security key…';
        try {
            const beginData = await Api.post(`${Config.app.apiPrefix}/auth/mfa/unlock/webauthn/begin`);
            const assertion = await navigator.credentials.get({
                publicKey: _webAuthnOptionsFromServer(beginData.options),
            });
            await Api.post(`${Config.app.apiPrefix}/auth/mfa/unlock/webauthn/finish`, {
                challenge_id: beginData.challenge_id,
                assertion: _serializeAssertion(assertion),
            });

            // Server verified — restore key from sessionStorage bypassing timestamp check
            _masterKeyObj = await Crypto.importKeyFromBase64url(keyB64url);
            _unlockFailures = 0;
            // Refresh cachedAt so the window stays open
            const newStored = JSON.parse(sessionStorage.getItem(Config.auth.sessionStorageKey) || '{}');
            newStored.cachedAt = Date.now();
            sessionStorage.setItem(Config.auth.sessionStorageKey, JSON.stringify(newStored));

            _setupAsymmetricKeys(_currentUser, _masterKeyObj)
                .then(() => Teams.processPendingTeamOperations().catch(() => {}))
                .catch(() => {});
            startIdentityWatch();

            const currentHash = globalThis.location.hash;
            if (!currentHash || currentHash === '#/' || currentHash === '#/login') {
                globalThis.location.hash = '#/files';
            } else {
                globalThis.dispatchEvent(new HashChangeEvent('hashchange'));
            }
        } catch (err) {
            if (status) status.textContent = err.message || 'Security key verification failed.';
        }
    }

    async function _handleKeyDerive(e) {
        e.preventDefault();
        const password = document.getElementById('key-password').value;
        const status = document.getElementById('key-status');
        const btn = e.target.querySelector('button[type="submit"]');

        btn.disabled = true;
        status.textContent = 'Deriving encryption key...';

        try {
            // Re-run the full OPAQUE login challenge to get a fresh export_key → KEK.
            // If MFA is enrolled, the server returns {mfa_required:true} — we already
            // have a valid session so we ignore the pending_token and just use exportKey.
            status.textContent = 'Running zero-knowledge auth…';
            const { data, exportKey } = await _runOpaqueLogin(_currentUser.username, password);
            if (!data.mfa_required) {
                _currentUser = data.user;
            }
            const kek = await Crypto.deriveOpaqueKEK(exportKey);

            _masterKeyObj = await Crypto.unwrapMasterKey(
                _currentUser.wrapped_master_key,
                _currentUser.wrapped_master_key_iv,
                kek
            );

            _unlockFailures = 0;
            await _saveSessionKeyData(_masterKeyObj, null);

            _setupAsymmetricKeys(_currentUser, _masterKeyObj)
                .then(() => Teams.processPendingTeamOperations().catch((err) => {
                    console.warn('Pending team operations check failed:', err.message);
                }))
                .catch((err) => {
                    console.error('Asymmetric key setup failed:', err);
                    Utils.showToast('Sharing keys could not be set up. User shares will not work this session.', 'warning');
                });

            status.textContent = '';
            // Start identity watch so SSE-delivered deactivation/revocation events
            // are received on this tab (same as the normal login path in app.js).
            startIdentityWatch();
            // After unlock, navigate to the current hash — but if the hash is #/login
            // (which is where the unlock prompt is rendered), redirect to #/files instead
            // so the user isn't sent back to the login form.
            const currentHash = globalThis.location.hash;
            if (!currentHash || currentHash === '#/' || currentHash === '#/login') {
                globalThis.location.hash = '#/files';
            } else {
                globalThis.dispatchEvent(new HashChangeEvent('hashchange'));
            }
        } catch {
            _unlockFailures++;
            if (_unlockFailures >= _UNLOCK_MAX_FAILURES) {
                // Too many wrong attempts — force a full logout so the user must
                // re-authenticate from the login screen.
                logout();
                return;
            }
            const remaining = _UNLOCK_MAX_FAILURES - _unlockFailures;
            status.textContent = `Incorrect password. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`;
            btn.disabled = false;
        }
    }

    // ------------------------------------------------------------------
    // Recovery key unlock
    // ------------------------------------------------------------------

    function renderRecoveryPrompt(container) {
        while (container.firstChild) container.firstChild.remove();

        const form = Utils.el('form', { className: 'auth-form', onSubmit: _handleRecoveryUnlock }, [
            Utils.el('h2', { textContent: 'Recovery Key Unlock' }),
            Utils.el('p', { className: 'text-muted', textContent: 'Enter the recovery key you saved when your account was created.' }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'recovery-key', textContent: 'Recovery Key' }),
                Utils.el('input', {
                    type: 'text', id: 'recovery-key', name: 'recovery-key',
                    autocomplete: 'off', required: 'true',
                    style: 'font-family:var(--font-family-mono)',
                }),
                Utils.el('p', { className: 'text-muted-sm', textContent: 'Long hex string from your recovery key file, saved when your account was created.' }),
            ]),
            Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Unlock' }),
            Utils.el('div', { style: 'text-align:center;margin-top:12px' }, [
                Utils.el('a', {
                    href: '#',
                    className: 'text-muted',
                    textContent: 'Use password instead',
                    onClick: (ev) => {
                        ev.preventDefault();
                        renderKeyPrompt(container);
                    },
                }),
            ]),
            Utils.el('p', { id: 'recovery-status', className: 'auth-status' }),
        ]);
        container.appendChild(form);
    }

    async function _handleRecoveryUnlock(e) {
        e.preventDefault();
        const recoveryKeyString = document.getElementById('recovery-key').value.trim();
        const status = document.getElementById('recovery-status');
        const btn = e.target.querySelector('button[type="submit"]');

        btn.disabled = true;
        status.textContent = 'Unlocking...';

        try {
            if (!_currentUser.recovery_key_wrapped || !_currentUser.recovery_key_iv) {
                throw new Error('No recovery key configured for this account.');
            }

            const recoveryKey = await Crypto.importRecoveryKey(recoveryKeyString);
            _masterKeyObj = await Crypto.unwrapMasterKey(
                _currentUser.recovery_key_wrapped,
                _currentUser.recovery_key_iv,
                recoveryKey
            );

            await _saveSessionKeyData(_masterKeyObj, null);

            // Set up asymmetric keys so share operations work this session
            _setupAsymmetricKeys(_currentUser, _masterKeyObj)
                .then(() => Teams.processPendingTeamOperations().catch((err) => {
                    console.warn('Pending team operations check failed:', err.message);
                }))
                .catch((err) => {
                    console.error('Asymmetric key setup failed:', err);
                    Utils.showToast('Sharing keys could not be set up. User shares will not work this session.', 'warning');
                });

            status.textContent = '';
            // Re-dispatch hashchange so the router navigates to whatever hash is
            // currently set — preserves deep links like #/files/<id> after a refresh.
            globalThis.dispatchEvent(new HashChangeEvent('hashchange'));
        } catch {
            status.textContent = 'Invalid recovery key. Please try again.';
            btn.disabled = false;
        }
    }

    // ------------------------------------------------------------------
    // Asymmetric key setup (Phase 5b — runs silently after login)
    // ------------------------------------------------------------------

    /**
     * Set up the user's hybrid X25519 + ML-KEM-768 asymmetric key pair.
     *
     * If the user already has keys registered: unwrap the private keys using
     * the masterKey and store in _asymmetricKeys.
     *
     * If no keys exist yet: generate a new key pair, wrap private keys with
     * masterKey, POST to /api/v1/auth/me/asymmetric-keys to register them,
     * then store in _asymmetricKeys.
     *
     * Called in background after login — never blocks the UI.
     */
    async function _setupAsymmetricKeys(user, masterKey) {
        if (!masterKey) return;

        if (user.x25519_private_wrapped && user.mlkem768_private_wrapped && user.asymmetric_key_iv) {
            // Keys already registered — unwrap private keys into memory
            const unwrapped = await Crypto.unwrapAsymmetricPrivateKeys(
                user.x25519_private_wrapped,
                user.mlkem768_private_wrapped,
                user.asymmetric_key_iv,
                masterKey,
                user.x25519_public_key
            );
            _asymmetricKeys = unwrapped;

            // T1-L3: silently re-wrap with fresh per-key IVs if legacy single-IV format detected.
            // Legacy format reused the same (masterKey, IV) pair for both private keys — catastrophic
            // under AES-GCM (reveals plaintext XOR). Re-upload is done once on next login.
            if (unwrapped.isLegacyIv) {
                try {
                    const { x25519PrivWrappedB64, mlkem768PrivWrappedB64, asymKeyIvB64 } =
                        await Crypto.wrapAsymmetricPrivateKeys(
                            { privateKey: unwrapped.x25519PrivateKey },
                            { secretKey: unwrapped.mlkem768SecretKey },
                            masterKey
                        );
                    await Api.post(`${Config.app.apiPrefix}/auth/me/asymmetric-keys`, {
                        x25519_public_key:        user.x25519_public_key,
                        mlkem768_public_key:      user.mlkem768_public_key,
                        x25519_private_wrapped:   x25519PrivWrappedB64,
                        mlkem768_private_wrapped: mlkem768PrivWrappedB64,
                        asymmetric_key_iv:        asymKeyIvB64,
                    });
                    _currentUser = { ..._currentUser,
                        x25519_private_wrapped:   x25519PrivWrappedB64,
                        mlkem768_private_wrapped: mlkem768PrivWrappedB64,
                        asymmetric_key_iv:        asymKeyIvB64,
                    };
                } catch (e) {
                    console.warn('Legacy IV re-wrap failed (will retry next login):', e);
                }
            }

            await _verifyAsymmetricKeyConsistency(user);
            return;
        }

        // No keys yet — generate, wrap, and register
        const { x25519KeyPair, mlkem768KeyPair } = await Crypto.generateAsymmetricKeyPair();
        const { x25519PublicKeyB64, mlkem768PublicKeyB64 } =
            await Crypto.exportAsymmetricPublicKeys(x25519KeyPair, mlkem768KeyPair);
        const { x25519PrivWrappedB64, mlkem768PrivWrappedB64, asymKeyIvB64 } =
            await Crypto.wrapAsymmetricPrivateKeys(x25519KeyPair, mlkem768KeyPair, masterKey);

        await Api.post(`${Config.app.apiPrefix}/auth/me/asymmetric-keys`, {
            x25519_public_key: x25519PublicKeyB64,
            mlkem768_public_key: mlkem768PublicKeyB64,
            x25519_private_wrapped: x25519PrivWrappedB64,
            mlkem768_private_wrapped: mlkem768PrivWrappedB64,
            asymmetric_key_iv: asymKeyIvB64,
        });

        // Update _currentUser with the new key material so it's available this session
        _currentUser = { ..._currentUser,
            x25519_public_key: x25519PublicKeyB64,
            mlkem768_public_key: mlkem768PublicKeyB64,
            x25519_private_wrapped: x25519PrivWrappedB64,
            mlkem768_private_wrapped: mlkem768PrivWrappedB64,
            asymmetric_key_iv: asymKeyIvB64,
        };

        // Store private keys in memory
        _asymmetricKeys = {
            x25519PrivateKey: x25519KeyPair.privateKey,
            mlkem768SecretKey: mlkem768KeyPair.secretKey,
        };
    }

    /**
     * Verify that the in-memory private keys correspond to the stored public keys
     * by doing a KEM roundtrip. Logs a console.error if there is a mismatch.
     */
    async function _verifyAsymmetricKeyConsistency(user) {
        if (!_asymmetricKeys || !user.x25519_public_key || !user.mlkem768_public_key) return;
        try {
            const testKey = await Crypto.generateFileKey();
            const enc = await Crypto.encapsulateFileKeyForUser(
                testKey, user.x25519_public_key, user.mlkem768_public_key
            );
            await Crypto.decapsulateFileKeyFromUser(
                enc.wrappedFileKeyB64, enc.keyIvB64,
                enc.ephemeralX25519PubB64, enc.kemCiphertextB64,
                _asymmetricKeys.x25519PrivateKey, _asymmetricKeys.mlkem768SecretKey
            );
        } catch (e) {
            const msg = `Key consistency check failed (${e.message}) — team operations may fail this session.`;
            console.error('[tusShare] ASYMMETRIC KEY MISMATCH:', e.message);
            Utils.showToast(msg, 'error');
        }
    }

    // ------------------------------------------------------------------
    // Registration via invite link
    // ------------------------------------------------------------------

    /**
     * Render the registration form for a user arriving via an invite link.
     *
     * Flow:
     *   1. Validate token against the server (fast check before showing the form).
     *   2. User picks username + password.
     *   3. Client generates all crypto material (salt, masterKey, asymmetric keys).
     *   4. POST /auth/register — server consumes invite, creates user, sets cookies.
     *   5. Store masterKey in session, show recovery key display.
     *   6. User confirms recovery key → navigate to #/files.
     */
    async function renderRegisterPage(container, token) {
        while (container.firstChild) container.firstChild.remove();

        // Step 1: validate token before showing form
        const checking = Utils.el('div', { className: 'auth-form' }, [
            Utils.el('p', { className: 'text-muted', textContent: 'Validating invite…' }),
        ]);
        container.appendChild(checking);

        try {
            await Api.get(`${Config.app.apiPrefix}/auth/invite/${encodeURIComponent(token)}`);
        } catch {
            while (container.firstChild) container.firstChild.remove();
            container.appendChild(Utils.el('div', { className: 'auth-form' }, [
                Utils.el('h2', { textContent: 'Invalid Invite' }),
                Utils.el('p', { className: 'auth-status', textContent: 'This invite link is invalid, expired, or has already been used.' }),
                Utils.el('p', {}, [
                    Utils.el('a', { href: '/#/login', textContent: 'Back to login' }),
                ]),
            ]));
            return;
        }

        // Step 2: show registration form
        while (container.firstChild) container.firstChild.remove();

        const form = Utils.el('form', { className: 'auth-form', onSubmit: (e) => _handleRegister(e, token, container) }, [
            Utils.el('h1', { textContent: Config.app.name }),
            Utils.el('h2', { textContent: 'Create Account' }),
            Utils.el('p', { className: 'text-muted', textContent: 'Choose a username and password for your new account.' }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'reg-username', textContent: 'Username' }),
                Utils.el('input', {
                    type: 'text', id: 'reg-username', name: 'username',
                    autocomplete: 'username', required: 'true',
                    maxlength: String(Config.auth.usernameMaxLength),
                    pattern: Config.auth.usernamePattern,
                    title: 'Letters, digits, . _ + - @',
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'reg-password', textContent: 'Password' }),
                Utils.el('input', {
                    type: 'password', id: 'reg-password', name: 'password',
                    autocomplete: 'new-password', required: 'true',
                    minlength: '8',
                    maxlength: String(Config.auth.passwordMaxLength),
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'reg-password2', textContent: 'Confirm Password' }),
                Utils.el('input', {
                    type: 'password', id: 'reg-password2', name: 'password2',
                    autocomplete: 'new-password', required: 'true',
                    maxlength: String(Config.auth.passwordMaxLength),
                }),
            ]),
            Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Create Account' }),
            Utils.el('p', { id: 'reg-status', className: 'auth-status' }),
        ]);
        container.appendChild(form);
        Utils.attachPasswordStrength(document.getElementById('reg-password'));
    }

    async function _handleRegister(e, token, container) {
        e.preventDefault();
        const username  = document.getElementById('reg-username').value.trim();
        const password  = document.getElementById('reg-password').value;
        const password2 = document.getElementById('reg-password2').value;
        const status    = document.getElementById('reg-status');
        const btn       = e.target.querySelector('button[type="submit"]');

        if (password !== password2) {
            status.textContent = 'Passwords do not match.';
            return;
        }

        btn.disabled = true;
        status.textContent = 'Starting OPAQUE registration…';

        try {
            // OPAQUE registration round 1 — client generates blinded OPRF input
            const opaque = await _loadOpaque();
            const { clientRegistrationState, registrationRequest } =
                opaque.client.startRegistration({ password });

            const round1 = await Api.post(`${Config.app.apiPrefix}/auth/opaque/register/start`, {
                token,
                username,
                client_registration_request: registrationRequest,
            });

            // Client processes server OPRF response and derives export_key
            status.textContent = 'Generating encryption keys…';
            const { registrationRecord, exportKey } = opaque.client.finishRegistration({
                clientRegistrationState,
                registrationResponse: round1.registration_response,
                password,
                identifiers: { client: username, server: 'tusshare' },
            });

            // Derive KEK from OPAQUE export_key (never sent to server)
            const kek = await Crypto.deriveOpaqueKEK(exportKey);

            // Generate and wrap master key
            const masterKey = await Crypto.generateMasterKey();
            const { wrappedKeyB64: wrappedMasterKeyB64, ivB64: wrappedMasterKeyIvB64 } =
                await Crypto.wrapMasterKey(masterKey, kek);

            // Generate recovery key
            const { recoveryKey, recoveryKeyString } = await Crypto.generateRecoveryKey();
            const { wrappedKeyB64: recoveryWrappedB64, ivB64: recoveryIvB64 } =
                await Crypto.wrapMasterKey(masterKey, recoveryKey);
            const recoveryKeyHash = await Crypto.hashRecoveryKey(recoveryKeyString);

            // Generate asymmetric key pair
            status.textContent = 'Generating sharing keys…';
            const { x25519KeyPair, mlkem768KeyPair } = await Crypto.generateAsymmetricKeyPair();
            const { x25519PublicKeyB64, mlkem768PublicKeyB64 } =
                await Crypto.exportAsymmetricPublicKeys(x25519KeyPair, mlkem768KeyPair);
            const { x25519PrivWrappedB64, mlkem768PrivWrappedB64, asymKeyIvB64 } =
                await Crypto.wrapAsymmetricPrivateKeys(x25519KeyPair, mlkem768KeyPair, masterKey);

            // OPAQUE registration round 2 — server stores record and creates user
            status.textContent = 'Creating account…';
            const data = await Api.post(`${Config.app.apiPrefix}/auth/opaque/register/finish`, {
                token,
                username,
                client_registration_record: registrationRecord,
                wrapped_master_key:    wrappedMasterKeyB64,
                wrapped_master_key_iv: wrappedMasterKeyIvB64,
                recovery_key_wrapped:  recoveryWrappedB64,
                recovery_key_iv:       recoveryIvB64,
                recovery_key_hash:     recoveryKeyHash,
                x25519_public_key:        x25519PublicKeyB64,
                mlkem768_public_key:      mlkem768PublicKeyB64,
                x25519_private_wrapped:   x25519PrivWrappedB64,
                mlkem768_private_wrapped: mlkem768PrivWrappedB64,
                asymmetric_key_iv:        asymKeyIvB64,
            });

            // Session setup
            _currentUser   = data.user;
            _masterKeyObj  = masterKey;
            _asymmetricKeys = {
                x25519PrivateKey:  x25519KeyPair.privateKey,
                mlkem768SecretKey: mlkem768KeyPair.secretKey,
            };
            await _saveSessionKeyData(_masterKeyObj, null);

            // Show recovery key — continue to MFA enrollment if required, otherwise files
            const _regDest = data.mfa_enrollment_required ? '/#/mfa' : '/#/files';
            renderRecoveryKeyDisplay(container, recoveryKeyString, _regDest);

        } catch (err) {
            status.textContent = err.message;
            btn.disabled = false;
        }
    }

    // ------------------------------------------------------------------
    // First-run bootstrap (admin account creation)
    // ------------------------------------------------------------------

    function renderBootstrap(container) {
        while (container.firstChild) container.firstChild.remove();

        const form = Utils.el('form', { className: 'auth-form', onSubmit: (e) => _handleBootstrap(e, container) }, [
            Utils.el('h1', { textContent: Config.app.name }),
            Utils.el('h2', { textContent: 'First-Run Setup' }),
            Utils.el('p', { className: 'text-muted', textContent:
                'No admin account exists yet. Enter the bootstrap token from the server logs and choose credentials for the initial admin account.' }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'bs-token', textContent: 'Bootstrap Token' }),
                Utils.el('input', {
                    type: 'text', id: 'bs-token', name: 'token',
                    autocomplete: 'off', required: 'true',
                    style: 'font-family:var(--font-family-mono)',
                    placeholder: 'Paste the token printed in the server log',
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'bs-username', textContent: 'Admin Username' }),
                Utils.el('input', {
                    type: 'text', id: 'bs-username', name: 'username',
                    autocomplete: 'username', required: 'true',
                    maxlength: String(Config.auth.usernameMaxLength),
                    pattern: Config.auth.usernamePattern,
                    title: 'Letters, digits, . _ + - @',
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'bs-password', textContent: 'Password' }),
                Utils.el('input', {
                    type: 'password', id: 'bs-password', name: 'password',
                    autocomplete: 'new-password', required: 'true',
                    minlength: '8',
                    maxlength: String(Config.auth.passwordMaxLength),
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'bs-password2', textContent: 'Confirm Password' }),
                Utils.el('input', {
                    type: 'password', id: 'bs-password2', name: 'password2',
                    autocomplete: 'new-password', required: 'true',
                    maxlength: String(Config.auth.passwordMaxLength),
                }),
            ]),
            Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Create Admin Account' }),
            Utils.el('p', { id: 'bs-status', className: 'auth-status' }),
        ]);
        container.appendChild(form);
        Utils.attachPasswordStrength(document.getElementById('bs-password'));
    }

    async function _handleBootstrap(e, container) {
        e.preventDefault();
        const token    = document.getElementById('bs-token').value.trim();
        const username = document.getElementById('bs-username').value.trim();
        const password  = document.getElementById('bs-password').value;
        const password2 = document.getElementById('bs-password2').value;
        const status    = document.getElementById('bs-status');
        const btn       = e.target.querySelector('button[type="submit"]');

        if (password !== password2) {
            status.textContent = 'Passwords do not match.';
            return;
        }

        btn.disabled = true;
        status.textContent = 'Starting OPAQUE registration…';

        try {
            const opaque = await _loadOpaque();
            const { clientRegistrationState, registrationRequest } =
                opaque.client.startRegistration({ password });

            const round1 = await Api.post(`${Config.app.apiPrefix}/auth/opaque/bootstrap/start`, {
                token,
                username,
                client_registration_request: registrationRequest,
            });

            status.textContent = 'Generating encryption keys…';
            const { registrationRecord, exportKey } = opaque.client.finishRegistration({
                clientRegistrationState,
                registrationResponse: round1.registration_response,
                password,
                identifiers: { client: username, server: 'tusshare' },
            });

            const kek = await Crypto.deriveOpaqueKEK(exportKey);

            const masterKey = await Crypto.generateMasterKey();
            const { wrappedKeyB64: wrappedMasterKeyB64, ivB64: wrappedMasterKeyIvB64 } =
                await Crypto.wrapMasterKey(masterKey, kek);

            const { recoveryKey, recoveryKeyString } = await Crypto.generateRecoveryKey();
            const { wrappedKeyB64: recoveryWrappedB64, ivB64: recoveryIvB64 } =
                await Crypto.wrapMasterKey(masterKey, recoveryKey);
            const recoveryKeyHash = await Crypto.hashRecoveryKey(recoveryKeyString);

            status.textContent = 'Generating sharing keys…';
            const { x25519KeyPair, mlkem768KeyPair } = await Crypto.generateAsymmetricKeyPair();
            const { x25519PublicKeyB64, mlkem768PublicKeyB64 } =
                await Crypto.exportAsymmetricPublicKeys(x25519KeyPair, mlkem768KeyPair);
            const { x25519PrivWrappedB64, mlkem768PrivWrappedB64, asymKeyIvB64 } =
                await Crypto.wrapAsymmetricPrivateKeys(x25519KeyPair, mlkem768KeyPair, masterKey);

            status.textContent = 'Creating admin account…';
            const data = await Api.post(`${Config.app.apiPrefix}/auth/opaque/bootstrap/finish`, {
                token,
                username,
                client_registration_record: registrationRecord,
                wrapped_master_key:    wrappedMasterKeyB64,
                wrapped_master_key_iv: wrappedMasterKeyIvB64,
                recovery_key_wrapped:  recoveryWrappedB64,
                recovery_key_iv:       recoveryIvB64,
                recovery_key_hash:     recoveryKeyHash,
                x25519_public_key:        x25519PublicKeyB64,
                mlkem768_public_key:      mlkem768PublicKeyB64,
                x25519_private_wrapped:   x25519PrivWrappedB64,
                mlkem768_private_wrapped: mlkem768PrivWrappedB64,
                asymmetric_key_iv:        asymKeyIvB64,
            });

            _currentUser = data.user;
            _masterKeyObj = masterKey;
            _asymmetricKeys = {
                x25519PrivateKey:  x25519KeyPair.privateKey,
                mlkem768SecretKey: mlkem768KeyPair.secretKey,
            };
            await _saveSessionKeyData(_masterKeyObj, null);

            renderRecoveryKeyDisplay(container, recoveryKeyString, '/#/admin');

        } catch (err) {
            status.textContent = err.message || 'Setup failed. Please check your entries and try again.';
            btn.disabled = false;
        }
    }

    // ------------------------------------------------------------------
    // ------------------------------------------------------------------
    // Forgot password (recovery key → new password → new recovery key)
    // ------------------------------------------------------------------

    function renderForgotPassword(container, prefillUsername = '') {
        while (container.firstChild) container.firstChild.remove();

        async function _handleSubmit(e) {
            e.preventDefault();
            const username        = document.getElementById('recover-username').value.trim();
            const recoveryKeyStr  = document.getElementById('recover-key').value.trim();
            const newPassword     = document.getElementById('recover-new-password').value;
            const confirmPassword = document.getElementById('recover-confirm-password').value;
            const status          = document.getElementById('recover-status');
            const btn             = e.target.querySelector('button[type="submit"]');

            if (newPassword !== confirmPassword) {
                status.textContent = 'Passwords do not match.';
                return;
            }

            btn.disabled = true;
            status.textContent = 'Verifying recovery key…';

            try {
                const opaque = await _loadOpaque();

                // OPAQUE registration round 1 — blinded with the new password
                const { clientRegistrationState, registrationRequest } =
                    opaque.client.startRegistration({ password: newPassword });

                const round1 = await Api.post(`${Config.app.apiPrefix}/auth/opaque/recover/start`, {
                    username,
                    client_registration_request: registrationRequest,
                });

                // Verify the recovery key locally: attempt AES-GCM unwrap of the master key.
                // The raw recovery key is never sent to the server.
                if (!round1.recovery_key_wrapped || !round1.recovery_key_iv) {
                    throw new Error('Invalid username or recovery key.');
                }

                let masterKey;
                try {
                    const recoveryKey = await Crypto.importRecoveryKey(recoveryKeyStr);
                    masterKey = await Crypto.unwrapMasterKey(
                        round1.recovery_key_wrapped,
                        round1.recovery_key_iv,
                        recoveryKey
                    );
                } catch {
                    throw new Error('Invalid username or recovery key.');
                }

                // Recovery key verified — finalise OPAQUE registration with the new password
                status.textContent = 'Setting new password…';
                const { registrationRecord, exportKey } = opaque.client.finishRegistration({
                    clientRegistrationState,
                    registrationResponse: round1.registration_response,
                    password: newPassword,
                    identifiers: { client: username, server: 'tusshare' },
                });

                // Derive new KEK from exportKey and re-wrap the master key under it
                const newKek = await Crypto.deriveOpaqueKEK(exportKey);
                const { wrappedKeyB64: newWrappedMkB64, ivB64: newWrappedMkIvB64 } =
                    await Crypto.wrapMasterKey(masterKey, newKek);

                // Generate a new recovery key and wrap the master key under it
                const { recoveryKey: newRKey, recoveryKeyString: newRKeyStr } =
                    await Crypto.generateRecoveryKey();
                const { wrappedKeyB64: newRKeyWrappedB64, ivB64: newRKeyIvB64 } =
                    await Crypto.wrapMasterKey(masterKey, newRKey);
                const newRKeyHash = await Crypto.hashRecoveryKey(newRKeyStr);

                // Proof of the old recovery key: SHA-256(old_recovery_key_string)
                // The server compares this against the stored hash — no raw key ever leaves the client
                const oldProof = await Crypto.hashRecoveryKey(recoveryKeyStr);

                // Round 2: commit new credentials and revoke existing sessions
                status.textContent = 'Finalising reset…';
                await Api.post(`${Config.app.apiPrefix}/auth/opaque/recover/finish`, {
                    username,
                    session_id:              round1.session_id,
                    client_registration_record: registrationRecord,
                    wrapped_master_key:      newWrappedMkB64,
                    wrapped_master_key_iv:   newWrappedMkIvB64,
                    recovery_key_wrapped:    newRKeyWrappedB64,
                    recovery_key_iv:         newRKeyIvB64,
                    recovery_key_hash:       newRKeyHash,
                    old_recovery_key_proof:  oldProof,
                });

                // Wipe any in-memory session state so stale key material can't
                // persist into the next login session.
                _currentUser = null;
                _masterKeyObj = null;
                _asymmetricKeys = null;
                sessionStorage.removeItem(Config.auth.sessionStorageKey);
                sessionStorage.removeItem(Config.publicDevice.sessionStorageKey);

                // Show the new recovery key — button leads to login
                renderRecoveryKeyDisplay(
                    container, newRKeyStr, '/#/login',
                    'Your password has been reset. Save your new recovery key — this is the only time it will be shown.'
                );

            } catch (err) {
                status.textContent = err.message || 'Password reset failed. Please try again.';
                btn.disabled = false;
            }
        }

        const form = Utils.el('form', { className: 'auth-form', onSubmit: _handleSubmit }, [
            Utils.el('h2', { textContent: 'Forgot Password' }),
            Utils.el('p', { className: 'text-muted', textContent:
                'Enter your username, recovery key, and a new password.' }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'recover-username', textContent: 'Username' }),
                Utils.el('input', {
                    type: 'text', id: 'recover-username', name: 'username',
                    autocomplete: 'username', required: 'true',
                    value: prefillUsername,
                    maxlength: String(Config.auth.usernameMaxLength),
                    pattern: Config.auth.usernamePattern,
                    title: 'Letters, digits, . _ + - @',
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'recover-key', textContent: 'Recovery Key' }),
                Utils.el('input', {
                    type: 'text', id: 'recover-key', name: 'recovery-key',
                    autocomplete: 'off', required: 'true',
                    style: 'font-family:var(--font-family-mono)',
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'recover-new-password', textContent: 'New Password' }),
                Utils.el('input', {
                    type: 'password', id: 'recover-new-password', name: 'new-password',
                    autocomplete: 'new-password', required: 'true',
                    minlength: '8',
                    maxlength: String(Config.auth.passwordMaxLength),
                }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'recover-confirm-password', textContent: 'Confirm New Password' }),
                Utils.el('input', {
                    type: 'password', id: 'recover-confirm-password', name: 'confirm-password',
                    autocomplete: 'new-password', required: 'true',
                    maxlength: String(Config.auth.passwordMaxLength),
                }),
            ]),
            Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Reset Password' }),
            Utils.el('div', { style: 'text-align:center;margin-top:12px' }, [
                Utils.el('a', {
                    href: '#',
                    className: 'text-muted',
                    textContent: '← Back to login',
                    onClick: (ev) => {
                        ev.preventDefault();
                        renderLogin(container);
                    },
                }),
            ]),
            Utils.el('p', { id: 'recover-status', className: 'auth-status' }),
        ]);
        container.appendChild(form);
        Utils.attachPasswordStrength(document.getElementById('recover-new-password'));
    }

    // Recovery key display (shown once after account creation)
    // ------------------------------------------------------------------

    function renderRecoveryKeyDisplay(container, recoveryKeyString, destination = '/#/files', subtitle = null) {
        while (container.firstChild) container.firstChild.remove();

        const defaultSubtitle = (
            'This is the ONLY time this key will be shown. If you forget your password, ' +
            'this key is the only way to recover your encrypted files. Store it somewhere safe.'
        );

        const card = Utils.el('div', { className: 'auth-form' }, [
            Utils.el('h2', { textContent: 'Save Your Recovery Key' }),
            Utils.el('p', { className: 'text-muted', textContent: subtitle || defaultSubtitle }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('input', {
                    type: 'text', id: 'recovery-key-display',
                    value: recoveryKeyString, readonly: 'true',
                    style: 'font-family:var(--font-family-mono);text-align:center;font-size:var(--font-size-base);user-select:all',
                }),
            ]),
            Utils.el('button', {
                className: 'btn btn-secondary btn-full',
                textContent: 'Copy to Clipboard',
                onClick: () => {
                    navigator.clipboard.writeText(recoveryKeyString).then(() => {
                        Utils.showToast('Recovery key copied', 'success');
                    });
                },
            }),
            Utils.el('button', {
                className: 'btn btn-primary btn-full',
                style: 'margin-top:8px',
                textContent: 'I have saved my recovery key',
                onClick: () => {
                    const before = globalThis.location.href;
                    globalThis.location.replace(destination);
                    // If the URL didn't change (destination hash was already active),
                    // the browser won't fire hashchange — dispatch it manually so the
                    // router re-renders the target page (e.g. login after password reset).
                    if (globalThis.location.href === before) {
                        globalThis.dispatchEvent(new HashChangeEvent('hashchange'));
                    }
                },
            }),
        ]);
        container.appendChild(card);
    }

    // ------------------------------------------------------------------
    // MFA challenge (post-OPAQUE login, before cookie issuance)
    // ------------------------------------------------------------------

    function _renderMfaChallenge(container, mfaData, exportKey, username, _isPublicDevice) {
        const { pending_token, methods, reset_required } = mfaData;
        while (container.firstChild) container.firstChild.remove();

        const hasTotp     = methods.includes('totp');
        const hasWebAuthn = methods.includes('webauthn');

        // If reset_required with no methods, redirect to enrollment
        if (reset_required && methods.length === 0) {
            _renderMfaEnrollmentGate(container, pending_token, exportKey, username);
            return;
        }

        const statusEl = Utils.el('p', { id: 'mfa-status', className: 'auth-status' });

        // Build tab definitions — always include Recovery Code as a fallback tab
        const tabDefs = [];
        if (hasWebAuthn) tabDefs.push({ id: 'webauthn', label: 'Security Key' });
        if (hasTotp)     tabDefs.push({ id: 'totp',     label: 'Authenticator' });
        tabDefs.push({ id: 'recovery', label: 'Recovery Code' });

        // --- Panel: WebAuthn ---
        const webAuthnBtn = Utils.el('button', {
            type: 'button', className: 'btn btn-secondary btn-full',
            textContent: 'Use Security Key / Biometrics',
            onClick: async (ev) => {
                ev.target.disabled = true;
                statusEl.textContent = 'Waiting for security key…';
                try {
                    const beginData = await Api.post(
                        `${Config.app.apiPrefix}/auth/webauthn/authenticate/begin`,
                        { pending_token },
                    );
                    const assertion = await navigator.credentials.get({
                        publicKey: _webAuthnOptionsFromServer(beginData.options),
                    });
                    await Api.post(`${Config.app.apiPrefix}/auth/webauthn/authenticate/finish`, {
                        pending_token,
                        challenge_id: beginData.challenge_id,
                        assertion: _serializeAssertion(assertion),
                    });
                    await _completeMfaSuccess(container, exportKey, username);
                } catch (err) {
                    statusEl.textContent = err.message || 'Security key verification failed.';
                    ev.target.disabled = false;
                }
            },
        });
        const webAuthnPanel = Utils.el('div', { id: 'mfa-panel-webauthn', role: 'tabpanel', 'aria-labelledby': 'mfa-tab-webauthn' }, [webAuthnBtn]);

        // --- Panel: TOTP ---
        const totpPanel = Utils.el('div', { id: 'mfa-panel-totp', role: 'tabpanel', 'aria-labelledby': 'mfa-tab-totp' }, [
            Utils.el('form', {
                className: 'mfa-totp-form',
                onSubmit: async (e) => {
                    e.preventDefault();
                    const code = document.getElementById('mfa-totp-code').value.trim();
                    const btn  = e.target.querySelector('button[type="submit"]');
                    btn.disabled = true;
                    statusEl.textContent = 'Verifying…';
                    try {
                        await Api.post(`${Config.app.apiPrefix}/auth/totp/verify`, {
                            pending_token,
                            totp_code: code,
                        });
                        await _completeMfaSuccess(container, exportKey, username);
                    } catch (err) {
                        statusEl.textContent = err.message || 'Invalid code. Please try again.';
                        btn.disabled = false;
                        document.getElementById('mfa-totp-code').value = '';
                        document.getElementById('mfa-totp-code').focus();
                    }
                },
            }, [
                Utils.el('div', { className: 'form-group' }, [
                    Utils.el('label', { for: 'mfa-totp-code', textContent: 'Authenticator Code' }),
                    Utils.el('input', {
                        type: 'text', id: 'mfa-totp-code', name: 'totp_code',
                        autocomplete: 'one-time-code', inputmode: 'numeric',
                        pattern: '[0-9]{6}', maxlength: '6', required: 'true',
                        placeholder: '000000',
                        style: 'font-family:var(--font-family-mono);letter-spacing:0.2em;font-size:1.3em',
                    }),
                ]),
                Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Verify Code' }),
            ]),
        ]);

        // --- Panel: Recovery Code ---
        const recoveryPanel = Utils.el('div', { id: 'mfa-panel-recovery', role: 'tabpanel', 'aria-labelledby': 'mfa-tab-recovery' }, [
            Utils.el('form', {
                onSubmit: async (e) => {
                    e.preventDefault();
                    const code = document.getElementById('mfa-recovery-code').value.trim().toUpperCase();
                    const btn  = e.target.querySelector('button[type="submit"]');
                    btn.disabled = true;
                    statusEl.textContent = 'Verifying…';
                    try {
                        await Api.post(`${Config.app.apiPrefix}/auth/mfa/verify-recovery`, {
                            pending_token,
                            recovery_code: code,
                        });
                        await _completeMfaSuccess(container, exportKey, username);
                    } catch (err) {
                        statusEl.textContent = err.message || 'Invalid recovery code.';
                        btn.disabled = false;
                    }
                },
            }, [
                Utils.el('div', { className: 'form-group' }, [
                    Utils.el('label', { for: 'mfa-recovery-code', textContent: 'Recovery Code' }),
                    Utils.el('input', {
                        type: 'text', id: 'mfa-recovery-code', name: 'recovery_code',
                        autocomplete: 'off', required: 'true',
                        style: 'font-family:var(--font-family-mono)',
                        placeholder: 'XXXXXXXXXXXXXXXXXXXXXXXX',
                    }),
                ]),
                Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Verify' }),
            ]),
        ]);

        const panels = { webauthn: webAuthnPanel, totp: totpPanel, recovery: recoveryPanel };

        // Tab buttons
        let activeTab = tabDefs[0].id;
        const tabBtns = {};

        function _switchTab(id) {
            activeTab = id;
            for (const { id: tid } of tabDefs) {
                const isActive = tid === id;
                tabBtns[tid].classList.toggle('active', isActive);
                tabBtns[tid].setAttribute('aria-selected', String(isActive));
                if (panels[tid]) panels[tid].hidden = !isActive;
            }
            statusEl.textContent = '';
            // Auto-trigger WebAuthn on tab switch (same as before)
            if (id === 'webauthn') webAuthnBtn.click();
        }

        const tabBar = Utils.el('div', { className: 'tabs mfa-tabs', role: 'tablist' });
        for (const { id, label } of tabDefs) {
            const btn = Utils.el('button', {
                type: 'button',
                className: 'tab' + (id === activeTab ? ' active' : ''),
                role: 'tab',
                id: `mfa-tab-${id}`,
                'aria-selected': String(id === activeTab),
                'aria-controls': `mfa-panel-${id}`,
                textContent: label,
                onClick: () => _switchTab(id),
            });
            tabBtns[id] = btn;
            tabBar.appendChild(btn);
        }

        // Keyboard nav: arrow keys cycle tabs
        tabBar.addEventListener('keydown', (e) => {
            if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
            const ids  = tabDefs.map(t => t.id);
            const idx  = ids.indexOf(activeTab);
            const next = e.key === 'ArrowRight' ? (idx + 1) % ids.length : (idx - 1 + ids.length) % ids.length;
            tabBtns[ids[next]].focus();
            _switchTab(ids[next]);
        });

        // Hide panels not for available methods (only keep defined panels)
        const panelChildren = tabDefs.map(({ id }) => panels[id]);
        // All panels except first start hidden
        panelChildren.slice(1).forEach(p => { p.hidden = true; });

        container.appendChild(Utils.el('div', { className: 'auth-form' }, [
            Utils.el('h2', { textContent: 'Two-Factor Authentication' }),
            Utils.el('p', { className: 'text-muted', textContent: 'Verify your identity to continue.' }),
            tabBar,
            ...panelChildren,
            statusEl,
        ]));

        // Auto-trigger WebAuthn if it's the default tab (avoids extra click)
        if (activeTab === 'webauthn') webAuthnBtn.click();
    }

    function _renderRecoveryChallenge(container, pending_token, exportKey, username) {
        while (container.firstChild) container.firstChild.remove();
        container.appendChild(Utils.el('form', {
            className: 'auth-form',
            onSubmit: async (e) => {
                e.preventDefault();
                const code = document.getElementById('mfa-recovery-code').value.trim().toUpperCase();
                const statusEl = document.getElementById('mfa-recovery-status');
                const btn = e.target.querySelector('button[type="submit"]');
                btn.disabled = true;
                if (statusEl) statusEl.textContent = 'Verifying…';
                try {
                    await Api.post(`${Config.app.apiPrefix}/auth/mfa/verify-recovery`, {
                        pending_token,
                        recovery_code: code,
                    });
                    await _completeMfaSuccess(container, exportKey, username);
                } catch (err) {
                    if (statusEl) statusEl.textContent = err.message || 'Invalid recovery code.';
                    btn.disabled = false;
                }
            },
        }, [
            Utils.el('h2', { textContent: 'Recovery Code' }),
            Utils.el('p', { className: 'text-muted', textContent: 'Enter one of your saved recovery codes.' }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'mfa-recovery-code', textContent: 'Recovery Code' }),
                Utils.el('input', {
                    type: 'text', id: 'mfa-recovery-code', name: 'recovery_code',
                    autocomplete: 'off', required: 'true',
                    style: 'font-family:var(--font-family-mono)',
                    placeholder: 'XXXXXXXXXXXXXXXXXXXXXXXX',
                }),
            ]),
            Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Verify' }),
            Utils.el('p', { id: 'mfa-recovery-status', className: 'auth-status' }),
        ]));
    }

    async function _completeMfaSuccess(container, exportKey, _username) {
        // MFA challenge completed — server has now issued session cookies.
        // Re-fetch the user profile (cookies are set now) and complete key derivation.
        const meData = await Api.get(`${Config.app.apiPrefix}/auth/me`);
        _currentUser = meData.user;

        if (_currentUser.is_admin) {
            globalThis.location.hash = '#/admin';
            return;
        }

        // IdP users (LDAP/OIDC) have no OPAQUE exportKey and no wrapped_master_key.
        // Skip KEK derivation — they access team/shared files without a personal key.
        if (!exportKey || !_currentUser.wrapped_master_key) {
            if (_currentUser.mfa_reset_required) {
                renderMfaSettings(container);
                return;
            }
            const pendingJoin = sessionStorage.getItem('pendingJoinHash');
            if (pendingJoin) {
                sessionStorage.removeItem('pendingJoinHash');
                globalThis.location.hash = pendingJoin;
            } else {
                globalThis.location.hash = '#/files';
            }
            return;
        }

        const kek = await Crypto.deriveOpaqueKEK(exportKey);
        _masterKeyObj = await Crypto.unwrapMasterKey(
            _currentUser.wrapped_master_key,
            _currentUser.wrapped_master_key_iv,
            kek,
        );

        await _saveSessionKeyData(_masterKeyObj, null);

        _setupAsymmetricKeys(_currentUser, _masterKeyObj).catch(() => {});
        Teams.processPendingTeamOperations().catch(() => {});

        // Check for MFA reset requirement (admin forced re-enrollment after bypass)
        if (_currentUser.mfa_reset_required) {
            renderMfaSettings(container);
            return;
        }

        const pendingJoin = sessionStorage.getItem('pendingJoinHash');
        if (pendingJoin) {
            sessionStorage.removeItem('pendingJoinHash');
            globalThis.location.hash = pendingJoin;
        } else {
            globalThis.location.hash = '#/files';
        }
    }

    function _renderMfaEnrollmentGate(container, _pending_token, _exportKey, _username) {
        while (container.firstChild) container.firstChild.remove();
        container.appendChild(Utils.el('div', { className: 'auth-form' }, [
            Utils.el('h2', { textContent: 'MFA Enrollment Required' }),
            Utils.el('p', { className: 'text-muted', textContent:
                'An administrator has required you to set up two-factor authentication before continuing.' }),
            Utils.el('button', {
                type: 'button', className: 'btn btn-primary btn-full',
                textContent: 'Set Up Authenticator App (TOTP)',
                onClick: async () => {
                    // First complete the pending_token auth so we have a session, then enroll
                    // For enrollment gate we need cookies first — but we have no MFA yet.
                    // The server should issue cookies for enrollment-only when reset_required
                    // is set and no credentials exist. For now, navigate to MFA settings after
                    // completing a password-based TOTP verification bypass by posting to a
                    // special enroll-start route (which requires an active session).
                    // This edge case is handled post-session by re-checking mfa_reset_required in _completeMfaSuccess.
                    Utils.showToast('Complete login first, then enroll in MFA from your settings.', 'info');
                },
            }),
        ]));
    }

    // ------------------------------------------------------------------
    // MFA settings page (TOTP enrollment, WebAuthn registration, credential list)
    // ------------------------------------------------------------------

    async function renderMfaSettings(container) {
        while (container.firstChild) container.firstChild.remove();

        const wrap = Utils.el('div', { className: 'auth-form', style: 'max-width:540px' });
        container.appendChild(wrap);

        wrap.appendChild(Utils.el('h2', { textContent: 'Two-Factor Authentication' }));
        wrap.appendChild(Utils.el('p', { id: 'mfa-settings-status', className: 'auth-status' }));

        try {
            const data = await Api.get(`${Config.app.apiPrefix}/auth/mfa/status`);
            if (data.enforcement === 'required' && data.active_count === 0) {
                wrap.appendChild(Utils.el('div', {
                    className: 'admin-transparency-banner',
                    style: 'margin-bottom:16px',
                }, [
                    Utils.el('span', { textContent: 'MFA enrollment is required. You must add at least one authentication method before accessing your files.' }),
                ]));
            }
            _renderMfaSettingsContent(wrap, data);
        } catch {
            wrap.appendChild(Utils.el('p', { className: 'auth-status', textContent: 'Failed to load MFA status.' }));
        }
    }

    function _renderMfaSettingsContent(wrap, data) {
        // Clear existing content below heading
        const heading = wrap.querySelector('h2');
        while (wrap.lastChild !== heading) wrap.lastChild.remove();

        const creds = data.credentials || [];

        if (creds.length === 0) {
            wrap.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No MFA methods enrolled.' }));
        } else {
            const list = Utils.el('ul', { style: 'list-style:none;padding:0;margin-bottom:16px' });
            creds.forEach(c => {
                const method = c.method === 'totp' ? 'Authenticator App' : 'Security Key';
                const used = c.last_used_at
                    ? `Last used: ${new Date(c.last_used_at * 1000).toLocaleDateString()}`
                    : 'Never used';
                const li = Utils.el('li', { style: 'display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)' }, [
                    Utils.el('span', {}, [
                        Utils.el('strong', { textContent: c.name }),
                        Utils.el('small', { className: 'text-muted', style: 'display:block', textContent: `${method} · ${used}` }),
                    ]),
                    Utils.el('button', {
                        type: 'button', className: 'btn btn-sm btn-danger',
                        textContent: 'Remove',
                        onClick: async (ev) => {
                            ev.target.disabled = true;
                            try {
                                await Api.del(`${Config.app.apiPrefix}/auth/mfa/credentials/${c.id}`);
                                Utils.showToast('Credential removed.', 'success');
                                const updated = await Api.get(`${Config.app.apiPrefix}/auth/mfa/status`);
                                _renderMfaSettingsContent(wrap, updated);
                            } catch (err) {
                                Utils.showToast(err.message || 'Failed to remove credential.', 'error');
                                ev.target.disabled = false;
                            }
                        },
                    }),
                ]);
                list.appendChild(li);
            });
            wrap.appendChild(list);
        }

        // Enroll TOTP
        wrap.appendChild(Utils.el('details', { style: 'margin-bottom:12px' }, [
            Utils.el('summary', { style: 'cursor:pointer;font-weight:600;padding:8px 0', textContent: '+ Add Authenticator App (TOTP)' }),
            _buildTotpEnrollForm(wrap, data),
        ]));

        // Enroll WebAuthn
        if (globalThis.PublicKeyCredential) {
            wrap.appendChild(Utils.el('details', { style: 'margin-bottom:12px' }, [
                Utils.el('summary', { style: 'cursor:pointer;font-weight:600;padding:8px 0', textContent: '+ Add Security Key / Biometrics (WebAuthn)' }),
                _buildWebAuthnEnrollForm(wrap),
            ]));
        }
    }

    function _buildTotpEnrollForm(wrapRef, _statusData) {
        const area = Utils.el('div', { style: 'padding:12px 0' });
        const startBtn = Utils.el('button', {
            type: 'button', className: 'btn btn-secondary',
            textContent: 'Generate QR Code',
        });
        area.appendChild(startBtn);

        startBtn.addEventListener('click', async () => {
            startBtn.disabled = true;
            try {
                const { secret_b32, cred_id, qr_data_url } = await Api.post(
                    `${Config.app.apiPrefix}/auth/totp/enroll/start`
                );

                while (area.firstChild) area.firstChild.remove();

                area.appendChild(Utils.el('p', { className: 'text-muted', style: 'margin-bottom:8px',
                    textContent: 'Scan this QR code with your authenticator app, then enter the 6-digit code to confirm.' }));

                const qrImg = Utils.el('img', {
                    src: qr_data_url,
                    alt: 'TOTP QR Code',
                    style: 'display:block;margin:0 auto 12px;background:#fff;padding:8px',
                    width: '180', height: '180',
                });
                area.appendChild(qrImg);

                area.appendChild(Utils.el('p', { style: 'font-family:var(--font-family-mono);font-size:0.85em;word-break:break-all;margin-bottom:12px',
                    textContent: `Manual entry: ${secret_b32}` }));

                const form = Utils.el('form', {
                    onSubmit: async (e) => {
                        e.preventDefault();
                        const code = document.getElementById('totp-confirm-code').value.trim();
                        const name = document.getElementById('totp-device-name').value.trim() || 'Authenticator App';
                        const btn2 = e.target.querySelector('button[type="submit"]');
                        btn2.disabled = true;
                        try {
                            const result = await Api.post(`${Config.app.apiPrefix}/auth/totp/enroll/finish`, {
                                cred_id, totp_code: code, name,
                            });
                            while (area.firstChild) area.firstChild.remove();
                            area.appendChild(Utils.el('h3', { textContent: 'Save Your Recovery Codes', style: 'margin-bottom:8px' }));
                            area.appendChild(Utils.el('p', { className: 'text-muted',
                                textContent: 'These one-time codes let you regain access if you lose your authenticator. Save them now — they cannot be shown again.' }));
                            const codeBlock = Utils.el('pre', {
                                style: 'background:var(--bg-secondary);padding:12px;border-radius:6px;font-size:0.9em;margin-bottom:12px',
                                textContent: result.recovery_codes.join('\n'),
                            });
                            area.appendChild(codeBlock);
                            area.appendChild(Utils.el('button', {
                                type: 'button', className: 'btn btn-primary',
                                textContent: 'I\'ve saved my recovery codes',
                                onClick: async () => { // NOSONAR — closure over wrapRef; unavoidable nesting depth
                                    Utils.showToast('TOTP authenticator enrolled!', 'success');
                                    const updated = await Api.get(`${Config.app.apiPrefix}/auth/mfa/status`);
                                    _renderMfaSettingsContent(wrapRef, updated);
                                },
                            }));
                        } catch (err) {
                            Utils.showToast(err.message || 'Enrollment failed. Please try again.', 'error');
                            btn2.disabled = false;
                        }
                    },
                }, [
                    Utils.el('div', { className: 'form-group' }, [
                        Utils.el('label', { for: 'totp-device-name', textContent: 'Device Name (optional)' }),
                        Utils.el('input', {
                            type: 'text', id: 'totp-device-name', name: 'name',
                            placeholder: 'e.g. Phone Authenticator', maxlength: '128',
                        }),
                    ]),
                    Utils.el('div', { className: 'form-group' }, [
                        Utils.el('label', { for: 'totp-confirm-code', textContent: '6-digit Code from App' }),
                        Utils.el('input', {
                            type: 'text', id: 'totp-confirm-code', name: 'code',
                            autocomplete: 'one-time-code', inputmode: 'numeric',
                            pattern: '[0-9]{6}', maxlength: '6', required: 'true',
                            style: 'font-family:var(--font-family-mono);letter-spacing:0.2em;font-size:1.3em',
                        }),
                    ]),
                    Utils.el('button', { type: 'submit', className: 'btn btn-primary', textContent: 'Confirm & Activate' }),
                ]);
                area.appendChild(form);
            } catch (err) {
                Utils.showToast(err.message || 'Failed to start enrollment.', 'error');
                startBtn.disabled = false;
            }
        });
        return area;
    }

    function _buildWebAuthnEnrollForm(wrapRef) {
        const area = Utils.el('div', { style: 'padding:12px 0' });
        const form = Utils.el('form', {
            onSubmit: async (e) => {
                e.preventDefault();
                if (!globalThis.isSecureContext) {
                    Utils.showToast('Security keys require HTTPS or localhost. Please access this page over a secure connection.', 'error');
                    return;
                }
                const name = document.getElementById('webauthn-key-name').value.trim() || 'Security Key';
                const btn = e.target.querySelector('button[type="submit"]');
                btn.disabled = true;
                // Phase 1: key interaction
                let credential;
                try {
                    const beginData = await Api.post(`${Config.app.apiPrefix}/auth/webauthn/register/begin`);
                    credential = await navigator.credentials.create({
                        publicKey: _webAuthnOptionsFromServer(beginData.options),
                    });
                    await new Promise(r => setTimeout(r, 500));
                    // Phase 2: server verification
                    await Api.post(`${Config.app.apiPrefix}/auth/webauthn/register/finish`, {
                        challenge_id: beginData.challenge_id,
                        attestation: _serializeAttestation(credential),
                        name,
                    });
                } catch (err) {
                    let msg;
                    if (err.name === 'SecurityError') {
                        msg = 'WebAuthn setup failed: the server\'s rpId does not match this page\'s origin. Ask your administrator to set WEBAUTHN_RP_ID to the correct domain.';
                    } else if (err.name === 'NotAllowedError') {
                        msg = 'Registration was cancelled or timed out.';
                    } else if (!credential) {
                        // navigator.credentials.create() threw — key interaction failed before any data reached the server
                        const isNfcDrop = err.name === 'NotReadableError' || err.name === 'AbortError' ||
                            (err.message && /transient/i.test(err.message));
                        if (isNfcDrop) {
                            msg = 'NFC transfer interrupted. The phone\'s checkmark is premature — the key is still sending data when it appears. Hold the key firmly against the phone until this page shows “Security key registered!”, then try again.';
                        } else {
                            msg = `Key interaction failed [${err.name}]: ${err.message || 'no detail'}`;
                        }
                    } else if (err.status >= 400) {
                        msg = `Server rejected the registration: ${err.message || 'check server logs'}`;
                    } else {
                        msg = `Registration failed [${err.name}]: ${err.message || 'no detail'}`;
                    }
                    Utils.showToast(msg, 'error');
                    btn.disabled = false;
                    return;
                }
                Utils.showToast('Security key registered!', 'success');
                const updated = await Api.get(`${Config.app.apiPrefix}/auth/mfa/status`);
                _renderMfaSettingsContent(wrapRef, updated);
            },
        }, [
            Utils.el('p', { className: 'text-muted', style: 'margin-bottom:8px',
                textContent: 'Insert your security key or use biometrics (Touch ID, Windows Hello, etc.) when prompted. Using NFC on mobile: tap your key, complete any PIN prompt, then keep the key held firmly against the phone — the phone\'s own checkmark appears before the transfer is done. Only remove the key when this page shows "Security key registered!".' }),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { for: 'webauthn-key-name', textContent: 'Key Name (optional)' }),
                Utils.el('input', {
                    type: 'text', id: 'webauthn-key-name', name: 'name',
                    placeholder: 'e.g. YubiKey 5', maxlength: '128',
                }),
            ]),
            Utils.el('button', { type: 'submit', className: 'btn btn-primary', textContent: 'Register Security Key' }),
        ]);
        area.appendChild(form);
        return area;
    }

    // ------------------------------------------------------------------
    // WebAuthn serialisation helpers
    // ------------------------------------------------------------------

    function _b64ToBytes(b64) {
        const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
        const bin = atob(padded.replaceAll('-', '+').replaceAll('_', '/'));
        return Uint8Array.from(bin, c => c.codePointAt(0));
    }

    function _webAuthnOptionsFromServer(opts) {
        const b64ToBytes = _b64ToBytes;
        const out = {...opts};
        if (out.challenge) out.challenge = b64ToBytes(out.challenge);
        if (out.user?.id) out.user = {...out.user, id: b64ToBytes(out.user.id)};
        if (out.allowCredentials) {
            out.allowCredentials = out.allowCredentials.map(c =>
                ({...c, id: b64ToBytes(c.id)})
            );
        }
        if (out.excludeCredentials) {
            out.excludeCredentials = out.excludeCredentials.map(c =>
                ({...c, id: b64ToBytes(c.id)})
            );
        }
        return out;
    }

    function _bytesToB64url(bytes) {
        return btoa(String.fromCodePoint(...new Uint8Array(bytes)))
            .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    }

    function _serializeAttestation(cred) {
        let transports = [];
        try {
            if (cred.response.getTransports) transports = cred.response.getTransports();
        } catch (_) { /* some Android browsers throw here after a successful NFC exchange */ }
        return {
            id: cred.id,
            rawId: _bytesToB64url(cred.rawId),
            type: cred.type,
            response: {
                attestationObject: _bytesToB64url(cred.response.attestationObject),
                clientDataJSON: _bytesToB64url(cred.response.clientDataJSON),
                transports,
            },
        };
    }

    function _serializeAssertion(cred) {
        return {
            id: cred.id,
            rawId: _bytesToB64url(cred.rawId),
            type: cred.type,
            response: {
                authenticatorData: _bytesToB64url(cred.response.authenticatorData),
                clientDataJSON: _bytesToB64url(cred.response.clientDataJSON),
                signature: _bytesToB64url(cred.response.signature),
                userHandle: cred.response.userHandle ? _bytesToB64url(cred.response.userHandle) : null,
            },
        };
    }

    // ------------------------------------------------------------------
    // MFA banner (optional-mode nudge)
    // ------------------------------------------------------------------

    async function checkMfaBanner(_container) {
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/auth/mfa/status`);
            if (data.enforcement !== 'optional') return;
            if (data.credentials.length > 0) return;
            if (data.banner_dismissed) return;

            const banner = Utils.el('div', {
                id: 'mfa-banner',
                className: 'alert alert-info',
                style: 'display:flex;justify-content:space-between;align-items:center;margin-bottom:12px',
            }, [
                Utils.el('span', { textContent: 'Your organization recommends enabling two-factor authentication for added security.' }),
                Utils.el('span', {}, [
                    Utils.el('a', {
                        href: '#/mfa', className: 'btn btn-sm btn-primary', style: 'margin-right:8px',
                        textContent: 'Set Up',
                    }),
                    Utils.el('button', {
                        type: 'button', className: 'btn btn-sm btn-secondary',
                        textContent: 'Dismiss',
                        onClick: async () => {
                            banner.remove();
                            await Api.post(`${Config.app.apiPrefix}/auth/mfa/banner/dismiss`).catch(() => {});
                        },
                    }),
                ]),
            ]);

            const appEl = document.getElementById('app');
            if (appEl?.firstChild) {
                appEl.insertBefore(banner, appEl.firstChild);
            }
        } catch {
            // Non-critical
        }
    }

    // ------------------------------------------------------------------
    // Logout / session check
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Identity watch — SSE stream that detects admin-forced changes
    // ------------------------------------------------------------------

    let _identitySource = null;
    let _identityReconnectTimer = null;

    function startIdentityWatch() {
        if (_identitySource) return;
        _connectIdentityWatch();
    }

    function _connectIdentityWatch() {
        const url = `${Config.app.apiPrefix}/events/identity`;
        const src = new EventSource(url, { withCredentials: true });

        src.onmessage = (e) => {
            let event;
            try { event = JSON.parse(e.data); } catch { return; }

            if (event.type === 'config_changed') {
                if (_currentUser && event.config) Object.assign(_currentUser, event.config);
                return;
            }

            if (event.type !== 'identity_changed') return;
            // Force logout — the admin has deactivated this account or revoked sessions.
            src.close();
            _identitySource = null;
            clearTimeout(_identityReconnectTimer);
            const reason = event.reason === 'deactivated'
                ? 'Your account has been deactivated.'
                : 'Your session was remotely revoked.';
            Utils.showToast(reason, 'error');
            // Brief delay so the toast is visible before the redirect.
            setTimeout(() => logout(), 1500);
        };

        src.onerror = () => {
            src.close();
            if (!_currentUser) return; // already logged out — don't reconnect
            // Reconnect after 10 s if the stream drops (network blip, server restart).
            _identityReconnectTimer = setTimeout(_connectIdentityWatch, 10_000);
        };

        _identitySource = src;
    }

    function stopIdentityWatch() {
        if (_identitySource) {
            _identitySource.close();
            _identitySource = null;
        }
        clearTimeout(_identityReconnectTimer);
    }

    async function logout() {
        stopIdentityWatch();

        // Dismiss the transfer panel immediately so the UI is clean at once,
        // then signal every active transfer to stop.  Uploads are stopped without
        // deleting the server-side partial so they appear as resumable pending rows
        // on the user's next login.  Downloads are aborted (no server state to keep).
        TransferManager.dismissAll();
        TransferManager.pauseAll();

        // Clear session-scoped toast history and unread counter.
        Utils.clearToastHistory();

        // Close any open confirm/prompt modals so they don't linger on the login page.
        document.querySelectorAll('.modal-overlay').forEach(el => {
            if (el.parentNode) el.remove();
        });

        try {
            await Api.post(`${Config.app.apiPrefix}/auth/logout`);
        } catch {}
        _currentUser = null;
        _masterKeyObj = null;
        sessionStorage.removeItem(Config.auth.sessionStorageKey);
        sessionStorage.removeItem(Config.publicDevice.sessionStorageKey);
        globalThis.location.hash = '#/login';
    }

    async function checkSession() {
        if (!sessionStorage.getItem(Config.auth.sessionStorageKey)) return false;
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/auth/me`);
            _currentUser = data.user;
            // Silently restore master key from cache if within the grace period,
            // so users aren't prompted for their password on every page reload.
            if (!_masterKeyObj) {
                const restored = await _restoreCachedMasterKey();
                if (restored && !_currentUser.is_admin) {
                    _setupAsymmetricKeys(_currentUser, _masterKeyObj).catch((err) => {
                        console.error('Asymmetric key setup failed after cache restore:', err);
                    });
                    Teams.processPendingTeamOperations().catch((err) => {
                        console.warn('Pending team operations check failed:', err.message);
                    });
                }
            }
            return true;
        } catch {
            _currentUser = null;
            _masterKeyObj = null;
            return false;
        }
    }

    async function refreshCurrentUser() {
        try {
            const meData = await Api.get(`${Config.app.apiPrefix}/auth/me`);
            _currentUser = meData.user;
        } catch {
            // Non-fatal: keep existing user object
        }
    }

    return {
        getCurrentUser,
        getMasterKeyObj,
        getAsymmetricKeys,
        renderLogin,
        renderBootstrap,
        renderKeyPrompt,
        renderRecoveryPrompt,
        renderRecoveryKeyDisplay,
        renderForgotPassword,
        renderRegisterPage,
        renderMfaSettings,
        renderOidcMfaChallenge,
        checkMfaBanner,
        logout,
        checkSession,
        touchKeyCache,
        startIdentityWatch,
        refreshCurrentUser,
        loadOpaque: _loadOpaque,
    };
})();


/**
 * StepUp — step-up authentication for sensitive actions.
 *
 * Usage (called automatically by Api when a 403 step_up_required is received):
 *   const token = await StepUp.challenge(actionKey, payloadHash);
 *   // token is the X-Step-Up-Token value to attach to the retry
 *
 * The challenge modal re-derives the KEK from the entered password, computes
 * an HMAC over the pending action payload, and POSTs to /auth/step-up.
 * On success the returned JWT is cached in memory for the sudo window duration.
 */
const StepUp = (() => {
    // In-memory token cache: actionKey → {token, expiresAt}
    // Allows the sudo window to work without re-prompting on every sensitive action.
    const _tokenCache = new Map();

    function _getCached(actionKey) {
        const entry = _tokenCache.get(actionKey);
        if (!entry) return null;
        if (Date.now() >= entry.expiresAt) {
            _tokenCache.delete(actionKey);
            return null;
        }
        return entry.token;
    }

    function _cache(actionKey, token, windowSeconds) {
        if (windowSeconds > 0) {
            // Cache for 90% of the window to avoid racing the server expiry
            _tokenCache.set(actionKey, {
                token,
                expiresAt: Date.now() + windowSeconds * 900,
            });
        }
        // windowSeconds=0 (single-use): don't cache — token is payload-bound
    }

    /**
     * Show the password challenge modal and return a step-up token.
     *
     * @param {string} actionKey   - The sensitive function key
     * @param {string} payloadHash - SHA-256 hex of the request body
     * @param {string} [challengeType='password'] - Challenge type from server
     * @returns {Promise<string>}  Resolved with the step-up token JWT
     * @throws If the user cancels or verification fails
     */
    async function challenge(actionKey, payloadHash, _challengeType = 'password') {
        // Check cache first (sudo window mode)
        const cached = _getCached(actionKey);
        if (cached) return cached;

        return new Promise((resolve, reject) => {
            _showPasswordModal(actionKey, payloadHash, resolve, reject);
        });
    }

    function _showPasswordModal(actionKey, payloadHash, resolve, reject) {
        const existing = document.getElementById('stepup-modal');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = 'stepup-modal';
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal stepup-modal">
                <div class="modal-header">
                    <h3>Confirm your identity</h3>
                </div>
                <div class="modal-body">
                    <p class="stepup-description">
                        This action requires re-authentication.
                        Please enter your password to continue.
                    </p>
                    <div class="stepup-action-label">
                        Action: <code class="stepup-action-key"></code>
                    </div>
                    <label for="stepup-password">Password</label>
                    <input type="password" id="stepup-password" class="stepup-password-input"
                           autocomplete="current-password" placeholder="Enter your password">
                    <div id="stepup-error" class="stepup-error hidden"></div>
                </div>
                <div class="modal-footer">
                    <button id="stepup-cancel" class="btn btn-secondary">Cancel</button>
                    <button id="stepup-confirm" class="btn btn-primary">Confirm</button>
                </div>
            </div>
        `;
        overlay.querySelector('.stepup-action-key').textContent = actionKey;
        document.body.appendChild(overlay);

        const passwordInput = overlay.querySelector('#stepup-password');
        const errorDiv = overlay.querySelector('#stepup-error');
        const confirmBtn = overlay.querySelector('#stepup-confirm');
        const cancelBtn = overlay.querySelector('#stepup-cancel');

        passwordInput.focus();

        function _showError(msg) {
            errorDiv.textContent = msg;
            errorDiv.classList.remove('hidden');
            passwordInput.value = '';
            passwordInput.focus();
        }

        function _dismiss() {
            overlay.remove();
        }

        cancelBtn.addEventListener('click', () => {
            _dismiss();
            reject(new Error('Step-up cancelled by user'));
        });

        async function _submit() {
            const password = passwordInput.value;
            if (!password) {
                _showError('Please enter your password.');
                return;
            }

            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Verifying…';
            errorDiv.classList.add('hidden');

            try {
                const user = Auth.getCurrentUser();
                if (!user) {
                    throw new Error('Session data unavailable — please log in again.');
                }

                const nowSeconds = Math.floor(Date.now() / 1000);
                const timestampBucket = Math.floor(nowSeconds / 30);

                // OPAQUE step-up: run login challenge, derive HMAC from session_key
                const opaque = await _loadOpaque();
                const { clientLoginState, startLoginRequest } =
                    opaque.client.startLogin({ password });

                const round1 = await Api.post(`${Config.app.apiPrefix}/auth/opaque/step-up/start`, {
                    action_key: actionKey,
                    payload_hash: payloadHash,
                    timestamp: nowSeconds,
                    client_step_up_start: startLoginRequest,
                });

                const canonicalUsername = round1.username || user.username;
                const loginResult = opaque.client.finishLogin({
                    clientLoginState,
                    loginResponse: round1.login_response,
                    password,
                    identifiers: { client: canonicalUsername, server: 'tusshare' },
                });
                if (!loginResult) throw new Error('Invalid credentials');

                const { finishLoginRequest, sessionKey } = loginResult;
                const hmac = await computeOpaqueStepUpHmac(
                    sessionKey, actionKey, payloadHash, timestampBucket
                );

                const reqBody = {
                    action_key: actionKey,
                    payload_hash: payloadHash,
                    timestamp: nowSeconds,
                    hmac,
                    session_id: round1.session_id,
                    client_login_finish: finishLoginRequest,
                };

                // POST to /auth/step-up
                const res = await fetch(`${Config.app.apiPrefix}/auth/step-up`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': Api.getCsrfToken(),
                    },
                    body: JSON.stringify(reqBody),
                    credentials: 'same-origin',
                });

                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    if (res.status === 403 && err.detail?.includes('locked')) {
                        _dismiss();
                        reject(new Error(err.detail || 'Session locked due to too many failures.'));
                        return;
                    }
                    _showError('Incorrect password or verification failed. Please try again.');
                    confirmBtn.disabled = false;
                    confirmBtn.textContent = 'Confirm';
                    return;
                }

                const data = await res.json();
                const token = data.step_up_token;

                // Cache for sudo window (server window; we use 90% to avoid racing expiry)
                _cache(actionKey, token, Auth.getCurrentUser()?.step_up_window_seconds ?? 300);

                _dismiss();
                resolve(token);

            } catch (err) {
                if (err.message !== 'Step-up cancelled by user') {
                    _showError(err.message || 'An error occurred. Please try again.');
                }
                confirmBtn.disabled = false;
                confirmBtn.textContent = 'Confirm';
            }
        }

        confirmBtn.addEventListener('click', _submit);
        passwordInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') _submit();
        });
    }

    return { challenge };
})();
