/**
 * OPAQUE module loader — singleton that initialises the @serenity-kit/opaque WASM once
 * and caches it for the lifetime of the page.  Used by Auth and StepUp.
 */
let _opaqueModule = null;
async function _loadOpaque() {
    if (_opaqueModule) return _opaqueModule;
    const mod = await import('/js/lib/opaque.js');
    await mod.ready;
    _opaqueModule = mod;
    return _opaqueModule;
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

    function renderLogin(container) {
        while (container.firstChild) container.removeChild(container.firstChild);
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

            _currentUser = data.user;

            // Admin accounts have no encryption keys — go straight to the admin panel
            if (data.user.is_admin) {
                status.textContent = '';
                window.location.hash = '#/admin';
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

            // Set up asymmetric PQ keys (generate + register if first login)
            _setupAsymmetricKeys(data.user, _masterKeyObj).catch((err) => {
                console.error('Asymmetric key setup failed:', err);
                Utils.showToast('Sharing keys could not be set up. User shares will not work this session.', 'warning');
            });

            // Process any pending team operations (rotation, key grants) in background
            Teams.processPendingTeamOperations().catch((err) => {
                console.warn('Pending team operations check failed:', err.message);
            });

            status.textContent = '';
            const pendingJoin = sessionStorage.getItem('pendingJoinHash');
            if (pendingJoin) {
                sessionStorage.removeItem('pendingJoinHash');
                window.location.hash = pendingJoin;
            } else {
                window.location.hash = '#/files';
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
        while (container.firstChild) container.removeChild(container.firstChild);

        const form = Utils.el('form', { className: 'auth-form', onSubmit: _handleKeyDerive }, [
            Utils.el('h2', { textContent: 'Encryption Key Required' }),
            Utils.el('p', { className: 'text-muted', textContent: 'Enter your password to unlock your encryption key.' }),
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
        container.appendChild(form);
    }

    async function _handleKeyDerive(e) {
        e.preventDefault();
        const password = document.getElementById('key-password').value;
        const status = document.getElementById('key-status');
        const btn = e.target.querySelector('button[type="submit"]');

        btn.disabled = true;
        status.textContent = 'Deriving encryption key...';

        try {
            // Re-run the full OPAQUE login challenge to get a fresh export_key → KEK
            status.textContent = 'Running zero-knowledge auth…';
            const { data, exportKey } = await _runOpaqueLogin(_currentUser.username, password);
            _currentUser = data.user;
            const kek = await Crypto.deriveOpaqueKEK(exportKey);

            _masterKeyObj = await Crypto.unwrapMasterKey(
                _currentUser.wrapped_master_key,
                _currentUser.wrapped_master_key_iv,
                kek
            );

            _unlockFailures = 0;
            await _saveSessionKeyData(_masterKeyObj, null);

            _setupAsymmetricKeys(_currentUser, _masterKeyObj).catch((err) => {
                console.error('Asymmetric key setup failed:', err);
                Utils.showToast('Sharing keys could not be set up. User shares will not work this session.', 'warning');
            });

            // Process any pending team operations (rotation, key grants) in background
            Teams.processPendingTeamOperations().catch((err) => {
                console.warn('Pending team operations check failed:', err.message);
            });

            status.textContent = '';
            // After unlock, navigate to the current hash — but if the hash is #/login
            // (which is where the unlock prompt is rendered), redirect to #/files instead
            // so the user isn't sent back to the login form.
            const currentHash = window.location.hash;
            if (!currentHash || currentHash === '#/' || currentHash === '#/login') {
                window.location.hash = '#/files';
            } else {
                window.dispatchEvent(new HashChangeEvent('hashchange'));
            }
        } catch (err) {
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
        while (container.firstChild) container.removeChild(container.firstChild);

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
            _setupAsymmetricKeys(_currentUser, _masterKeyObj).catch((err) => {
                console.error('Asymmetric key setup failed:', err);
                Utils.showToast('Sharing keys could not be set up. User shares will not work this session.', 'warning');
            });

            // Process any pending team operations (rotation, key grants) in background
            Teams.processPendingTeamOperations().catch((err) => {
                console.warn('Pending team operations check failed:', err.message);
            });

            status.textContent = '';
            // Re-dispatch hashchange so the router navigates to whatever hash is
            // currently set — preserves deep links like #/files/<id> after a refresh.
            window.dispatchEvent(new HashChangeEvent('hashchange'));
        } catch (err) {
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
            _asymmetricKeys = await Crypto.unwrapAsymmetricPrivateKeys(
                user.x25519_private_wrapped,
                user.mlkem768_private_wrapped,
                user.asymmetric_key_iv,
                masterKey,
                user.x25519_public_key
            );
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
        _currentUser = Object.assign({}, _currentUser, {
            x25519_public_key: x25519PublicKeyB64,
            mlkem768_public_key: mlkem768PublicKeyB64,
            x25519_private_wrapped: x25519PrivWrappedB64,
            mlkem768_private_wrapped: mlkem768PrivWrappedB64,
            asymmetric_key_iv: asymKeyIvB64,
        });

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
        while (container.firstChild) container.removeChild(container.firstChild);

        // Step 1: validate token before showing form
        const checking = Utils.el('div', { className: 'auth-form' }, [
            Utils.el('p', { className: 'text-muted', textContent: 'Validating invite…' }),
        ]);
        container.appendChild(checking);

        try {
            await Api.get(`${Config.app.apiPrefix}/auth/invite/${encodeURIComponent(token)}`);
        } catch {
            while (container.firstChild) container.removeChild(container.firstChild);
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
        while (container.firstChild) container.removeChild(container.firstChild);

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

            // Show recovery key (one-time display before going to files)
            renderRecoveryKeyDisplay(container, recoveryKeyString);

        } catch (err) {
            status.textContent = err.message;
            btn.disabled = false;
        }
    }

    // ------------------------------------------------------------------
    // First-run bootstrap (admin account creation)
    // ------------------------------------------------------------------

    function renderBootstrap(container) {
        while (container.firstChild) container.removeChild(container.firstChild);

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
            status.textContent = err.message;
            btn.disabled = false;
        }
    }

    // ------------------------------------------------------------------
    // ------------------------------------------------------------------
    // Forgot password (recovery key → new password → new recovery key)
    // ------------------------------------------------------------------

    function renderForgotPassword(container, prefillUsername = '') {
        while (container.firstChild) container.removeChild(container.firstChild);

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
    }

    // Recovery key display (shown once after account creation)
    // ------------------------------------------------------------------

    function renderRecoveryKeyDisplay(container, recoveryKeyString, destination = '/#/files', subtitle = null) {
        while (container.firstChild) container.removeChild(container.firstChild);

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
                    const before = window.location.href;
                    window.location.replace(destination);
                    // If the URL didn't change (destination hash was already active),
                    // the browser won't fire hashchange — dispatch it manually so the
                    // router re-renders the target page (e.g. login after password reset).
                    if (window.location.href === before) {
                        window.dispatchEvent(new HashChangeEvent('hashchange'));
                    }
                },
            }),
        ]);
        container.appendChild(card);
    }

    // ------------------------------------------------------------------
    // Logout / session check
    // ------------------------------------------------------------------

    async function logout() {
        // Dismiss the transfer panel immediately so the UI is clean at once,
        // then signal every active transfer to stop.  Uploads are stopped without
        // deleting the server-side partial so they appear as resumable pending rows
        // on the user's next login.  Downloads are aborted (no server state to keep).
        TransferManager.dismissAll();
        TransferManager.pauseAll();

        // Close any open confirm/prompt modals so they don't linger on the login page.
        document.querySelectorAll('.modal-overlay').forEach(el => {
            if (el.parentNode) el.parentNode.removeChild(el);
        });

        try {
            await Api.post(`${Config.app.apiPrefix}/auth/logout`);
        } catch {}
        _currentUser = null;
        _masterKeyObj = null;
        sessionStorage.removeItem(Config.auth.sessionStorageKey);
        sessionStorage.removeItem(Config.publicDevice.sessionStorageKey);
        window.location.hash = '#/login';
    }

    async function checkSession() {
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
        logout,
        checkSession,
        touchKeyCache,
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
    async function challenge(actionKey, payloadHash, challengeType = 'password') {
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
                        Action: <code class="stepup-action-key">${actionKey}</code>
                    </div>
                    <label for="stepup-password">Password</label>
                    <input type="password" id="stepup-password" class="stepup-password-input"
                           autocomplete="current-password" placeholder="Enter your password">
                    <div id="stepup-error" class="stepup-error" style="display:none"></div>
                </div>
                <div class="modal-footer">
                    <button id="stepup-cancel" class="btn btn-secondary">Cancel</button>
                    <button id="stepup-confirm" class="btn btn-primary">Confirm</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);

        const passwordInput = overlay.querySelector('#stepup-password');
        const errorDiv = overlay.querySelector('#stepup-error');
        const confirmBtn = overlay.querySelector('#stepup-confirm');
        const cancelBtn = overlay.querySelector('#stepup-cancel');

        passwordInput.focus();

        function _showError(msg) {
            errorDiv.textContent = msg;
            errorDiv.style.display = '';
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
            errorDiv.style.display = 'none';

            try {
                const user = Auth.getCurrentUser();
                if (!user) {
                    throw new Error('Session data unavailable — please log in again.');
                }

                const nowSeconds = Math.floor(Date.now() / 1000);
                const timestampBucket = Math.floor(nowSeconds / 30);
                let reqBody;

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

                const loginResult = opaque.client.finishLogin({
                    clientLoginState,
                    loginResponse: round1.login_response,
                    password,
                    identifiers: { client: user.username, server: 'tusshare' },
                });
                if (!loginResult) throw new Error('Invalid credentials');

                const { finishLoginRequest, sessionKey } = loginResult;
                const hmac = await computeOpaqueStepUpHmac(
                    sessionKey, actionKey, payloadHash, timestampBucket
                );

                reqBody = {
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
                _cache(actionKey, token, Config.auth.stepUpWindowSeconds ?? 300);

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
