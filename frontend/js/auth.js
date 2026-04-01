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
            Utils.el('button', { type: 'submit', className: 'btn btn-primary btn-full', textContent: 'Log In' }),
            Utils.el('p', { id: 'login-status', className: 'auth-status' }),
        ]);
        container.appendChild(form);
    }

    async function _handleLogin(e) {
        e.preventDefault();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const status = document.getElementById('login-status');
        const btn = e.target.querySelector('button[type="submit"]');

        btn.disabled = true;
        status.textContent = 'Authenticating...';

        try {
            const data = await Api.post(`${Config.app.apiPrefix}/auth/login`, { username, password });
            _currentUser = data.user;

            status.textContent = 'Deriving encryption key...';

            // Derive KEK from password + salt, then unwrap the master key
            const kek = await Crypto.deriveKEK(password, data.user.encryption_salt);

            if (data.user.wrapped_master_key && data.user.wrapped_master_key_iv) {
                // New model: unwrap the stored master key
                _masterKeyObj = await Crypto.unwrapMasterKey(
                    data.user.wrapped_master_key,
                    data.user.wrapped_master_key_iv,
                    kek
                );
            } else {
                // Legacy fallback: KEK *is* the master key (pre-migration accounts)
                _masterKeyObj = kek;
            }

            // Store salt in session so key-prompt can re-derive on refresh
            sessionStorage.setItem(Config.auth.sessionStorageKey, JSON.stringify({
                salt: data.user.encryption_salt,
            }));

            // Set up asymmetric PQ keys (generate + register if first login)
            _setupAsymmetricKeys(data.user, _masterKeyObj).catch((err) => {
                console.error('Asymmetric key setup failed:', err);
                Utils.showToast('Sharing keys could not be set up. User shares will not work this session.', 'warning');
            });

            status.textContent = '';
            window.location.hash = '#/files';
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
            const kek = await Crypto.deriveKEK(password, _currentUser.encryption_salt);

            if (_currentUser.wrapped_master_key && _currentUser.wrapped_master_key_iv) {
                _masterKeyObj = await Crypto.unwrapMasterKey(
                    _currentUser.wrapped_master_key,
                    _currentUser.wrapped_master_key_iv,
                    kek
                );
            } else {
                _masterKeyObj = kek;
            }

            sessionStorage.setItem(Config.auth.sessionStorageKey, JSON.stringify({
                salt: _currentUser.encryption_salt,
            }));

            _setupAsymmetricKeys(_currentUser, _masterKeyObj).catch((err) => {
                console.error('Asymmetric key setup failed:', err);
                Utils.showToast('Sharing keys could not be set up. User shares will not work this session.', 'warning');
            });

            status.textContent = '';
            if (window.location.hash === '#/files') {
                window.dispatchEvent(new HashChangeEvent('hashchange'));
            } else {
                window.location.hash = '#/files';
            }
        } catch (err) {
            status.textContent = 'Failed to unlock. Check your password.';
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

            sessionStorage.setItem(Config.auth.sessionStorageKey, JSON.stringify({
                salt: _currentUser.encryption_salt,
            }));

            // Set up asymmetric keys so share operations work this session
            _setupAsymmetricKeys(_currentUser, _masterKeyObj).catch((err) => {
                console.error('Asymmetric key setup failed:', err);
                Utils.showToast('Sharing keys could not be set up. User shares will not work this session.', 'warning');
            });

            status.textContent = '';
            if (window.location.hash === '#/files') {
                window.dispatchEvent(new HashChangeEvent('hashchange'));
            } else {
                window.location.hash = '#/files';
            }
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
        status.textContent = 'Generating encryption keys…';

        try {
            // Generate client-side salt (32 random bytes, hex-encoded)
            const saltBytes = crypto.getRandomValues(new Uint8Array(32));
            const saltHex   = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');

            // Generate masterKey + recovery key bundle
            const bundle = await Crypto.generateRegistrationBundle(password, saltHex);

            // Generate asymmetric key pair
            status.textContent = 'Generating sharing keys…';
            const { x25519KeyPair, mlkem768KeyPair } = await Crypto.generateAsymmetricKeyPair();
            const { x25519PublicKeyB64, mlkem768PublicKeyB64 } =
                await Crypto.exportAsymmetricPublicKeys(x25519KeyPair, mlkem768KeyPair);
            const { x25519PrivWrappedB64, mlkem768PrivWrappedB64, asymKeyIvB64 } =
                await Crypto.wrapAsymmetricPrivateKeys(x25519KeyPair, mlkem768KeyPair, bundle.masterKey);

            status.textContent = 'Creating account…';

            const data = await Api.post(`${Config.app.apiPrefix}/auth/register`, {
                token,
                username,
                password,
                encryption_salt:       saltHex,
                wrapped_master_key:    bundle.wrappedMasterKeyB64,
                wrapped_master_key_iv: bundle.wrappedMasterKeyIvB64,
                recovery_key_wrapped:  bundle.recoveryWrappedB64,
                recovery_key_iv:       bundle.recoveryIvB64,
                recovery_key_hash:     bundle.recoveryKeyHash,
                x25519_public_key:        x25519PublicKeyB64,
                mlkem768_public_key:      mlkem768PublicKeyB64,
                x25519_private_wrapped:   x25519PrivWrappedB64,
                mlkem768_private_wrapped: mlkem768PrivWrappedB64,
                asymmetric_key_iv:        asymKeyIvB64,
            });

            // Session setup — mirrors post-login flow
            _currentUser   = data.user;
            _masterKeyObj  = bundle.masterKey;
            _asymmetricKeys = {
                x25519PrivateKey:  x25519KeyPair.privateKey,
                mlkem768SecretKey: mlkem768KeyPair.secretKey,
            };
            sessionStorage.setItem(Config.auth.sessionStorageKey, JSON.stringify({
                salt: saltHex,
            }));

            // Show recovery key (one-time display before going to files)
            renderRecoveryKeyDisplay(container, bundle.recoveryKeyString);

        } catch (err) {
            status.textContent = err.message;
            btn.disabled = false;
        }
    }

    // ------------------------------------------------------------------
    // Recovery key display (shown once after account creation)
    // ------------------------------------------------------------------

    function renderRecoveryKeyDisplay(container, recoveryKeyString) {
        while (container.firstChild) container.removeChild(container.firstChild);

        const card = Utils.el('div', { className: 'auth-form' }, [
            Utils.el('h2', { textContent: 'Save Your Recovery Key' }),
            Utils.el('p', { className: 'text-muted', textContent:
                'This is the ONLY time this key will be shown. If you forget your password, ' +
                'this key is the only way to recover your encrypted files. Store it somewhere safe.' }),
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
                    window.location.replace('/#/files');
                },
            }),
        ]);
        container.appendChild(card);
    }

    // ------------------------------------------------------------------
    // Logout / session check
    // ------------------------------------------------------------------

    async function logout() {
        try {
            await Api.post(`${Config.app.apiPrefix}/auth/logout`);
        } catch {}
        _currentUser = null;
        _masterKeyObj = null;
        sessionStorage.removeItem(Config.auth.sessionStorageKey);
        window.location.hash = '#/login';
    }

    async function checkSession() {
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/auth/me`);
            _currentUser = data.user;
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
        renderKeyPrompt,
        renderRecoveryPrompt,
        renderRecoveryKeyDisplay,
        renderRegisterPage,
        logout,
        checkSession,
    };
})();
