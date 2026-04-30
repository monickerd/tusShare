/**
 * tusShare — SPA router and application shell.
 *
 * Hash-based routing: #/login, #/files, #/files/{id}, #/shared,
 * #/shares, #/admin, #/s/{token}, #/l/{slug}
 */
const App = (() => {
    const _appEl = () => document.getElementById('app');

    // Theme config fetched from /api/v1/theme on startup.
    // Used by _renderShell to apply org brand name and logo.
    let _themeConfig = null;

    async function _loadTheme() {
        try {
            _themeConfig = await Api.get(`${Config.app.apiPrefix}/theme`);
            if (_themeConfig.brand_name) {
                document.title = _themeConfig.brand_name;
            }
        } catch {
            _themeConfig = {};
        }
    }

    // Apply data-ui-* attributes to <body> from theme.ui flags.
    // Each flag key (snake_case) becomes data-ui-<kebab-case>="true"/"false".
    // CSS targets body[data-ui-<flag>="false"] to suppress controlled elements.
    // Called once on init; <body> persists across route changes so no re-apply needed.
    function _applyThemeFlags() {
        const ui = (_themeConfig && _themeConfig.ui) || {};
        for (const [flag, value] of Object.entries(ui)) {
            document.body.setAttribute(
                'data-ui-' + flag.replace(/_/g, '-'),
                value ? 'true' : 'false',
            );
        }
    }

    function _buildBrandEl() {
        const name    = (_themeConfig && _themeConfig.brand_name) || Config.app.name;
        const logoUrl = _themeConfig && _themeConfig.logo_url;
        if (logoUrl) {
            return Utils.el('a', { href: '#/files', className: 'header-brand' }, [
                Utils.el('img', { src: logoUrl, alt: name, className: 'header-logo' }),
            ]);
        }
        return Utils.el('a', { href: '#/files', className: 'header-brand', textContent: name });
    }

    const _routes = [
        { pattern: /^#\/login$/,                                                              handler: _routeLogin },
        { pattern: /^#\/pinned$/,                                                             handler: _routePinned },
        { pattern: /^#\/files\/([a-f0-9-]+)$/,                                               handler: _routeFolder },
        { pattern: /^#\/files$/,                                                              handler: _routeFiles },
        { pattern: /^#\/shared$/,                                                             handler: _routeShared },
        { pattern: /^#\/shares\/received$/,                                                   handler: _routeReceivedShares },
        { pattern: /^#\/shares$/,                                                             handler: _routeShares },
        { pattern: /^#\/team-folders\/([a-f0-9-]+)$/,                                        handler: _routeTeamFolder },
        { pattern: /^#\/team-folders$/,                                                       handler: _routeTeamFolders },
        { pattern: /^#\/teams\/([0-9a-f-]+)$/,                                               handler: _routeTeamDetail },
        { pattern: /^#\/teams$/,                                                              handler: _routeTeams },
        { pattern: /^#\/admin$/,                                                              handler: _routeAdmin },
        { pattern: /^#\/setup$/,                                                              handler: _routeSetup },
        { pattern: /^#\/join\/([0-9a-f-]+)\/([0-9a-f-]+)\/([A-Za-z0-9_-]+)$/,               handler: _routeEphemeralJoin },
        { pattern: /^#\/mfa$/,                                                                handler: _routeMfa },
        { pattern: /^#\/s\/(.+)$/,                                                            handler: _routePublicShare },
        { pattern: /^#\/l\/(.+)$/,                                                            handler: _routeShortLink },
    ];

    async function init() {
        // Load org theme config (brand name, logo, ui flags) before rendering anything.
        // Errors are swallowed — falls back to Config.app.name gracefully.
        await _loadTheme();
        _applyThemeFlags();

        // Fetch server-enforced chunk size so uploads use the correct value.
        // Fire-and-forget: falls back to the Config default if the fetch fails.
        Upload.fetchAndSetChunkSize();

        // OIDC callback detection — check query params set by the server after the
        // IdP redirect.  Must run before the normal auth check so we handle the
        // callback URL before it is stripped by the SPA router.
        const _qs = new URLSearchParams(window.location.search);
        if (_qs.has('oidc_error')) {
            // Clean the query string and show login with an error banner
            history.replaceState(null, '', '/');
            window.location.hash = '#/login';
            await _routeLogin(_appEl());
            Utils.showToast('Sign-in via identity provider failed. Please try again.', 'error');
            return;
        }
        if (_qs.has('mfa_pending')) {
            const pendingToken = _qs.get('mfa_pending');
            history.replaceState(null, '', '/');
            window.location.hash = '#/login';
            // Fetch available MFA methods from the pending token context
            // by attempting a TOTP verify with an empty code — actually, we call
            // a dedicated endpoint to list the methods for a pending token.
            try {
                const mfaInfo = await Api.post(
                    `${Config.app.apiPrefix}/auth/mfa/pending-info`,
                    { pending_token: pendingToken },
                );
                Auth.renderOidcMfaChallenge(_appEl(), pendingToken, mfaInfo.methods || []);
            } catch {
                // If we can't determine methods, show an empty challenge — the MFA
                // verify endpoints will reject the token if it's expired.
                Auth.renderOidcMfaChallenge(_appEl(), pendingToken, []);
            }
            return;
        }

        // Path-based public routes — handled before auth check so unauthenticated
        // users land on the correct page rather than being bounced to login.
        const path = window.location.pathname;

        // /register/<token> — invite-based registration (no auth required)
        if (path.startsWith('/register/')) {
            const token = path.slice('/register/'.length);
            Auth.renderRegisterPage(_appEl(), token);
            return;
        }

        // /s/<token>#shareKey and /l/<slug>#shareKey — public share views
        if (path.startsWith('/s/')) {
            const token          = path.slice(3);
            const shareKeyB64url = window.location.hash.slice(1);
            Shares.renderPublicSharePage(_appEl(), token, shareKeyB64url);
            return;
        }
        if (path.startsWith('/l/')) {
            const slug           = path.slice(3);
            const shareKeyB64url = window.location.hash.slice(1);
            Shares.renderShortLinkPage(_appEl(), slug, shareKeyB64url);
            return;
        }

        window.addEventListener('hashchange', _onHashChange);

        // Check for existing session
        const hasSession = await Auth.checkSession();

        if (!hasSession) {
            // If the user landed on a join link without a session, save the intent so
            // auth.js can redirect back to it after a successful login.
            const h = window.location.hash;
            if (h && h.startsWith('#/join/')) {
                sessionStorage.setItem('pendingJoinHash', h);
            }
            // Setting hash to #/login won't fire hashchange if the hash is already
            // #/login (browser no-ops same-value assignments). Render directly so
            // a refresh on the login page doesn't hang on "Loading tusShare...".
            window.location.hash = '#/login';
            await _routeLogin(_appEl());
            return;
        }

        // Session exists but may need key derivation (page refresh).
        // Admin accounts have no encryption keys — skip the key prompt entirely.
        // Public-device sessions: no key prompt — the tab close cleared sessionStorage
        // intentionally, so go to login instead of asking for the password again.
        if (!Auth.getMasterKeyObj() && !Auth.getCurrentUser()?.is_admin) {
            const user = Auth.getCurrentUser();
            if (user?.is_public_device) {
                // Public-device session: tab close cleared key material intentionally.
                // Go to login rather than prompting for the password again.
                window.location.hash = '#/login';
                await _routeLogin(_appEl());
                return;
            }
            const container = _appEl();
            Auth.renderKeyPrompt(container);
            return;
        }

        // MFA enforcement gate: if required mode and user has no credentials,
        // redirect to #/mfa enrollment before allowing any file access.
        if (!Auth.getCurrentUser()?.is_admin) {
            try {
                const mfaStatus = await Api.get(`${Config.app.apiPrefix}/auth/mfa/status`);
                if (mfaStatus.enforcement === 'required' && mfaStatus.active_count === 0) {
                    window.location.hash = '#/mfa';
                    _onHashChange();
                    return;
                }
                // Show nudge banner in optional mode (non-blocking)
                if (mfaStatus.enforcement === 'optional') {
                    Auth.checkMfaBanner(_appEl());
                }
            } catch {
                // Non-critical — proceed without enforcement
            }
        }

        // Start persistent identity watch so all tabs detect admin-forced changes.
        Auth.startIdentityWatch();

        // Navigate to current hash or default
        const defaultHash = Auth.getCurrentUser()?.is_admin ? '#/admin' : '#/files';
        if (!window.location.hash || window.location.hash === '#/') {
            window.location.hash = defaultHash;
        } else {
            _onHashChange();
        }
    }

    function _onHashChange() {
        const hash = window.location.hash || '#/login';
        const container = _appEl();

        // Tear down any active live-update stream. File routes re-open it
        // once their folder finishes loading; all other routes leave it closed.
        Files.stopLive();

        // Public / semi-public routes — no auth check at router level.
        // #/join/ is handled by Teams.renderEphemeralJoinPage which saves intent
        // and redirects to #/login if the user is not authenticated.
        if (hash.startsWith('#/s/') || hash.startsWith('#/l/') || hash.startsWith('#/join/')) {
            for (const route of _routes) {
                const match = hash.match(route.pattern);
                if (match) {
                    route.handler(container, ...match.slice(1));
                    return;
                }
            }
        }

        // Login route
        if (hash === '#/login') {
            _routeLogin(container);
            return;
        }

        // All other routes require auth
        if (!Auth.getCurrentUser()) {
            window.location.hash = '#/login';
            return;
        }

        // Need master key for file operations; admin accounts have no keys
        if (!Auth.getMasterKeyObj()) {
            if (Auth.getCurrentUser()?.is_admin) {
                // Admin only has access to the admin route and the first-run wizard.
                // Redirect away from file routes, but let #/admin and #/setup fall through.
                if (hash !== '#/admin' && hash !== '#/setup') {
                    window.location.hash = '#/admin';
                    return;
                }
            } else {
                Auth.renderKeyPrompt(container);
                return;
            }
        }

        _updateSidebarActive(hash);

        for (const route of _routes) {
            const match = hash.match(route.pattern);
            if (match) {
                route.handler(container, ...match.slice(1));
                return;
            }
        }

        // 404 — redirect to files
        window.location.hash = '#/files';
    }

    async function _routeLogin(container) {
        // On first run, show the bootstrap UI instead of the login form.
        try {
            const status = await Api.get(`${Config.app.apiPrefix}/auth/opaque/bootstrap/status`);
            if (status.needs_bootstrap) {
                Auth.renderBootstrap(container);
                return;
            }
        } catch {
            // If the status check fails (network error, server starting up), fall through to login.
        }
        Auth.renderLogin(container);
    }

    function _routePinned(container) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        main.appendChild(Utils.el('div', { className: 'page-content' }, [
            Utils.el('h2', { textContent: 'Pinned' }),
            Utils.el('p', { className: 'text-muted', textContent: 'No pinned items yet. Pinning files and folders for quick access is coming soon.' }),
        ]));
    }

    function _routeFiles(container) {
        _renderShell(container);
        Files.renderFileBrowser(document.getElementById('main-content'));
    }

    function _routeFolder(container, folderId) {
        _renderShell(container);
        Files.renderFileBrowser(document.getElementById('main-content'), { initialFolderId: folderId });
    }

    async function _routeShared(container) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/folders`);
            if (data.shared_folder) {
                Files.renderFileBrowser(main, { shared: true });
                Files.loadFolder(data.shared_folder.id);
            } else {
                main.textContent = 'No shared folder available.';
            }
        } catch (err) {
            main.textContent = 'Failed to load shared folder: ' + err.message;
        }
    }

    function _routeShares(container) {
        _renderShell(container);
        Shares.renderSharesPage(document.getElementById('main-content'));
    }

    function _routeReceivedShares(container) {
        _renderShell(container);
        Shares.renderReceivedSharesPage(document.getElementById('main-content'));
    }

    function _routeTeamFolder(container, folderId) {
        _renderShell(container);
        Files.renderFileBrowser(document.getElementById('main-content'), { teamView: true, initialFolderId: folderId });
    }

    function _routeTeamFolders(container) {
        _renderShell(container);
        Teams.renderTeamFoldersPage(document.getElementById('main-content'));
    }

    function _routeTeams(container) {
        _renderShell(container);
        Teams.renderTeamsPage(document.getElementById('main-content'));
    }

    function _routeTeamDetail(container, teamId) {
        _renderShell(container);
        Teams.renderTeamDetailPage(document.getElementById('main-content'), teamId);
    }

    async function _routeAdmin(container) {
        const user = Auth.getCurrentUser();
        if (!user || !user.is_admin) {
            window.location.hash = '#/files';
            return;
        }
        // Check first-run flag before rendering admin panel.
        // On error (network/auth) fall through to normal admin panel.
        try {
            const { settings } = await Api.get(`${Config.app.apiPrefix}/admin/settings`);
            if (!settings || settings.first_run_completed !== '1') {
                window.location.hash = '#/setup';
                return;
            }
        } catch { /* fall through */ }
        _renderShell(container);
        Admin.renderAdminPage(document.getElementById('main-content'));
    }

    function _routeSetup(container) {
        const user = Auth.getCurrentUser();
        if (!user || !user.is_admin) {
            window.location.hash = '#/login';
            return;
        }
        _renderShell(container);
        Wizard.renderSetupWizard(document.getElementById('main-content'));
    }

    function _routeMfa(container) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        Auth.renderMfaSettings(main);
    }

    function _routePublicShare(container, token) {
        // Public share pages are now served via path-based routing in init().
        // This hash-based fallback handles direct #/s/ navigation within the SPA.
        const shareKeyB64url = '';  // No fragment available via hash routing
        Shares.renderPublicSharePage(container, token, shareKeyB64url);
    }

    function _routeShortLink(container, slug) {
        const shareKeyB64url = '';
        Shares.renderShortLinkPage(container, slug, shareKeyB64url);
    }

    function _routeEphemeralJoin(container, teamId, slotId, kEphemeralB64url) {
        Teams.renderEphemeralJoinPage(container, teamId, slotId, kEphemeralB64url);
    }

    // -----------------------------------------------------------------------
    // Account menu dropdown
    // -----------------------------------------------------------------------

    let _accountMenuOpen = false;
    let _accountMenuEl = null;

    function _toggleAccountMenu() {
        if (_accountMenuOpen) {
            _closeAccountMenu();
        } else {
            _openAccountMenu();
        }
    }

    function _closeAccountMenu() {
        if (_accountMenuEl && _accountMenuEl.parentNode) {
            _accountMenuEl.parentNode.removeChild(_accountMenuEl);
        }
        _accountMenuEl = null;
        _accountMenuOpen = false;
    }

    function _openAccountMenu() {
        _closeAccountMenu();
        _accountMenuOpen = true;
        Utils.markAllRead();

        const panel = Utils.el('div', { className: 'account-menu' });

        // Close when clicking outside
        const _outsideClick = (e) => {
            const btn = document.querySelector('.header-account-btn');
            if (!panel.contains(e.target) && e.target !== btn && !btn?.contains(e.target)) {
                _closeAccountMenu();
                document.removeEventListener('mousedown', _outsideClick, true);
            }
        };
        document.addEventListener('mousedown', _outsideClick, true);

        // Tab bar
        const tabs = ['Notifications', 'Transfers', 'My Account'];
        let _activeTab = 'Notifications';
        const contentEl = Utils.el('div', { className: 'account-menu-content' });

        const tabBar = Utils.el('div', { className: 'account-menu-tabs' },
            tabs.map(label => {
                const btn = Utils.el('button', {
                    className: 'account-menu-tab' + (label === _activeTab ? ' active' : ''),
                    textContent: label,
                    onClick: () => {
                        _activeTab = label;
                        panel.querySelectorAll('.account-menu-tab').forEach(b =>
                            b.classList.toggle('active', b.textContent === label));
                        _renderTabContent(contentEl, label);
                    },
                });
                return btn;
            })
        );

        panel.appendChild(tabBar);
        panel.appendChild(contentEl);
        _renderTabContent(contentEl, _activeTab);

        document.querySelector('.header-actions')?.appendChild(panel);
        _accountMenuEl = panel;
    }

    function _renderTabContent(container, tab) {
        while (container.firstChild) container.removeChild(container.firstChild);
        if (tab === 'Notifications')  _renderNotificationsTab(container);
        else if (tab === 'Transfers') _renderTransfersTab(container);
        else                          _renderMyAccountTab(container);
    }

    function _renderNotificationsTab(container) {
        const history = Utils.getToastHistory();
        if (history.length === 0) {
            container.appendChild(Utils.el('p', { className: 'account-menu-empty', textContent: 'No notifications this session.' }));
            return;
        }
        const list = Utils.el('ul', { className: 'notification-list' });
        for (let i = history.length - 1; i >= 0; i--) {
            const n = history[i];
            list.appendChild(Utils.el('li', { className: `notification-item notification-item--${n.type}` }, [
                Utils.el('span', { className: 'notification-msg', textContent: n.message }),
                Utils.el('span', { className: 'notification-time', textContent: Utils.timeAgo(n.timestamp.toISOString()) }),
            ]));
        }
        container.appendChild(list);
    }

    function _renderTransfersTab(container) {
        const transfers = TransferManager.getAll();
        if (transfers.length === 0) {
            container.appendChild(Utils.el('p', { className: 'account-menu-empty', textContent: 'No active transfers.' }));
            return;
        }
        const list = Utils.el('ul', { className: 'transfer-list' });
        for (const t of transfers) {
            list.appendChild(Utils.el('li', { className: `transfer-item transfer-item--${t.status}` }, [
                Utils.el('span', { className: 'transfer-item-icon', textContent: t.type === 'upload' ? '↑' : '↓' }),
                Utils.el('span', { className: 'transfer-item-name', textContent: t.label }),
                Utils.el('span', { className: 'transfer-item-pct',  textContent: t.pct }),
            ]));
        }
        container.appendChild(list);
    }

    function _renderMyAccountTab(container) {
        const user = Auth.getCurrentUser();
        if (!user) return;

        // --- Roles ---
        const rolesSection = Utils.el('section', { className: 'account-section' }, [
            Utils.el('h4', { className: 'account-section-title', textContent: 'Roles' }),
            Utils.el('p', { className: 'account-section-body', textContent: [...user.roles].join(', ') || 'none' }),
        ]);

        // --- Key & auth status ---
        const keyStatus = user.wrapped_master_key ? 'Encryption key present' : 'No encryption key';
        const idpStatus = user.auth_method === 'opaque' ? 'Password (OPAQUE)' : user.auth_method;
        const keySection = Utils.el('section', { className: 'account-section' }, [
            Utils.el('h4', { className: 'account-section-title', textContent: 'Account' }),
            Utils.el('p', { className: 'account-section-body' }, [
                Utils.el('span', { textContent: `Auth: ${idpStatus}` }), Utils.el('br'),
                Utils.el('span', { textContent: keyStatus }),
            ]),
        ]);

        // --- MFA & Security ---
        const mfaSection = Utils.el('section', { className: 'account-section' }, [
            Utils.el('h4', { className: 'account-section-title', textContent: 'Security' }),
            Utils.el('a', { href: '#/mfa', className: 'btn btn-secondary btn-sm', textContent: 'MFA Settings',
                onClick: () => _closeAccountMenu() }),
        ]);

        // Change password — deferred: requires OPAQUE re-registration flow (not yet implemented)

        // --- Sessions (async) ---
        const sessionsSection = Utils.el('section', { className: 'account-section' });
        sessionsSection.appendChild(Utils.el('h4', { className: 'account-section-title', textContent: 'Active Sessions' }));
        const sessionsList = Utils.el('div', { className: 'account-section-body' });
        sessionsList.textContent = 'Loading…';
        sessionsSection.appendChild(sessionsList);
        Api.get(`${Config.app.apiPrefix}/auth/me/sessions`).then(data => {
            sessionsList.textContent = '';
            if (!data.sessions.length) { sessionsList.textContent = 'No other sessions.'; return; }
            const ul = Utils.el('ul', { className: 'sessions-list' });
            for (const s of data.sessions) {
                const label = [
                    s.is_current ? '(this session)' : '',
                    s.is_public_device ? 'Public device' : '',
                    s.last_active_at ? `Last active ${Utils.timeAgo(s.last_active_at)}` : `Created ${Utils.timeAgo(s.created_at)}`,
                ].filter(Boolean).join(' · ');
                const revokeBtn = s.is_current ? null : Utils.el('button', {
                    className: 'btn btn-danger btn-xs',
                    textContent: 'Revoke',
                    onClick: async () => {
                        try {
                            await Api.del(`${Config.app.apiPrefix}/auth/me/sessions/${s.id}`);
                            li.remove();
                            Utils.showToast('Session revoked', 'success');
                        } catch (e) {
                            Utils.showToast(`Failed: ${e.message}`, 'error');
                        }
                    },
                });
                const li = Utils.el('li', { className: 'session-item' + (s.is_current ? ' session-item--current' : '') }, [
                    Utils.el('span', { textContent: label }),
                    ...(revokeBtn ? [revokeBtn] : []),
                ]);
                ul.appendChild(li);
            }
            sessionsList.appendChild(ul);
            if (data.sessions.length > 1) {
                const revokeAllBtn = Utils.el('button', {
                    className: 'btn btn-danger btn-sm',
                    style: 'margin-top:8px',
                    textContent: 'Revoke all other sessions',
                    onClick: async () => {
                        try {
                            const r = await Api.del(`${Config.app.apiPrefix}/auth/me/sessions`);
                            Utils.showToast(`${r.revoked} session(s) revoked`, 'success');
                            sessionsList.textContent = 'No other sessions.';
                        } catch (e) {
                            Utils.showToast(`Failed: ${e.message}`, 'error');
                        }
                    },
                });
                sessionsList.appendChild(revokeAllBtn);
            }
        }).catch(() => { sessionsList.textContent = 'Could not load sessions.'; });

        // --- Activity log (async) ---
        const activitySection = Utils.el('section', { className: 'account-section' });
        activitySection.appendChild(Utils.el('h4', { className: 'account-section-title', textContent: 'Recent Activity' }));
        const activityList = Utils.el('div', { className: 'account-section-body' });
        activityList.textContent = 'Loading…';
        activitySection.appendChild(activityList);
        Api.get(`${Config.app.apiPrefix}/auth/me/activity`).then(data => {
            activityList.textContent = '';
            if (!data.events.length) { activityList.textContent = 'No activity recorded.'; return; }
            const ul = Utils.el('ul', { className: 'activity-list' });
            for (const ev of data.events.slice(0, 10)) {
                ul.appendChild(Utils.el('li', { className: 'activity-item' }, [
                    Utils.el('span', { className: 'activity-type', textContent: ev.event_type }),
                    Utils.el('span', { className: 'activity-time', textContent: Utils.timeAgo(ev.timestamp) }),
                ]));
            }
            activityList.appendChild(ul);
        }).catch(() => { activityList.textContent = 'Could not load activity.'; });

        // --- Delete account (async: check admin setting) ---
        const deleteSection = Utils.el('section', { className: 'account-section' });
        Api.get(`${Config.app.apiPrefix}/admin/settings`).then(data => {
            if (data.settings?.allow_user_delete_own_account === 'true') {
                deleteSection.appendChild(Utils.el('h4', { className: 'account-section-title account-section-title--danger', textContent: 'Danger Zone' }));
                deleteSection.appendChild(Utils.el('button', {
                    className: 'btn btn-danger btn-sm',
                    textContent: 'Delete My Account',
                    onClick: async () => {
                        const confirmed = await Utils.showConfirm(
                            'This will permanently delete your account and all your files. This cannot be undone. Continue?'
                        );
                        if (!confirmed) return;
                        try {
                            await Api.del(`${Config.app.apiPrefix}/auth/me`);
                            Auth.logout();
                        } catch (e) {
                            Utils.showToast(`Delete failed: ${e.message}`, 'error');
                        }
                    },
                }));
            }
        }).catch(() => {});

        const sections = [rolesSection, keySection, mfaSection, sessionsSection, activitySection, deleteSection];
        for (const s of sections) container.appendChild(s);
    }

    function _renderShell(container) {
        // Only re-render shell if not already present
        if (container.querySelector('.app-shell')) return;

        while (container.firstChild) container.removeChild(container.firstChild);
        const user = Auth.getCurrentUser();

        const sidebarToggle = Utils.el('button', {
            className: 'sidebar-toggle',
            title: 'Toggle sidebar',
            textContent: '\u2630',
            onClick: () => {
                const sb = document.querySelector('.sidebar');
                if (sb) sb.classList.toggle('open');
            },
        });

        const nav = Utils.el('nav', { className: 'sidebar-nav' }, [
            Utils.el('a', { href: '#/pinned', className: 'sidebar-link', id: 'nav-pinned', textContent: 'Pinned' }),

            Utils.el('a', { href: '#/files', className: 'sidebar-link', id: 'nav-files', textContent: 'My Files' }),
            Utils.el('div', { className: 'sidebar-submenu' }, [
                Utils.el('a', { href: '#/shares', className: 'sidebar-link sidebar-sublink', id: 'nav-shares', textContent: 'Shared From Me' }),
            ]),

            Utils.el('div', { className: 'sidebar-section-label', textContent: 'Shared' }),
            Utils.el('div', { className: 'sidebar-submenu' }, [
                Utils.el('a', { href: '#/shares/received', className: 'sidebar-link sidebar-sublink', id: 'nav-received', textContent: 'Shared With Me' }),
                Utils.el('a', { href: '#/team-folders',    className: 'sidebar-link sidebar-sublink', id: 'nav-team-folders', textContent: 'Team Folders' }),
            ]),

            Utils.el('a', { href: '#/teams', className: 'sidebar-link', id: 'nav-teams', textContent: 'Manage Teams' }),
        ]);
        if (user && user.is_admin) {
            nav.appendChild(Utils.el('a', {
                href: '#/admin', className: 'sidebar-link sidebar-admin', id: 'nav-admin', textContent: 'Admin',
            }));
        }

        const unreadDot = Utils.el('span', { className: 'header-unread-dot' });
        const accountBtn = Utils.el('button', {
            className: 'btn btn-sm header-account-btn',
            onClick: _toggleAccountMenu,
        }, [
            Utils.el('span', { textContent: user ? user.username : '' }),
            unreadDot,
        ]);
        Utils.onUnreadChange(count => {
            unreadDot.classList.toggle('header-unread-dot--active', count > 0);
        });

        const shellChildren = [
            Utils.el('header', { className: 'app-header' }, [
                Utils.el('div', { style: 'display:flex;align-items:center;gap:8px' }, [
                    sidebarToggle,
                    _buildBrandEl(),
                ]),
                Utils.el('div', { className: 'header-actions' }, [
                    accountBtn,
                    Utils.el('button', {
                        className: 'btn btn-secondary btn-sm',
                        textContent: 'Logout',
                        onClick: () => Auth.logout(),
                    }),
                ]),
            ]),
        ];

        // Public device banner — shown when the user checked "Public Device" at login.
        // Dismissed by clicking X (removes it from DOM and clears the sessionStorage flag
        // so it does not re-appear on route changes within the same tab).
        const cfg = Config.publicDevice;
        if (cfg.bannerVisible && sessionStorage.getItem(cfg.sessionStorageKey) === '1') {
            const banner = Utils.el('div', { className: 'public-device-banner' }, [
                Utils.el('span', { textContent: cfg.bannerText }),
                Utils.el('button', {
                    className: 'public-device-banner-dismiss',
                    title: 'Dismiss',
                    textContent: '\u00d7',   // ×
                    onClick: () => {
                        sessionStorage.removeItem(cfg.sessionStorageKey);
                        if (banner.parentNode) banner.parentNode.removeChild(banner);
                    },
                }),
            ]);
            shellChildren.push(banner);
        }

        // Admin transparency banner — shown when key escrow is active for one or more
        // of the user's teams. Suppressible via theme.json ui.admin_transparency_banner=false.
        // Dismissed per-session; will reappear on next login if escrow is still active.
        const _ESCROW_DISMISSED_KEY = 'escrow_banner_dismissed';
        if (
            user && user.escrow_active &&
            !sessionStorage.getItem(_ESCROW_DISMISSED_KEY)
        ) {
            const escrowBanner = Utils.el('div', { className: 'admin-transparency-banner' }, [
                Utils.el('span', {
                    textContent: 'Admin key escrow is active: designated escrow agents may access the encryption keys for one or more teams you belong to.',
                }),
                Utils.el('button', {
                    className: 'admin-transparency-banner-dismiss',
                    title: 'Dismiss',
                    textContent: '\u00d7',   // ×
                    onClick: () => {
                        sessionStorage.setItem(_ESCROW_DISMISSED_KEY, '1');
                        if (escrowBanner.parentNode) escrowBanner.parentNode.removeChild(escrowBanner);
                    },
                }),
            ]);
            shellChildren.push(escrowBanner);
        }

        shellChildren.push(
            Utils.el('div', { className: 'app-body' }, [
                Utils.el('aside', { className: 'sidebar', id: 'folder-sidebar' }, [
                    nav,
                    Utils.el('div', { id: 'folder-tree', className: 'folder-tree' }),
                ]),
                Utils.el('div', { id: 'main-content', className: 'app-main' }),
            ]),
        );

        const shell = Utils.el('div', { className: 'app-shell' }, shellChildren);

        container.appendChild(shell);
    }

    function _updateSidebarActive(hash) {
        const rules = [
            { id: 'nav-pinned',       test: h => h === '#/pinned' },
            { id: 'nav-files',        test: h => /^#\/files(\/.*)?$/.test(h) },
            { id: 'nav-shares',       test: h => h === '#/shares' },
            { id: 'nav-received',     test: h => h === '#/shares/received' },
            { id: 'nav-team-folders', test: h => /^#\/team-folders(\/.*)?$/.test(h) },
            { id: 'nav-teams',        test: h => /^#\/teams(\/.*)?$/.test(h) },
            { id: 'nav-admin',        test: h => h === '#/admin' },
        ];
        rules.forEach(({ id, test }) => {
            const el = document.getElementById(id);
            if (el) el.classList.toggle('active', test(hash));
        });
    }

    // Auto-init when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return { init };
})();
