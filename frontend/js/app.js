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
            if (_themeConfig.favicon_url) {
                let link = document.querySelector("link[rel~='icon']");
                if (!link) {
                    link = document.createElement('link');
                    link.rel = 'icon';
                    document.head.appendChild(link);
                }
                link.href = _themeConfig.favicon_url;
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
        const ui = _themeConfig?.ui || {};
        for (const [flag, value] of Object.entries(ui)) {
            document.body.setAttribute(
                'data-ui-' + flag.replaceAll('_', '-'),
                value ? 'true' : 'false',
            );
        }
    }

    function _buildNotifIcon() {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('width', '18');
        svg.setAttribute('height', '18');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
        svg.setAttribute('stroke-width', '1.5');
        svg.setAttribute('stroke-linecap', 'round');
        svg.setAttribute('stroke-linejoin', 'round');
        svg.setAttribute('aria-hidden', 'true');
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', 'M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z');
        svg.appendChild(path);
        return svg;
    }

    function _buildBrandEl() {
        const name    = _themeConfig?.brand_name || Config.app.name;
        const logoUrl = _themeConfig?.logo_url;
        if (logoUrl) {
            return Utils.el('a', { href: '#/files', className: 'header-brand' }, [
                Utils.el('img', { src: logoUrl, alt: name, className: 'header-logo', loading: 'lazy' }),
            ]);
        }
        return Utils.el('a', { href: '#/files', className: 'header-brand', textContent: name });
    }

    const _routes = [
        { pattern: /^#\/login$/,                                                              handler: _routeLogin },
        { pattern: /^#\/pinned$/,                                                             handler: _routePinned },
        { pattern: /^#\/account(\?.*)?$/,                                                     handler: _routeAccount },
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
        { pattern: /^#\/search(\?.*)?$/,                                                      handler: _routeSearch },
        { pattern: /^#\/mfa$/,                                                                handler: _routeMfa },
        { pattern: /^#\/s\/(.+)$/,                                                            handler: _routePublicShare },
        { pattern: /^#\/l\/(.+)$/,                                                            handler: _routeShortLink },
        { pattern: /^#\/trash\/teams\/([a-f0-9-]+)$/,                                         handler: _routeTeamTrash },
        { pattern: /^#\/trash$/,                                                               handler: _routeTrash },
    ];

    async function _handleOidcCallbacks(qs) {
        if (qs.has('oidc_error')) {
            history.replaceState(null, '', '/');
            globalThis.location.hash = '#/login';
            await _routeLogin(_appEl());
            Utils.showToast('Sign-in via identity provider failed. Please try again.', 'error');
            return true;
        }
        if (qs.has('mfa_challenge')) {
            const challengeId = qs.get('mfa_challenge');
            history.replaceState(null, '', '/');
            globalThis.location.hash = '#/login';
            try {
                const challengeData = await Api.get(
                    `${Config.app.apiPrefix}/auth/mfa/challenge/${encodeURIComponent(challengeId)}`,
                );
                const pendingToken = challengeData.pending_token;
                const mfaInfo = await Api.post(
                    `${Config.app.apiPrefix}/auth/mfa/pending-info`,
                    { pending_token: pendingToken },
                );
                Auth.renderOidcMfaChallenge(_appEl(), pendingToken, mfaInfo.methods || []);
            } catch {
                // Challenge expired or already used — send to login.
                Auth.renderOidcMfaChallenge(_appEl(), '', []);
            }
            return true;
        }
        return false;
    }

    async function _checkKeyAndMfa() {
        if (!Auth.getMasterKeyObj() && !Auth.getCurrentUser()?.is_admin) {
            const user = Auth.getCurrentUser();
            if (user?.is_public_device) {
                globalThis.location.hash = '#/login';
                await _routeLogin(_appEl());
                return true;
            }
            Auth.renderKeyPrompt(_appEl());
            return true;
        }
        if (!Auth.getCurrentUser()?.is_admin) {
            try {
                const mfaStatus = await Api.get(`${Config.app.apiPrefix}/auth/mfa/status`);
                if (mfaStatus.enforcement === 'required' && mfaStatus.active_count === 0) {
                    globalThis.location.hash = '#/mfa';
                    _onHashChange();
                    return true;
                }
                if (mfaStatus.enforcement === 'optional') {
                    Auth.checkMfaBanner(_appEl());
                }
            } catch {
                // Non-critical — proceed without enforcement
            }
        }
        return false;
    }

    async function init() {
        await _loadTheme();
        _applyThemeFlags();
        Upload.fetchAndSetChunkSize();

        const _qs = new URLSearchParams(globalThis.location.search);
        if (await _handleOidcCallbacks(_qs)) return;

        // Path-based public routes — handled before auth check so unauthenticated
        // users land on the correct page rather than being bounced to login.
        const path = globalThis.location.pathname;
        if (path.startsWith('/register/')) {
            Auth.renderRegisterPage(_appEl(), path.slice('/register/'.length));
            return;
        }
        if (path.startsWith('/s/')) {
            Shares.renderPublicSharePage(_appEl(), path.slice(3), globalThis.location.hash.slice(1));
            return;
        }
        if (path.startsWith('/l/')) {
            Shares.renderShortLinkPage(_appEl(), path.slice(3), globalThis.location.hash.slice(1));
            return;
        }

        globalThis.addEventListener('hashchange', (e) => {
            const mc = document.getElementById('main-content');
            if (mc && mc.scrollTop > 0) {
                const oldHash = new URL(e.oldURL).hash || '#/';
                sessionStorage.setItem('scroll:' + oldHash, String(mc.scrollTop));
            }
            _onHashChange();
        });

        const hasSession = await Auth.checkSession();
        if (!hasSession) {
            const h = globalThis.location.hash;
            if (h?.startsWith('#/join/')) {
                sessionStorage.setItem('pendingJoinHash', h.slice(0, 512));  // NOSONAR — constrained to #/join/ prefix by preceding check
            }
            globalThis.location.hash = '#/login';
            await _routeLogin(_appEl());
            return;
        }

        if (await _checkKeyAndMfa()) return;

        Auth.startIdentityWatch();
        await _loadPinnedFolders();

        const defaultHash = Auth.getCurrentUser()?.is_admin ? '#/admin' : '#/files';
        if (!globalThis.location.hash || globalThis.location.hash === '#/') {
            globalThis.location.hash = defaultHash;
        } else {
            _onHashChange();
        }
    }

    function _guardKeyPrompt(hash, container) {
        if (!Auth.getMasterKeyObj()) {
            if (Auth.getCurrentUser()?.is_admin) {
                if (hash !== '#/admin' && hash !== '#/setup' && hash !== '#/mfa') {
                    globalThis.location.hash = '#/admin';
                    return true;
                }
            } else {
                Auth.renderKeyPrompt(container);
                return true;
            }
        }
        return false;
    }

    function _onHashChange() {
        const hash = globalThis.location.hash || '#/login';
        const container = _appEl();

        const _mc = document.getElementById('main-content');
        if (_mc) _mc.setAttribute('aria-busy', 'true');

        Files.stopLive();
        _closeNotifBubble();
        const _sb = document.querySelector('.sidebar');
        if (_sb) _sb.classList.remove('open');
        const _up = document.querySelector('.mobile-util-panel');
        if (_up) _up.classList.remove('open');
        const _ub = document.querySelector('.mobile-util-backdrop');
        if (_ub) _ub.classList.remove('open');

        // Update browser tab title on each navigation.
        const _titleMap = [
            ['#/team-folders', 'Team Folders'], ['#/teams', 'Teams'],
            ['#/shares/received', 'Shared To Me'], ['#/shares', 'Shares'],
            ['#/pinned', 'Favourites'], ['#/account', 'Account'],
            ['#/admin', 'Admin'], ['#/files', 'My Files'], ['#/login', 'Login'],
        ];
        const _appName  = _themeConfig?.brand_name || Config.app.name;
        const _titleHit = _titleMap.find(([prefix]) => hash.startsWith(prefix));
        document.title  = _titleHit ? `${_titleHit[1]} — ${_appName}` : _appName;

        // Public / semi-public routes — no auth check at router level.
        if (hash.startsWith('#/s/') || hash.startsWith('#/l/') || hash.startsWith('#/join/')) {
            for (const route of _routes) {
                const match = route.pattern.exec(hash);
                if (match) {
                    route.handler(container, ...match.slice(1));
                    return;
                }
            }
        }

        if (hash === '#/login') {
            _routeLogin(container);
            return;
        }

        if (!Auth.getCurrentUser()) {
            globalThis.location.hash = '#/login';
            return;
        }

        if (_guardKeyPrompt(hash, container)) return;

        _updateSidebarActive(hash);

        // Show spinner while the route handler loads data; it will be replaced by content.
        if (_mc) {
            while (_mc.firstChild) _mc.firstChild.remove();
            _mc.appendChild(Utils.el('div', { className: 'route-loading' }, [
                Utils.el('div', { className: 'loading-spinner' }),
            ]));
        }

        for (const route of _routes) {
            const match = route.pattern.exec(hash);
            if (match) {
                route.handler(container, ...match.slice(1));
                return;
            }
        }

        globalThis.location.hash = '#/files';
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

    // -----------------------------------------------------------------------
    // Pinned Folders — DB-backed (ui_prefs.pinned_folders)
    // -----------------------------------------------------------------------

    let _pinnedFolders = [];

    function _getPinnedFolders() {
        return _pinnedFolders;
    }

    function _savePinnedFolders(pins) {
        _pinnedFolders = pins;
        Api.patch(`${Config.app.apiPrefix}/auth/me/prefs`, { pinned_folders: pins }).catch(() => {});
    }

    async function _loadPinnedFolders() {
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/auth/me/prefs`);
            _pinnedFolders = data.ui_prefs?.pinned_folders || [];
        } catch {
            _pinnedFolders = [];
        }
    }

    function _pinFolder(id, name, hash, teamId, teamName, path) {
        const pins = _getPinnedFolders().filter(p => p.id !== id);
        pins.push({ id, name, hash,
            team_id: teamId || null, team_name: teamName || null, path: path || null });
        _savePinnedFolders(pins);
        const el = document.getElementById('pinned-folders-sidebar');
        if (el) _renderPinnedSidebar(el);
    }

    function _unpinFolder(id) {
        _savePinnedFolders(_getPinnedFolders().filter(p => p.id !== id));
        const el = document.getElementById('pinned-folders-sidebar');
        if (el) _renderPinnedSidebar(el);
    }

    function _renderPinnedSidebar(container) {
        container.innerHTML = '';
        const pins = _getPinnedFolders();

        // "Favourites" label is always a clickable link to the full page
        container.appendChild(Utils.el('a', {
            href: '#/pinned',
            className: 'sidebar-section-label sidebar-section-label--link',
            textContent: 'Favourites',
        }));
        if (!pins.length) return;

        for (const pin of pins) {
            const row = Utils.el('div', { className: 'pinned-folder-row' });
            row.appendChild(Utils.el('a', {
                href: pin.hash || `#/files/${pin.id}`,
                className: 'sidebar-link sidebar-sublink pinned-folder-link',
                textContent: pin.name,
                style: 'flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap',
            }));
            const unpinBtn = Utils.el('button', {
                className: 'pinned-unpin-btn',
                title: 'Remove from Favourites',
                textContent: '×',
            });
            unpinBtn.addEventListener('click', (e) => {
                e.preventDefault();
                _unpinFolder(pin.id);
            });
            row.appendChild(unpinBtn);
            container.appendChild(row);
        }
    }

    function _routePinned(container) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        while (main.firstChild) main.firstChild.remove();
        const page = Utils.el('div', { className: 'page-content' });
        main.appendChild(page);
        _renderPinnedPage(page);
    }

    function _makePinnedViewToggle(tileActive) {
        const tileBtn = Utils.el('button', {
            className: 'view-toggle-btn' + (tileActive ? ' active' : ''),
            title: 'Tile view',
        });
        tileBtn.appendChild(Utils.el('span', { className: 'view-toggle-grid-icon' }));
        const listBtn = Utils.el('button', {
            className: 'view-toggle-btn' + (tileActive ? '' : ' active'),
            title: 'List view',
        });
        listBtn.appendChild(Utils.el('span', { className: 'view-toggle-list-icon' }));
        return { tileBtn, listBtn };
    }

    function _renderPinnedPage(page) {
        page.innerHTML = '';
        const pins = _getPinnedFolders();

        const savedView = localStorage.getItem('tus_pinned_view') || 'tile';
        let view = savedView;

        const { tileBtn, listBtn } = _makePinnedViewToggle(view === 'tile');

        const header = Utils.el('div', { className: 'page-header' });
        header.appendChild(Utils.el('div', { style: 'display:flex;align-items:center;gap:16px' }, [
            Utils.el('h2', { textContent: 'Favourites', style: 'margin:0' }),
            Utils.el('div', { style: 'display:flex;align-items:center;gap:4px' }, [tileBtn, listBtn]),
        ]));
        page.appendChild(header);

        if (pins.length === 0) {
            page.appendChild(Utils.el('p', { className: 'text-muted', style: 'margin-top:16px', textContent: 'No favourites yet. Navigate to a folder and click the ☆ in the breadcrumb trail to pin it.' }));
            return;
        }

        const filterInput = Utils.el('input', {
            type: 'text',
            className: 'input-sm toolbar-filter',
            placeholder: 'Filter favourites…',
            style: 'margin:12px 0',
        });
        page.appendChild(filterInput);

        const contentEl = Utils.el('div');
        page.appendChild(contentEl);

        function _renderTile() {
            contentEl.innerHTML = '';
            const grid = Utils.el('div', { className: 'pinned-tile-grid' });
            for (const pin of pins) {
                const card = Utils.el('div', { className: 'pinned-card', dataset: { name: pin.name } });
                const cardInner = Utils.el('div', { className: 'pinned-card-inner' });

                const link = Utils.el('a', {
                    href: pin.hash || `#/files/${pin.id}`,
                    className: 'pinned-card-link',
                });
                link.appendChild(Utils.el('div', { className: 'pinned-card-name', textContent: pin.name }));
                const label = pin.team_name ? `Team: ${pin.team_name}` : 'Personal';
                link.appendChild(Utils.el('div', { className: 'pinned-card-meta', textContent: label }));
                cardInner.appendChild(link);

                const infoBtn = Utils.el('button', {
                    className: 'pinned-card-info',
                    title: 'Folder info',
                    'aria-label': 'Folder info',
                    textContent: '?',
                });
                infoBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const pathStr = pin.path || (pin.team_name ? `Team Folders / ${pin.name}` : `My Files / ${pin.name}`);
                    const modalContent = Utils.el('div', { style: 'padding:4px 0' });
                    modalContent.appendChild(Utils.el('p', { className: 'pinned-path-modal-label', textContent: 'Path:' }));
                    modalContent.appendChild(Utils.el('p', { className: 'pinned-path-modal-path', textContent: pathStr }));
                    const rmBtn = Utils.el('button', {
                        className: 'btn btn-danger btn-sm',
                        style: 'margin-top:12px',
                        textContent: 'Remove from Favourites',
                    });
                    modalContent.appendChild(rmBtn);
                    const close = Utils.showModal(pin.name, modalContent);
                    rmBtn.addEventListener('click', () => {
                        close();
                        _unpinFolder(pin.id);
                        _renderPinnedPage(page);
                    });
                });
                cardInner.appendChild(infoBtn);
                card.appendChild(cardInner);
                grid.appendChild(card);
            }
            contentEl.appendChild(grid);
            filterInput.oninput = () => {
                const q = filterInput.value.toLowerCase();
                for (const card of grid.querySelectorAll('.pinned-card')) {
                    card.style.display = !q || (card.dataset.name || '').toLowerCase().includes(q) ? '' : 'none';
                }
            };
        }

        function _renderList() {
            contentEl.innerHTML = '';
            const rows = [];
            for (const pin of pins) {
                const row = Utils.el('div', { className: 'pinned-list-row', dataset: { name: pin.name } });

                const nameEl = Utils.el('a', {
                    href: pin.hash || `#/files/${pin.id}`,
                    className: 'pinned-list-name',
                    textContent: pin.name,
                });
                row.appendChild(nameEl);

                const pathStr = pin.path || (pin.team_name ? `Team Folders / ${pin.name}` : `My Files / ${pin.name}`);
                const pathEl = Utils.el('span', {
                    className: 'pinned-list-path',
                    textContent: pathStr,
                    title: pathStr,
                });
                // Mobile long-press → modal showing full path
                Utils.addLongPress(pathEl, () => {
                    const modalContent = Utils.el('div', { style: 'padding:4px 0' });
                    modalContent.appendChild(Utils.el('p', { className: 'pinned-path-modal-label', textContent: 'Full path:' }));
                    modalContent.appendChild(Utils.el('p', { className: 'pinned-path-modal-path', textContent: pathStr }));
                    Utils.showModal(`Path — ${pin.name}`, modalContent);
                });
                row.appendChild(pathEl);

                const unpinBtn = Utils.el('button', {
                    className: 'pinned-unpin-btn',
                    title: 'Remove from Favourites',
                    'aria-label': 'Remove from Favourites',
                    textContent: '×',
                });
                unpinBtn.addEventListener('click', () => {
                    _unpinFolder(pin.id);
                    _renderPinnedPage(page);
                });
                row.appendChild(unpinBtn);

                rows.push(row);
                contentEl.appendChild(row);
            }
            filterInput.oninput = () => {
                const q = filterInput.value.toLowerCase();
                for (const row of rows) {
                    row.style.display = !q || (row.dataset.name || '').toLowerCase().includes(q) ? '' : 'none';
                }
            };
        }

        function _applyView() {
            filterInput.value = '';
            if (view === 'list') _renderList();
            else _renderTile();
        }

        tileBtn.addEventListener('click', () => {
            if (view === 'tile') return;
            view = 'tile';
            tileBtn.classList.add('active');
            listBtn.classList.remove('active');
            localStorage.setItem('tus_pinned_view', 'tile');
            _applyView();
        });
        listBtn.addEventListener('click', () => {
            if (view === 'list') return;
            view = 'list';
            listBtn.classList.add('active');
            tileBtn.classList.remove('active');
            localStorage.setItem('tus_pinned_view', 'list');
            _applyView();
        });

        _applyView();
    }

    function pinCurrentFolder(id, name, hash, teamId, teamName, path) {
        _pinFolder(id, name, hash, teamId, teamName, path);
    }

    function unpinCurrentFolder(id) {
        _unpinFolder(id);
    }

    function isPinned(id) {
        return _getPinnedFolders().some(p => p.id === id);
    }

    async function _routeSearch(container) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        while (main.firstChild) main.firstChild.remove();
        const params = new URLSearchParams(globalThis.location.hash.split('?')[1] || '');
        const q = params.get('q') || '';

        const page = Utils.el('div', { className: 'page-content' });
        page.appendChild(Utils.el('h2', { textContent: q ? `Search: ${q}` : 'File Search', style: 'margin-bottom:12px' }));

        const searchRow = Utils.el('div', { style: 'display:flex;gap:8px;margin-bottom:16px' });
        const input = Utils.el('input', {
            type: 'text',
            className: 'input-sm',
            value: q,
            placeholder: 'Search filenames…',
            style: 'width:280px',
        });
        const btn = Utils.el('button', { className: 'btn btn-primary btn-sm', textContent: 'Search' });
        searchRow.append(input, btn);
        page.appendChild(searchRow);

        const resultsEl = Utils.el('div');
        page.appendChild(resultsEl);
        main.appendChild(page);

        const _doSearch = async (term) => {
            if (!term.trim()) { resultsEl.innerHTML = ''; return; }
            resultsEl.textContent = 'Searching…';
            try {
                const data = await Api.get(`${Config.app.apiPrefix}/files/search?q=${encodeURIComponent(term.trim())}`);
                resultsEl.innerHTML = '';
                const files = data.files || [];
                if (!files.length) {
                    resultsEl.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No files found.' }));
                    return;
                }
                const tbl = Utils.el('table', { className: 'file-table' });
                tbl.innerHTML = '<thead><tr><th>Name</th><th>Size</th><th>Location</th><th>Modified</th></tr></thead>';
                const tbody = Utils.el('tbody');
                for (const f of files) {
                    const nameLink = Utils.el('a', { href: '#', textContent: f.original_name, className: 'file-name-link' });
                    nameLink.addEventListener('click', (e) => {
                        e.preventDefault();
                        Files.downloadFileById(f.id, f);
                    });
                    const folderLink = f.folder_id
                        ? Utils.el('a', { href: `#/files/${f.folder_id}`, textContent: f.folder_path || f.folder_id, className: 'folder-link' })
                        : Utils.el('span', { textContent: '(root)', className: 'text-muted' });
                    tbody.appendChild(Utils.el('tr', {}, [
                        Utils.el('td', {}, [nameLink]),
                        Utils.el('td', { textContent: Utils.formatBytes(f.size_bytes) }),
                        Utils.el('td', {}, [folderLink]),
                        Utils.el('td', { textContent: Utils.timeAgo(f.created_at) }),
                    ]));
                }
                tbl.appendChild(tbody);
                resultsEl.appendChild(tbl);
            } catch (e) {
                resultsEl.innerHTML = '';
                resultsEl.appendChild(Utils.el('p', { className: 'text-error', textContent: 'Search failed: ' + e.message }));
            }
        };

        btn.addEventListener('click', () => {
            globalThis.location.hash = `#/search?q=${encodeURIComponent(input.value.trim())}`;
            _doSearch(input.value.trim());
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') btn.click();
        });

        if (q) _doSearch(q);
    }

    function _routeFiles(container) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        Files.renderFileBrowser(main);
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

    async function _routeTeamFolders(container) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        await Teams.renderTeamFoldersPage(main);
    }

    function _routeTeams(container) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        while (main.firstChild) main.firstChild.remove();
        const wrap = Utils.el('div', { className: 'page-content' });
        main.appendChild(wrap);
        Teams.renderTeamsPage(wrap);
    }

    function _routeTeamDetail(container, teamId) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        while (main.firstChild) main.firstChild.remove();
        const wrap = Utils.el('div', { className: 'page-content' });
        main.appendChild(wrap);
        Teams.renderTeamDetailPage(wrap, teamId);
    }

    async function _routeAdmin(container) {
        const user = Auth.getCurrentUser();
        if (!user?.is_admin) {
            globalThis.location.hash = '#/files';
            return;
        }
        // Check first-run flag before rendering admin panel.
        // On error (network/auth) fall through to normal admin panel.
        try {
            const { settings } = await Api.get(`${Config.app.apiPrefix}/admin/settings`);
            if (settings?.first_run_completed.value !== '1') {
                globalThis.location.hash = '#/setup';
                return;
            }
        } catch (e) { console.warn('Admin settings check failed, proceeding', e); }
        _renderShell(container);
        Admin.renderAdminPage(document.getElementById('main-content'));
    }

    function _routeSetup(container) {
        const user = Auth.getCurrentUser();
        if (!user?.is_admin) {
            globalThis.location.hash = '#/login';
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
    // Activity event labels + detail modal (shared by bubble and account page)
    // -----------------------------------------------------------------------

    const _ACTIVITY_LABELS = {
        upload:                  'Uploaded file',
        download:                'Downloaded file',
        view:                    'Viewed file',
        delete:                  'Deleted file',
        share:                   'Shared file',
        login_success:           'Logged in',
        login_failed:            'Login failed',
        mfa_totp_verified:       'MFA verified (TOTP)',
        mfa_webauthn_verified:   'MFA verified (security key)',
        mfa_recovery_code_used:  'Used recovery code',
        mfa_credential_removed:  'Removed MFA credential',
        step_up_granted:         'Step-up verified',
        step_up_failed:          'Step-up failed',
        step_up_lockout:         'Step-up locked out',
        session_unlock_webauthn: 'Session unlocked',
        password_changed:        'Password changed',
        team_created:            'Created team',
    };

    function _showAccountEventDetailModal(ev) {
        function kv(label, value) {
            if (value === null || value === undefined || value === '') return null;
            return Utils.el('tr', {}, [
                Utils.el('td', { style: 'font-weight:600;padding:3px 14px 3px 0;white-space:nowrap;vertical-align:top;color:var(--color-text-muted)', textContent: label }),
                Utils.el('td', { style: 'padding:3px 0;word-break:break-all;font-family:monospace;font-size:var(--font-size-sm)', textContent: String(value) }),
            ]);
        }
        const wrap = Utils.el('div');
        const table = Utils.el('table', { style: 'border-collapse:collapse;width:100%' });
        for (const row of [
            kv('Time',        ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 19) : ''),
            kv('Source',      ev.source),
            kv('Outcome',     ev.outcome),
            kv('Severity',    ev.severity),
            kv('IP',          ev.ip_address),
            kv('Session',     ev.session_id),
            kv('File',        ev.target_name),
            kv('File ID',     ev.target_id),
            kv('Target type', ev.target_type),
        ].filter(Boolean)) table.appendChild(row);
        wrap.appendChild(table);
        if (ev.detail && typeof ev.detail === 'object') {
            const rest = Object.fromEntries(Object.entries(ev.detail).filter(([k]) => k !== 'path'));
            if (Object.keys(rest).length) {
                wrap.appendChild(Utils.el('pre', {
                    style: 'margin-top:12px;padding:8px;background:var(--color-bg);border-radius:var(--radius);font-size:var(--font-size-xs);overflow-x:auto',
                    textContent: JSON.stringify(rest, null, 2),
                }));
            }
        }
        Utils.showModal(_ACTIVITY_LABELS[ev.event_type] || ev.event_type, wrap);
    }

    // -----------------------------------------------------------------------
    // Notification bubble (header icon → small popup)
    // -----------------------------------------------------------------------

    let _notifBubbleOpen = false;
    let _notifBubbleEl = null;

    function _closeNotifBubble() {
        if (_notifBubbleEl?.parentNode) _notifBubbleEl.remove();
        _notifBubbleEl = null;
        _notifBubbleOpen = false;
        const _nb = document.querySelector('.header-notif-btn');
        if (_nb) _nb.setAttribute('aria-expanded', 'false');
    }

    function _toggleNotifBubble() {
        if (_notifBubbleOpen) { _closeNotifBubble(); } else { _openNotifBubble(); }
    }

    function _openNotifBubble() {
        _closeNotifBubble();
        _notifBubbleOpen = true;
        Utils.markAllRead();
        const _nb = document.querySelector('.header-notif-btn');
        if (_nb) _nb.setAttribute('aria-expanded', 'true');

        const panel = Utils.el('div', { className: 'notif-popup' });

        const _outsideClick = (e) => {
            const btn = document.querySelector('.header-notif-btn');
            if (!panel.contains(e.target) && e.target !== btn && !btn?.contains(e.target)) {
                _closeNotifBubble();
                document.removeEventListener('mousedown', _outsideClick, true);
            }
        };
        document.addEventListener('mousedown', _outsideClick, true);

        panel.appendChild(Utils.el('div', { className: 'notif-popup-header', textContent: 'Notifications' }));
        const listEl = Utils.el('div', { className: 'notif-popup-body' });
        listEl.textContent = 'Loading…';
        panel.appendChild(listEl);
        panel.appendChild(Utils.el('div', { className: 'notif-popup-footer' }, [
            Utils.el('a', {
                href: '#/account?tab=activity&filter=notifications',
                className: 'notif-see-more',
                textContent: 'See more',
                onClick: () => _closeNotifBubble(),
            }),
        ]));

        document.querySelector('.header-actions')?.appendChild(panel);
        _notifBubbleEl = panel;

        const _renderFallbackToasts = () => {
            const history = Utils.getToastHistory();
            if (!history.length) {
                listEl.appendChild(Utils.el('p', { className: 'notif-popup-empty', textContent: 'No notifications.' }));
                return;
            }
            const ul = Utils.el('ul', { className: 'notification-list' });
            for (let i = Math.min(history.length, 5) - 1; i >= 0; i--) {
                const n = history[i];
                ul.appendChild(Utils.el('li', { className: `notification-item notification-item--${n.type}` }, [
                    Utils.el('span', { className: 'notification-msg', textContent: n.message }),
                    Utils.el('span', { className: 'notification-time', textContent: Utils.timeAgo(n.timestamp.toISOString()) }),
                ]));
            }
            listEl.appendChild(ul);
        };

        Api.get(`${Config.app.apiPrefix}/auth/me/activity?activity_filter=notifications&page=1`).then(data => {
            listEl.textContent = '';
            const events = (data.events || []).slice(0, 5);
            if (!events.length) { _renderFallbackToasts(); return; }
            const ul = Utils.el('ul', { className: 'notification-list' });
            for (const ev of events) {
                const label  = _ACTIVITY_LABELS[ev.event_type] || ev.event_type.replaceAll('_', ' ');
                const detail = ev.target_name ? `: ${ev.target_name}` : '';
                const li = Utils.el('li', { className: 'notification-item notification-item--info notif-item-clickable' }, [
                    Utils.el('span', { className: 'notification-msg', textContent: label + detail }),
                    Utils.el('span', { className: 'notification-time', textContent: Utils.timeAgo(ev.timestamp) }),
                ]);
                li.addEventListener('click', () => _showAccountEventDetailModal(ev));
                ul.appendChild(li);
            }
            listEl.appendChild(ul);
        }).catch(() => {
            listEl.textContent = '';
            _renderFallbackToasts();
        });
    }

    // -----------------------------------------------------------------------
    // My Account — full page route (#/account)
    // -----------------------------------------------------------------------

    function _routeAccount(container) {
        _renderShell(container);
        const main = document.getElementById('main-content');
        const params = new URLSearchParams(globalThis.location.hash.split('?')[1] || '');
        _renderAccountPage(main, params.get('tab') || 'info', params.get('filter') || null);
    }

    function _renderAccountPage(main, initialTab, initialFilter) {
        while (main.firstChild) main.firstChild.remove();
        const user = Auth.getCurrentUser();
        if (!user) return;

        const TABS = [
            { id: 'info',       label: 'Account Info' },
            { id: 'appearance', label: 'Appearance' },
            { id: 'teams',      label: 'Team Membership' },
            { id: 'activity',   label: 'Recent Activity' },
            { id: 'security',   label: 'Security' },
            { id: 'transfers',  label: 'Active Transfers' },
        ];
        const validIds = new Set(TABS.map(t => t.id));
        let activeTab = validIds.has(initialTab) ? initialTab : 'info';

        const page = Utils.el('div', { className: 'page-content acct-page' });
        page.appendChild(Utils.el('h2', { textContent: user.username, style: 'margin-bottom:2px' }));
        page.appendChild(Utils.el('p', { className: 'text-muted', style: 'margin-bottom:20px;font-size:var(--font-size-sm)', textContent: 'My Account' }));

        const tabBar   = Utils.el('div', { className: 'acct-tab-bar', role: 'tablist' });
        const contentEl = Utils.el('div', { className: 'acct-tab-content', id: 'acct-tab-content', role: 'tabpanel' });

        const _activateTab = (tabId) => {
            activeTab = tabId;
            tabBar.querySelectorAll('.acct-tab').forEach(b => {
                const isActive = b.dataset.tabId === tabId;
                b.classList.toggle('active', isActive);
                b.setAttribute('aria-selected', String(isActive));
            });
            contentEl.setAttribute('aria-labelledby', `acct-tab-btn-${tabId}`);
            while (contentEl.firstChild) contentEl.firstChild.remove();
            if      (tabId === 'info')       _renderAcctInfoTab(contentEl, user);
            else if (tabId === 'appearance') _renderAcctAppearanceTab(contentEl);
            else if (tabId === 'teams')      _renderAcctTeamsTab(contentEl);
            else if (tabId === 'activity')   _renderAcctActivityTab(contentEl, tabId === initialTab ? initialFilter : null);
            else if (tabId === 'security')   _renderAcctSecurityTab(contentEl, user);
            else if (tabId === 'transfers')  _renderAcctTransfersTab(contentEl);
        };

        for (const tab of TABS) {
            const btn = Utils.el('button', {
                id: `acct-tab-btn-${tab.id}`,
                className: 'acct-tab' + (tab.id === activeTab ? ' active' : ''),
                textContent: tab.label,
                role: 'tab',
                'aria-selected': String(tab.id === activeTab),
                'aria-controls': 'acct-tab-content',
                onClick: () => _activateTab(tab.id),
            });
            btn.dataset.tabId = tab.id;
            tabBar.appendChild(btn);
        }

        page.appendChild(tabBar);
        page.appendChild(contentEl);
        main.appendChild(page);
        _activateTab(activeTab);
    }

    function _applyAppearance(theme, textSize) {
        document.documentElement.dataset.theme = theme;
        if (textSize && textSize !== 'medium') {
            document.documentElement.dataset.textSize = textSize;
        } else {
            delete document.documentElement.dataset.textSize;
        }
        try {
            localStorage.setItem('tus_theme', theme);
            if (textSize && textSize !== 'medium') {
                localStorage.setItem('tus_text_size', textSize);
            } else {
                localStorage.removeItem('tus_text_size');
            }
        } catch (_) { /* storage unavailable — apply in-session only */ }
    }

    function _renderAcctAppearanceTab(container) {
        const currentTheme    = document.documentElement.dataset.theme    || 'system';
        const currentTextSize = document.documentElement.dataset.textSize || 'medium';

        const _row = (labelText, control) => Utils.el('div', { className: 'acct-appearance-row' }, [
            Utils.el('label', { className: 'acct-appearance-label', textContent: labelText }),
            control,
        ]);

        const themeSelect = Utils.el('select', { className: 'input-sm' }, [
            Utils.el('option', { value: 'system', textContent: 'System default (follow OS)' }),
            Utils.el('option', { value: 'dark',   textContent: 'Dark' }),
            Utils.el('option', { value: 'light',  textContent: 'Light' }),
        ]);
        themeSelect.value = currentTheme;

        const sizeSelect = Utils.el('select', { className: 'input-sm' }, [
            Utils.el('option', { value: 'small',  textContent: 'Small (13 px)' }),
            Utils.el('option', { value: 'medium', textContent: 'Medium (16 px) — default' }),
            Utils.el('option', { value: 'large',  textContent: 'Large (19 px)' }),
        ]);
        sizeSelect.value = currentTextSize;

        const _onChange = () => _applyAppearance(themeSelect.value, sizeSelect.value);
        themeSelect.addEventListener('change', _onChange);
        sizeSelect.addEventListener('change', _onChange);

        container.appendChild(Utils.el('section', { className: 'account-section' }, [
            Utils.el('h4', { className: 'account-section-title', textContent: 'Appearance' }),
            Utils.el('div', { className: 'account-section-body' }, [
                _row('Theme', themeSelect),
                _row('Text size', sizeSelect),
                Utils.el('p', { className: 'text-muted', style: 'margin-top:12px;font-size:var(--font-size-sm)', textContent: 'Changes apply immediately and are saved for this browser.' }),
            ]),
        ]));
    }

    function _renderAcctInfoTab(container, user) {
        const keyStatus  = user.wrapped_master_key ? 'Encryption key present' : 'No encryption key';
        const authMethod = user.auth_method === 'opaque' ? 'Password (OPAQUE)' : (user.auth_method || 'unknown');
        const table = Utils.el('table', { className: 'acct-info-table' });
        for (const [label, value] of [
            ['Username',       user.username],
            ['Authentication', authMethod],
            ['Encryption key', keyStatus],
            ['Roles',          [...(user.roles || [])].join(', ') || 'none'],
        ]) {
            table.appendChild(Utils.el('tr', {}, [
                Utils.el('th', { textContent: label }),
                Utils.el('td', { textContent: value }),
            ]));
        }
        container.appendChild(Utils.el('section', { className: 'account-section' }, [
            Utils.el('h4', { className: 'account-section-title', textContent: 'Account Information' }),
            table,
        ]));
    }

    function _renderAcctTeamsTab(container) {
        container.textContent = 'Loading…';
        Api.get(`${Config.app.apiPrefix}/teams`).then(data => {
            container.textContent = '';
            const teams = data.teams || [];
            if (!teams.length) {
                container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'You are not a member of any teams.' }));
                return;
            }
            const table = Utils.el('table', { className: 'admin-table' });
            table.innerHTML = '<thead><tr><th>Team</th><th>Your Role</th><th>Description</th></tr></thead>';
            const tbody = Utils.el('tbody');
            for (const t of teams) {
                tbody.appendChild(Utils.el('tr', {}, [
                    Utils.el('td', {}, [Utils.el('a', { href: `#/teams/${t.id}`, textContent: t.name, className: 'folder-link' })]),
                    Utils.el('td', { textContent: t.my_role || '' }),
                    Utils.el('td', { textContent: t.description || '' }),
                ]));
            }
            table.appendChild(tbody);
            container.appendChild(table);
        }).catch(() => { container.textContent = 'Could not load team membership.'; });
    }

    function _renderAcctActivityTab(container, initialFilter) {
        const filterRow = Utils.el('div', { style: 'display:flex;align-items:center;gap:8px;margin-bottom:14px' });
        filterRow.appendChild(Utils.el('label', { textContent: 'Show:', style: 'font-size:var(--font-size-sm);color:var(--color-text-muted)' }));
        const filterSel = Utils.el('select', { className: 'input-sm' }, [
            Utils.el('option', { value: '',              textContent: 'All activity' }),
            Utils.el('option', { value: 'notifications', textContent: 'File transfers only' }),
        ]);
        if (initialFilter === 'notifications') filterSel.value = 'notifications';
        filterRow.appendChild(filterSel);

        const tableWrap  = Utils.el('div');
        const loadMoreBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Load more',
            style: 'margin-top:12px;display:none',
        });

        container.appendChild(filterRow);
        container.appendChild(tableWrap);
        container.appendChild(loadMoreBtn);

        let page = 1;
        let allEvents = [];

        const _buildEventsTable = (events) => {
            const table = Utils.el('table', { className: 'admin-table' });
            table.appendChild(Utils.el('thead', {}, [
                Utils.el('tr', {}, [
                    Utils.el('th', { textContent: 'Time',         style: 'width:140px;white-space:nowrap' }),
                    Utils.el('th', { textContent: 'Event',        style: 'white-space:nowrap' }),
                    Utils.el('th', { textContent: 'File / Detail' }),
                    Utils.el('th', { textContent: 'IP',           style: 'width:130px' }),
                ]),
            ]));
            const tbody = Utils.el('tbody');
            if (!events.length) {
                tbody.appendChild(Utils.el('tr', {}, [
                    Utils.el('td', { colSpan: 4, className: 'text-muted', textContent: 'No activity recorded.', style: 'text-align:center;padding:12px' }),
                ]));
            }
            for (const ev of events) {
                const label = _ACTIVITY_LABELS[ev.event_type] || ev.event_type.replaceAll('_', ' ');
                const typeLink = Utils.el('a', {
                    href: '#', textContent: label, style: 'cursor:pointer',
                    onClick: (e) => { e.preventDefault(); _showAccountEventDetailModal(ev); },
                });
                const detail = ev.target_name || (ev.detail?.path ?? '');
                tbody.appendChild(Utils.el('tr', {}, [
                    Utils.el('td', { textContent: ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 16) : '', style: 'white-space:nowrap;font-family:monospace;font-size:var(--font-size-sm)' }),
                    Utils.el('td', {}, [typeLink]),
                    Utils.el('td', { textContent: detail }),
                    Utils.el('td', { textContent: ev.ip_address || '', style: 'font-family:monospace;font-size:var(--font-size-sm)' }),
                ]));
            }
            table.appendChild(tbody);
            return table;
        };

        const _load = async (reset) => {
            if (reset) { page = 1; allEvents = []; tableWrap.textContent = 'Loading…'; }
            const qs = new URLSearchParams({ page });
            if (filterSel.value) qs.set('activity_filter', filterSel.value);
            try {
                const data = await Api.get(`${Config.app.apiPrefix}/auth/me/activity?${qs}`);
                allEvents.push(...(data.events || []));
                page++;
                tableWrap.innerHTML = '';
                tableWrap.appendChild(_buildEventsTable(allEvents));
                loadMoreBtn.style.display = data.has_more ? '' : 'none';
            } catch {
                if (reset) tableWrap.textContent = 'Could not load activity.';
            }
        };

        filterSel.addEventListener('change', () => _load(true));
        loadMoreBtn.addEventListener('click', () => _load(false));
        _load(true);
    }

    function _renderAcctSecurityTab(container, user) {
        container.appendChild(Utils.el('section', { className: 'account-section' }, [
            Utils.el('h4', { className: 'account-section-title', textContent: 'Multi-Factor Authentication' }),
            Utils.el('div', { className: 'account-section-body' }, [
                Utils.el('a', { href: '#/mfa', className: 'btn btn-secondary btn-sm', textContent: 'MFA Settings' }),
            ]),
        ]));

        if (user.auth_method === 'opaque') {
            const changePwSection = Utils.el('section', { className: 'account-section' });
            changePwSection.appendChild(Utils.el('h4', { className: 'account-section-title', textContent: 'Password' }));
            const changePwBody = Utils.el('div', { className: 'account-section-body' });

            function _showChangePwBtn() {
                while (changePwBody.firstChild) changePwBody.firstChild.remove();
                changePwBody.appendChild(Utils.el('button', {
                    className: 'btn btn-secondary btn-sm',
                    textContent: 'Change Password',
                    onClick: _showChangePwForm,
                }));
            }

            function _showChangePwForm() {
                while (changePwBody.firstChild) changePwBody.firstChild.remove();
                const newPwInput     = Utils.el('input', { type: 'password', id: 'change-pw-new',     autocomplete: 'new-password' });
                const confirmPwInput = Utils.el('input', { type: 'password', id: 'change-pw-confirm', autocomplete: 'new-password' });
                const statusEl       = Utils.el('p', { className: 'text-muted-sm' });
                const submitBtn      = Utils.el('button', {
                    className: 'btn btn-primary btn-sm', textContent: 'Change Password',
                    onClick: () => _doChangePw(newPwInput.value, confirmPwInput.value, statusEl, submitBtn),
                });
                const cancelBtn = Utils.el('button', {
                    className: 'btn btn-secondary btn-sm', textContent: 'Cancel',
                    onClick: _showChangePwBtn,
                });
                changePwBody.appendChild(Utils.el('div', { className: 'change-pw-form' }, [
                    Utils.el('div', { className: 'form-group' }, [
                        Utils.el('label', { 'for': 'change-pw-new',     textContent: 'New password' }), newPwInput,
                    ]),
                    Utils.el('div', { className: 'form-group' }, [
                        Utils.el('label', { 'for': 'change-pw-confirm', textContent: 'Confirm new password' }), confirmPwInput,
                    ]),
                    statusEl,
                    Utils.el('div', { className: 'btn-row-sm' }, [submitBtn, cancelBtn]),
                ]));
                Utils.attachPasswordStrength(newPwInput);
                newPwInput.focus();
            }

            async function _doChangePw(newPw, confirmPw, statusEl, submitBtn) {
                statusEl.textContent = '';
                if (!newPw || newPw.length < 8) { statusEl.textContent = 'Password must be at least 8 characters.'; return; }
                if (newPw !== confirmPw) { statusEl.textContent = 'Passwords do not match.'; return; }
                const masterKey = Auth.getMasterKeyObj();
                if (!masterKey) { statusEl.textContent = 'Encryption key not loaded. Re-enter your password to unlock first.'; return; }
                submitBtn.disabled = true;
                statusEl.textContent = 'Generating new credentials…';
                try {
                    const opaque = await Auth.loadOpaque();
                    const { clientRegistrationState, registrationRequest } =
                        opaque.client.startRegistration({ password: newPw });
                    const round1 = await Api.post(
                        `${Config.app.apiPrefix}/auth/opaque/password-change/start`,
                        { client_registration_request: registrationRequest },
                    );
                    const { registrationRecord, exportKey } = opaque.client.finishRegistration({
                        clientRegistrationState,
                        registrationResponse: round1.registration_response,
                        password: newPw,
                        identifiers: { client: user.username, server: 'tusshare' },
                    });
                    const newKek = await Crypto.deriveOpaqueKEK(exportKey);
                    const { wrappedKeyB64, ivB64 } = await Crypto.wrapMasterKey(masterKey, newKek);
                    // Api auto-handles step-up: server returns 403 step_up_required,
                    // Api prompts for current password, then retries with X-Step-Up-Token.
                    statusEl.textContent = 'Confirm current password when prompted…';
                    await Api.post(
                        `${Config.app.apiPrefix}/auth/opaque/password-change/finish`,
                        {
                            client_registration_record: registrationRecord,
                            wrapped_master_key:         wrappedKeyB64,
                            wrapped_master_key_iv:      ivB64,
                        },
                    );
                    Utils.showToast('Password changed successfully.', 'success');
                    _showChangePwBtn();
                } catch (err) {
                    if (err.message !== 'Step-up cancelled by user') {
                        statusEl.textContent = err.message || 'Password change failed. Please try again.';
                    }
                    submitBtn.disabled = false;
                }
            }

            _showChangePwBtn();
            changePwSection.appendChild(changePwBody);
            container.appendChild(changePwSection);
        }

        const sessionsSection = Utils.el('section', { className: 'account-section' });
        sessionsSection.appendChild(Utils.el('h4', { className: 'account-section-title', textContent: 'Active Sessions' }));
        const sessionsList = Utils.el('div', { className: 'account-section-body' });
        sessionsList.textContent = 'Loading…';
        sessionsSection.appendChild(sessionsList);
        container.appendChild(sessionsSection);

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
                sessionsList.appendChild(Utils.el('button', {
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
                }));
            }
        }).catch(() => { sessionsList.textContent = 'Could not load sessions.'; });

        const deleteSection = Utils.el('section', { className: 'account-section' });
        container.appendChild(deleteSection);
        Api.get(`${Config.app.apiPrefix}/auth/public-settings`).then(data => {
            if (data.allow_user_delete_own_account !== 'true') return;
            const canDeleteOwned = data.can_delete_owned_shared === 'true';
            deleteSection.appendChild(Utils.el('h4', { className: 'account-section-title account-section-title--danger', textContent: 'Danger Zone' }));
            deleteSection.appendChild(Utils.el('button', {
                className: 'btn btn-danger btn-sm',
                textContent: 'Delete My Account',
                onClick: async () => { // NOSONAR — closures inside this handler are unavoidably nested (async API checks inside a .then callback)
                    let ownedTeams = [];
                    try {
                        const owned = await Api.get(`${Config.app.apiPrefix}/auth/me/owned-shared`);
                        ownedTeams = owned.owned_teams || [];
                    } catch { /* proceed without warning if check fails */ }
                    if (ownedTeams.length > 0) {
                        const teamList = ownedTeams.map(t => `"${t.name}"`).join(', '); // NOSONAR — deep in onClick inside .then; nesting unavoidable
                        if (!canDeleteOwned) {
                            Utils.showToast(
                                `You own ${ownedTeams.length > 1 ? 'teams' : 'a team'} (${teamList}). ` +
                                'Promote another member to Owner first, then delete your account.',
                                'warning',
                            );
                            return;
                        }
                        if (!await Utils.showConfirm(
                            `You own the following team${ownedTeams.length > 1 ? 's' : ''}: ${teamList}.\n\n` +
                            'Deleting your account will permanently delete these teams and all their content. ' +
                            'This cannot be undone. Continue?'
                        )) return;
                    } else if (!await Utils.showConfirm(
                            'This will permanently delete your account and all your files. This cannot be undone. Continue?'
                        )) {
                        return;
                    }
                    try {
                        await Api.del(`${Config.app.apiPrefix}/auth/me`);
                        Auth.logout();
                    } catch (e) {
                        Utils.showToast(`Delete failed: ${e.message}`, 'error');
                    }
                },
            }));
        }).catch(() => {});
    }

    function _renderAcctTransfersTab(container) {
        const transfers = TransferManager.getAll();
        if (transfers.length > 0) {
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
        const pendingSection = Utils.el('div', { className: 'transfer-pending-section' });
        container.appendChild(pendingSection);
        Api.get(`${Config.app.apiPrefix}/uploads/pending`).then(data => {
            const pending = data.pending_uploads ?? [];
            if (pending.length === 0) {
                if (transfers.length === 0) {
                    pendingSection.appendChild(Utils.el('p', { className: 'account-menu-empty', textContent: 'No active transfers.' }));
                }
                return;
            }
            pendingSection.appendChild(Utils.el('p', { className: 'transfer-pending-label', textContent: 'Interrupted uploads' }));
            const pList = Utils.el('ul', { className: 'transfer-list' });
            for (const u of pending) {
                const pct  = u.total_size > 0 ? Math.round((u.current_offset / u.total_size) * 100) : 0;
                const href = u.folder_id ? `#/files/${u.folder_id}` : '#/files';
                pList.appendChild(Utils.el('li', { className: 'transfer-item transfer-item--pending' }, [
                    Utils.el('span', { className: 'transfer-item-icon', textContent: '↺' }),
                    Utils.el('span', { className: 'transfer-item-name', textContent: u.original_name }),
                    Utils.el('a', { className: 'transfer-item-resume-link', href, textContent: `${pct}%` }),
                ]));
            }
            pendingSection.appendChild(pList);
        }).catch(() => {
            if (transfers.length === 0) {
                pendingSection.appendChild(Utils.el('p', { className: 'account-menu-empty', textContent: 'No active transfers.' }));
            }
        });
    }

    function _fmtDate(iso) {
        if (!iso) return '—';
        try { return new Date(iso).toLocaleString(); } catch { return iso; }
    }

    function _routeTrash(container) {
        _renderShell(container);
        _renderTrashPage(document.getElementById('main-content'), null);
    }

    function _routeTeamTrash(container, teamId) {
        _renderShell(container);
        _renderTrashPage(document.getElementById('main-content'), teamId);
    }

    let _trashRenderGen = 0;

    async function _renderTrashPage(container, teamId) {
        const gen = ++_trashRenderGen;
        container.innerHTML = '<p class="text-muted" style="padding:24px">Loading trash…</p>';
        const api = Config.app.apiPrefix;
        const url = teamId ? `${api}/trash/teams/${teamId}` : `${api}/trash`;

        let data;
        try {
            data = await Api.get(url);
        } catch (err) {
            if (gen !== _trashRenderGen) return;
            container.innerHTML = '';
            container.appendChild(Utils.el('p', { className: 'text-muted', style: 'padding:24px', textContent: 'Failed to load trash: ' + err.message }));
            return;
        }

        if (gen !== _trashRenderGen) return;
        container.innerHTML = '';

        // Header
        const titleText = teamId ? 'Team Trash' : 'My Trash';
        const header = Utils.el('div', { style: 'display:flex;align-items:center;gap:12px;padding:16px 24px 8px' }, [
            Utils.el('h2', { textContent: titleText, style: 'margin:0;flex:1' }),
        ]);

        const retentionHint = Utils.el('p', {
            className: 'text-muted',
            style: 'padding:0 24px 8px;font-size:0.9em',
            textContent: `Items are permanently deleted after ${data.retention_days} day(s) in trash.`,
        });

        container.appendChild(header);
        container.appendChild(retentionHint);

        const files = data.files || [];
        const folders = data.folders || [];
        const allItems = [
            ...files.map(f => ({ ...f, _kind: 'file' })),
            ...folders.map(f => ({ ...f, _kind: 'folder' })),
        ].sort((a, b) => (a.deleted_at || '').localeCompare(b.deleted_at || ''));

        if (allItems.length === 0) {
            container.appendChild(Utils.el('p', { className: 'text-muted', style: 'padding:0 24px', textContent: 'Trash is empty.' }));
            return;
        }

        // Bulk action bar
        const bulkBar = Utils.el('div', { style: 'display:flex;gap:8px;padding:0 24px 12px;align-items:center' });
        const selectAllChk = Utils.el('input', { type: 'checkbox', title: 'Select all' });
        const restoreBtn = Utils.el('button', { className: 'btn btn-sm btn-secondary', textContent: 'Restore Selected', disabled: true, title: 'Select items to enable' });
        const deleteBtn  = Utils.el('button', { className: 'btn btn-sm btn-danger',   textContent: 'Delete Selected',  disabled: true, title: 'Select items to enable' });
        const selCount   = Utils.el('span', { className: 'text-muted', style: 'font-size:0.9em', textContent: '' });
        bulkBar.appendChild(selectAllChk);
        bulkBar.appendChild(restoreBtn);
        bulkBar.appendChild(deleteBtn);
        bulkBar.appendChild(selCount);
        container.appendChild(bulkBar);

        // Table
        const table = Utils.el('table', { className: 'data-table', style: 'width:100%;border-collapse:collapse' });
        const thead = Utils.el('thead');
        thead.appendChild(Utils.el('tr', {}, [
            Utils.el('th', { style: 'width:32px' }),
            Utils.el('th', { textContent: 'Name' }),
            Utils.el('th', { textContent: 'Type' }),
            Utils.el('th', { textContent: 'Deleted' }),
            Utils.el('th', { textContent: 'Expires' }),
            Utils.el('th', { textContent: 'Deleted By' }),
            Utils.el('th', { textContent: 'Actions' }),
        ]));
        table.appendChild(thead);

        const tbody = Utils.el('tbody');
        const checkboxes = [];

        for (const item of allItems) {
            const chk = Utils.el('input', { type: 'checkbox' });
            checkboxes.push({ chk, item });

            const restoreItemBtn = Utils.el('button', {
                className: 'btn btn-xs btn-secondary',
                textContent: 'Restore',
                style: 'margin-right:4px',
            });
            const deleteItemBtn = Utils.el('button', {
                className: 'btn btn-xs btn-danger',
                textContent: 'Delete',
            });

            restoreItemBtn.addEventListener('click', async () => {
                restoreItemBtn.disabled = true;
                try {
                    const endpoint = item._kind === 'file'
                        ? `${api}/trash/files/${item.id}/restore`
                        : `${api}/trash/folders/${item.id}/restore`;
                    await Api.post(endpoint, {});
                    Utils.showToast('Restored', 'success');
                    _renderTrashPage(container, teamId);
                } catch (err) {
                    Utils.showToast('Restore failed: ' + err.message, 'error');
                    restoreItemBtn.disabled = false;
                }
            });

            deleteItemBtn.addEventListener('click', async () => {
                if (!confirm(`Permanently delete "${item.original_name || item.name}"? This cannot be undone.`)) return;
                deleteItemBtn.disabled = true;
                try {
                    const endpoint = item._kind === 'file'
                        ? `${api}/trash/files/${item.id}`
                        : `${api}/trash/folders/${item.id}`;
                    await Api.del(endpoint);
                    Utils.showToast('Permanently deleted', 'success');
                    _renderTrashPage(container, teamId);
                } catch (err) {
                    Utils.showToast('Delete failed: ' + err.message, 'error');
                    deleteItemBtn.disabled = false;
                }
            });

            const tr = Utils.el('tr', {}, [
                Utils.el('td', {}, [chk]),
                Utils.el('td', { textContent: item.original_name || item.name || item.id }),
                Utils.el('td', { textContent: item._kind }),
                Utils.el('td', { textContent: _fmtDate(item.deleted_at) }),
                Utils.el('td', { textContent: _fmtDate(item.permanent_delete_at) }),
                Utils.el('td', { textContent: item.deleted_by_username || '—' }),
                Utils.el('td', {}, [restoreItemBtn, deleteItemBtn]),
            ]);
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        container.appendChild(table);

        // Bulk action wiring
        function _updateBulkBar() {
            const sel = checkboxes.filter(c => c.chk.checked);
            const n = sel.length;
            restoreBtn.disabled = n === 0;
            deleteBtn.disabled  = n === 0;
            selCount.textContent = n > 0 ? `${n} selected` : '';
            selectAllChk.indeterminate = n > 0 && n < checkboxes.length;
            selectAllChk.checked = n === checkboxes.length;
        }

        checkboxes.forEach(c => c.chk.addEventListener('change', _updateBulkBar));
        selectAllChk.addEventListener('change', () => {
            checkboxes.forEach(c => { c.chk.checked = selectAllChk.checked; });
            _updateBulkBar();
        });

        restoreBtn.addEventListener('click', async () => {
            const sel = checkboxes.filter(c => c.chk.checked).map(c => c.item);
            if (!sel.length) return;
            restoreBtn.disabled = true;
            try {
                const body = {
                    file_ids:   sel.filter(i => i._kind === 'file').map(i => i.id),
                    folder_ids: sel.filter(i => i._kind === 'folder').map(i => i.id),
                };
                const res = await Api.post(`${api}/trash/recover-bulk`, body);
                const restoreSuffix = res.failed ? `, ${res.failed} failed` : '';
                Utils.showToast(`Restored ${res.restored_files + res.restored_folders} item(s)${restoreSuffix}`, 'success');
                _renderTrashPage(container, teamId);
            } catch (err) {
                Utils.showToast('Bulk restore failed: ' + err.message, 'error');
                restoreBtn.disabled = false;
            }
        });

        deleteBtn.addEventListener('click', async () => {
            const sel = checkboxes.filter(c => c.chk.checked).map(c => c.item);
            if (!sel.length) return;
            if (!confirm(`Permanently delete ${sel.length} item(s)? This cannot be undone.`)) return;
            deleteBtn.disabled = true;
            try {
                const body = {
                    file_ids:   sel.filter(i => i._kind === 'file').map(i => i.id),
                    folder_ids: sel.filter(i => i._kind === 'folder').map(i => i.id),
                };
                const res = await Api.post(`${api}/trash/bulk-delete`, body);
                const deleteSuffix = res.failed ? `, ${res.failed} failed` : '';
                Utils.showToast(`Deleted ${res.deleted_files + res.deleted_folders} item(s)${deleteSuffix}`, 'success');
                _renderTrashPage(container, teamId);
            } catch (err) {
                Utils.showToast('Bulk delete failed: ' + err.message, 'error');
                deleteBtn.disabled = false;
            }
        });
    }

    function _renderShell(container) {
        // Only re-render shell if not already present
        if (container.querySelector('.app-shell')) return;

        while (container.firstChild) container.firstChild.remove();
        const user = Auth.getCurrentUser();

        const sidebarToggle = Utils.el('button', {
            className: 'sidebar-toggle',
            title: 'Menu',
            'aria-label': 'Menu',
            textContent: '\u2630',
        });

        const nav = Utils.el('nav', { className: 'sidebar-nav' }, [
            Utils.el('a', { href: '#/files', className: 'sidebar-link', id: 'nav-files', textContent: 'My Files' }),

            Utils.el('div', { className: 'sidebar-section-label', textContent: 'Teams' }),
            Utils.el('div', { className: 'sidebar-submenu' }, [
                Utils.el('a', { href: '#/team-folders', className: 'sidebar-link sidebar-sublink', id: 'nav-team-folders', textContent: 'Team Folders' }),
                Utils.el('a', { href: '#/teams',        className: 'sidebar-link sidebar-sublink', id: 'nav-teams',        textContent: 'Manage Teams' }),
            ]),

            Utils.el('div', { className: 'sidebar-section-label', textContent: 'Shared' }),
            Utils.el('div', { className: 'sidebar-submenu' }, [
                Utils.el('a', { href: '#/shares',          className: 'sidebar-link sidebar-sublink', id: 'nav-shares',   textContent: 'Shared From Me' }),
                Utils.el('a', { href: '#/shares/received', className: 'sidebar-link sidebar-sublink', id: 'nav-received', textContent: 'Shared To Me' }),
            ]),

            Utils.el('div', { className: 'sidebar-section-label', textContent: 'Recent' }),
            Utils.el('div', { className: 'sidebar-submenu', id: 'sidebar-recent-submenu' }, []),

        ]);
        if (user?.is_admin) {
            nav.appendChild(Utils.el('a', {
                href: '#/admin', className: 'sidebar-link sidebar-admin', id: 'nav-admin', textContent: 'Admin Dashboard',
            }));
        }

        const unreadDot = Utils.el('span', { className: 'header-unread-dot' });
        const notifBtn = Utils.el('button', {
            className: 'btn-icon header-notif-btn',
            title: 'Notifications',
            'aria-label': 'Notifications',
            'aria-haspopup': 'true',
            'aria-expanded': 'false',
            onClick: _toggleNotifBubble,
        }, [_buildNotifIcon(), unreadDot]);
        Utils.onUnreadChange(count => {
            unreadDot.classList.toggle('header-unread-dot--active', count > 0);
        });
        const accountLink = Utils.el('a', {
            href: '#/account',
            className: 'btn btn-sm header-account-btn mobile-hidden',
            textContent: user ? user.username : '',
        });

        const logoutBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm mobile-hidden',
            textContent: 'Logout',
            onClick: () => Auth.logout(),
        });

        // Global file search bar
        const searchInput = Utils.el('input', {
            type: 'text',
            className: 'global-search-input mobile-hidden',
            placeholder: 'Search files…',
            style: 'width:40%',
        });
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && searchInput.value.trim()) {
                globalThis.location.hash = `#/search?q=${encodeURIComponent(searchInput.value.trim())}`;
                searchInput.value = '';
            }
        });

        // --- Mobile utility panel (hamburger → left side panel) ---
        const mobileUtilBackdrop = Utils.el('div', { className: 'mobile-util-backdrop' });
        const mobileUtilPanel = Utils.el('div', { className: 'mobile-util-panel' });

        function _closeMobileUtil() {
            mobileUtilPanel.classList.remove('open');
            mobileUtilBackdrop.classList.remove('open');
        }
        mobileUtilBackdrop.addEventListener('click', _closeMobileUtil);

        const utilSearch = Utils.el('input', {
            type: 'text',
            className: 'mobile-util-search',
            placeholder: 'Search files…',
        });
        utilSearch.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && utilSearch.value.trim()) {
                _closeMobileUtil();
                globalThis.location.hash = `#/search?q=${encodeURIComponent(utilSearch.value.trim())}`;
                utilSearch.value = '';
            }
        });

        const utilAccountLink = Utils.el('a', {
            href: '#/account',
            className: 'mobile-util-account-link',
            textContent: user ? user.username : 'My Account',
            onClick: _closeMobileUtil,
        });

        const utilLogoutBtn = Utils.el('button', {
            className: 'mobile-util-logout-btn',
            textContent: 'Logout',
            onClick: () => { _closeMobileUtil(); Auth.logout(); },
        });

        mobileUtilPanel.appendChild(utilSearch);
        mobileUtilPanel.appendChild(utilAccountLink);
        mobileUtilPanel.appendChild(utilLogoutBtn);

        if (user?.is_admin) {
            mobileUtilPanel.appendChild(Utils.el('a', {
                href: '#/admin',
                className: 'mobile-util-account-link',
                textContent: 'Admin',
                onClick: _closeMobileUtil,
            }));
        }

        sidebarToggle.addEventListener('click', () => {
            mobileUtilPanel.classList.add('open');
            mobileUtilBackdrop.classList.add('open');
        });

        // --- Mobile bottom nav bar ---
        const bnBackdrop = Utils.el('div', { className: 'bn-backdrop' });

        function _closeBnSubmenus() {
            document.querySelectorAll('.bn-item.open').forEach(el => el.classList.remove('open'));
            bnBackdrop.classList.remove('active');
        }

        bnBackdrop.addEventListener('click', _closeBnSubmenus);

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') _closeBnSubmenus();
        }, { once: false });

        function _makeBnItem(iconOrEl, href, id, ariaLabel) {
            const a = Utils.el('a', {
                href,
                className: 'bn-tab',
                id: `bn-${id}`,
                'aria-label': ariaLabel,
            });
            if (typeof iconOrEl === 'string') {
                a.appendChild(Utils.el('span', { className: 'bn-icon', textContent: iconOrEl }));
            } else {
                a.appendChild(iconOrEl);
            }
            const wrap = Utils.el('div', { className: 'bn-item' });
            wrap.appendChild(a);
            return wrap;
        }

        function _makeBnSubmenuItem(iconOrEl, id, ariaLabel) {
            const item = Utils.el('div', { className: 'bn-item', id: `bn-wrap-${id}` });
            const btn = Utils.el('button', {
                className: 'bn-tab',
                id: `bn-${id}`,
                'aria-haspopup': 'true',
                'aria-expanded': 'false',
                'aria-label': ariaLabel,
            });
            if (typeof iconOrEl === 'string') {
                btn.appendChild(Utils.el('span', { className: 'bn-icon', textContent: iconOrEl }));
            } else {
                btn.appendChild(iconOrEl);
            }

            const submenu = Utils.el('div', { className: 'bn-submenu', role: 'menu' });
            item.appendChild(btn);
            item.appendChild(submenu);

            btn.addEventListener('click', () => {
                const isOpen = item.classList.contains('open');
                _closeBnSubmenus();
                if (!isOpen) {
                    item.classList.add('open');
                    btn.setAttribute('aria-expanded', 'true');
                    bnBackdrop.classList.add('active');
                }
            });

            item.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') { _closeBnSubmenus(); btn.focus(); }
            });

            return { item, submenu };
        }

        function _mkSvg(innerHTML, attrs = {}) {
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.setAttribute('viewBox', '0 0 24 24');
            svg.setAttribute('width', '22');
            svg.setAttribute('height', '22');
            svg.setAttribute('aria-hidden', 'true');
            for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, v);
            svg.innerHTML = innerHTML;
            return svg;
        }
        const _iconHome  = () => _mkSvg('<path fill="currentColor" d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/>');
        const _iconShare = () => _mkSvg('<path fill="currentColor" d="M6.99 11L3 15l3.99 4v-3H14v-2H6.99v-3zM21 9l-3.99-4v3H10v2h7.01v3L21 9z"/>');
        const _iconStar  = () => _mkSvg('<polygon fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" points="12,2 15.09,8.26 22,9.27 17,14.14 18.18,21.02 12,17.77 5.82,21.02 7,14.14 2,9.27 8.91,8.26"/>');
        const _iconClock = () => _mkSvg(
            '<circle cx="12" cy="12" r="9" stroke-width="1.5"/>' +
            '<path stroke-linecap="round" stroke-width="1.5" d="M12 7v5l3.5 3.5"/>',
            { fill: 'none', stroke: 'currentColor' }
        );
        // Three-person team icon.
        // Front body: cubic bezier with steep sides and flat apex — avoids the deep-U
        // of a circular arc. Control points give nearly vertical tangents at the base
        // and a horizontal tangent at the peak (~y=12).
        // Back bodies: same bezier shape, shifted left/right. A clipPath defined by the
        // front body's closed region automatically hides wherever the back arcs pass
        // "behind" the front person — no intersection math required.
        const _iconPerson = () => _mkSvg(
            '<defs><clipPath id="tcb">' +
            '<path clip-rule="evenodd" d="M-5-5H30V30H-5Z ' +
            'M3 22C3 13 7 12 12 12C17 12 21 13 21 22L21 28L3 28Z"/>' +
            '</clipPath></defs>' +
            // Left person body — outer edge raised to y=19, apex at y=10, wider spread
            '<path stroke-width="1.2" stroke-linecap="round" clip-path="url(#tcb)"' +
            ' d="M-4 19C-4 11 0 10 5 10C9 10 11 14 11 22"/>' +
            '<circle cx="3" cy="5.5" r="2.2" stroke-width="1.5"/>' +
            // Right person body (mirror)
            '<path stroke-width="1.2" stroke-linecap="round" clip-path="url(#tcb)"' +
            ' d="M13 22C13 14 15 10 19 10C24 10 28 11 28 19"/>' +
            '<circle cx="21" cy="5.5" r="2.2" stroke-width="1.5"/>' +
            // Front person body (full, drawn on top)
            '<path stroke-width="2" stroke-linecap="round"' +
            ' d="M3 22C3 13 7 12 12 12C17 12 21 13 21 22"/>' +
            '<circle cx="12" cy="7.5" r="3" stroke-width="2"/>',
            { fill: 'none', stroke: 'currentColor', overflow: 'visible' }
        );

        const { item: bnTeams, submenu: bnTeamsMenu } = _makeBnSubmenuItem(_iconPerson(), 'teams', 'Teams');
        bnTeamsMenu.appendChild(Utils.el('a', { href: '#/team-folders', className: 'bn-submenu-link', role: 'menuitem', textContent: 'Team Folders' }));
        bnTeamsMenu.appendChild(Utils.el('a', { href: '#/teams',        className: 'bn-submenu-link', role: 'menuitem', textContent: 'Manage Teams' }));

        const { item: bnShared, submenu: bnSharedMenu } = _makeBnSubmenuItem(_iconShare(), 'shared', 'Shared');
        bnSharedMenu.appendChild(Utils.el('a', { href: '#/shares',          className: 'bn-submenu-link', role: 'menuitem', textContent: 'Shared By Me' }));
        bnSharedMenu.appendChild(Utils.el('a', { href: '#/shares/received', className: 'bn-submenu-link', role: 'menuitem', textContent: 'Shared To Me' }));

        const { item: bnRecent, submenu: bnRecentMenu } = _makeBnSubmenuItem(_iconClock(), 'recent', 'Recent');

        // Close submenu when a submenu link is clicked
        [bnTeamsMenu, bnSharedMenu].forEach(menu => {
            menu.querySelectorAll('.bn-submenu-link').forEach(link => {
                link.addEventListener('click', _closeBnSubmenus);
            });
        });

        // Populate Recent in both sidebar and bottom nav from a single fetch
        Api.get(`${Config.app.apiPrefix}/auth/me/recent-folders`).then(data => {
            const items = (data.recent_folders || []).slice(0, 4);
            const sidebarSlot = document.getElementById('sidebar-recent-submenu');
            if (sidebarSlot) {
                if (items.length) {
                    for (const item of items) {
                        sidebarSlot.appendChild(Utils.el('a', {
                            href: item.hash,
                            className: 'sidebar-link sidebar-sublink',
                            title: item.folder_name,
                            textContent: item.folder_name,
                        }));
                    }
                }
            }
            for (const item of items) {
                const link = Utils.el('a', { href: item.hash, className: 'bn-submenu-link', role: 'menuitem', textContent: item.folder_name });
                link.addEventListener('click', _closeBnSubmenus);
                bnRecentMenu.appendChild(link);
            }
        }).catch(() => {});

        const bnTransferBtn = Utils.el('button', {
            className: 'bn-tab',
            id: 'bn-transfers',
            'aria-label': 'Transfer progress',
        });
        const bnTransferArrows = Utils.el('span', { className: 'bn-transfer-arrows' });
        bnTransferArrows.appendChild(Utils.el('span', { className: 'bn-transfer-up',   textContent: '↑' }));
        bnTransferArrows.appendChild(Utils.el('span', { className: 'bn-transfer-down', textContent: '↓' }));
        bnTransferArrows.appendChild(Utils.el('span', { className: 'bn-transfer-flash' }));
        bnTransferBtn.appendChild(bnTransferArrows);
        const bnTransferItem = Utils.el('div', { className: 'bn-item' });
        bnTransferItem.appendChild(bnTransferBtn);
        TransferManager.setMobileBtn(bnTransferBtn);

        const bottomNav = Utils.el('nav', { className: 'mobile-bottom-nav', 'aria-label': 'Mobile navigation' }, [
            _makeBnItem(_iconHome(), '#/files', 'files', 'My Files'),
            bnTeams,
            bnShared,
            bnRecent,
            _makeBnItem(_iconStar(), '#/pinned', 'pinned', 'Favourites'),
            bnTransferItem,
        ]);
        bottomNav.appendChild(bnBackdrop);

        const shellChildren = [
            Utils.el('a', { href: '#main-content', className: 'skip-link', textContent: 'Skip to main content' }),
            Utils.el('header', { className: 'app-header' }, [
                Utils.el('div', { style: 'display:flex;align-items:center;gap:8px' }, [
                    sidebarToggle,
                    _buildBrandEl(),
                ]),
                searchInput,
                Utils.el('div', { className: 'header-actions' }, [
                    notifBtn,
                    accountLink,
                    logoutBtn,
                ]),
            ]),
            mobileUtilBackdrop,
            mobileUtilPanel,
        ];

        // Public device banner — shown when the user checked "Public Device" at login.
        // Dismissed by clicking X (removes it from DOM and clears the sessionStorage flag
        // so it does not re-appear on route changes within the same tab).
        const cfg = Config.publicDevice;
        const _bannerVisible = _themeConfig?.ui?.public_device_banner_visible ?? true;
        const _bannerText    = _themeConfig?.public_device_banner_text ?? cfg.bannerText;
        if (_bannerVisible && sessionStorage.getItem(cfg.sessionStorageKey) === '1') {
            const banner = Utils.el('div', { className: 'public-device-banner' }, [
                Utils.el('span', { textContent: _bannerText }),
                Utils.el('button', {
                    className: 'public-device-banner-dismiss',
                    title: 'Dismiss',
                    'aria-label': 'Dismiss',
                    textContent: '\u00d7',   //×
                    onClick: () => {
                        sessionStorage.removeItem(cfg.sessionStorageKey);
                        if (banner.parentNode) banner.remove();
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
            user?.escrow_active &&
            !sessionStorage.getItem(_ESCROW_DISMISSED_KEY)
        ) {
            const escrowBanner = Utils.el('div', { className: 'admin-transparency-banner' }, [
                Utils.el('span', {
                    textContent: 'Admin key escrow is active: designated escrow agents may access the encryption keys for one or more teams you belong to.',
                }),
                Utils.el('button', {
                    className: 'admin-transparency-banner-dismiss',
                    title: 'Dismiss',
                    'aria-label': 'Dismiss',
                    textContent: '\u00d7',   // ×
                    onClick: () => {
                        sessionStorage.setItem(_ESCROW_DISMISSED_KEY, '1');
                        if (escrowBanner.parentNode) escrowBanner.remove();
                    },
                }),
            ]);
            shellChildren.push(escrowBanner);
        }

        const pinnedSection = Utils.el('div', { id: 'pinned-folders-sidebar', className: 'pinned-folders-sidebar' });
        _renderPinnedSidebar(pinnedSection);

        shellChildren.push(
            Utils.el('div', { className: 'app-body' }, [
                Utils.el('aside', { className: 'sidebar', id: 'folder-sidebar' }, [
                    nav,
                    pinnedSection,
                ]),
                Utils.el('div', { id: 'main-content', className: 'app-main' }),
            ]),
            bottomNav,
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

        // Bottom nav: highlight active tab
        const bnRules = [
            { id: 'bn-files',   test: h => /^#\/files(\/.*)?$/.test(h) },
            { id: 'bn-pinned',  test: h => h === '#/pinned' },
            { id: 'bn-teams',   test: h => /^#\/(team-folders|teams)(\/.*)?$/.test(h) },
            { id: 'bn-shared',  test: h => /^#\/shares(\/.*)?$/.test(h) },
        ];
        bnRules.forEach(({ id, test }) => {
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

    return { init, pinCurrentFolder, unpinCurrentFolder, isPinned, reloadTheme: _loadTheme };
})();
