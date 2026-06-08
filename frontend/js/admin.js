/**
 * tusShare — Admin dashboard.
 *
 * Single-page layout with four collapsible sections:
 *   1. System Settings  — global limits, thresholds, chunk size, open registration
 *   2. Disk Usage       — filesystem stats + per-user breakdown
 *   3. User Management  — list, edit quotas/limits/status, delete
 *   4. Invites          — create single-use registration links, revoke pending ones
 *
 * Design note: all size values are stored in bytes by the API. The UI converts
 * to/from MB for display. Bandwidth limit is stored in bytes/second; displayed as MB/s.
 * A value of 0 means "no limit" for every size/bandwidth setting.
 *
 * Future: invite creation and user management may be delegated to scoped roles
 * (e.g. team_supervisor with a "create_invite" permission). The section structure
 * here is designed to be extracted into per-permission sub-views without rework.
 */
const Admin = (() => {
    const _api = () => Config.app.apiPrefix;
    const _MB  = Config.admin.bytesPerMb;

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------

    const _ADMIN_TABS = [
        {
            id: 'system',
            label: 'System',
            sections: [
                ['settings',       'System Settings',        _renderSettings],
                ['storage',        'Storage',                _renderStorageSection],
                ['disk',           'Disk Usage',             _renderDiskUsage],
                ['theme',          'Theme & Branding',       _renderTheme],
                ['notifications',  'Notification Channels',  _renderNotificationsSection],
            ],
        },
        {
            id: 'users',
            label: 'Users',
            sections: [
                ['users',            'User Management',    _renderUsers],
                ['invites',          'Invites',             _renderInvites],
                ['service-accounts', 'Service Accounts',   _renderServiceAccountsSection],
                ['idp',              'Identity Providers',  _renderIdpSection],
            ],
        },
        {
            id: 'teams',
            label: 'Teams',
            sections: [
                ['teams', 'Team Management', _renderTeams],
            ],
        },
        {
            id: 'roles',
            label: 'Roles & Policies',
            sections: [
                ['roles',  'Roles & Permissions',  _renderRoles],
                ['mfa',    'MFA Policy',            _renderMfaAdmin],
                ['policy', 'Policy Engine',         _renderPolicySection],
                ['escrow', 'Escrow by Default',     _renderEscrowSection],
            ],
        },
        {
            id: 'security',
            label: 'Security & Privacy',
            sections: [
                ['profiles',        'Settings Profile',       _renderProfilesSection],
                ['api-keys',        'API Keys',               _renderApiKeysSection],
                ['antivirus',       'Antivirus',              _renderAntivirusSection],
                ['sharing',         'Sharing Restrictions',   _renderSharingSection],
                ['rate-limits',     'Rate Limiting',          _renderRateLimits],
                ['session-policy',  'Session & Auth Policy',  _renderSessionPolicy],
            ],
        },
        {
            id: 'audit',
            label: 'Audit',
            sections: [
                ['audit', 'Audit & SIEM', _renderAuditSection],
            ],
        },
        {
            id: 'export',
            label: 'Import / Export',
            sections: [
                ['export', 'Import / Export', _renderExportSection],
            ],
        },
    ];

    // Maps section IDs to the flags (any one of which) that grant access.
    // Sections whose ID is absent are shown to all admins.
    const _SECTION_FLAGS = {
        'settings':         ['system_settings_manage', 'org_settings_manage'],
        'storage':          ['system_settings_manage'],
        'disk':             ['disk_usage_view'],
        'theme':            ['system_settings_manage', 'org_settings_manage'],
        'notifications':    ['integrations_notifications_manage'],
        'users':            ['users_view', 'users_manage'],
        'invites':          ['users_invite_manage'],
        'service-accounts': ['service_accounts_manage'],
        'idp':              ['integrations_idp_manage', 'system_settings_manage'],
        'teams':            ['teams_manage'],
        'roles':            ['roles_manage', 'roles_create'],
        'mfa':              ['users_mfa_manage'],
        'policy':           ['policies_view', 'policies_manage'],
        'escrow':           ['escrow_manage'],
        'profiles':         ['org_settings_manage', 'sharing_manage'],
        'api-keys':         ['integrations_notifications_manage', 'system_settings_manage'],
        'antivirus':        ['system_settings_manage'],
        'sharing':          ['sharing_manage'],
        'rate-limits':      ['system_settings_manage'],
        'session-policy':   ['system_settings_manage'],
        'audit':            ['audit_log_view'],
        'export':           ['system_settings_manage'],
    };

    // ------------------------------------------------------------------
    // Layout prefs — load / save / apply
    // ------------------------------------------------------------------

    async function _loadAdminPrefs() {
        try {
            const data = await Api.get(`${_api()}/auth/me/prefs`);
            return data.ui_prefs || {};
        } catch {
            return {};
        }
    }

    async function _saveAdminPrefs(layout) {
        try {
            await Api.patch(`${_api()}/auth/me/prefs`, { admin_layout: layout });
        } catch { /* non-critical — layout just reverts on next load */ }
    }

    async function _saveRoleOrderPref(order) {
        try {
            await Api.patch(`${_api()}/auth/me/prefs`, { role_order: order });
        } catch { /* non-critical */ }
    }

    // Module-level role order loaded from server prefs; null = use default sort
    let _adminRoleOrder = null;

    function _applyLayoutPrefs(prefs) {
        const layout = prefs?.admin_layout;
        if (!layout) return _ADMIN_TABS.map(t => ({ ...t, sections: [...t.sections] }));

        const byId = Object.fromEntries(
            _ADMIN_TABS.map(t => [t.id, { ...t, sections: [...t.sections] }])
        );
        const tabOrder = (layout.tabOrder || []).filter(id => byId[id]);
        const seen = new Set(tabOrder);
        _ADMIN_TABS.forEach(t => { if (!seen.has(t.id)) tabOrder.push(t.id); });

        return tabOrder.map(tabId => {
            const tab = byId[tabId];
            const savedOrder = layout.sectionOrder?.[tabId];
            if (!savedOrder) return tab;
            const bySection = Object.fromEntries(tab.sections.map(s => [s[0], s]));
            const ordered = savedOrder.filter(sid => bySection[sid]);
            const seenS = new Set(ordered);
            tab.sections.forEach(s => { if (!seenS.has(s[0])) ordered.push(s[0]); });
            tab.sections = ordered.map(sid => bySection[sid]);
            return tab;
        });
    }

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------

    function _sectionVisibleForFlags(id, flags) {
        const req = _SECTION_FLAGS[id];
        return !req || req.some(f => flags[f] === '1');
    }

    function _filterTabsByFlags(tabs, flags) {
        return tabs
            .map(tab => ({
                ...tab,
                sections: tab.sections.filter(([id]) => _sectionVisibleForFlags(id, flags)),
            }))
            .filter(tab => tab.sections.length > 0);
    }

    function renderAdminPage(container) {
        container.innerHTML = '<p class="text-muted loading-msg">Loading…</p>';
        _loadAdminPrefs().then(prefs => {
            _adminRoleOrder = Array.isArray(prefs.role_order) ? prefs.role_order : null;
            const flags = Auth.getCurrentUser()?.flags || {};
            _renderAdmin(container, _filterTabsByFlags(_applyLayoutPrefs(prefs), flags));
        });
    }

    function _insertionTarget(elements, clientPos, axis) {
        for (const el of elements) {
            const rect = el.getBoundingClientRect();
            const mid  = axis === 'h' ? rect.left + rect.width / 2 : rect.top + rect.height / 2;
            if (clientPos < mid) return el;
        }
        return null;
    }

    function _renderAdmin(container, liveTabs) {
        container.innerHTML = '';

        let rearranging   = false;
        let activeTabId   = liveTabs[0]?.id ?? 'system';
        const visitedTabs = new Set();
        const paneEls     = {};   // tabId → pane element
        const expanders   = {};   // sectionId → expand()
        let   dragListeners = [];

        // -- header --
        const rearrangeBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm admin-rearrange-btn',
            textContent: '⠿ Rearrange',
            onClick: _toggleRearrange,
        });
        const header = Utils.el('div', { className: 'admin-header' }, [
            Utils.el('h2', { className: 'admin-title', textContent: 'Admin Dashboard' }),
            rearrangeBtn,
        ]);

        // -- ribbon --
        const ribbon = Utils.el('div', { className: 'admin-ribbon', role: 'tablist' });

        // -- page shell --
        const page = Utils.el('div', { className: 'admin-page' }, [header, ribbon]);

        // -- build tabs + panes --
        liveTabs.forEach(tab => {
            const pane = Utils.el('div', { className: 'admin-tab-pane', id: `admin-tab-${tab.id}`, role: 'tabpanel', 'aria-labelledby': `admin-ribbon-tab-${tab.id}` });
            pane.dataset.tabId = tab.id;
            pane.style.display = 'none';

            tab.sections.forEach(([id, title, renderFn]) => {
                const { el, expand } = _buildSection(id, title, renderFn);
                el.dataset.sectionId = id;
                el.dataset.tabId     = tab.id;
                expanders[id]        = expand;
                pane.appendChild(el);
            });

            paneEls[tab.id] = pane;
            page.appendChild(pane);

            const btn = Utils.el('button', {
                id: `admin-ribbon-tab-${tab.id}`,
                className: 'admin-ribbon-tab',
                role: 'tab',
                'aria-selected': 'false',
                'aria-controls': `admin-tab-${tab.id}`,
                onClick: () => !rearranging && _activateTab(tab.id),
            });
            btn.dataset.tabId = tab.id;
            btn.appendChild(Utils.el('span', { className: 'drag-handle', textContent: '⠿' }));
            btn.appendChild(Utils.el('span', { textContent: tab.label }));
            ribbon.appendChild(btn);
        });

        container.appendChild(page);
        _activateTab(activeTabId);

        // -- tab activation --
        function _activateTab(id) {
            activeTabId = id;
            Object.entries(paneEls).forEach(([k, p]) => { p.style.display = k === id ? '' : 'none'; });
            ribbon.querySelectorAll('.admin-ribbon-tab').forEach(b => {
                const isActive = b.dataset.tabId === id;
                b.classList.toggle('active', isActive);
                b.setAttribute('aria-selected', String(isActive));
            });
            if (!visitedTabs.has(id)) {
                visitedTabs.add(id);
                const first = paneEls[id]?.querySelector(':scope > .admin-section');
                if (first) expanders[first.dataset.sectionId]?.();
            }
            if (rearranging) _setupSectionDrag(id);
        }

        // -- rearrange toggle --
        function _toggleRearrange() {
            rearranging = !rearranging;
            rearrangeBtn.textContent = rearranging ? '✓ Done' : '⠿ Rearrange';
            rearrangeBtn.classList.toggle('btn-primary',   rearranging);
            rearrangeBtn.classList.toggle('btn-secondary', !rearranging);
            page.classList.toggle('admin-rearranging', rearranging);
            if (rearranging) {
                _setupTabDrag();
                _setupSectionDrag(activeTabId);
            } else {
                _teardownDrag();
                const tabOrder = [...ribbon.querySelectorAll('.admin-ribbon-tab')].map(b => b.dataset.tabId);
                const sectionOrder = {};
                tabOrder.forEach(tid => { // NOSONAR — closure over sectionOrder/paneEls; nesting depth is unavoidable
                    const pane = paneEls[tid];
                    if (pane) sectionOrder[tid] = [...pane.querySelectorAll(':scope > .admin-section')].map(el => el.dataset.sectionId); // NOSONAR — deep in drag handler; nesting unavoidable
                });
                _saveAdminPrefs({ tabOrder, sectionOrder });
            }
        }

        // Shared insertion-line indicators — moved into place in the DOM during drag
        const _tabIndicator = Utils.el('div', { className: 'drop-indicator-h' });
        const _secIndicator  = Utils.el('div', { className: 'drop-indicator-v' });

        function _on(el, event, fn) {
            el.addEventListener(event, fn);
            dragListeners.push({ el, event, fn });
        }

        let sectionDragListeners = [];
        function _sOn(el, event, fn) {
            el.addEventListener(event, fn);
            sectionDragListeners.push({ el, event, fn });
        }

        // -- tab drag (horizontal) --
        function _setupTabDrag() {
            let draggedId = null;
            [...ribbon.querySelectorAll('.admin-ribbon-tab')].forEach(btn => {
                btn.setAttribute('draggable', 'true');
                _on(btn, 'dragstart', e => { // NOSONAR — closure over btn/draggedId; unavoidable nesting
                    draggedId = btn.dataset.tabId;
                    e.dataTransfer.effectAllowed = 'move';
                    requestAnimationFrame(() => btn.classList.add('dragging'));
                });
                _on(btn, 'dragend', () => { // NOSONAR — closure over btn/draggedId
                    btn.classList.remove('dragging');
                    _tabIndicator.remove();
                    draggedId = null;
                });
            });
            _on(ribbon, 'dragover', e => {
                if (!draggedId) return;
                e.preventDefault();
                const siblings = [...ribbon.querySelectorAll('.admin-ribbon-tab:not(.dragging)')];
                const before   = _insertionTarget(siblings, e.clientX, 'h');
                if (before) before.before(_tabIndicator);
                else         ribbon.appendChild(_tabIndicator);
            });
            _on(ribbon, 'dragleave', e => {
                if (!ribbon.contains(e.relatedTarget)) _tabIndicator.remove();
            });
            _on(ribbon, 'drop', e => {
                e.preventDefault();
                if (!draggedId || !_tabIndicator.parentNode) return;
                const dragged = ribbon.querySelector(`[data-tab-id="${draggedId}"]`);
                if (dragged) _tabIndicator.before(dragged);
                _tabIndicator.remove();
            });
        }

        // -- section drag (vertical) --
        function _setupSectionDrag(tabId) {
            // Tear down previous section bindings before re-binding for new tab
            sectionDragListeners.forEach(({ el, event, fn }) => el.removeEventListener(event, fn));
            sectionDragListeners = [];
            _secIndicator.remove();

            const pane = paneEls[tabId];
            if (!pane) return;
            let draggedId = null;

            [...pane.querySelectorAll(':scope > .admin-section')].forEach(sec => {
                sec.setAttribute('draggable', 'true');
                _sOn(sec, 'dragstart', e => { // NOSONAR — closure over sec/draggedId; unavoidable nesting
                    draggedId = sec.dataset.sectionId;
                    e.dataTransfer.effectAllowed = 'move';
                    e.stopPropagation();
                    requestAnimationFrame(() => sec.classList.add('dragging'));
                });
                _sOn(sec, 'dragend', e => { // NOSONAR — closure over sec/draggedId
                    e.stopPropagation();
                    sec.classList.remove('dragging');
                    _secIndicator.remove();
                    draggedId = null;
                });
            });
            _sOn(pane, 'dragover', e => {
                if (!draggedId) return;
                e.preventDefault();
                const siblings = [...pane.querySelectorAll(':scope > .admin-section:not(.dragging)')];
                const before   = _insertionTarget(siblings, e.clientY, 'v');
                if (before) before.before(_secIndicator);
                else         pane.appendChild(_secIndicator);
            });
            _sOn(pane, 'dragleave', e => {
                if (!pane.contains(e.relatedTarget)) _secIndicator.remove();
            });
            _sOn(pane, 'drop', e => {
                e.preventDefault(); e.stopPropagation();
                if (!draggedId || !_secIndicator.parentNode) return;
                const dragged = pane.querySelector(`[data-section-id="${draggedId}"]`);
                if (dragged) _secIndicator.before(dragged);
                _secIndicator.remove();
            });
        }

        function _teardownDrag() {
            sectionDragListeners.forEach(({ el, event, fn }) => el.removeEventListener(event, fn));
            sectionDragListeners = [];
            dragListeners.forEach(({ el, event, fn }) => el.removeEventListener(event, fn));
            dragListeners = [];
            _tabIndicator.remove();
            _secIndicator.remove();
            ribbon.querySelectorAll('.admin-ribbon-tab').forEach(el => {
                el.removeAttribute('draggable');
                el.classList.remove('dragging');
            });
            Object.values(paneEls).forEach(p => p.querySelectorAll(':scope > .admin-section').forEach(el => { // NOSONAR — double-forEach cleanup; nesting depth is unavoidable
                el.removeAttribute('draggable');
                el.classList.remove('dragging');
            }));
        }
    }

    // ------------------------------------------------------------------
    // Shared form-row helpers (used across multiple settings sections)
    // ------------------------------------------------------------------

    const _row = (label, hint, input) => Utils.el('div', { className: 'settings-row' }, [
        Utils.el('label', { className: 'settings-label', textContent: label }),
        Utils.el('div', { className: 'settings-input-wrap' }, [
            input,
            hint ? Utils.el('span', { className: 'settings-hint', textContent: hint }) : null,
        ].filter(Boolean)),
    ]);

    const _mkField = (label, inp, hint) => {
        const row = Utils.el('div', { style: 'margin-bottom:10px' });
        row.appendChild(Utils.el('label', { textContent: label, style: 'display:block;font-size:var(--font-size-sm);margin-bottom:4px' }));
        row.appendChild(inp);
        if (hint) row.appendChild(Utils.el('p', { textContent: hint, style: 'font-size:var(--font-size-sm);color:var(--color-muted,#888);margin:2px 0 0' }));
        return row;
    };

    // ------------------------------------------------------------------
    // Section scaffold — collapsible wrapper
    // ------------------------------------------------------------------

    function _buildSection(id, title, renderFn) {
        let loaded = false;
        const body = Utils.el('div', { className: 'admin-section-body' });
        body.style.display = 'none';

        const toggle = Utils.el('button', {
            className: 'admin-section-toggle collapsed',
            textContent: title,
            'aria-expanded': 'false',
            onClick: () => {
                const open = body.style.display !== 'none';
                body.style.display = open ? 'none' : '';
                toggle.classList.toggle('collapsed', open);
                toggle.setAttribute('aria-expanded', open ? 'false' : 'true');
                if (!open && !loaded) { loaded = true; renderFn(body); }
            },
        });

        const el = Utils.el('div', { className: 'admin-section', id: `admin-${id}` }, [
            Utils.el('div', { className: 'admin-section-header' }, [
                Utils.el('span', { className: 'drag-handle section-drag-handle', textContent: '⠿' }),
                toggle,
            ]),
            body,
        ]);

        function expand() {
            if (body.style.display !== 'none') return;
            body.style.display = '';
            toggle.classList.remove('collapsed');
            toggle.setAttribute('aria-expanded', 'true');
            if (!loaded) { loaded = true; renderFn(body); }
        }

        return { el, expand };
    }

    // ------------------------------------------------------------------
    // Section 1: System Settings
    // ------------------------------------------------------------------

    async function _renderSettings(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let s;
        try {
            const data = await Api.get(`${_api()}/admin/settings`);
            s = data.settings;
        } catch (err) {
            _showError(container, 'Failed to load settings: ' + err.message);
            return;
        }

        const _numVal = (key, divisor = 1) => {
            const raw = Number.parseInt(s[key] || '0', 10);
            return divisor > 1 ? Math.round(raw / divisor) : raw;
        };

        const fldMaxFileSize = Utils.el('input', {
            type: 'number', min: '0', className: 'input-sm',
            value: String(_numVal('global_max_file_size', _MB)),
            title: '0 = no limit',
        });
        const fldBandwidth = Utils.el('input', {
            type: 'number', min: '0', className: 'input-sm',
            value: String(_numVal('global_bandwidth_limit', _MB)),
            title: '0 = no limit',
        });
        const fldDiskWarn = Utils.el('input', {
            type: 'number', min: '0', max: '100', className: 'input-sm',
            value: String(_numVal('disk_warning_threshold')),
        });
        const fldChunkSize = Utils.el('input', {
            type: 'number', min: '1', className: 'input-sm',
            value: String(_numVal('default_chunk_size', _MB)),
        });
        const fldOpenReg = Utils.el('input', {
            type: 'checkbox',
            checked: s['open_registration'] === 'true',
        });
        const fldAllowSelfDelete = Utils.el('input', {
            type: 'checkbox',
            checked: s['allow_user_delete_own_account'] === 'true',
        });
        const fldMultiOwner = Utils.el('input', {
            type: 'checkbox',
            checked: s['allow_multi_team_owner'] === 'true',
        });

        // Server Tuning fields (Phase 3) — use safe accessor for nested settings format
        const _sv = (key, def) => s[key]?.value ?? s[key] ?? def;
        const fldTusExpiry = Utils.el('input', {
            type: 'number', min: '1', max: '168', className: 'input-sm',
            value: String(Number.parseInt(_sv('tus_upload_expiry_hours', '24'), 10)),
        });
        const fldEvictStride = Utils.el('input', {
            type: 'number', min: '0', max: '256', className: 'input-sm',
            value: String(Number.parseInt(_sv('upload_evict_stride_mb', '32'), 10)),
        });
        const fldRpName = Utils.el('input', {
            type: 'text', className: 'input-sm', maxLength: '128',
            value: _sv('webauthn_rp_name', 'tusShare'),
        });
        const fldAllowHttpIdp = Utils.el('input', {
            type: 'checkbox',
            checked: _sv('allow_http_idp', 'false') === 'true',
        });

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Save Settings',
            onClick: async () => {
                const chunkMb = Number.parseInt(fldChunkSize.value, 10);
                if (Number.isNaN(chunkMb) || chunkMb < 1) {
                    Utils.showToast('Default chunk size must be at least 1 MB', 'error');
                    return;
                }
                const rpName = fldRpName.value.trim();
                if (!rpName) {
                    Utils.showToast('WebAuthn display name cannot be empty', 'error');
                    return;
                }
                const payload = {
                    global_max_file_size:          String(Number.parseInt(fldMaxFileSize.value, 10) * _MB),
                    global_bandwidth_limit:         String(Number.parseInt(fldBandwidth.value, 10)   * _MB),
                    disk_warning_threshold:         String(Number.parseInt(fldDiskWarn.value, 10)),
                    default_chunk_size:             String(chunkMb * _MB),
                    open_registration:              fldOpenReg.checked ? 'true' : 'false',
                    allow_user_delete_own_account:  fldAllowSelfDelete.checked ? 'true' : 'false',
                    allow_multi_team_owner:         fldMultiOwner.checked ? 'true' : 'false',
                    tus_upload_expiry_hours:        String(Number.parseInt(fldTusExpiry.value, 10)),
                    upload_evict_stride_mb:         String(Number.parseInt(fldEvictStride.value, 10)),
                    webauthn_rp_name:               rpName,
                    allow_http_idp:                 fldAllowHttpIdp.checked ? 'true' : 'false',
                };
                saveBtn.disabled = true;
                try {
                    await Api.put(`${_api()}/admin/settings`, { settings: payload });
                    Utils.showToast('Settings saved', 'success');
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                } finally {
                    saveBtn.disabled = false;
                }
            },
        });

        container.innerHTML = '';
        container.appendChild(Utils.el('div', { className: 'settings-form' }, [
            _row('Global max file size (MB)', '0 = no global limit', fldMaxFileSize),
            _row('Global bandwidth limit (MB/s)', '0 = no global limit (upload + download combined per user)', fldBandwidth),
            _row('Disk warning threshold (%)', 'Admin alert when filesystem usage reaches this %', fldDiskWarn),
            _row('Default chunk size (MB)', 'Enforced server-side; clients fetch this value on startup and use it for new uploads', fldChunkSize),
            _row('Open registration', 'Allow anyone to register without an invite', fldOpenReg),
            _row('Allow users to delete their own account', 'When enabled, users can permanently delete their account from the account menu', fldAllowSelfDelete),
            _row('Allow multiple team owners', 'When enabled, team owners may promote supervisors to co-owner', fldMultiOwner),
            Utils.el('div', { className: 'settings-divider', style: 'margin:16px 0 12px;border-top:1px solid var(--color-border);' }),
            Utils.el('h4', { textContent: 'Server Tuning', style: 'margin:0 0 10px;font-size:var(--font-size-sm);text-transform:uppercase;color:var(--color-muted,#888);letter-spacing:.05em' }),
            _row('Incomplete upload expiry (hours)', 'How long incomplete TUS uploads are retained before cleanup', fldTusExpiry),
            _row('Page-cache eviction stride (MB)', '0 = disabled. Lower (8–32) for RAM-constrained hosts; higher (64–256) for NFS/SMB', fldEvictStride),
            _row('WebAuthn display name', 'Human-readable name shown in authenticator dialogs (e.g. passkey registration prompts)', fldRpName),
            _row('Allow HTTP OIDC issuers', '⚠ Only enable on trusted internal networks without TLS', fldAllowHttpIdp),
            Utils.el('div', { className: 'settings-actions' }, [saveBtn]),
        ]));

        // Hardware scan — runs a capability scan and renders tuning recommendations
        const hwSection = Utils.el('div', { style: 'margin-top:24px' });
        hwSection.appendChild(Utils.el('h4', { textContent: 'Hardware Capability Scan', style: 'margin-bottom:6px' }));
        hwSection.appendChild(Utils.el('p', { className: 'text-muted', style: 'margin-bottom:8px;font-size:var(--font-size-sm)', textContent: 'Detects CPU, memory, and storage capabilities and provides tuning recommendations.' }));
        const hwResultWrap = Utils.el('div');
        const hwBtn = Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Run Hardware Scan' });
        hwBtn.addEventListener('click', async () => {
            hwBtn.disabled = true;
            hwBtn.textContent = 'Scanning…';
            hwResultWrap.innerHTML = '';
            try {
                const result = await Api.get(`${_api()}/admin/hw-scan`);
                hwResultWrap.innerHTML = '';
                if (result.recommendations?.length) {
                    const list = Utils.el('ul', { style: 'font-size:var(--font-size-sm);margin:8px 0 0;padding-left:18px' });
                    for (const rec of result.recommendations) {
                        list.appendChild(Utils.el('li', { textContent: rec }));
                    }
                    hwResultWrap.appendChild(list);
                }
                const summary = Utils.el('pre', { style: 'font-size:var(--font-size-xs);background:var(--color-surface-secondary);padding:8px;border-radius:4px;overflow-x:auto;margin-top:8px;white-space:pre-wrap' });
                summary.textContent = JSON.stringify(result, null, 2);
                hwResultWrap.appendChild(summary);
            } catch (err) {
                hwResultWrap.appendChild(Utils.el('p', { className: 'text-danger', textContent: 'Scan failed: ' + err.message }));
            } finally {
                hwBtn.disabled = false;
                hwBtn.textContent = 'Run Hardware Scan';
            }
        });
        hwSection.appendChild(hwBtn);
        hwSection.appendChild(hwResultWrap);
        container.appendChild(hwSection);
    }

    // ------------------------------------------------------------------
    // Section 2: Disk Usage
    // ------------------------------------------------------------------

    async function _renderDiskUsage(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let data;
        try {
            data = await Api.get(`${_api()}/admin/disk-usage`);
        } catch (err) {
            _showError(container, 'Failed to load disk usage: ' + err.message);
            return;
        }

        const pct    = data.usage_percent;
        const warn   = data.warning;
        const barPct = Math.min(pct, 100);

        const bar = Utils.el('div', { className: 'disk-bar' }, [
            Utils.el('div', {
                className: 'disk-bar-fill' + (warn ? ' disk-bar-warn' : ''),
                style: `width:${barPct}%`,
            }),
        ]);

        const fsLine = Utils.el('p', { className: 'disk-fs-summary' });
        const warnSuffix = warn ? ' ⚠ above warning threshold' : '';
        fsLine.textContent = data.filesystem_total > 0
            ? `${_fmtBytes(data.filesystem_total - data.filesystem_free)} used of ${_fmtBytes(data.filesystem_total)} (${pct}%)${warnSuffix}`
            : 'Filesystem size unavailable';

        // Per-user table
        const thead = Utils.el('thead', {}, [
            Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Username' }),
                Utils.el('th', { textContent: 'Used' }),
                Utils.el('th', { textContent: 'Quota' }),
                Utils.el('th', { textContent: 'Usage' }),
            ]),
        ]);

        const tbody = Utils.el('tbody');
        for (const u of data.users) {
            const quota = u.disk_quota || 0;
            const used  = u.disk_used  || 0;
            const uPct  = quota > 0 ? Math.min(Math.round(used / quota * 100), 100) : null;

            tbody.appendChild(Utils.el('tr', {}, [
                Utils.el('td', { textContent: u.username }),
                Utils.el('td', { textContent: _fmtBytes(used) }),
                Utils.el('td', { textContent: quota > 0 ? _fmtBytes(quota) : '—' }),
                Utils.el('td', {
                    textContent: uPct === null ? '—' : `${uPct}%`,
                    className: uPct !== null && uPct >= 90 ? 'text-warn' : '',  // NOSONAR — compound condition; simpler negated form is less readable
                }),
            ]));
        }

        container.innerHTML = '';
        container.appendChild(Utils.el('div', { className: 'disk-usage-section' }, [
            bar,
            fsLine,
            Utils.el('table', { className: 'admin-table' }, [thead, tbody]),
        ]));
    }

    // ------------------------------------------------------------------
    // Section 3: User Management
    // ------------------------------------------------------------------

    async function _renderUsers(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let data;
        try {
            data = await Api.get(`${_api()}/admin/users`);
        } catch (err) {
            _showError(container, 'Failed to load users: ' + err.message);
            return;
        }

        const currentUser = Auth.getCurrentUser();
        container.innerHTML = '';
        const widget = _makeSortablePagedTable({
            columns: [
                { label: 'Username',        key: 'username' },
                { label: 'Roles',           key: null, sortable: false },
                { label: 'Disk Used',       key: 'disk_used' },
                { label: 'Quota (MB)',      key: null, sortable: false },
                { label: 'BW Limit (MB/s)', key: null, sortable: false },
                { label: 'File Limit (MB)', key: null, sortable: false },
                { label: 'Active',          key: 'is_active' },
                { label: 'Actions',         key: null, sortable: false },
            ],
            items:    data.users,
            pageSize: 10,
            filterFn: (u, text) =>
                u.username.toLowerCase().includes(text) || u.id.toLowerCase().includes(text),
            buildRow: (u) => _buildUserRow(u, currentUser, () => _renderUsers(container)),
        });
        widget.querySelector('table').classList.add('admin-users-table');
        container.appendChild(widget);
    }

    function _buildUserRow(u, currentUser, refreshFn) {
        const isSelf = u.id === currentUser.id;

        // Editable number input (0 = no limit; blank also treated as 0)
        const _numInput = (val, divisor = 1) => Utils.el('input', {
            type: 'number', min: '0', className: 'input-xs',
            value: val == null ? '' : String(Math.round(val / divisor)),
            placeholder: '0=none',
        });

        const fldQuota = _numInput(u.disk_quota, _MB);
        const fldBw    = _numInput(u.bandwidth_limit, _MB);
        const fldMax   = _numInput(u.max_file_size, _MB);
        const fldActive = Utils.el('input', {
            type: 'checkbox',
            checked: u.is_active !== false,
            disabled: isSelf,
            title: isSelf ? 'Cannot deactivate yourself' : '',
        });

        const saveBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-xs',
            textContent: 'Save',
            onClick: async () => {
                const _parseMb = (input) => {
                    const n = Number.parseInt(input.value, 10);
                    return !Number.isNaN(n) && n !== 0 ? n * _MB : null;
                };
                const payload = {
                    is_active:       fldActive.checked,
                    disk_quota:      _parseMb(fldQuota),
                    bandwidth_limit: _parseMb(fldBw),
                    max_file_size:   _parseMb(fldMax),
                };
                // Remove null fields so the server only updates what changed
                Object.keys(payload).forEach(k => payload[k] === null && delete payload[k]);
                if (Object.keys(payload).length === 0) {
                    Utils.showToast('Nothing to save', 'info');
                    return;
                }
                // Re-add null values for limit fields so they can be cleared
                if (fldQuota.value === '' || Number.parseInt(fldQuota.value, 10) === 0) payload.disk_quota = null;
                if (fldBw.value    === '' || Number.parseInt(fldBw.value,    10) === 0) payload.bandwidth_limit = null;
                if (fldMax.value   === '' || Number.parseInt(fldMax.value,   10) === 0) payload.max_file_size = null;
                saveBtn.disabled = true;
                try {
                    await Api.put(`${_api()}/admin/users/${u.id}`, payload);
                    Utils.showToast(`Saved ${u.username}`, 'success');
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                } finally {
                    saveBtn.disabled = false;
                }
            },
        });

        let deleteBtn = null;
        if (!isSelf) {
            if (u.scheduled_delete_at) {
                const deleteDate = u.scheduled_delete_at.slice(0, 10);
                deleteBtn = Utils.el('button', {
                    className: 'btn btn-warning btn-xs',
                    textContent: `Recover (deletes ${deleteDate})`,
                    onClick: async () => {
                        if (!confirm(`Cancel scheduled deletion of "${u.username}" and restore their access?`)) return;
                        try {
                            await Api.post(`${_api()}/admin/users/${u.id}/recover`);
                            Utils.showToast(`Restored ${u.username}`, 'success');
                            refreshFn();
                        } catch (err) {
                            Utils.showToast('Recover failed: ' + err.message, 'error');
                        }
                    },
                });
            } else {
                deleteBtn = Utils.el('button', {
                    className: 'btn btn-danger btn-xs',
                    textContent: 'Delete',
                    onClick: async () => {
                        if (!confirm(`Delete user "${u.username}" and all their files? This cannot be undone.`)) return;
                        try {
                            await Api.del(`${_api()}/admin/users/${u.id}`);
                            Utils.showToast(`Deleted ${u.username}`, 'success');
                            refreshFn();
                        } catch (err) {
                            Utils.showToast('Delete failed: ' + err.message, 'error');
                        }
                    },
                });
            }
        }

        const detailBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-xs',
            textContent: 'Detail',
            onClick: () => _showUserDetailModal(u.id, u.username),
        });

        const actions = Utils.el('td', { className: 'admin-actions' }, [
            detailBtn,
            saveBtn,
            deleteBtn,
        ].filter(Boolean));

        return Utils.el('tr', { className: u.is_active === false ? 'row-inactive' : '' }, [
            Utils.el('td', { textContent: u.username + (isSelf ? ' (you)' : '') }),
            Utils.el('td', { textContent: (u.roles || []).join(', ') || '—' }),
            Utils.el('td', { textContent: _fmtBytes(u.disk_used || 0) }),
            Utils.el('td', {}, [fldQuota]),
            Utils.el('td', {}, [fldBw]),
            Utils.el('td', {}, [fldMax]),
            Utils.el('td', {}, [fldActive]),
            actions,
        ]);
    }

    // ------------------------------------------------------------------
    // Section: Team Management (admin view of all teams)
    // ------------------------------------------------------------------

    async function _renderTeams(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let data;
        try {
            data = await Api.get(`${_api()}/admin/teams`);
        } catch (err) {
            _showError(container, 'Failed to load teams: ' + err.message);
            return;
        }

        if (!data.teams.length) {
            container.innerHTML = '<p class="text-muted">No teams found.</p>';
            return;
        }

        container.innerHTML = '';
        container.appendChild(_makeSortablePagedTable({
            columns: [
                { label: 'Name',    key: 'name' },
                { label: 'Owner',   key: 'owner_username' },
                { label: 'Members', key: 'member_count' },
                { label: 'Created', key: 'created_at' },
                { label: 'Actions', key: null, sortable: false },
            ],
            items:    data.teams,
            pageSize: 10,
            filterFn: (t, text) =>
                t.name.toLowerCase().includes(text) ||
                (t.owner_username || '').toLowerCase().includes(text) ||
                t.id.toLowerCase().includes(text),
            buildRow: (t) => _buildTeamRow(t, () => _renderTeams(container)),
        }));
    }

    function _buildTeamRow(t, refreshFn) {
        const detailBtn = Utils.el('button', {
            className: 'btn btn-sm btn-secondary',
            textContent: 'Details',
            onClick: () => _showTeamDetailModal(t.id, t.name),
        });

        let actionBtn;
        if (t.scheduled_delete_at) {
            const deleteDate = t.scheduled_delete_at.slice(0, 10);
            actionBtn = Utils.el('button', {
                className: 'btn btn-sm btn-warning',
                textContent: `Recover (deletes ${deleteDate})`,
                onClick: async () => {
                    if (!confirm(`Cancel scheduled deletion of team "${t.name}" and restore member access?`)) return;
                    actionBtn.disabled = true;
                    try {
                        await Api.post(`${_api()}/admin/teams/${t.id}/recover`);
                        Utils.showToast(`Team "${t.name}" restored`, 'success');
                        refreshFn();
                    } catch (err) {
                        Utils.showToast('Recover failed: ' + err.message, 'error');
                        actionBtn.disabled = false;
                    }
                },
            });
        } else {
            actionBtn = Utils.el('button', {
                className: 'btn btn-sm btn-danger',
                textContent: 'Delete',
                onClick: async () => {
                    if (!confirm(`Delete team "${t.name}"? This will remove all member access and cannot be undone.`)) return;
                    actionBtn.disabled = true;
                    try {
                        await Api.del(`${_api()}/admin/teams/${t.id}`);
                        Utils.showToast(`Team "${t.name}" deleted`, 'success');
                        refreshFn();
                    } catch (err) {
                        Utils.showToast('Delete failed: ' + err.message, 'error');
                        actionBtn.disabled = false;
                    }
                },
            });
        }

        const created = t.created_at ? t.created_at.replace('T', ' ').slice(0, 10) : '—';

        return Utils.el('tr', {}, [
            Utils.el('td', { textContent: t.name }),
            Utils.el('td', { textContent: t.owner_username }),
            Utils.el('td', { textContent: String(t.member_count) }),
            Utils.el('td', { textContent: created }),
            Utils.el('td', {}, [
                Utils.el('div', { style: 'display:flex;gap:6px' }, [detailBtn, actionBtn]),
            ]),
        ]);
    }

    async function _showTeamDetailModal(teamId, teamName) {
        const wrap = Utils.el('div', { style: 'min-width:480px;max-width:640px' });
        wrap.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'Loading…' }));
        Utils.showModal(`Team: ${teamName || teamId}`, wrap);

        let team, members, customRolesData;
        try {
            [{ team, members }, customRolesData] = await Promise.all([
                Api.get(`${_api()}/admin/teams/${teamId}`),
                Api.get(`${_api()}/admin/teams/${teamId}/custom-roles`).catch(() => ({ roles: [], flags: [] })),
            ]);
        } catch (e) {
            wrap.innerHTML = '';
            wrap.appendChild(Utils.el('p', { className: 'text-error', textContent: 'Failed to load: ' + e.message }));
            return;
        }

        wrap.innerHTML = '';

        const grid = Utils.el('div', { style: 'display:grid;grid-template-columns:1fr 1fr;gap:4px 16px;margin-bottom:14px;font-size:var(--font-size-sm)' });
        const _row = (label, value) => {
            grid.appendChild(Utils.el('span', { textContent: label + ':', style: 'font-weight:600;color:var(--color-text-muted)' }));
            grid.appendChild(Utils.el('span', { textContent: value || '—', style: 'word-break:break-all' }));
        };
        _row('ID', team.id);
        _row('Name', team.name);
        _row('Owner', team.owner_username);
        _row('Created', team.created_at ? team.created_at.replace('T', ' ').slice(0, 19) : '—');
        _row('Key rotation', team.rotation_pending ? 'Pending' : 'Up to date');
        if (team.description) _row('Description', team.description);
        wrap.appendChild(grid);

        // ---- Members header + Add Member form ----
        wrap.appendChild(Utils.el('h6', { textContent: 'Members', style: 'margin:12px 0 6px;font-size:var(--font-size-sm);font-weight:600' }));

        const membersArr = members.slice();

        // Add Member inline form
        const addMemberForm = Utils.el('div', { style: 'display:flex;gap:6px;align-items:center;margin-bottom:10px;flex-wrap:wrap' });
        const addUsernameInput = Utils.el('input', {
            type: 'text', placeholder: 'Username…',
            className: 'input-sm',
            style: 'width:160px',
        });
        const addRoleSel = Utils.el('select', { className: 'input-sm', style: 'width:130px' });
        [['team_member', 'Member'], ['team_manager', 'Supervisor'], ['team_admin', 'Owner']].forEach(([val, label]) => {
            addRoleSel.appendChild(Utils.el('option', { value: val, textContent: label }));
        });
        const addBtn = Utils.el('button', {
            className: 'btn btn-sm btn-primary',
            textContent: 'Add',
            onClick: async () => {
                const uname = addUsernameInput.value.trim();
                if (!uname) { Utils.showToast('Enter a username', 'warning'); return; }
                addBtn.disabled = true;
                try {
                    const result = await Api.post(`${_api()}/admin/teams/${teamId}/members`, {
                        username: uname,
                        role: addRoleSel.value,
                    });
                    Utils.showToast(`${result.username} added to team`, 'success');
                    addUsernameInput.value = '';
                    membersArr.push({
                        id: result.user_id,
                        username: result.username,
                        is_active: true,
                        key_confirmed: false,
                        key_delivery_pending: true,
                        joined_at: new Date().toISOString(),
                        role_id: result.role,
                        role_name: addRoleSel.options[addRoleSel.selectedIndex].textContent,
                    });
                    _renderMemberTable();
                } catch (err) {
                    Utils.showToast('Add failed: ' + err.message, 'error');
                } finally {
                    addBtn.disabled = false;
                }
            },
        });
        addMemberForm.append(addUsernameInput, addRoleSel, addBtn);
        wrap.appendChild(addMemberForm);

        const _keyStatus = (m) => {
            if (m.key_delivery_pending) return 'No key yet';
            return m.key_confirmed ? 'Confirmed' : 'Pending';
        };

        const _buildMemberRow = (m) => {
            const removeBtn = Utils.el('button', {
                className: 'btn btn-xs btn-danger',
                textContent: 'Remove',
            });
            removeBtn.addEventListener('click', async () => {
                if (!confirm(`Remove "${m.username}" from team "${team.name || teamName}"?\n\nThis will revoke their access and mark the team for key rotation.`)) return;
                removeBtn.disabled = true;
                try {
                    await Api.del(`${_api()}/admin/teams/${teamId}/members/${m.id}`);
                    Utils.showToast(`${m.username} removed from team`, 'success');
                    let idx = -1;
                    for (let i = 0; i < membersArr.length; i++) {
                        if (membersArr[i].id === m.id) { idx = i; break; }
                    }
                    if (idx !== -1) membersArr.splice(idx, 1);
                    _renderMemberTable();
                } catch (err) {
                    Utils.showToast('Remove failed: ' + err.message, 'error');
                    removeBtn.disabled = false;
                }
            });
            return Utils.el('tr', {}, [
                Utils.el('td', { textContent: m.username }),
                Utils.el('td', { textContent: m.role_name || '—' }),
                Utils.el('td', { textContent: _keyStatus(m) }),
                Utils.el('td', { textContent: m.joined_at ? m.joined_at.slice(0, 10) : '—' }),
                Utils.el('td', {}, [removeBtn]),
            ]);
        };

        const _renderMemberTable = () => {
            const memberSection = wrap.querySelector('.team-member-section');
            if (memberSection) memberSection.remove();

            const section = Utils.el('div', { className: 'team-member-section' });

            if (membersArr.length === 0) {
                section.appendChild(Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-sm)', textContent: 'No members.' }));
            } else {
                const memberWidget = _makeSortablePagedTable({
                    columns: [
                        { label: 'Username', key: 'username' },
                        { label: 'Role',     key: 'role_name' },
                        { label: 'Key',      key: 'key_confirmed' },
                        { label: 'Joined',   key: 'joined_at' },
                        { label: 'Actions',  key: null, sortable: false },
                    ],
                    items:    membersArr,
                    pageSize: 10,
                    filterFn: (m, text) => m.username.toLowerCase().includes(text),
                    buildRow: _buildMemberRow,
                });
                memberWidget.querySelector('table').style.fontSize = '12px';
                section.appendChild(memberWidget);
            }

            wrap.appendChild(section);
        };

        _renderMemberTable();

        // ---- Custom Roles section ----
        wrap.appendChild(Utils.el('h6', {
            textContent: 'Custom Roles',
            style: 'margin:18px 0 6px;font-size:var(--font-size-sm);font-weight:600',
        }));

        const customRoles = (customRolesData.roles || []);

        if (customRoles.length === 0) {
            wrap.appendChild(Utils.el('p', {
                className: 'text-muted',
                style: 'font-size:var(--font-size-sm)',
                textContent: 'No custom roles defined for this team.',
            }));
        } else {
            const customRolesContainer = Utils.el('div', { className: 'custom-roles-container' });

            // Build flag label map from metadata
            const flagLabels = {};
            for (const f of (customRolesData.flags || [])) flagLabels[f.flag] = f.label;

            for (const role of customRoles) {
                // Permissions summary (only enabled flags)
                const enabledFlags = Object.entries(role.permissions || {})
                    .filter(([, v]) => v === '1')
                    .map(([k]) => flagLabels[k] || k);
                const permSummary = enabledFlags.length
                    ? enabledFlags.join(', ')
                    : 'No extra permissions';

                const roleCard = Utils.el('div', {
                    style: 'border:1px solid var(--color-border);border-radius:6px;padding:10px 12px;margin-bottom:10px',
                });

                roleCard.appendChild(Utils.el('div', { style: 'display:flex;align-items:baseline;gap:8px;margin-bottom:4px' }, [
                    Utils.el('strong', { style: 'font-size:var(--font-size-sm)', textContent: role.name }),
                    Utils.el('span', { style: 'font-size:11px;color:var(--color-text-muted)', textContent: permSummary }),
                ]));
                if (role.description) {
                    roleCard.appendChild(Utils.el('p', {
                        style: 'font-size:11px;color:var(--color-text-muted);margin:0 0 6px',
                        textContent: role.description,
                    }));
                }

                // Current assignees list
                const assignmentsArr = (role.assignments || []).slice();
                const assignList = Utils.el('div', { style: 'display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px' });

                const _rebuildAssignList = () => {
                    assignList.innerHTML = '';
                    if (assignmentsArr.length === 0) {
                        assignList.appendChild(Utils.el('span', {
                            style: 'font-size:11px;color:var(--color-text-muted)',
                            textContent: 'No members assigned',
                        }));
                        return;
                    }
                    for (const a of assignmentsArr) {
                        const chip = Utils.el('span', {
                            style: 'display:inline-flex;align-items:center;gap:4px;background:var(--color-bg-secondary);border:1px solid var(--color-border);border-radius:4px;padding:1px 6px;font-size:11px',
                        });
                        chip.appendChild(Utils.el('span', { textContent: a.username }));
                        const revokeX = Utils.el('button', {
                            style: 'background:none;border:none;cursor:pointer;color:var(--color-text-muted);padding:0;line-height:1;font-size:13px',
                            textContent: '×',
                            title: `Remove ${a.username} from ${role.name}`,
                        });
                        revokeX.addEventListener('click', async () => {
                            if (!confirm(`Remove ${a.username} from custom role "${role.name}"?`)) return;
                            revokeX.disabled = true;
                            try {
                                await Api.del(`${_api()}/admin/teams/${teamId}/custom-roles/${role.id}/assignments/${a.user_id}`);
                                const idx = assignmentsArr.findIndex(x => x.user_id === a.user_id);
                                if (idx !== -1) assignmentsArr.splice(idx, 1);
                                _rebuildAssignList();
                                _rebuildAssignDropdown();
                            } catch (err) {
                                Utils.showToast('Revoke failed: ' + err.message, 'error');
                                revokeX.disabled = false;
                            }
                        });
                        chip.appendChild(revokeX);
                        assignList.appendChild(chip);
                    }
                };

                // Assign dropdown (team members not yet assigned this role)
                const assignSel = Utils.el('select', { className: 'input-sm', style: 'width:160px' });
                const assignBtn = Utils.el('button', {
                    className: 'btn btn-xs btn-secondary',
                    textContent: 'Assign',
                    onClick: async () => {
                        if (!assignSel.value) return;
                        assignBtn.disabled = true;
                        try {
                            await Api.post(
                                `${_api()}/admin/teams/${teamId}/custom-roles/${role.id}/assignments`,
                                { user_id: assignSel.value },
                            );
                            const username = assignSel.options[assignSel.selectedIndex].textContent;
                            assignmentsArr.push({ user_id: assignSel.value, username });
                            _rebuildAssignList();
                            _rebuildAssignDropdown();
                        } catch (err) {
                            Utils.showToast('Assign failed: ' + err.message, 'error');
                        } finally {
                            assignBtn.disabled = false;
                        }
                    },
                });

                const _rebuildAssignDropdown = () => {
                    const assignedIds = new Set(assignmentsArr.map(a => a.user_id));
                    assignSel.innerHTML = '';
                    const eligible = membersArr.filter(m => !assignedIds.has(m.id));
                    if (eligible.length === 0) {
                        assignSel.appendChild(Utils.el('option', { value: '', textContent: 'All members assigned', disabled: true }));
                        assignBtn.disabled = true;
                    } else {
                        assignSel.appendChild(Utils.el('option', { value: '', textContent: '— assign member —', disabled: true, selected: true }));
                        for (const m of eligible) {
                            assignSel.appendChild(Utils.el('option', { value: m.id, textContent: m.username }));
                        }
                        assignBtn.disabled = false;
                    }
                };

                _rebuildAssignList();
                _rebuildAssignDropdown();

                roleCard.appendChild(assignList);
                roleCard.appendChild(Utils.el('div', { style: 'display:flex;gap:6px;align-items:center' }, [assignSel, assignBtn]));
                customRolesContainer.appendChild(roleCard);
            }

            wrap.appendChild(customRolesContainer);
        }
    }

    // ------------------------------------------------------------------
    // Section 4: Invites
    // ------------------------------------------------------------------

    async function _renderInvites(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';

        let data;
        try {
            data = await Api.get(`${_api()}/admin/invites`);
        } catch (err) {
            _showError(container, 'Failed to load invites: ' + err.message);
            return;
        }

        const createBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Create Invite Link',
            onClick: () => _createInvite(container),
        });

        // Pending invites only in main list; used invites shown in a collapsed sub-section.
        // Expired (and unused) invites are excluded — they can no longer be used.
        const now = new Date().toISOString();
        const pending = data.invites.filter(i => !i.used_at && i.expires_at > now);
        const used    = data.invites.filter(i =>  i.used_at);

        const pendingRows = pending.length === 0
            ? [Utils.el('p', { className: 'text-muted', textContent: 'No pending invites.' })]
            : pending.map(i => _buildInviteRow(i, () => _renderInvites(container)));

        const usedSection = used.length === 0 ? null : (() => {
            const tbody = Utils.el('tbody');
            used.forEach(i => {
                tbody.appendChild(Utils.el('tr', { className: 'row-used' }, [
                    Utils.el('td', { textContent: i.created_at ? i.created_at.slice(0, 10) : '—' }),
                    Utils.el('td', { textContent: i.expires_at ? i.expires_at.slice(0, 10) : '—' }),
                    Utils.el('td', { textContent: i.used_at ? i.used_at.slice(0, 10) : '—' }),
                    Utils.el('td', { textContent: i.used_by_username || '—' }),
                Utils.el('td', { textContent: i.used_by_ip || '—' }),
                ]));
            });
            return Utils.el('details', { className: 'admin-used-invites' }, [
                Utils.el('summary', { textContent: `${used.length} used invite${used.length === 1 ? '' : 's'}` }),
                Utils.el('table', { className: 'admin-table admin-table-sm' }, [
                    Utils.el('thead', {}, [
                        Utils.el('tr', {}, [
                            Utils.el('th', { textContent: 'Created' }),
                            Utils.el('th', { textContent: 'Expired' }),
                            Utils.el('th', { textContent: 'Used At' }),
                            Utils.el('th', { textContent: 'Used By' }),
                            Utils.el('th', { textContent: 'Used By IP' }),
                        ]),
                    ]),
                    tbody,
                ]),
            ]);
        })();

        container.innerHTML = '';
        const parts = [
            Utils.el('div', { className: 'invites-header' }, [createBtn]),
            Utils.el('div', { className: 'invites-pending' }, pendingRows),
        ];
        if (usedSection) parts.push(usedSection);
        parts.forEach(p => container.appendChild(p));
    }

    function _buildInviteRow(invite, refreshFn) {
        const expiresDate = invite.expires_at ? invite.expires_at.slice(0, 10) : '—';
        const createdDate = invite.created_at ? invite.created_at.slice(0, 10) : '—';

        const revokeBtn = Utils.el('button', {
            className: 'btn btn-danger btn-xs',
            textContent: 'Revoke',
            onClick: async () => {
                if (!confirm('Revoke this invite? Anyone with the link will no longer be able to register.')) return;
                try {
                    await Api.del(`${_api()}/admin/invites/${invite.id}`);
                    Utils.showToast('Invite revoked', 'success');
                    refreshFn();
                } catch (err) {
                    Utils.showToast('Revoke failed: ' + err.message, 'error');
                }
            },
        });

        return Utils.el('div', { className: 'invite-row' }, [
            Utils.el('span', { className: 'invite-meta', textContent: `Created ${createdDate} · Expires ${expiresDate}` }),
            revokeBtn,
        ]);
    }

    async function _createInvite(container) {
        let data;
        try {
            data = await Api.post(`${_api()}/admin/invites`);
        } catch (err) {
            Utils.showToast('Failed to create invite: ' + err.message, 'error');
            return;
        }

        const inviteUrl = `${globalThis.location.origin}/register/${data.token}`;

        // Short-link row — hidden until the "Short Link" button is clicked
        const shortLinkInput = Utils.el('input', {
            type: 'text', readOnly: true,
            className: 'invite-url-input',
            onClick: (e) => e.target.select(),
        });
        const shortLinkCopyBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Copy',
            onClick: () => {
                navigator.clipboard.writeText(shortLinkInput.value).then(
                    () => Utils.showToast('Short link copied', 'success'),
                    () => Utils.showToast('Copy failed — select and copy manually', 'error'),
                );
            },
        });
        const shortLinkRow = Utils.el('div', {
            className: 'invite-url-row',
            style: 'display:none',
        }, [shortLinkInput, shortLinkCopyBtn]);

        const shortLinkBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Short Link',
            onClick: async () => {
                shortLinkBtn.disabled = true;
                shortLinkBtn.textContent = 'Generating…';
                try {
                    const sl = await Api.post(
                        `${_api()}/admin/invites/${data.id}/short-link`,
                        { token: data.token, expires_at: data.expires_at },
                    );
                    shortLinkInput.value = `${globalThis.location.origin}/${sl.slug}`;
                    shortLinkRow.style.display = '';
                    shortLinkBtn.style.display = 'none';
                } catch (err) {
                    Utils.showToast('Short link failed: ' + err.message, 'error');
                    shortLinkBtn.disabled = false;
                    shortLinkBtn.textContent = 'Short Link';
                }
            },
        });

        // Show a dismissable one-time display banner at the top of the invites section
        const banner = Utils.el('div', { className: 'invite-banner' }, [
            Utils.el('p', { className: 'invite-banner-warn', textContent: '⚠ Copy this link now — it will not be shown again.' }),
            Utils.el('div', { className: 'invite-url-row' }, [
                Utils.el('input', {
                    type: 'text', readOnly: true,
                    className: 'invite-url-input',
                    value: inviteUrl,
                    onClick: (e) => e.target.select(),
                }),
                Utils.el('button', {
                    className: 'btn btn-secondary btn-sm',
                    textContent: 'Copy',
                    onClick: () => {
                        navigator.clipboard.writeText(inviteUrl).then(
                            () => Utils.showToast('Invite URL copied', 'success'),
                            () => Utils.showToast('Copy failed — select and copy manually', 'error'),
                        );
                    },
                }),
                shortLinkBtn,
            ]),
            shortLinkRow,
            Utils.el('p', { className: 'text-muted', textContent: `Expires: ${data.expires_at.replace('T', ' ')} UTC · Valid for ${Config.admin.inviteExpireHours} hours` }),
            Utils.el('button', {
                className: 'btn btn-secondary btn-sm',
                textContent: 'Done',
                onClick: () => _renderInvites(container),
            }),
        ]);

        // Prepend banner (without clearing the section's header)
        container.insertBefore(banner, container.firstChild);
    }

    // ------------------------------------------------------------------
    // Section 5: Theme & Branding
    // ------------------------------------------------------------------

    async function _renderTheme(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';

        let current;
        try {
            current = await Api.get(`${_api()}/theme`);
        } catch (err) {
            _showError(container, 'Failed to load theme config: ' + err.message);
            return;
        }

        const statusLines = [
            Utils.el('p', {}, [
                Utils.el('strong', { textContent: 'Brand name: ' }),
                Utils.el('span', { textContent: current.brand_name || '(default — tusShare)' }),
            ]),
            Utils.el('p', {}, [
                Utils.el('strong', { textContent: 'Logo: ' }),
                Utils.el('span', { textContent: current.logo_url ? 'Configured' : 'None (text brand name)' }),
            ]),
        ];

        const reloadBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Reload Theme from Disk',
            onClick: async () => {
                reloadBtn.disabled = true;
                reloadBtn.textContent = 'Reloading…';
                try {
                    const result = await Api.post(`${_api()}/admin/theme/reload`);
                    Utils.showToast(
                        `Theme reloaded — ${result.color_overrides} color override(s)` +
                        (result.brand_name ? `, brand: ${result.brand_name}` : '') +
                        (result.has_logo ? ', logo set' : ''),
                        'success',
                    );
                    _renderTheme(container);
                } catch (err) {
                    Utils.showToast('Reload failed: ' + err.message, 'error');
                    reloadBtn.disabled = false;
                    reloadBtn.textContent = 'Reload Theme from Disk';
                }
            },
        });

        container.innerHTML = '';
        container.appendChild(Utils.el('div', { className: 'settings-form' }, [
            Utils.el('div', { className: 'theme-status' }, statusLines),
            Utils.el('p', { className: 'settings-hint' }, [
                Utils.el('span', {
                    textContent: 'Edit ',
                }),
                Utils.el('code', { textContent: '/data/theme.json' }),
                Utils.el('span', {
                    textContent: ' on the server, then click Reload. ' +
                        'Color overrides take effect on the next page load. ' +
                        'See ',
                }),
                Utils.el('code', { textContent: 'frontend/themes/theme.json.example' }),
                Utils.el('span', { textContent: ' for the full schema.' }),
            ]),
            Utils.el('div', { className: 'settings-actions' }, [reloadBtn]),
        ]));
    }

    // ------------------------------------------------------------------
    // Section 6: Roles & Permissions
    // ------------------------------------------------------------------

    // Team role IDs and their labels as shown in the Teams UI
    const _TEAM_ROLE_IDS = new Set(['team_admin', 'team_manager', 'team_member']);

    // Display tier for sorting main roles highest-authority first (lower = higher authority)
    const _ROLE_TIER_ORDER = { server_admin: 1, admin: 1, org_admin: 2, operational_admin: 3 };
    const _TEAM_ROLE_ALIAS = {
        team_admin:   'Owner',
        team_manager: 'Supervisor',
        team_member:  'Member',
    };

    // Category display order and labels
    const _FLAG_CATEGORIES = [
        { key: 'admin',        label: 'Administration' },
        { key: 'roles',        label: 'Role Management' },
        { key: 'observability',label: 'Observability' },
        { key: 'audit',        label: 'Audit Trail' },
        { key: 'integrations', label: 'Integrations' },
        { key: 'policy',       label: 'Policy Engine' },
        { key: 'files',        label: 'File Access' },
        { key: 'security',     label: 'Security' },
        { key: 'sharing',      label: 'Sharing' },
    ];

    async function _renderRoles(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let data, capData, flagMeta;
        try {
            [data, capData, flagMeta] = await Promise.all([
                Api.get(`${_api()}/admin/roles`),
                Api.get(`${_api()}/admin/roles/capabilities`),
                Api.get(`${_api()}/admin/roles/flag-metadata`).catch(() => ({ requires: {}, related: {} })),
            ]);
        } catch (err) {
            _showError(container, 'Failed to load roles: ' + err.message);
            return;
        }

        const { roles, flags, admin_tier: adminTier } = data;
        const grantableFlags = new Set(capData.grantable_flags || []);
        const scopeBanner = (!capData.scope.org_wide && capData.scope.team_ids)
            ? `Scoped admin — managing teams: ${capData.scope.team_ids.join(', ') || '(none)'}`
            : null;

        // Index flags by category for grouped rendering
        const flagsByCategory = {};
        for (const f of flags) {
            if (!flagsByCategory[f.category]) flagsByCategory[f.category] = [];
            flagsByCategory[f.category].push(f);
        }

        const createBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Create Custom Role',
            onClick: () => _showCreateRoleModal(flags, grantableFlags, () => _renderRoles(container), flagMeta),
        });

        const refresh = () => _renderRoles(container);
        const teamRoles  = roles.filter(r =>  _TEAM_ROLE_IDS.has(r.id));
        const otherRoles = roles.filter(r => !_TEAM_ROLE_IDS.has(r.id));

        // Sort: tiered system roles first (highest authority = lowest tier number),
        // then remaining system roles alphabetically, then custom roles alphabetically.
        // Apply saved custom order from localStorage on top of defaults.
        const _tierOf = r => _ROLE_TIER_ORDER[r.id] ?? (r.is_system ? 50 : 99);
        otherRoles.sort((a, b) => {
            const td = _tierOf(a) - _tierOf(b);
            if (td !== 0) return td;
            return (a.name || '').localeCompare(b.name || '');
        });

        if (Array.isArray(_adminRoleOrder)) {
            const idxMap = Object.fromEntries(_adminRoleOrder.map((id, i) => [id, i]));
            otherRoles.sort((a, b) => {
                const ai = idxMap[a.id] ?? 9999, bi = idxMap[b.id] ?? 9999;
                if (ai !== bi) return ai - bi;
                return _tierOf(a) - _tierOf(b) || (a.name || '').localeCompare(b.name || '');
            });
        }

        const buildList = (list, withAlias) => {
            const el = Utils.el('div', { className: 'roles-list' });
            for (const role of list) {
                el.appendChild(_buildRoleCard(
                    role, flags, flagsByCategory, adminTier, refresh,
                    withAlias ? _TEAM_ROLE_ALIAS[role.id] : undefined,
                    flagMeta,
                ));
            }
            return el;
        };

        let rolesRearranging = false;
        let rolesDragListeners = [];
        const rolesDragIndicator = Utils.el('div', { className: 'drop-indicator-v' });

        const rearrangeRolesBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: '⠿ Rearrange',
        });

        const _teardownRolesDrag = () => {
            rolesDragListeners.forEach(({ el: el2, event, fn }) => el2.removeEventListener(event, fn));
            rolesDragListeners = [];
            rolesDragIndicator.remove();
            rolesList.querySelectorAll('.role-card').forEach(c => {
                c.removeAttribute('draggable');
                c.classList.remove('dragging');
            });
        };

        const _setupRolesDrag = () => {
            const _on2 = (el2, event, fn) => { el2.addEventListener(event, fn); rolesDragListeners.push({ el: el2, event, fn }); };
            let draggedId = null;
            for (const card of rolesList.querySelectorAll('.role-card')) {
                card.setAttribute('draggable', 'true');
                _on2(card, 'dragstart', e => {
                    draggedId = card.id.replace('role-card-', '');
                    e.dataTransfer.effectAllowed = 'move';
                    requestAnimationFrame(card.classList.add.bind(card.classList, 'dragging'));
                });
                _on2(card, 'dragend', () => {
                    card.classList.remove('dragging');
                    rolesDragIndicator.remove();
                    draggedId = null;
                });
            }
            _on2(rolesList, 'dragover', e => {
                if (!draggedId) return;
                e.preventDefault();
                const siblings = [...rolesList.querySelectorAll('.role-card:not(.dragging)')];
                const before   = _insertionTarget(siblings, e.clientY, 'v');
                if (before) before.before(rolesDragIndicator);
                else         rolesList.appendChild(rolesDragIndicator);
            });
            _on2(rolesList, 'dragleave', e => {
                if (!rolesList.contains(e.relatedTarget)) rolesDragIndicator.remove();
            });
            _on2(rolesList, 'drop', e => {
                e.preventDefault();
                const dragged = rolesList.querySelector(`#role-card-${draggedId}`);
                if (!dragged) return;
                rolesDragIndicator.before(dragged);
                rolesDragIndicator.remove();
            });
        };

        rearrangeRolesBtn.addEventListener('click', () => {
            rolesRearranging = !rolesRearranging;
            rearrangeRolesBtn.textContent      = rolesRearranging ? '✓ Done' : '⠿ Rearrange';
            rearrangeRolesBtn.classList.toggle('btn-primary',   rolesRearranging);
            rearrangeRolesBtn.classList.toggle('btn-secondary', !rolesRearranging);
            if (rolesRearranging) {
                _setupRolesDrag();
            } else {
                _teardownRolesDrag();
                const order = [...rolesList.querySelectorAll('.role-card')].map(c => c.id.replace('role-card-', ''));
                _adminRoleOrder = order;
                _saveRoleOrderPref(order);
            }
        });

        const rolesList = buildList(otherRoles, false);

        container.innerHTML = '';
        if (scopeBanner) {
            container.appendChild(Utils.el('p', {
                className: 'admin-scope-banner',
                textContent: scopeBanner,
            }));
        }
        container.appendChild(Utils.el('div', { className: 'roles-header' }, [createBtn, rearrangeRolesBtn]));
        container.appendChild(rolesList);
        container.appendChild(Utils.el('div', { className: 'roles-section-header' }, [
            Utils.el('h3', { textContent: 'Team Roles' }),
            Utils.el('p', { className: 'text-muted roles-section-note',
                textContent: 'These roles are assigned per-team and control what members can do within their team\'s folders. The label used in the Teams view is shown in parentheses.' }),
        ]));
        container.appendChild(buildList(teamRoles, true));
    }

    function _hasDepWarnings(role, flagMeta) {
        if (role.is_system) return false;
        const requires = flagMeta?.requires ?? {};
        const perms = role.permissions ?? {};
        for (const [flag, deps] of Object.entries(requires)) {
            if ((perms[flag]?.value ?? '0') !== '1') continue;
            for (const dep of deps) {
                if ((perms[dep]?.value ?? '0') !== '1') return true;
            }
        }
        return false;
    }

    function _buildRoleCard(role, flags, flagsByCategory, adminTier, refreshFn, alias, flagMeta) {
        const body = Utils.el('div', { className: 'role-card-body', style: 'display:none' });
        let bodyLoaded = false;

        const hasWarnings = _hasDepWarnings(role, flagMeta);

        const toggleBtn = Utils.el('button', {
            className: 'role-card-toggle collapsed',
            onClick: () => {
                const open = body.style.display !== 'none';
                body.style.display = open ? 'none' : '';
                toggleBtn.classList.toggle('collapsed', open);
                if (!open && !bodyLoaded) {
                    bodyLoaded = true;
                    _populateRoleCardBody(body, role, flags, flagsByCategory, adminTier, refreshFn, flagMeta || { requires: {}, related: {} });
                }
            },
        });
        if (hasWarnings) {
            toggleBtn.appendChild(Utils.el('span', {
                className: 'role-card-warn-icon',
                textContent: '⚠',
                title: 'This role has permission dependency warnings — expand to review',
            }));
        }
        toggleBtn.appendChild(Utils.el('span', { className: 'role-card-name', textContent: role.name }));
        if (alias) {
            toggleBtn.appendChild(Utils.el('span', { className: 'role-card-alias', textContent: `(${alias})` }));
        }
        toggleBtn.appendChild(Utils.el('span', {
            className: 'role-card-badge' + (role.is_system ? ' badge-system' : ' badge-custom'),
            textContent: role.is_system ? 'system' : 'custom',
        }));

        const card = Utils.el('div', {
            className: 'role-card',
            id: `role-card-${role.id}`,
        }, [
            Utils.el('div', { className: 'role-card-header' }, [toggleBtn]),
            body,
        ]);
        return card;
    }

    function _appendDepItems(container, items, className) {
        for (const text of items) {
            container.appendChild(Utils.el('div', { className, textContent: text }));
        }
    }

    function _collectFlagWarnings(flagInputs, requires) {
        const warnings = [];
        for (const [flag, deps] of Object.entries(requires)) {
            if (!flagInputs[flag]?.checked) continue;
            for (const dep of deps) {
                if (flagInputs[dep] && !flagInputs[dep].checked)
                    warnings.push(`⚠ "${flag}" requires "${dep}" to also be enabled.`);
            }
        }
        return warnings;
    }

    function _populateRoleCardBody(container, role, flags, flagsByCategory, adminTier, refreshFn, flagMeta) {
        // Rename / description form (always shown — system roles can be renamed)
        const fldName = Utils.el('input', {
            type: 'text', className: 'input-sm', value: role.name,
            placeholder: 'Role name',
        });
        const fldDesc = Utils.el('input', {
            type: 'text', className: 'input-sm', value: role.description,
            placeholder: 'Description',
        });
        const saveMetaBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Save Name/Desc',
            onClick: async () => {
                saveMetaBtn.disabled = true;
                try {
                    await Api.patch(`${_api()}/admin/roles/${role.id}`, {
                        name:        fldName.value.trim(),
                        description: fldDesc.value.trim(),
                    });
                    Utils.showToast('Role updated', 'success');
                    refreshFn();
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                    saveMetaBtn.disabled = false;
                }
            },
        });

        const deleteBtn = Utils.el('button', {
            className: 'btn btn-danger btn-sm',
            textContent: 'Delete Role',
            onClick: async () => {
                const warningText = role.is_system
                    ? `DELETE SYSTEM ROLE "${role.name}"?\n\n`
                        + `This is a built-in role. Deleting it will:\n`
                        + `• Remove it from every user who currently holds it\n`
                        + `• Break any integrations that reference the role ID "${role.id}" directly\n`
                        + `• Require server_admin privilege (tier 1)\n\n`
                        + `This cannot be undone without re-creating the role. Proceed?`
                    : `Delete role "${role.name}"? All users currently holding this role will lose it.`;
                if (!confirm(warningText)) return;
                try {
                    await Api.del(`${_api()}/admin/roles/${role.id}`);
                    Utils.showToast(`Role "${role.name}" deleted`, 'success');
                    refreshFn();
                } catch (err) {
                    Utils.showToast('Delete failed: ' + err.message, 'error');
                }
            },
        });

        // Permission flag toggles, grouped by category
        // flagInputs: flag → { chk (value checkbox), lockChk (lock checkbox) }
        const flagInputs = {};
        const flagSections = _FLAG_CATEGORIES
            .filter(cat => flagsByCategory[cat.key])
            .map((cat, catIdx) => {
                const rows = (flagsByCategory[cat.key] || []).map(f => {
                    const permData = role.permissions?.[f.flag] || { value: '0', is_locked: false, locked_min_tier: null };
                    const isLocked  = permData.is_locked;
                    const lockTier  = permData.locked_min_tier;
                    // canEdit: flag is unlocked, OR this admin's tier is within the lock threshold
                    const canEdit   = !isLocked || (lockTier !== null && adminTier <= lockTier);

                    const chk = Utils.el('input', {
                        type: 'checkbox',
                        checked: permData.value === '1',
                        disabled: !canEdit,
                        title: f.is_sensitive ? 'Sensitive — requires Server Admin or Org Admin to activate' : '',
                    });
                    const lockChk = Utils.el('input', {
                        type: 'checkbox',
                        checked: isLocked,
                        disabled: !canEdit,
                        title: 'Lock — lower-tier admins cannot change this flag',
                    });
                    flagInputs[f.flag] = { chk, lockChk };

                    const badges = [
                        f.is_sensitive ? Utils.el('span', { className: 'flag-sensitive-badge', textContent: 'sensitive' }) : null,
                        isLocked && !canEdit ? Utils.el('span', { className: 'flag-locked-badge', textContent: `locked ≤ tier ${lockTier}` }) : null,
                    ].filter(Boolean);

                    return Utils.el('div', { className: 'flag-row' + (f.is_sensitive ? ' flag-sensitive' : '') + (isLocked ? ' flag-locked' : '') }, [
                        Utils.el('div', { className: 'flag-lock-cell' }, [
                            Utils.el('label', { className: 'flag-lock-label', title: 'Lock this flag' }, [lockChk]),
                        ]),
                        Utils.el('div', { className: 'flag-content-cell' }, [
                            Utils.el('label', { className: 'flag-label' }, [
                                chk,
                                Utils.el('span', { className: 'flag-name', textContent: f.flag }),
                                ...badges,
                            ]),
                            Utils.el('span', { className: 'flag-desc', textContent: f.description }),
                        ]),
                    ]);
                });
                const lockHeaderCell = catIdx === 0
                    ? Utils.el('div', { className: 'flag-lock-col-header' }, [
                        Utils.el('span', { textContent: 'Lock' }),
                        Utils.el('span', {
                            className: 'flag-lock-help',
                            textContent: '?',
                            title: 'Locking stops these users from being able to further delegate management of this permission to lower-level admins.',
                        }),
                    ])
                    : Utils.el('div', { className: 'flag-lock-cell' });
                return Utils.el('div', { className: 'flag-category' }, [
                    Utils.el('div', { className: 'flag-row flag-category-row' }, [
                        lockHeaderCell,
                        Utils.el('div', { className: 'flag-content-cell' }, [
                            Utils.el('h5', { className: 'flag-category-label', textContent: cat.label }),
                        ]),
                    ]),
                    ...rows,
                ]);
            });

        const saveFlagsBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Save Permissions',
            onClick: async () => {
                const permissions = {};
                for (const [flag, { chk, lockChk }] of Object.entries(flagInputs)) {
                    permissions[flag] = {
                        value:           chk.checked ? '1' : '0',
                        is_locked:       lockChk.checked,
                        locked_min_tier: lockChk.checked ? adminTier : null,
                    };
                }
                saveFlagsBtn.disabled = true;
                try {
                    await Api.put(`${_api()}/admin/roles/${role.id}/permissions`, { permissions });
                    Utils.showToast('Permissions saved', 'success');
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                } finally {
                    saveFlagsBtn.disabled = false;
                }
            },
        });

        // Dependency warnings panel — updated live as checkboxes change
        const depWarnings = Utils.el('div', { className: 'flag-dep-warnings', style: 'display:none' });
        const requires = flagMeta?.requires ?? {};
        const related  = flagMeta?.related  ?? {};

        function _updateDepWarnings() {
            const warnings = [];
            const hints    = [];

            for (const [flag, deps] of Object.entries(requires)) {
                if (!flagInputs[flag]?.chk?.checked) continue;
                for (const dep of deps) {
                    if (!flagInputs[dep]?.chk?.checked) {
                        warnings.push(`⚠ "${flag}" requires "${dep}" to also be enabled.`);
                    }
                }
            }

            for (const [flag, rels] of Object.entries(related)) {
                if (!flagInputs[flag]?.chk?.checked) continue;
                const missing = rels.filter(r => flagInputs[r]?.chk && !flagInputs[r].chk.checked);
                if (missing.length) {
                    hints.push(`💡 "${flag}" is often used with: ${missing.join(', ')}`);
                }
            }

            depWarnings.innerHTML = '';
            if (warnings.length || hints.length) {
                depWarnings.style.display = '';
                _appendDepItems(depWarnings, warnings, 'flag-dep-warning');
                _appendDepItems(depWarnings, hints, 'flag-dep-hint');
            } else {
                depWarnings.style.display = 'none';
            }
        }

        // Wire change listeners to all checkboxes
        for (const { chk } of Object.values(flagInputs)) {
            chk.addEventListener('change', _updateDepWarnings);
        }
        // Run once on render to catch pre-existing issues
        _updateDepWarnings();

        container.innerHTML = '';
        container.appendChild(Utils.el('div', { className: 'role-card-content' }, [
            depWarnings,
            Utils.el('div', { className: 'role-meta-form' }, [
                Utils.el('div', { className: 'role-meta-fields' }, [
                    Utils.el('label', { textContent: 'Name' }),
                    fldName,
                    Utils.el('label', { textContent: 'Description' }),
                    fldDesc,
                ]),
                Utils.el('div', { className: 'role-meta-actions' }, [
                    saveMetaBtn,
                    deleteBtn,
                ].filter(Boolean)),
            ]),
            Utils.el('div', { className: 'role-flags' }, [
                Utils.el('h4', { className: 'role-flags-title', textContent: 'Permission Flags' }),
                ...flagSections,
                Utils.el('div', { className: 'role-flags-actions' }, [saveFlagsBtn]),
            ]),
        ]));
    }

    function _showCreateRoleModal(flags, grantableFlags, refreshFn, flagMeta) {
        // Reuse the existing modal infrastructure — build a form in a dialog
        const flagsByCategory = {};
        for (const f of flags) {
            if (!flagsByCategory[f.category]) flagsByCategory[f.category] = [];
            flagsByCategory[f.category].push(f);
        }

        const fldId   = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'e.g. finance_reviewer' });
        const fldName = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'Role display name' });
        const fldDesc = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'Optional description' });

        const flagInputs = {};
        const flagSections = _FLAG_CATEGORIES
            .filter(cat => flagsByCategory[cat.key])
            .map(cat => {
                const rows = (flagsByCategory[cat.key] || []).map(f => {
                    const canGrant = grantableFlags.has(f.flag);
                    let chkTitle = '';
                    if (f.is_sensitive) chkTitle = 'Sensitive — only Server/Org Admin may activate';
                    else if (!canGrant) chkTitle = 'You do not hold this permission and cannot grant it';
                    const chk = Utils.el('input', {
                        type: 'checkbox',
                        disabled: !canGrant,
                        title: chkTitle,
                    });
                    flagInputs[f.flag] = chk;
                    const badges = [
                        f.is_sensitive ? Utils.el('span', { className: 'flag-sensitive-badge', textContent: 'sensitive' }) : null,
                        canGrant ? null : Utils.el('span', { className: 'flag-locked-badge', textContent: 'not held' }),
                    ].filter(Boolean);
                    const lockedClass = canGrant ? '' : ' flag-locked';
                    return Utils.el('div', { className: 'flag-row' + (f.is_sensitive ? ' flag-sensitive' : '') + lockedClass }, [
                        Utils.el('div', { className: 'flag-lock-cell' }),
                        Utils.el('div', { className: 'flag-content-cell' }, [
                            Utils.el('label', { className: 'flag-label' }, [
                                chk,
                                Utils.el('span', { className: 'flag-name', textContent: f.flag }),
                                ...badges,
                            ]),
                            Utils.el('span', { className: 'flag-desc', textContent: f.description }),
                        ]),
                    ]);
                });
                return Utils.el('div', { className: 'flag-category' }, [
                    Utils.el('h5', { className: 'flag-category-label', textContent: cat.label }),
                    ...rows,
                ]);
            });

        // Live dependency-warning banner (shown at top of modal)
        const modalDepWarnings = Utils.el('div', { className: 'flag-dep-warnings', style: 'display:none' });
        const _modalRequires = flagMeta?.requires ?? {};
        const _modalRelated  = flagMeta?.related  ?? {};
        function _updateModalDepWarnings() {
            const warnings = _collectFlagWarnings(flagInputs, _modalRequires);
            const hints = [];
            for (const [flag, rels] of Object.entries(_modalRelated)) {
                if (!flagInputs[flag]?.checked) continue;
                const missing = rels.filter(r => flagInputs[r] && !flagInputs[r].checked);
                if (missing.length) hints.push(`💡 "${flag}" is often used with: ${missing.join(', ')}`);
            }
            modalDepWarnings.innerHTML = '';
            if (warnings.length || hints.length) {
                modalDepWarnings.style.display = '';
                _appendDepItems(modalDepWarnings, warnings, 'flag-dep-warning');
                _appendDepItems(modalDepWarnings, hints, 'flag-dep-hint');
            } else {
                modalDepWarnings.style.display = 'none';
            }
        }
        for (const chk of Object.values(flagInputs)) {
            chk.addEventListener('change', _updateModalDepWarnings);
        }

        const errorEl = Utils.el('p', { className: 'text-error', style: 'display:none' });

        const createBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Create Role',
            onClick: async () => {
                const id = fldId.value.trim();
                const name = fldName.value.trim();
                if (!id || !name) {
                    errorEl.textContent = 'Role ID and name are required.';
                    errorEl.style.display = '';
                    return;
                }
                const permissions = {};
                for (const [flag, chk] of Object.entries(flagInputs)) {
                    permissions[flag] = chk.checked ? '1' : '0';
                }
                createBtn.disabled = true;
                try {
                    await Api.post(`${_api()}/admin/roles`, {
                        id, name, description: fldDesc.value.trim(), permissions,
                    });
                    Utils.showToast(`Role "${name}" created`, 'success');
                    Utils.closeModal();
                    refreshFn();
                } catch (err) {
                    errorEl.textContent = 'Create failed: ' + err.message;
                    errorEl.style.display = '';
                    createBtn.disabled = false;
                }
            },
        });

        const cancelBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Cancel',
            onClick: () => Utils.closeModal(),
        });

        const formContent = Utils.el('div', { className: 'create-role-form' }, [
            modalDepWarnings,
            Utils.el('div', { className: 'role-meta-fields' }, [
                Utils.el('label', { textContent: 'Role ID (slug, e.g. finance_reviewer)' }),
                fldId,
                Utils.el('label', { textContent: 'Display Name' }),
                fldName,
                Utils.el('label', { textContent: 'Description' }),
                fldDesc,
            ]),
            Utils.el('div', { className: 'role-flags' }, [
                Utils.el('h4', { className: 'role-flags-title', textContent: 'Initial Permission Flags' }),
                Utils.el('p', { className: 'text-muted settings-hint', textContent: 'Permissions you do not hold yourself cannot be granted (inheritance cap enforced server-side).' }),
                ...flagSections,
            ]),
            errorEl,
            Utils.el('div', { className: 'modal-actions' }, [createBtn, cancelBtn]),
        ]);

        Utils.showModal('Create Custom Role', formContent);
    }

    // ------------------------------------------------------------------
    // Section 7: Policy Engine
    // ------------------------------------------------------------------
    // Three sub-sections rendered in one collapsible panel:
    //   (a) Field Registry — list + add LDAP/OIDC fields
    //   (b) Admin Scopes   — scope conditions per user/role
    //   (c) Policies       — policy list with conditions; add/delete conditions

    const _POLICY_OPERATORS = ['=', '!=', 'contains', 'starts_with', 'ends_with', 'in'];

    async function _renderPolicySection(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let fieldsData, scopesData, policiesData;
        try {
            [fieldsData, scopesData, policiesData] = await Promise.all([
                Api.get(`${_api()}/admin/policy-fields`),
                Api.get(`${_api()}/admin/scopes`),
                Api.get(`${_api()}/admin/policies`),
            ]);
        } catch (err) {
            _showError(container, 'Failed to load policy data: ' + err.message);
            return;
        }

        container.innerHTML = '';
        container.appendChild(_buildFieldRegistry(fieldsData.fields, () => _renderPolicySection(container)));
        container.appendChild(_buildAdminScopes(scopesData.conditions, fieldsData.fields, () => _renderPolicySection(container)));
        container.appendChild(_buildPoliciesPanel(policiesData.policies, fieldsData.fields, () => _renderPolicySection(container)));
    }

    // ── (a) Field Registry ──────────────────────────────────────────────

    function _buildFieldRegistry(fields, refreshFn) {
        const wrap = Utils.el('div', { className: 'policy-subsection' });

        const header = Utils.el('div', { className: 'policy-sub-header' }, [
            Utils.el('h4', { textContent: 'Field Registry' }),
            Utils.el('button', {
                className: 'btn btn-primary btn-xs',
                textContent: 'Add Field',
                onClick: () => _showAddFieldModal(fields, refreshFn),
            }),
        ]);
        wrap.appendChild(header);

        if (!fields.length) {
            wrap.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No custom fields registered.' }));
            return wrap;
        }

        const table = Utils.el('table', { className: 'policy-table' });
        table.innerHTML = `<thead><tr>
            <th>Name</th><th>Label</th><th>Source</th><th>Type</th><th>Claim Path</th><th></th>
        </tr></thead>`;
        const tbody = Utils.el('tbody');
        for (const f of fields) {
            const isInternal = f.source === 'internal';
            const deleteBtn = isInternal ? null : Utils.el('button', {
                className: 'btn btn-danger btn-xs',
                textContent: 'Delete',
                onClick: async () => {
                    if (!confirm(`Delete field "${f.name}"?`)) return;
                    try {
                        await Api.del(`${_api()}/admin/policy-fields/${f.name}`);
                        Utils.showToast('Field deleted', 'success');
                        refreshFn();
                    } catch (err) {
                        Utils.showToast('Delete failed: ' + err.message, 'error');
                    }
                },
            });
            const tr = Utils.el('tr');
            const nameTd = Utils.el('td');
            nameTd.appendChild(Utils.el('code', { textContent: f.name }));
            const labelTd = Utils.el('td', { textContent: f.display_label });
            const sourceTd = Utils.el('td');
            sourceTd.appendChild(Utils.el('span', { className: `badge badge-${f.source}`, textContent: f.source }));
            const typeTd = Utils.el('td', { textContent: f.data_type });
            const claimTd = Utils.el('td', { textContent: f.claim_path || '—' });
            const actionTd = Utils.el('td');
            if (deleteBtn) actionTd.appendChild(deleteBtn);
            tr.append(nameTd, labelTd, sourceTd, typeTd, claimTd, actionTd);
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
        return wrap;
    }

    function _showAddFieldModal(existingFields, refreshFn) {
        const nameEl     = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'e.g. department' });
        const labelEl    = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'e.g. Department' });
        const sourceEl   = Utils.el('select', { className: 'input-sm' });
        ['ldap', 'oidc'].forEach(s => {
            sourceEl.appendChild(Utils.el('option', { value: s, textContent: s.toUpperCase() }));
        });
        const typeEl     = Utils.el('select', { className: 'input-sm' });
        ['string', 'boolean'].forEach(t => {
            typeEl.appendChild(Utils.el('option', { value: t, textContent: t }));
        });
        const pathEl     = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'e.g. ou or https://app.com/department' });
        const errorEl    = Utils.el('p', { className: 'text-error', style: 'display:none' });

        const addBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Register Field',
            onClick: async () => {
                addBtn.disabled = true;
                errorEl.style.display = 'none';
                try {
                    await Api.post(`${_api()}/admin/policy-fields`, {
                        name:          nameEl.value.trim(),
                        display_label: labelEl.value.trim(),
                        source:        sourceEl.value,
                        data_type:     typeEl.value,
                        claim_path:    pathEl.value.trim(),
                    });
                    Utils.showToast('Field registered', 'success');
                    Utils.closeModal();
                    refreshFn();
                } catch (err) {
                    errorEl.textContent = 'Failed: ' + err.message;
                    errorEl.style.display = '';
                    addBtn.disabled = false;
                }
            },
        });

        Utils.showModal('Register Policy Field', Utils.el('div', { className: 'policy-modal-form' }, [
            Utils.el('label', { textContent: 'Field name (snake_case)' }), nameEl,
            Utils.el('label', { textContent: 'Display label' }), labelEl,
            Utils.el('label', { textContent: 'Source' }), sourceEl,
            Utils.el('label', { textContent: 'Data type' }), typeEl,
            Utils.el('label', { textContent: 'Claim path (LDAP attr or OIDC claim key)' }), pathEl,
            errorEl,
            Utils.el('div', { className: 'modal-actions' }, [
                addBtn,
                Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Cancel', onClick: () => Utils.closeModal() }),
            ]),
        ]));
    }

    // ── (b) Admin Scopes ───────────────────────────────────────────────

    function _buildAdminScopes(conditions, fields, refreshFn) {
        const wrap = Utils.el('div', { className: 'policy-subsection' });

        const header = Utils.el('div', { className: 'policy-sub-header' }, [
            Utils.el('h4', { textContent: 'Admin Scope Conditions' }),
            Utils.el('p', { className: 'text-muted policy-sub-hint', textContent: 'Scope conditions restrict which users an admin can target. All conditions for an admin are ANDed — more conditions = narrower scope.' }),
            Utils.el('button', {
                className: 'btn btn-primary btn-xs',
                textContent: 'Add Scope Condition',
                onClick: () => _showAddScopeModal(fields, refreshFn),
            }),
        ]);
        wrap.appendChild(header);

        if (!conditions.length) {
            wrap.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No scope conditions defined. All admins are unrestricted.' }));
            return wrap;
        }

        // Group by holder
        const byHolder = {};
        for (const c of conditions) {
            const key = `${c.holder_type}:${c.holder_id}`;
            if (!byHolder[key]) byHolder[key] = { holder_type: c.holder_type, holder_id: c.holder_id, conds: [] };
            byHolder[key].conds.push(c);
        }

        const list = Utils.el('div', { className: 'scope-groups' });
        for (const group of Object.values(byHolder)) {
            const title = group.holder_type === 'user'
                ? `User: ${group.holder_id}`
                : `Role: ${group.holder_id}`;
            const groupEl = Utils.el('div', { className: 'scope-group' }, [
                Utils.el('div', { className: 'scope-group-title', textContent: title }),
            ]);
            for (const c of group.conds) {
                const row = Utils.el('div', { className: 'scope-cond-row' }, [
                    Utils.el('code', { textContent: `${c.field} ${c.operator} "${c.value}"` }),
                    Utils.el('button', {
                        className: 'btn btn-danger btn-xs',
                        textContent: 'Delete',
                        onClick: async () => {
                            if (!confirm('Delete this scope condition? Affected policy conditions will be flagged for review.')) return;
                            try {
                                await Api.del(`${_api()}/admin/scopes/conditions/${c.id}`);
                                Utils.showToast('Scope condition deleted', 'success');
                                refreshFn();
                            } catch (err) {
                                Utils.showToast('Delete failed: ' + err.message, 'error');
                            }
                        },
                    }),
                ]);
                groupEl.appendChild(row);
            }
            list.appendChild(groupEl);
        }
        wrap.appendChild(list);
        return wrap;
    }

    function _showAddScopeModal(fields, refreshFn) {
        const holderTypeEl = Utils.el('select', { className: 'input-sm' });
        ['user', 'role'].forEach(t => holderTypeEl.appendChild(Utils.el('option', { value: t, textContent: t })));
        const holderIdEl = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'User UUID or role name' });
        const fieldEl    = _buildFieldSelect(fields);
        const opEl       = _buildOperatorSelect();
        const valueEl    = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'Condition value' });
        const errorEl    = Utils.el('p', { className: 'text-error', style: 'display:none' });

        const addBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Add',
            onClick: async () => {
                addBtn.disabled = true;
                errorEl.style.display = 'none';
                try {
                    await Api.post(`${_api()}/admin/scopes`, {
                        holder_type: holderTypeEl.value,
                        holder_id:   holderIdEl.value.trim(),
                        field:       fieldEl.value,
                        operator:    opEl.value,
                        value:       valueEl.value.trim(),
                    });
                    Utils.showToast('Scope condition added', 'success');
                    Utils.closeModal();
                    refreshFn();
                } catch (err) {
                    errorEl.textContent = 'Failed: ' + err.message;
                    errorEl.style.display = '';
                    addBtn.disabled = false;
                }
            },
        });

        Utils.showModal('Add Admin Scope Condition', Utils.el('div', { className: 'policy-modal-form' }, [
            Utils.el('label', { textContent: 'Holder type' }), holderTypeEl,
            Utils.el('label', { textContent: 'Holder ID (user UUID or role name)' }), holderIdEl,
            Utils.el('label', { textContent: 'Field' }), fieldEl,
            Utils.el('label', { textContent: 'Operator' }), opEl,
            Utils.el('label', { textContent: 'Value' }), valueEl,
            errorEl,
            Utils.el('div', { className: 'modal-actions' }, [
                addBtn,
                Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Cancel', onClick: () => Utils.closeModal() }),
            ]),
        ]));
    }

    // ── (c) Policies ────────────────────────────────────────────────────

    function _buildPoliciesPanel(policies, fields, refreshFn) {
        const wrap = Utils.el('div', { className: 'policy-subsection' });

        const header = Utils.el('div', { className: 'policy-sub-header' }, [
            Utils.el('h4', { textContent: 'Policies' }),
            Utils.el('p', { className: 'text-muted policy-sub-hint', textContent: 'Policies grant folder access based on user attributes. All conditions on a policy must match (AND semantics).' }),
            Utils.el('button', {
                className: 'btn btn-primary btn-xs',
                textContent: 'New Policy',
                onClick: () => _showCreatePolicyModal(refreshFn),
            }),
        ]);
        wrap.appendChild(header);

        if (!policies.length) {
            wrap.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No policies defined.' }));
            return wrap;
        }

        const list = Utils.el('div', { className: 'policy-list' });
        for (const policy of policies) {
            list.appendChild(_buildPolicyCard(policy, fields, refreshFn));
        }
        wrap.appendChild(list);
        return wrap;
    }

    function _buildPolicyCard(policy, fields, refreshFn) {
        const detached = policy.conditions.some(c => c.scope_detached);

        const body = Utils.el('div', { className: 'policy-card-body', style: 'display:none' });
        let bodyLoaded = false;

        const scopeBadge = policy.scope_type === 'team'
            ? Utils.el('span', { className: 'badge badge-team', textContent: 'team' })
            : Utils.el('span', { className: 'badge badge-org', textContent: 'org' });

        // Escrow badge + toggle button in header
        const escrowBadge = policy.escrow_enabled
            ? Utils.el('span', { className: 'badge badge-escrow', textContent: 'escrow' })
            : null;

        const escrowToggleBtn = Utils.el('button', {
            className: 'btn btn-xs btn-secondary policy-escrow-toggle',
            textContent: policy.escrow_enabled ? 'Disable escrow' : 'Enable escrow',
            title: 'Toggle key escrow for teams covered by this policy',
            onClick: async (e) => {
                e.stopPropagation();
                escrowToggleBtn.disabled = true;
                try {
                    await Api.patch(`${_api()}/admin/policies/${policy.id}`, {
                        escrow_enabled: !policy.escrow_enabled,
                    });
                    Utils.showToast(
                        policy.escrow_enabled ? 'Escrow disabled' : 'Escrow enabled',
                        'success',
                    );
                    refreshFn();
                } catch (err) {
                    Utils.showToast('Failed: ' + err.message, 'error');
                    escrowToggleBtn.disabled = false;
                }
            },
        });

        const detachBanner = detached
            ? Utils.el('div', { className: 'scope-detach-banner', textContent: 'One or more inherited restrictions have been removed from a parent scope. Review and confirm this policy\'s conditions.' })
            : null;

        const toggleBtn = Utils.el('button', {
            className: 'policy-card-toggle collapsed',
            onClick: () => {
                const open = body.style.display !== 'none';
                body.style.display = open ? 'none' : '';
                toggleBtn.classList.toggle('collapsed', open);
                if (!open && !bodyLoaded) {
                    bodyLoaded = true;
                    _populatePolicyBody(body, policy, fields, refreshFn);
                }
            },
        });
        toggleBtn.appendChild(Utils.el('span', { textContent: policy.name }));
        toggleBtn.appendChild(scopeBadge);
        if (escrowBadge) toggleBtn.appendChild(escrowBadge);

        const deleteBtn = Utils.el('button', {
            className: 'btn btn-danger btn-xs policy-card-delete',
            textContent: 'Delete',
            onClick: async (e) => {
                e.stopPropagation();
                if (!confirm(`Delete policy "${policy.name}" and all its conditions?`)) return;
                try {
                    await Api.del(`${_api()}/admin/policies/${policy.id}`);
                    Utils.showToast('Policy deleted', 'success');
                    refreshFn();
                } catch (err) {
                    Utils.showToast('Delete failed: ' + err.message, 'error');
                }
            },
        });

        const card = Utils.el('div', { className: `policy-card${detached ? ' policy-card-detached' : ''}` }, [
            Utils.el('div', { className: 'policy-card-header' }, [toggleBtn, escrowToggleBtn, deleteBtn]),
            detachBanner,
            body,
        ].filter(Boolean));

        return card;
    }

    function _buildConditionRow(cond, policy, refreshFn) {
        const isInherited = cond.inherited_scope_id !== null;
        const isDetached  = cond.scope_detached;
        const deleteCondBtn = isInherited ? null : Utils.el('button', {
            className: 'btn btn-danger btn-xs',
            textContent: 'Remove',
            onClick: async () => {
                try {
                    await Api.del(`${_api()}/admin/policies/${policy.id}/conditions/${cond.id}`);
                    Utils.showToast('Condition removed', 'success');
                    refreshFn();
                } catch (err) {
                    Utils.showToast('Failed: ' + err.message, 'error');
                }
            },
        });

        let inheritedCell;
        if (!isInherited) {
            inheritedCell = Utils.el('span', { textContent: '—' });
        } else if (isDetached) {
            inheritedCell = Utils.el('span', { className: 'text-warn', textContent: 'detached' });
        } else {
            inheritedCell = Utils.el('span', { className: 'text-muted', textContent: 'locked' });
        }

        const tr = Utils.el('tr', { className: isDetached ? 'cond-row-detached' : '' });
        const condFieldTd = Utils.el('td');
        condFieldTd.appendChild(Utils.el('code', { textContent: cond.field }));
        const condOpTd    = Utils.el('td', { textContent: cond.operator });
        const condValueTd = Utils.el('td', { textContent: cond.value });
        const condStrictTd = Utils.el('td', { textContent: cond.strict ? 'yes' : 'no' });
        const inheritedTd = Utils.el('td');
        inheritedTd.appendChild(inheritedCell);
        const actionTd = Utils.el('td');
        if (deleteCondBtn) actionTd.appendChild(deleteCondBtn);
        tr.append(condFieldTd, condOpTd, condValueTd, condStrictTd, inheritedTd, actionTd);
        return tr;
    }

    function _populatePolicyBody(container, policy, fields, refreshFn) {
        container.innerHTML = '';

        // ── Conditions ──────────────────────────────────────────────────
        const condHeader = Utils.el('h5', { className: 'policy-body-section-title', textContent: 'Conditions' });
        container.appendChild(condHeader);

        if (policy.conditions.length) {
            const table = Utils.el('table', { className: 'policy-table' });
            table.innerHTML = `<thead><tr>
                <th>Field</th><th>Operator</th><th>Value</th><th>Strict</th><th>Inherited</th><th></th>
            </tr></thead>`;
            const tbody = Utils.el('tbody');
            for (const cond of policy.conditions) {
                tbody.appendChild(_buildConditionRow(cond, policy, refreshFn));
            }
            table.appendChild(tbody);
            container.appendChild(table);
        } else {
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No conditions yet. Add at least one condition for this policy to match users.' }));
        }

        container.appendChild(Utils.el('button', {
            className: 'btn btn-primary btn-xs policy-add-cond-btn',
            textContent: '+ Add Condition',
            onClick: () => _showAddConditionModal(policy, fields, refreshFn),
        }));

        // ── Effects ─────────────────────────────────────────────────────
        const effectsHeader = Utils.el('h5', {
            className: 'policy-body-section-title policy-effects-title',
            textContent: 'Effects',
        });
        container.appendChild(effectsHeader);

        const effectsWrap = Utils.el('div', { className: 'policy-effects-wrap' });
        container.appendChild(effectsWrap);

        _loadAndRenderEffects(effectsWrap, policy, refreshFn);
    }

    async function _loadAndRenderEffects(wrap, policy, refreshFn) {
        wrap.innerHTML = '<span class="text-muted">Loading…</span>';
        try {
            const data = await Api.get(`${_api()}/admin/policies/${policy.id}/effects`);
            _renderEffects(wrap, policy, data.effects || [], refreshFn);
        } catch (err) {
            wrap.innerHTML = '';
            const _effErrSpan = Utils.el('span', { className: 'text-error' });
            _effErrSpan.textContent = `Failed to load effects: ${err.message}`;
            wrap.appendChild(_effErrSpan);
        }
    }

    function _effectDetailText(eff) {
        if (eff.effect_type === 'team_member') return `role: ${eff.role_level}`;
        if (eff.effect_type === 'team_escrow') {
            if (eff.escrow_override === 1) return 'force-on';
            if (eff.escrow_override === 0) return 'force-off';
            return 'override';
        }
        return `${eff.permission}${eff.recursive ? ', recursive' : ''}`;
    }

    function _buildEffectRow(eff, policy, wrap, refreshFn) {
        let badgeClass;
        if (eff.effect_type === 'team_member') badgeClass = 'team';
        else if (eff.effect_type === 'team_escrow') badgeClass = 'escrow';
        else badgeClass = 'folder';
        const typeBadge = Utils.el('span', {
            className: `badge badge-effect-${badgeClass}`,
            textContent: eff.effect_type,
        });

        const deleteBtn = Utils.el('button', {
            className: 'btn btn-danger btn-xs',
            textContent: 'Remove',
            onClick: async () => {
                if (!confirm('Remove this effect? Policy-sourced grants for this effect will be revoked for all users.')) return;
                try {
                    await Api.del(`${_api()}/admin/policies/${policy.id}/effects/${eff.id}`);
                    Utils.showToast('Effect removed', 'success');
                    _loadAndRenderEffects(wrap, policy, refreshFn);
                } catch (err) {
                    Utils.showToast('Failed: ' + err.message, 'error');
                }
            },
        });

        const tr = document.createElement('tr');
        const typeTd = Utils.el('td');
        typeTd.appendChild(typeBadge);
        const targetTd = Utils.el('td');
        targetTd.appendChild(Utils.el('code', { className: 'policy-uuid-cell', textContent: eff.target_id }));
        const detailTd = Utils.el('td', { className: 'text-muted', textContent: _effectDetailText(eff) });
        const actionTd = Utils.el('td');
        actionTd.appendChild(deleteBtn);
        tr.append(typeTd, targetTd, detailTd, actionTd);
        return tr;
    }

    function _renderEffects(wrap, policy, effects, refreshFn) {
        wrap.innerHTML = '';

        if (effects.length) {
            const table = Utils.el('table', { className: 'policy-table' });
            table.innerHTML = `<thead><tr>
                <th>Type</th><th>Target ID</th><th>Details</th><th></th>
            </tr></thead>`;
            const tbody = Utils.el('tbody');
            for (const eff of effects) {
                tbody.appendChild(_buildEffectRow(eff, policy, wrap, refreshFn));
            }
            table.appendChild(tbody);
            wrap.appendChild(table);
        } else {
            wrap.appendChild(Utils.el('p', { className: 'text-muted policy-effects-empty', textContent: 'No effects yet. Add an effect to define what this policy grants.' }));
        }

        wrap.appendChild(Utils.el('button', {
            className: 'btn btn-primary btn-xs policy-add-cond-btn',
            textContent: '+ Add Effect',
            onClick: () => _showAddEffectModal(policy, wrap, refreshFn),
        }));
    }

    function _showAddEffectModal(policy, effectsWrap, refreshFn) {
        const typeEl = Utils.el('select', { className: 'input-sm' });
        ['team_member', 'folder_acl', 'team_escrow'].forEach(t =>
            typeEl.appendChild(Utils.el('option', { value: t, textContent: t })));

        const targetEl = Utils.el('input', {
            type: 'text', className: 'input-sm',
            placeholder: 'Team UUID or Folder UUID',
        });

        // team_member fields
        const roleLevelEl = Utils.el('select', { className: 'input-sm' });
        ['team_member', 'team_manager', 'team_admin'].forEach(r =>
            roleLevelEl.appendChild(Utils.el('option', { value: r, textContent: r })));
        const teamMemberWrap = Utils.el('div', {}, [
            Utils.el('label', { textContent: 'Role level' }), roleLevelEl,
        ]);

        // folder_acl fields
        const permEl = Utils.el('select', { className: 'input-sm' });
        ['read', 'write', 'admin'].forEach(p => permEl.appendChild(Utils.el('option', { value: p, textContent: p })));
        const recursiveEl = Utils.el('input', { type: 'checkbox' });
        recursiveEl.checked = true;
        const folderAclWrap = Utils.el('div', {}, [
            Utils.el('label', { textContent: 'Permission' }), permEl,
            Utils.el('div', { className: 'policy-strict-row' }, [
                recursiveEl, Utils.el('label', { textContent: ' Recursive (inherit to subfolders)' }),
            ]),
        ]);

        // team_escrow fields — per-team override
        const escrowOverrideEl = Utils.el('select', { className: 'input-sm' });
        [
            { value: '1', text: '1 — force ON (enable escrow for this team regardless of policy default)' },
            { value: '0', text: '0 — force OFF (disable escrow for this team regardless of policy default)' },
        ].forEach(o => escrowOverrideEl.appendChild(Utils.el('option', { value: o.value, textContent: o.text })));
        const teamEscrowWrap = Utils.el('div', {}, [
            Utils.el('label', { textContent: 'Escrow override' }),
            escrowOverrideEl,
            Utils.el('p', {
                className: 'text-muted policy-sub-hint',
                textContent: 'Overrides the policy-level escrow_enabled for this specific team only.',
            }),
        ]);

        function _syncFields() {
            const t = typeEl.value;
            teamMemberWrap.style.display = t === 'team_member' ? '' : 'none';
            folderAclWrap.style.display  = t === 'folder_acl'  ? '' : 'none';
            teamEscrowWrap.style.display = t === 'team_escrow' ? '' : 'none';
        }
        typeEl.addEventListener('change', _syncFields);
        _syncFields();

        const errorEl = Utils.el('p', { className: 'text-error', style: 'display:none' });

        const addBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Add',
            onClick: async () => {
                addBtn.disabled = true;
                errorEl.style.display = 'none';
                const payload = {
                    effect_type: typeEl.value,
                    target_id:   targetEl.value.trim(),
                };
                if (typeEl.value === 'team_member') {
                    payload.role_level = roleLevelEl.value;
                } else if (typeEl.value === 'folder_acl') {
                    payload.permission = permEl.value;
                    payload.recursive  = recursiveEl.checked;
                } else {
                    payload.escrow_override = Number.parseInt(escrowOverrideEl.value, 10);
                }
                try {
                    await Api.post(`${_api()}/admin/policies/${policy.id}/effects`, payload);
                    Utils.showToast('Effect added', 'success');
                    Utils.closeModal();
                    _loadAndRenderEffects(effectsWrap, policy, refreshFn);
                } catch (err) {
                    errorEl.textContent = 'Failed: ' + err.message;
                    errorEl.style.display = '';
                    addBtn.disabled = false;
                }
            },
        });

        Utils.showModal(`Add Effect — ${policy.name}`, Utils.el('div', { className: 'policy-modal-form' }, [
            Utils.el('label', { textContent: 'Effect type' }), typeEl,
            Utils.el('label', { textContent: 'Target ID (team or folder UUID)' }), targetEl,
            teamMemberWrap,
            folderAclWrap,
            teamEscrowWrap,
            errorEl,
            Utils.el('div', { className: 'modal-actions' }, [
                addBtn,
                Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Cancel', onClick: () => Utils.closeModal() }),
            ]),
        ]));
    }

    function _showCreatePolicyModal(refreshFn) {
        const nameEl      = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'e.g. Finance Team Access' });
        const scopeTypeEl = Utils.el('select', { className: 'input-sm' });
        ['org', 'team'].forEach(t => scopeTypeEl.appendChild(Utils.el('option', { value: t, textContent: t })));
        const scopeIdWrap = Utils.el('div', { style: 'display:none' }, [
            Utils.el('label', { textContent: 'Team ID or Name' }),
            Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'Team UUID or name', id: 'new-policy-scope-id' }),
            Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-sm);margin:2px 0 0', textContent: 'Enter the team\'s UUID or name. If multiple teams share a name, use the UUID.' }),
        ]);
        scopeTypeEl.addEventListener('change', () => {
            scopeIdWrap.style.display = scopeTypeEl.value === 'team' ? '' : 'none';
        });
        // Escrow toggle
        const escrowEl = Utils.el('input', { type: 'checkbox', id: 'new-policy-escrow' });
        const escrowRow = Utils.el('div', { className: 'policy-strict-row' }, [
            escrowEl,
            Utils.el('label', { htmlFor: 'new-policy-escrow', textContent: 'Enable key escrow' }),
        ]);
        const escrowHint = Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-xs);margin:0 0 var(--space-2)', textContent: 'When enabled, designated escrow agents receive a copy of the team encryption key for all teams covered by this policy, allowing emergency access.' });
        const errorEl = Utils.el('p', { className: 'text-error', style: 'display:none' });

        const createBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Create',
            onClick: async () => {
                createBtn.disabled = true;
                errorEl.style.display = 'none';
                const scopeIdInput = scopeIdWrap.querySelector('#new-policy-scope-id');
                try {
                    await Api.post(`${_api()}/admin/policies`, {
                        name:           nameEl.value.trim(),
                        scope_type:     scopeTypeEl.value,
                        scope_id:       scopeTypeEl.value === 'team' ? (scopeIdInput?.value.trim() || null) : null,
                        escrow_enabled: escrowEl.checked,
                    });
                    Utils.showToast('Policy created', 'success');
                    Utils.closeModal();
                    refreshFn();
                } catch (err) {
                    errorEl.textContent = 'Failed: ' + err.message;
                    errorEl.style.display = '';
                    createBtn.disabled = false;
                }
            },
        });

        Utils.showModal('Create Policy', Utils.el('div', { className: 'policy-modal-form' }, [
            Utils.el('label', { textContent: 'Policy name' }), nameEl,
            Utils.el('label', { textContent: 'Scope' }), scopeTypeEl,
            scopeIdWrap,
            escrowRow,
            escrowHint,
            errorEl,
            Utils.el('div', { className: 'modal-actions' }, [
                createBtn,
                Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Cancel', onClick: () => Utils.closeModal() }),
            ]),
        ]));
    }

    function _showAddConditionModal(policy, fields, refreshFn) {
        const fieldEl = _buildFieldSelect(fields);
        const opEl    = _buildOperatorSelect();
        const valueEl = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'Condition value' });
        const strictEl = Utils.el('input', { type: 'checkbox' });
        const errorEl  = Utils.el('p', { className: 'text-error', style: 'display:none' });

        const addBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Add',
            onClick: async () => {
                addBtn.disabled = true;
                errorEl.style.display = 'none';
                try {
                    await Api.post(`${_api()}/admin/policies/${policy.id}/conditions`, {
                        field:    fieldEl.value,
                        operator: opEl.value,
                        value:    valueEl.value.trim(),
                        strict:   strictEl.checked,
                    });
                    Utils.showToast('Condition added', 'success');
                    Utils.closeModal();
                    refreshFn();
                } catch (err) {
                    errorEl.textContent = 'Failed: ' + err.message;
                    errorEl.style.display = '';
                    addBtn.disabled = false;
                }
            },
        });

        Utils.showModal(`Add Condition — ${policy.name}`, Utils.el('div', { className: 'policy-modal-form' }, [
            Utils.el('label', { textContent: 'Field' }), fieldEl,
            Utils.el('label', { textContent: 'Operator' }), opEl,
            Utils.el('label', { textContent: 'Value' }), valueEl,
            Utils.el('div', { className: 'policy-strict-row' }, [
                strictEl,
                Utils.el('label', { textContent: ' Case-sensitive match' }),
            ]),
            errorEl,
            Utils.el('div', { className: 'modal-actions' }, [
                addBtn,
                Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Cancel', onClick: () => Utils.closeModal() }),
            ]),
        ]));
    }

    // ── Shared UI helpers ────────────────────────────────────────────────

    function _buildFieldSelect(fields) {
        const sel = Utils.el('select', { className: 'input-sm' });
        for (const f of fields) {
            sel.appendChild(Utils.el('option', {
                value:       f.name,
                textContent: `${f.display_label} (${f.name})`,
            }));
        }
        return sel;
    }

    function _buildOperatorSelect() {
        const sel = Utils.el('select', { className: 'input-sm' });
        for (const op of _POLICY_OPERATORS) {
            sel.appendChild(Utils.el('option', { value: op, textContent: op }));
        }
        return sel;
    }

    // ------------------------------------------------------------------
    // MFA Policy section
    // ------------------------------------------------------------------

    async function _renderMfaAdmin(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let s;
        try {
            const data = await Api.get(`${_api()}/admin/settings`);
            s = data.settings;
        } catch (err) {
            _showError(container, 'Failed to load settings: ' + err.message);
            return;
        }

        const currentEnforcement = s['mfa_enforcement'] || 'off';
        const selEnforcement = Utils.el('select', { className: 'input-sm' });
        for (const [val, label] of [['off', 'Off — MFA not required'], ['optional', 'Optional — encourage but don\'t require'], ['required', 'Required — block access until enrolled']]) {
            selEnforcement.appendChild(Utils.el('option', { value: val, textContent: label, selected: val === currentEnforcement }));
        }

        let currentMethods = ['totp', 'webauthn'];
        try { currentMethods = JSON.parse(s['mfa_allowed_methods'] || '["totp","webauthn"]'); } catch {}
        const cbTotp = Utils.el('input', { type: 'checkbox', checked: currentMethods.includes('totp') });
        const cbWebAuthn = Utils.el('input', { type: 'checkbox', checked: currentMethods.includes('webauthn') });

        const cbOidcExempt = Utils.el('input', { type: 'checkbox', checked: s['mfa_oidc_exempt'] === '1' });

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Save MFA Policy',
            onClick: async () => {
                const methods = [];
                if (cbTotp.checked) methods.push('totp');
                if (cbWebAuthn.checked) methods.push('webauthn');
                if (methods.length === 0 && selEnforcement.value !== 'off') {
                    Utils.showToast('At least one MFA method must be enabled', 'error');
                    return;
                }
                saveBtn.disabled = true;
                try {
                    await Api.put(`${_api()}/admin/settings`, {
                        settings: {
                            mfa_enforcement:    selEnforcement.value,
                            mfa_allowed_methods: JSON.stringify(methods.length ? methods : ['totp', 'webauthn']),
                            mfa_oidc_exempt:    cbOidcExempt.checked ? '1' : '0',
                        },
                    });
                    Utils.showToast('MFA policy saved', 'success');
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                } finally {
                    saveBtn.disabled = false;
                }
            },
        });

        const methodsWrap = Utils.el('div', { style: 'display:flex;gap:16px;align-items:center' }, [
            Utils.el('label', { style: 'display:flex;gap:4px;align-items:center' }, [cbTotp,    Utils.el('span', { textContent: 'TOTP' })]),
            Utils.el('label', { style: 'display:flex;gap:4px;align-items:center' }, [cbWebAuthn, Utils.el('span', { textContent: 'WebAuthn / Passkey' })]),
        ]);

        container.innerHTML = '';
        container.appendChild(Utils.el('div', { className: 'settings-form' }, [
            _row('Enforcement mode', 'Controls whether MFA is enforced globally', selEnforcement),
            _row('Allowed methods', 'Which MFA methods users may register', methodsWrap),
            _row('OIDC / SSO exempt', 'Users authenticated via OIDC/SAML skip MFA enforcement', cbOidcExempt),
            Utils.el('div', { className: 'settings-actions' }, [saveBtn]),
        ]));

        // Per-user MFA management table
        const mfaUserSection = Utils.el('div', { style: 'margin-top:24px' });
        container.appendChild(mfaUserSection);
        _renderMfaUserTable(mfaUserSection);
    }

    async function _renderMfaUserTable(container) {
        container.innerHTML = '<p class="text-muted">Loading user MFA status…</p>';
        let users;
        try {
            const data = await Api.get(`${_api()}/admin/users`);
            users = data.users;
        } catch (err) {
            _showError(container, 'Failed to load users: ' + err.message);
            return;
        }

        const mfaCache = new Map();

        function _populateMfa(mfaCell, actionsCell, u, mfaData) {
            const creds = mfaData.credentials || [];
            mfaCell.className   = '';
            mfaCell.textContent = creds.length === 0 ? 'None' : creds.map(c => c.method).join(', ');
            actionsCell.innerHTML = '';

            if (creds.length > 0) {
                const wipeBtn = Utils.el('button', {
                    className: 'btn btn-danger btn-xs',
                    textContent: 'Wipe All MFA',
                    onClick: async () => {
                        if (!confirm(`Remove all MFA credentials for "${u.username}"? They will need to re-enroll.`)) return;
                        wipeBtn.disabled = true;
                        try {
                            await Api.del(`${_api()}/admin/users/${u.id}/mfa`);
                            Utils.showToast(`MFA wiped for ${u.username}`, 'success');
                            mfaCache.delete(u.id);
                            _renderMfaUserTable(container);
                        } catch (err) {
                            Utils.showToast('Wipe failed: ' + err.message, 'error');
                            wipeBtn.disabled = false;
                        }
                    },
                });
                actionsCell.appendChild(wipeBtn);
            }

            const resetBtn = Utils.el('button', {
                className: 'btn btn-secondary btn-xs',
                textContent: mfaData.reset_required ? 'Reset Pending' : 'Force Re-enroll',
                disabled: mfaData.reset_required,
                onClick: async () => {
                    if (!confirm(`Force "${u.username}" to re-enroll MFA on next login?`)) return;
                    resetBtn.disabled = true;
                    try {
                        await Api.post(`${_api()}/admin/users/${u.id}/mfa/reset`, {});
                        Utils.showToast(`MFA reset flag set for ${u.username}`, 'success');
                        resetBtn.textContent = 'Reset Pending';
                    } catch (err) {
                        Utils.showToast('Reset failed: ' + err.message, 'error');
                        resetBtn.disabled = false;
                    }
                },
            });
            actionsCell.appendChild(resetBtn);
        }

        function _buildMfaRow(u) {
            const mfaCell    = Utils.el('td', { textContent: '…', className: 'text-muted' });
            const actionsCell = Utils.el('td', { className: 'admin-actions' });

            if (mfaCache.has(u.id)) {
                _populateMfa(mfaCell, actionsCell, u, mfaCache.get(u.id));
            } else {
                Api.get(`${_api()}/admin/users/${u.id}/mfa`).then(mfaData => {
                    mfaCache.set(u.id, mfaData);
                    _populateMfa(mfaCell, actionsCell, u, mfaData);
                }).catch(() => {
                    mfaCell.textContent = '(error)';
                });
            }

            return Utils.el('tr', {}, [
                Utils.el('td', { textContent: u.username }),
                mfaCell,
                actionsCell,
            ]);
        }

        container.innerHTML = '';
        container.appendChild(Utils.el('h4', { textContent: 'Per-User MFA Status', style: 'margin-bottom:8px' }));
        container.appendChild(_makeSortablePagedTable({
            columns: [
                { label: 'Username',        key: 'username' },
                { label: 'MFA Credentials', key: null, sortable: false },
                { label: 'Actions',         key: null, sortable: false },
            ],
            items:    users,
            pageSize: 10,
            filterFn: (u, text) => u.username.toLowerCase().includes(text) || u.id.toLowerCase().includes(text),
            buildRow: _buildMfaRow,
        }));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _showError(container, msg) {
        container.innerHTML = '';
        const p = Utils.el('p', { className: 'text-error' });
        p.textContent = msg;
        container.appendChild(p);
    }

    // ------------------------------------------------------------------
    // Shared: sortable + paginated table widget
    // Usage: _makeSortablePagedTable({ columns, items, pageSize, filterFn, buildRow })
    //   columns  — [{ label, key, sortable }]  key=null disables sort for that col
    //   items    — source array (not mutated)
    //   filterFn — (item, lowerCaseText) -> bool
    //   buildRow — (item) -> <tr> element
    // ------------------------------------------------------------------

    function _makeSortablePagedTable({ columns, items, pageSize = 10, filterFn, buildRow }) {
        let currentPage = 1;
        let sortKey     = null;
        let sortDir     = 'asc';
        let filterText  = '';

        const filterInput = Utils.el('input', {
            type: 'text', placeholder: 'Filter by name or ID…',
            className: 'input-sm',
            style: 'margin-bottom:8px;width:100%;max-width:360px;display:block',
        });

        const thead = Utils.el('thead');
        const tbody = Utils.el('tbody');
        const table = Utils.el('table', { className: 'admin-table' }, [thead, tbody]);

        const countMsg    = Utils.el('span', { style: 'font-size:var(--font-size-sm);color:var(--color-text-muted)' });
        const loadMoreBtn = Utils.el('button', {
            className: 'btn btn-sm btn-secondary',
            textContent: 'Load More',
            style: 'display:none',
        });
        const footer = Utils.el('div', { style: 'display:flex;align-items:center;gap:10px;margin-top:6px' },
            [loadMoreBtn, countMsg]);

        const headerRow = Utils.el('tr');
        for (const col of columns) {
            const sortable = col.sortable !== false && col.key != null;
            const th = Utils.el('th', {
                textContent: col.label,
                style: sortable ? 'cursor:pointer;user-select:none' : '',
            });
            if (sortable) {
                th.addEventListener('click', () => {
                    if (sortKey === col.key) {
                        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
                    } else {
                        sortKey = col.key;
                        sortDir = 'asc';
                    }
                    currentPage = 1;
                    _updateHeaders();
                    _render();
                });
            }
            col._th = th;
            headerRow.appendChild(th);
        }
        thead.appendChild(headerRow);

        function _updateHeaders() {
            for (const col of columns) {
                if (!col._th || col.sortable === false || col.key == null) continue;
                const arrow = sortDir === 'asc' ? ' ▲' : ' ▼';
                col._th.textContent = col.label + (sortKey === col.key ? arrow : '');
            }
        }

        function _render() {
            const filtered = filterText && filterFn
                ? items.filter(item => filterFn(item, filterText))
                : items.slice();

            if (sortKey) {
                filtered.sort((a, b) => {
                    const av = String(a[sortKey] ?? '').toLowerCase();
                    const bv = String(b[sortKey] ?? '').toLowerCase();
                    const cmp = av.localeCompare(bv, undefined, { numeric: true });
                    return sortDir === 'asc' ? cmp : -cmp;
                });
            }

            const total   = filtered.length;
            const visible = filtered.slice(0, currentPage * pageSize);

            tbody.innerHTML = '';
            for (const item of visible) {
                tbody.appendChild(buildRow(item));
            }

            countMsg.textContent = `Showing ${visible.length} of ${total}`;
            loadMoreBtn.style.display = visible.length < total ? '' : 'none';
        }

        filterInput.addEventListener('input', () => {
            filterText = filterInput.value.trim().toLowerCase();
            currentPage = 1;
            _render();
        });
        loadMoreBtn.addEventListener('click', () => { currentPage++; _render(); });

        _render();

        const wrap = Utils.el('div');
        wrap.appendChild(filterInput);
        wrap.appendChild(table);
        wrap.appendChild(footer);
        return wrap;
    }

    // ------------------------------------------------------------------
    // Identity Providers section
    // ------------------------------------------------------------------

    async function _renderIdpSection(container) {
        container.innerHTML = '<p class="text-muted loading-msg">Loading…</p>';
        try {
            const data = await Api.get(`${_api()}/admin/identity-providers`);
            _renderIdpList(container, data.providers || []);
        } catch (err) {
            _showError(container, `Failed to load: ${err.message}`);
        }
    }

    function _renderIdpList(container, providers) {
        container.innerHTML = '';
        const wrap = Utils.el('div');
        container.appendChild(wrap);

        wrap.appendChild(Utils.el('button', {
            className: 'btn btn-primary', style: 'margin-bottom:16px',
            textContent: '+ Add Provider',
            onClick: () => _showIdpModal(null, container),
        }));

        if (providers.length === 0) {
            wrap.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No identity providers configured.' }));
            return;
        }

        const table = Utils.el('table', { className: 'admin-table' });
        table.appendChild(Utils.el('thead', {}, [
            Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Name' }),
                Utils.el('th', { textContent: 'Type' }),
                Utils.el('th', { textContent: 'Claim Mode' }),
                Utils.el('th', { textContent: 'Active' }),
                Utils.el('th', { textContent: 'Actions' }),
            ]),
        ]));
        const tbody = Utils.el('tbody');
        for (const prov of providers) {
            tbody.appendChild(_buildIdpRow(prov, container));
        }
        table.appendChild(tbody);
        wrap.appendChild(table);
    }

    function _buildIdpRow(prov, container) {
        const statusBadge = Utils.el('span', {
            className: prov.is_active ? 'badge badge-active' : 'badge badge-custom',
            textContent: prov.is_active ? 'Active' : 'Inactive',
        });
        const actions = Utils.el('div', { className: 'row-actions' }, [
            Utils.el('button', {
                className: 'btn btn-sm', textContent: 'Edit',
                onClick: () => _showIdpModal(prov, container),
            }),
            Utils.el('button', {
                className: 'btn btn-sm', textContent: 'Test',
                onClick: async (ev) => {
                    ev.target.disabled = true;
                    ev.target.textContent = 'Testing…';
                    try {
                        const res = await Api.post(`${_api()}/admin/identity-providers/${prov.id}/test`);
                        if (res.ok) {
                            Utils.showToast('Connection test passed ✓', 'success');
                        } else {
                            Utils.showToast(`Connection test failed: ${res.error}`, 'error');
                        }
                    } catch (err) {
                        Utils.showToast(`Test error: ${err.message}`, 'error');
                    } finally {
                        ev.target.disabled = false;
                        ev.target.textContent = 'Test';
                    }
                },
            }),
            Utils.el('button', {
                className: 'btn btn-sm', textContent: 'Wizard',
                onClick: () => _showIdpWizard(prov),
            }),
            Utils.el('button', {
                className: 'btn btn-sm btn-danger', textContent: 'Delete',
                onClick: async (ev) => {
                    if (!confirm(`Delete provider "${prov.name}"? Users authenticated via this provider will lose IdP login.`)) return;
                    ev.target.disabled = true;
                    try {
                        await Api.del(`${_api()}/admin/identity-providers/${prov.id}`);
                        Utils.showToast('Provider deleted', 'success');
                        _renderIdpSection(container);
                    } catch (err) {
                        Utils.showToast(`Delete failed: ${err.message}`, 'error');
                        ev.target.disabled = false;
                    }
                },
            }),
        ]);

        return Utils.el('tr', {}, [
            Utils.el('td', { textContent: prov.name }),
            Utils.el('td', { textContent: prov.provider_type.toUpperCase() }),
            Utils.el('td', { textContent: prov.claim_mode || (prov.provider_type === 'ldap' ? 'live' : '—') }),
            Utils.el('td', {}, [statusBadge]),
            Utils.el('td', {}, [actions]),
        ]);
    }

    async function _showIdpModal(existing, listContainer) {
        const isEdit = !!existing;
        let editData = existing;

        if (isEdit) {
            try {
                editData = await Api.get(`${_api()}/admin/identity-providers/${existing.id}`);
            } catch (err) {
                Utils.showToast(`Failed to load provider: ${err.message}`, 'error');
                return;
            }
        }

        const modal = Utils.el('div', { className: 'modal-overlay' });
        const dialog = Utils.el('div', { className: 'modal', style: 'max-width:560px' });
        modal.appendChild(dialog);
        document.body.appendChild(modal);

        const close = () => modal.remove();
        dialog.appendChild(Utils.el('div', { className: 'modal-header' }, [
            Utils.el('h3', { textContent: isEdit ? `Edit: ${existing.name}` : 'Add Identity Provider' }),
            Utils.el('button', { className: 'modal-close', textContent: '×', onClick: close }),
        ]));

        const body = Utils.el('div', { className: 'modal-body' });
        dialog.appendChild(body);

        // Provider type selector (only for new providers)
        let selectedType = existing?.provider_type || 'ldap';
        const typeRow = isEdit ? null : Utils.el('div', { className: 'form-group' }, [
            Utils.el('label', { textContent: 'Provider Type' }),
            Utils.el('select', {
                id: 'idp-type-select',
                onChange: (ev) => { selectedType = ev.target.value; renderForm(); },
            }, [
                Utils.el('option', { value: 'ldap', textContent: 'LDAP / Active Directory' }),
                Utils.el('option', { value: 'oidc', textContent: 'OIDC (Azure AD, Okta, Google, etc.)' }),
            ]),
        ]);

        const formContainer = Utils.el('div');
        if (typeRow) body.appendChild(typeRow);
        body.appendChild(formContainer);

        const statusEl = Utils.el('p', { className: 'auth-status' });
        body.appendChild(statusEl);

        function renderForm() {
            formContainer.innerHTML = '';
            const cfg = editData?.config || {};
            if (selectedType === 'ldap') {
                formContainer.appendChild(_buildLdapForm(cfg, editData));
            } else {
                formContainer.appendChild(_buildOidcForm(cfg, editData));
            }
            const saveBtn = Utils.el('button', {
                type: 'button', className: 'btn btn-primary btn-full',
                textContent: isEdit ? 'Save Changes' : 'Add Provider',
                onClick: () => _saveIdpProvider(selectedType, isEdit, editData?.id, listContainer, statusEl, close),
            });
            formContainer.appendChild(saveBtn);
        }
        renderForm();
    }

    function _buildLdapForm(cfg, existing) {
        const name = existing?.name || '';
        return Utils.el('div', {}, [
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Display Name' }),
                Utils.el('input', { type: 'text', id: 'idp-name', value: name, placeholder: 'e.g. Acme LDAP', maxlength: '128' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Server URI' }),
                Utils.el('input', { type: 'text', id: 'ldap-server-uri', value: cfg.server_uri || '', placeholder: 'ldaps://ldap.example.com:636' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Bind DN (service account)' }),
                Utils.el('input', { type: 'text', id: 'ldap-bind-dn', value: cfg.bind_dn || '', placeholder: 'cn=svc,ou=ServiceAccounts,dc=example,dc=com' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Bind Password' }),
                Utils.el('input', { type: 'password', id: 'ldap-bind-password', value: cfg.bind_password || '', autocomplete: 'new-password' }),
                Utils.el('small', { className: 'text-muted', textContent: 'Leave unchanged to keep the existing password.' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Base DN' }),
                Utils.el('input', { type: 'text', id: 'ldap-base-dn', value: cfg.base_dn || '', placeholder: 'dc=example,dc=com' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'User Filter' }),
                Utils.el('input', { type: 'text', id: 'ldap-user-filter', value: cfg.user_filter || '(&(objectClass=user)(sAMAccountName={username}))', maxlength: '512' }),
                Utils.el('small', { className: 'text-muted', textContent: 'Must contain exactly one {username} placeholder.' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Username Attribute' }),
                Utils.el('input', { type: 'text', id: 'ldap-username-attr', value: cfg.username_attr || 'sAMAccountName', maxlength: '64' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'TLS Mode' }),
                (() => {
                    const sel = document.createElement('select');
                    sel.id = 'ldap-tls';
                    for (const [val, lbl] of [['verify','Verify TLS (recommended)'],['starttls','STARTTLS'],['skip_verify','Skip verification (dev only)']]) {
                        const opt = document.createElement('option');
                        opt.value = val; opt.textContent = lbl;
                        if ((cfg.tls || 'verify') === val) opt.selected = true;
                        sel.appendChild(opt);
                    }
                    return sel;
                })(),
            ]),
        ]);
    }

    function _buildOidcForm(cfg, existing) {
        const name = existing?.name || '';
        const claimMode = existing?.claim_mode || 'at_login';
        return Utils.el('div', {}, [
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Display Name' }),
                Utils.el('input', { type: 'text', id: 'idp-name', value: name, placeholder: 'e.g. Azure AD', maxlength: '128' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Issuer URL' }),
                Utils.el('input', { type: 'url', id: 'oidc-issuer-url', value: cfg.issuer_url || '', placeholder: 'https://login.microsoftonline.com/{tenant}/v2.0' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Client ID' }),
                Utils.el('input', { type: 'text', id: 'oidc-client-id', value: cfg.client_id || '' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Client Secret' }),
                Utils.el('input', { type: 'password', id: 'oidc-client-secret', value: cfg.client_secret || '', autocomplete: 'new-password' }),
                Utils.el('small', { className: 'text-muted', textContent: 'Leave unchanged to keep the existing secret.' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Redirect URI' }),
                Utils.el('input', { type: 'url', id: 'oidc-redirect-uri', value: cfg.redirect_uri || (globalThis.location.origin + '/api/v1/auth/oidc/callback') }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Username Attribute' }),
                Utils.el('input', { type: 'text', id: 'oidc-username-attr', value: cfg.username_attr || 'email', maxlength: '64' }),
                Utils.el('small', { className: 'text-muted', textContent: 'Claim name to use as the display username (e.g. email, preferred_username).' }),
            ]),
            Utils.el('div', { className: 'form-group' }, [
                Utils.el('label', { textContent: 'Claim Mode' }),
                (() => {
                    const sel = document.createElement('select');
                    sel.id = 'oidc-claim-mode';
                    for (const [val, lbl] of [['at_login','At login (cached)'],['live_refetch','Live refetch (always current)']]) {
                        const opt = document.createElement('option');
                        opt.value = val; opt.textContent = lbl;
                        if (claimMode === val) opt.selected = true;
                        sel.appendChild(opt);
                    }
                    return sel;
                })(),
                Utils.el('small', { className: 'text-muted', textContent: 'Live refetch requires offline_access scope and uses the refresh token.' }),
                Utils.el('small', { style: 'display:block;margin-top:4px;color:var(--color-warning,#d97706)', textContent: 'With “At login” mode, OIDC attribute changes — including account revocation at the IdP — take effect only at the user’s next login.' }),
            ]),
        ]);
    }

    async function _saveIdpProvider(type, isEdit, existingId, listContainer, statusEl, close) {
        statusEl.textContent = '';
        const name = document.getElementById('idp-name')?.value?.trim();
        if (!name) { statusEl.textContent = 'Name is required.'; return; }

        let config = {};
        if (type === 'ldap') {
            config = {
                server_uri:     document.getElementById('ldap-server-uri')?.value?.trim(),
                bind_dn:        document.getElementById('ldap-bind-dn')?.value?.trim(),
                bind_password:  document.getElementById('ldap-bind-password')?.value,
                base_dn:        document.getElementById('ldap-base-dn')?.value?.trim(),
                user_filter:    document.getElementById('ldap-user-filter')?.value?.trim(),
                username_attr:  document.getElementById('ldap-username-attr')?.value?.trim() || 'sAMAccountName',
                tls:            document.getElementById('ldap-tls')?.value || 'verify',
            };
        } else {
            config = {
                issuer_url:     document.getElementById('oidc-issuer-url')?.value?.trim(),
                client_id:      document.getElementById('oidc-client-id')?.value?.trim(),
                client_secret:  document.getElementById('oidc-client-secret')?.value,
                redirect_uri:   document.getElementById('oidc-redirect-uri')?.value?.trim(),
                username_attr:  document.getElementById('oidc-username-attr')?.value?.trim() || 'email',
            };
        }

        const claimMode = type === 'oidc' ? (document.getElementById('oidc-claim-mode')?.value || 'at_login') : null;

        const payload = { name, provider_type: type, config, claim_mode: claimMode, is_active: true };

        try {
            statusEl.textContent = 'Saving…';
            if (isEdit) {
                await Api.put(`${_api()}/admin/identity-providers/${existingId}`, payload);
            } else {
                await Api.post(`${_api()}/admin/identity-providers`, payload);
            }
            Utils.showToast(isEdit ? 'Provider updated' : 'Provider added', 'success');
            close();
            _renderIdpSection(listContainer);
        } catch (err) {
            statusEl.textContent = `Error: ${err.message}`;
        }
    }

    async function _showIdpWizard(prov) {
        const modal = Utils.el('div', { className: 'modal-overlay' });
        const dialog = Utils.el('div', { className: 'modal', style: 'max-width:640px' });
        modal.appendChild(dialog);
        document.body.appendChild(modal);

        const close = () => modal.remove();
        dialog.appendChild(Utils.el('div', { className: 'modal-header' }, [
            Utils.el('h3', { textContent: `Attribute Wizard: ${prov.name}` }),
            Utils.el('button', { className: 'modal-close', textContent: '×', onClick: close }),
        ]));

        const body = Utils.el('div', { className: 'modal-body' });
        dialog.appendChild(body);
        body.innerHTML = '<p class="text-muted">Loading attributes…</p>';

        try {
            const data = await Api.get(`${_api()}/admin/identity-providers/${prov.id}/wizard`);
            body.innerHTML = '';

            if (data.error) {
                body.appendChild(Utils.el('p', { className: 'error-text', textContent: data.error }));
            } else {
                const items = data.attributes || data.claims || [];
                if (data.note) {
                    body.appendChild(Utils.el('p', { className: 'text-muted', style: 'margin-bottom:12px', textContent: data.note }));
                }
                if (items.length === 0) {
                    body.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No attributes returned.' }));
                } else {
                    body.appendChild(Utils.el('p', { className: 'text-muted', style: 'margin-bottom:12px' }, [
                        document.createTextNode('Select which attributes to register as policy fields. '),
                        Utils.el('a', {
                            href: '#/admin',
                            textContent: 'Policy Fields',
                            onClick: (ev) => { ev.preventDefault(); close(); },
                        }),
                        document.createTextNode(' can also be edited directly.'),
                    ]));

                    const table = Utils.el('table', { className: 'admin-table', style: 'margin-bottom:12px' });
                    table.appendChild(Utils.el('thead', {}, [Utils.el('tr', {}, [
                        Utils.el('th', { textContent: 'Attribute' }),
                        Utils.el('th', { textContent: 'Example Value' }),
                        Utils.el('th', { textContent: 'Register' }),
                    ])]));
                    const tbody = Utils.el('tbody');
                    for (const item of items) {
                        tbody.appendChild(Utils.el('tr', {}, [
                            Utils.el('td', { textContent: item.name }),
                            Utils.el('td', { textContent: item.example_value, style: 'color:var(--text-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap' }),
                            Utils.el('td', {}, [Utils.el('button', {
                                className: 'btn btn-sm',
                                textContent: 'Register as policy field',
                                onClick: async (ev) => {
                                    ev.target.disabled = true;
                                    ev.target.textContent = 'Saving…';
                                    try {
                                        await Api.post(`${_api()}/admin/policy-fields`, {
                                            name: item.name,
                                            display_label: item.name,
                                            source: prov.provider_type,
                                            data_type: 'string',
                                            claim_path: item.name,
                                        });
                                        ev.target.textContent = 'Registered ✓';
                                        Utils.showToast(`Policy field '${item.name}' registered`, 'success');
                                    } catch (err) {
                                        ev.target.disabled = false;
                                        ev.target.textContent = 'Register as policy field';
                                        Utils.showToast(`Error: ${err.message}`, 'error');
                                    }
                                },
                            })]),
                        ]));
                    }
                    table.appendChild(tbody);
                    body.appendChild(table);
                }
            }

            body.appendChild(Utils.el('button', { className: 'btn btn-secondary', textContent: 'Close', onClick: close }));
        } catch (err) {
            _showError(body, `Failed to load wizard: ${err.message}`);
        }
    }

    // ------------------------------------------------------------------
    // Section: Audit & SIEM
    // ------------------------------------------------------------------

    async function _renderAuditSection(container) {
        container.innerHTML = '<p class="text-muted loading-msg">Loading…</p>';
        try {
            const [logsData, siemData, settingsData] = await Promise.all([
                Api.get(`${_api()}/admin/audit/logs?limit=50`),
                Api.get(`${_api()}/admin/audit/siem`),
                Api.get(`${_api()}/admin/settings`),
            ]);
            _renderAudit(container, logsData.events || [], siemData.destinations || [], settingsData.settings || {}, siemData.filter_profiles || []);
        } catch (err) {
            _showError(container, `Failed to load: ${err.message}`);
        }
    }

    function _renderAudit(container, events, destinations, settings, filterProfiles) {
        container.innerHTML = '';
        const wrap = Utils.el('div');
        container.appendChild(wrap);

        // --- Retention setting ---
        const retentionDays = Number.parseInt(settings['audit_retention_days'] || '365', 10);
        const retInput = Utils.el('input', {
            type: 'number', min: '1', max: '3650', className: 'input-sm',
            value: String(retentionDays), style: 'width:80px; margin-right:8px',
        });
        const retBtn = Utils.el('button', {
            className: 'btn btn-sm btn-primary', textContent: 'Save',
            onClick: async () => {
                retBtn.disabled = true;
                try {
                    await Api.put(`${_api()}/admin/settings`, { settings: { audit_retention_days: retInput.value } });
                    Utils.showToast('Retention policy saved', 'success');
                } catch (e) {
                    Utils.showToast('Failed to save: ' + e.message, 'error');
                } finally {
                    retBtn.disabled = false;
                }
            },
        });
        wrap.appendChild(Utils.el('div', { className: 'settings-row', style: 'margin-bottom:16px' }, [
            Utils.el('label', { className: 'settings-label', textContent: 'Event retention (days)' }),
            Utils.el('div', { className: 'settings-input-wrap' }, [
                retInput,
                retBtn,
                Utils.el('span', { className: 'settings-hint', textContent: 'Max 3650 days. Events older than this may be purged.' }),
            ]),
        ]));

        // --- Log query ---
        wrap.appendChild(Utils.el('h4', { textContent: 'Query log', style: 'margin:0 0 8px' }));

        const etInput  = Utils.el('input', { type: 'text',   className: 'input-sm', placeholder: 'Event types (e.g. auth.*)', style: 'width:200px; margin-right:8px' });
        const sevSel   = Utils.el('select', { className: 'input-sm', style: 'margin-right:8px' });
        ['info','warning','critical'].forEach(s => {
            const o = Utils.el('option', { value: s, textContent: s });
            if (s === 'info') o.selected = true;
            sevSel.appendChild(o);
        });
        const uidInput = Utils.el('input', { type: 'text',   className: 'input-sm', placeholder: 'Actor user ID',             style: 'width:200px; margin-right:8px' });
        const sinceIn  = Utils.el('input', { type: 'datetime-local', className: 'input-sm', style: 'margin-right:8px' });
        const untilIn  = Utils.el('input', { type: 'datetime-local', className: 'input-sm', style: 'margin-right:8px' });

        const queryBtn  = Utils.el('button', { className: 'btn btn-sm btn-primary', textContent: 'Search' });
        const exportBtn = Utils.el('button', { className: 'btn btn-sm',             textContent: 'Export CSV', style: 'margin-left:8px' });

        // Auto-refresh controls
        const refreshChk = Utils.el('input', { type: 'checkbox', id: 'audit-autorefresh', style: 'margin-left:16px; cursor:pointer' });
        const refreshSel = Utils.el('select', { className: 'input-sm', style: 'width:80px' });
        [['5s', 5], ['10s', 10], ['30s', 30]].forEach(([label, val]) => {
            const o = Utils.el('option', { value: val, textContent: label });
            if (val === 10) o.selected = true;
            refreshSel.appendChild(o);
        });
        const refreshLabel = Utils.el('label', { htmlFor: 'audit-autorefresh', textContent: 'Auto-refresh', style: 'cursor:pointer; font-size:.9em' });

        const filterRow = Utils.el('div', { style: 'display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px; align-items:center' }, [
            etInput, sevSel, uidInput,
            Utils.el('span', { textContent: 'From:', style: 'font-size:.85em' }), sinceIn,
            Utils.el('span', { textContent: 'To:',   style: 'font-size:.85em' }), untilIn,
            queryBtn, exportBtn,
            Utils.el('span', { style: 'display:flex; align-items:center; gap:6px; margin-left:8px' }, [
                refreshChk, refreshLabel, refreshSel,
            ]),
        ]);
        wrap.appendChild(filterRow);

        const histTable = _buildAuditTable(events);
        wrap.appendChild(histTable);

        const _buildQs = (limit = 200) => {
            const p = new URLSearchParams({ limit });
            if (etInput.value.trim())    p.set('event_types', etInput.value.trim());
            if (sevSel.value !== 'info') p.set('severity', sevSel.value);
            if (uidInput.value.trim())   p.set('user_id', uidInput.value.trim());
            if (sinceIn.value) p.set('since', sinceIn.value.replace('T', ' '));
            if (untilIn.value) p.set('until', untilIn.value.replace('T', ' '));
            return p.toString();
        };

        queryBtn.onclick = async () => {
            queryBtn.disabled = true;
            try {
                const data = await Api.get(`${_api()}/admin/audit/logs?${_buildQs(200)}`);
                _populateAuditTable(histTable, data.events || []);
            } catch (e) {
                Utils.showToast('Query failed: ' + e.message, 'error');
            } finally {
                queryBtn.disabled = false;
            }
        };

        exportBtn.onclick = () => {
            globalThis.location = `${_api()}/admin/audit/logs/export?${_buildQs(200)}`;
        };

        // Auto-refresh: polls the pull API at the selected interval.
        // Clears itself if the table is removed from the DOM (navigation away).
        let _refreshTimer = null;
        const _stopRefresh = () => { if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; } };
        const _startRefresh = () => {
            _stopRefresh();
            _refreshTimer = setInterval(async () => {
                if (!histTable.isConnected) { _stopRefresh(); return; }
                try {
                    const data = await Api.get(`${_api()}/admin/audit/logs?${_buildQs(50)}`);
                    _populateAuditTable(histTable, data.events || []);
                } catch {}
            }, Number.parseInt(refreshSel.value, 10) * 1000);
        };
        refreshChk.onchange = () => refreshChk.checked ? _startRefresh() : _stopRefresh();
        refreshSel.onchange = () => { if (refreshChk.checked) _startRefresh(); };

        // --- SIEM destinations ---
        wrap.appendChild(Utils.el('hr', { style: 'margin:24px 0' }));
        wrap.appendChild(Utils.el('h4', { textContent: 'SIEM Destinations', style: 'margin:0 0 12px' }));

        const siemWrap = Utils.el('div');
        wrap.appendChild(siemWrap);
        _renderSiemList(siemWrap, destinations, filterProfiles);
    }

    // --- Audit table helpers ---

    // -----------------------------------------------------------------------
    // User detail modal (B1 + B2)
    // -----------------------------------------------------------------------

    async function _renderTransferLocks(locksWrap, userId) {
        const data = await Api.get(`${_api()}/admin/users/${userId}/transfer-locks`);
        locksWrap.innerHTML = '';
        if (!data.files?.length) {
            locksWrap.appendChild(Utils.el('p', { textContent: 'No transfer locks on record.', className: 'text-muted', style: 'font-size:var(--font-size-sm);margin:4px 0' }));
            return;
        }
        const tbl = Utils.el('table', { className: 'admin-table', style: 'font-size:var(--font-size-sm);margin-top:4px' });
        tbl.appendChild(Utils.el('thead', {}, [Utils.el('tr', {}, [
            Utils.el('th', { textContent: 'File' }),
            Utils.el('th', { textContent: 'Locked at' }),
            Utils.el('th', { textContent: 'Locked by' }),
            Utils.el('th'),
        ])]));
        const tbody = Utils.el('tbody');
        for (const f of data.files) {
            tbody.appendChild(_buildTransferLockRow(f));
        }
        tbl.appendChild(tbody);
        locksWrap.appendChild(tbl);
    }

    function _buildTransferLockRow(f) {
        const clearBtn = Utils.el('button', { className: 'btn btn-xs btn-secondary', textContent: 'Clear lock' });
        clearBtn.addEventListener('click', async () => {
            if (!confirm(`Clear transfer lock on "${f.sanitized_name}"?`)) return;
            clearBtn.disabled = true;
            try {
                await Api.del(`${_api()}/admin/files/${f.id}/transfer-lock`);
                clearBtn.closest('tr').remove();
                Utils.showToast('Transfer lock cleared', 'success');
            } catch (err) {
                Utils.showToast('Clear failed: ' + err.message, 'error');
                clearBtn.disabled = false;
            }
        });
        return Utils.el('tr', {}, [
            Utils.el('td', { textContent: f.sanitized_name }),
            Utils.el('td', { textContent: f.locked_at ? String(f.locked_at).slice(0, 16).replace('T', ' ') : '' }),
            Utils.el('td', { textContent: f.locked_by_username || '' }),
            Utils.el('td', {}, [clearBtn]),
        ]);
    }

    async function _runMgmtAction(btn, errEl, action) {
        btn.disabled = true;
        errEl.style.display = 'none';
        try { await action(); } catch (err) {
            errEl.textContent = err.message;
            errEl.style.display = '';
        } finally { btn.disabled = false; }
    }

    async function _showUserDetailModal(userId, username) {
        const wrap = Utils.el('div', { style: 'min-width:560px;max-width:720px' });
        wrap.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'Loading…' }));
        Utils.showModal(`User: ${username || userId}`, wrap);

        let user, allRoles, capData;
        try {
            [{ user }, { roles: allRoles }, capData] = await Promise.all([
                Api.get(`${_api()}/admin/users/${userId}`),
                Api.get(`${_api()}/admin/roles`).catch(() => ({ roles: [] })),
                Api.get(`${_api()}/admin/roles/capabilities`),
            ]);
        } catch (e) {
            wrap.innerHTML = '';
            wrap.appendChild(Utils.el('p', { className: 'text-error', textContent: 'Failed to load: ' + e.message }));
            return;
        }
        const grantableRoleIds = new Set(capData.grantable_role_ids || []);

        wrap.innerHTML = '';

        // ---- Identity card ----
        const grid = Utils.el('div', { style: 'display:grid;grid-template-columns:1fr 1fr;gap:4px 16px;margin-bottom:14px;font-size:var(--font-size-sm)' });
        const _row = (label, value) => {
            grid.appendChild(Utils.el('span', { textContent: label + ':', style: 'font-weight:600;color:var(--color-text-muted)' }));
            grid.appendChild(Utils.el('span', { textContent: value || '—', style: 'word-break:break-all' }));
        };
        _row('UUID', user.id);
        _row('Username', user.username);
        _row('Auth method', user.auth_method);
        _row('Status', user.is_active ? 'Active' : 'Locked');
        _row('MFA', user.mfa_enabled ? 'Enabled' : 'Not configured');
        _row('Created', user.created_at ? user.created_at.replace('T', ' ').slice(0, 19) : '—');
        _row('Last login', user.last_login_at ? user.last_login_at.replace('T', ' ').slice(0, 19) : '—');
        _row('Last login IP', user.last_login_ip);
        wrap.appendChild(grid);

        // ---- Tab bar ----
        const tabBar   = Utils.el('div', { className: 'tabs', style: 'margin-bottom:0' });
        const tabPanes = Utils.el('div', { style: 'padding-top:12px' });
        wrap.appendChild(tabBar);
        wrap.appendChild(tabPanes);

        const _makePaneTab = (label, buildFn) => {
            const pane = Utils.el('div', { style: 'display:none' });
            let loaded = false;
            const btn = Utils.el('button', { className: 'tab', textContent: label });
            btn.addEventListener('click', () => {
                for (const b of tabBar.querySelectorAll('.tab')) b.classList.remove('active');
                btn.classList.add('active');
                for (const p of tabPanes.querySelectorAll(':scope > div')) p.style.display = 'none';
                pane.style.display = '';
                if (!loaded) { loaded = true; buildFn(pane); }
            });
            tabBar.appendChild(btn);
            tabPanes.appendChild(pane);
            return { btn, pane };
        };

        // ---- Tab: Roles ----
        function _renderRolesInner(rolesWrap, currentRoles) {
            rolesWrap.innerHTML = '';
            if (!currentRoles.length) {
                rolesWrap.appendChild(Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-sm)', textContent: 'No roles assigned.' }));
            }
            for (const r of currentRoles) {
                const row = Utils.el('div', { style: 'display:flex;align-items:center;gap:8px;margin-bottom:4px' });
                row.appendChild(Utils.el('span', { textContent: r.name || r.id, style: 'font-size:var(--font-size-sm);flex:1' }));
                const remBtn = Utils.el('button', { className: 'btn btn-xs btn-danger', textContent: 'Remove' });
                remBtn.addEventListener('click', async () => {
                    remBtn.disabled = true;
                    try {
                        await Api.del(`${_api()}/admin/users/${user.id}/roles/${r.id}`);
                        Utils.showToast(`Role ${r.name || r.id} removed`, 'success');
                        const fresh = await Api.get(`${_api()}/admin/users/${user.id}`);
                        _renderRolesInner(rolesWrap, fresh.user.roles);
                    } catch (error_) {
                        Utils.showToast('Remove failed: ' + error_.message, 'error');
                        remBtn.disabled = false;
                    }
                });
                row.appendChild(remBtn);
                rolesWrap.appendChild(row);
            }
            const assignedIds = new Set(currentRoles.map(r => r.id));
            const available = (allRoles || []).filter(r => !assignedIds.has(r.id) && grantableRoleIds.has(r.id));
            if (available.length) {
                const addRow = Utils.el('div', { style: 'display:flex;gap:8px;margin-top:6px' });
                const roleSel = Utils.el('select', { className: 'input-sm', style: 'flex:1' });
                for (const r of available) roleSel.appendChild(Utils.el('option', { value: r.id, textContent: r.name || r.id }));
                const addBtn = Utils.el('button', { className: 'btn btn-xs btn-primary', textContent: '+ Add role' });
                addBtn.addEventListener('click', async () => {
                    addBtn.disabled = true;
                    try {
                        await Api.post(`${_api()}/admin/users/${user.id}/roles/${roleSel.value}`, {});
                        Utils.showToast('Role added', 'success');
                        const fresh = await Api.get(`${_api()}/admin/users/${user.id}`);
                        _renderRolesInner(rolesWrap, fresh.user.roles);
                    } catch (error_) {
                        Utils.showToast('Add failed: ' + error_.message, 'error');
                        addBtn.disabled = false;
                    }
                });
                addRow.append(roleSel, addBtn);
                rolesWrap.appendChild(addRow);
            }
        }

        const { btn: rolesTabBtn } = _makePaneTab('Roles', (pane) => {
            if (!capData.scope.org_wide) {
                pane.appendChild(Utils.el('p', {
                    className: 'admin-scope-banner',
                    style: 'margin:0 0 8px',
                    textContent: 'Scoped admin — role assignment limited to grantable roles within your team scope.',
                }));
            }
            const rolesWrap = Utils.el('div', { style: 'margin-bottom:8px' });
            pane.appendChild(rolesWrap);
            _renderRolesInner(rolesWrap, user.roles || []);
        });

        // ---- Tab: Team Membership ----
        const _tmKeyStatus = (t) => {
            if (t.key_delivery_pending) return 'No key yet';
            return t.key_confirmed ? 'Confirmed' : 'Pending';
        };

        const _buildTeamMemberRow = (teamsArr, renderFn, t) => {
            const removeBtn = Utils.el('button', {
                className: 'btn btn-xs btn-danger',
                textContent: 'Remove',
            });
            removeBtn.addEventListener('click', async () => {
                if (!confirm(`Remove ${user.username} from team "${t.team_name}"?\n\nThis revokes their access and marks the team for key rotation.`)) return;
                removeBtn.disabled = true;
                try {
                    await Api.del(`${_api()}/admin/teams/${t.team_id}/members/${user.id}`);
                    Utils.showToast(`Removed from ${t.team_name}`, 'success');
                    let idx = -1;
                    for (let i = 0; i < teamsArr.length; i++) {
                        if (teamsArr[i].team_id === t.team_id) { idx = i; break; }
                    }
                    if (idx !== -1) teamsArr.splice(idx, 1);
                    renderFn();
                } catch (err) {
                    Utils.showToast('Remove failed: ' + err.message, 'error');
                    removeBtn.disabled = false;
                }
            });
            return Utils.el('tr', {}, [
                Utils.el('td', { textContent: t.team_name }),
                Utils.el('td', { textContent: t.team_role_name || '—' }),
                Utils.el('td', { textContent: _tmKeyStatus(t) }),
                Utils.el('td', { textContent: t.joined_at ? t.joined_at.slice(0, 10) : '—' }),
                Utils.el('td', {}, [removeBtn]),
            ]);
        };

        _makePaneTab('Team Membership', async (pane) => {
            const teamsArr = (user.teams || []).slice();

            // Add to Team form — always visible
            const addForm = Utils.el('div', { style: 'display:flex;gap:6px;align-items:center;margin-bottom:10px;flex-wrap:wrap' });
            const teamSel = Utils.el('select', { className: 'input-sm', style: 'width:180px' });
            teamSel.appendChild(Utils.el('option', { value: '', textContent: 'Loading teams…', disabled: true, selected: true }));
            const roleSel = Utils.el('select', { className: 'input-sm', style: 'width:130px' });
            [['team_member', 'Member'], ['team_manager', 'Supervisor'], ['team_admin', 'Owner']].forEach(([val, label]) => {
                roleSel.appendChild(Utils.el('option', { value: val, textContent: label }));
            });
            const addBtn = Utils.el('button', {
                className: 'btn btn-sm btn-primary',
                textContent: 'Add to Team',
                onClick: async () => {
                    if (!teamSel.value) { Utils.showToast('Select a team', 'warning'); return; }
                    addBtn.disabled = true;
                    try {
                        await Api.post(`${_api()}/admin/teams/${teamSel.value}/members`, {
                            username: user.username,
                            role: roleSel.value,
                        });
                        const teamName = teamSel.options[teamSel.selectedIndex].textContent;
                        Utils.showToast(`Added to ${teamName}`, 'success');
                        teamsArr.push({
                            team_id: teamSel.value,
                            team_name: teamName,
                            team_role_id: roleSel.value,
                            team_role_name: roleSel.options[roleSel.selectedIndex].textContent,
                            key_confirmed: false,
                            key_delivery_pending: true,
                            joined_at: new Date().toISOString(),
                        });
                        // Remove this team from the dropdown so it can't be added twice
                        const opt = teamSel.querySelector(`option[value="${teamSel.value}"]`);
                        if (opt) opt.remove();
                        teamSel.value = '';
                        _renderTeamMembershipTable();
                    } catch (err) {
                        Utils.showToast('Add failed: ' + err.message, 'error');
                    } finally {
                        addBtn.disabled = false;
                    }
                },
            });
            addForm.append(teamSel, roleSel, addBtn);
            pane.appendChild(addForm);

            // Populate team dropdown (exclude teams user already belongs to)
            try {
                const { teams: allTeams } = await Api.get(`${_api()}/admin/teams`);
                const memberTeamIds = new Set(teamsArr.map(t => t.team_id));
                teamSel.innerHTML = '';
                teamSel.appendChild(Utils.el('option', { value: '', textContent: '— select team —', disabled: true, selected: true }));
                allTeams
                    .filter(t => !memberTeamIds.has(t.id))
                    .forEach(t => teamSel.appendChild(Utils.el('option', { value: t.id, textContent: t.name })));
            } catch {
                teamSel.innerHTML = '';
                teamSel.appendChild(Utils.el('option', { value: '', textContent: 'Failed to load teams', disabled: true }));
            }

            const _renderTeamMembershipTable = () => {
                const existing = pane.querySelector('.team-membership-table-wrap');
                if (existing) existing.remove();
                const tableWrap = Utils.el('div', { className: 'team-membership-table-wrap' });
                if (teamsArr.length === 0) {
                    tableWrap.appendChild(Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-sm)', textContent: 'Not a member of any teams.' }));
                } else {
                    const widget = _makeSortablePagedTable({
                        columns: [
                            { label: 'Team',    key: 'team_name' },
                            { label: 'Role',    key: 'team_role_name' },
                            { label: 'Key',     key: 'key_confirmed' },
                            { label: 'Joined',  key: 'joined_at' },
                            { label: 'Actions', key: null, sortable: false },
                        ],
                        items:    teamsArr,
                        pageSize: 10,
                        filterFn: (t, text) => t.team_name.toLowerCase().includes(text),
                        buildRow: _buildTeamMemberRow.bind(null, teamsArr, _renderTeamMembershipTable),
                    });
                    widget.querySelector('table').style.fontSize = '12px';
                    tableWrap.appendChild(widget);
                }
                pane.appendChild(tableWrap);
            };
            _renderTeamMembershipTable();
        });

        // ---- Tab: Audit Trail ----
        _makePaneTab('Audit Trail', (pane) => {
            const filterInput = Utils.el('input', {
                type: 'text', placeholder: 'Filter by event type…',
                className: 'input-sm',
                style: 'margin-bottom:8px;width:100%;max-width:320px;display:block',
            });
            pane.appendChild(filterInput);

            const thead = Utils.el('thead', {}, [
                Utils.el('tr', {}, [
                    Utils.el('th', { textContent: 'Time',    style: 'width:140px;white-space:nowrap' }),
                    Utils.el('th', { textContent: 'Type',    style: 'white-space:nowrap' }),
                    Utils.el('th', { textContent: 'Sev',     style: 'width:70px' }),
                    Utils.el('th', { textContent: 'Outcome', style: 'width:75px' }),
                    Utils.el('th', { textContent: 'IP' }),
                ]),
            ]);
            const tbody = Utils.el('tbody');
            const table = Utils.el('table', { className: 'admin-table', style: 'font-size:var(--font-size-sm)' }, [thead, tbody]);
            pane.appendChild(table);

            const footer = Utils.el('div', { style: 'display:flex;align-items:center;gap:10px;margin-top:6px' });
            const loadMoreBtn = Utils.el('button', {
                className: 'btn btn-sm btn-secondary',
                style: 'display:none',
                textContent: 'Load More',
            });
            const countMsg = Utils.el('span', { style: 'font-size:var(--font-size-sm);color:var(--color-text-muted)' });
            footer.append(loadMoreBtn, countMsg);
            pane.appendChild(footer);

            let auditOffset   = 0;
            const allEvents     = [];
            let filterText    = '';
            const PAGE_SIZE   = 10;

            const _onAuditTypeLinkClick = (e) => {
                e.preventDefault();
                _showEventDetailModal(e.currentTarget._auditEv);
            };

            const _appendEvents = (events) => {
                allEvents.push(...events);
                _rerender();
            };

            const _rerender = () => {
                const filtered = [];
                for (const ev of allEvents) {
                    if (!filterText || ev.event_type.toLowerCase().includes(filterText)) filtered.push(ev);
                }
                tbody.innerHTML = '';
                for (const ev of filtered) {
                    const typeLink = Utils.el('a', {
                        textContent: ev.event_type,
                        href: '#',
                        style: 'cursor:pointer',
                    });
                    typeLink._auditEv = ev;
                    typeLink.addEventListener('click', _onAuditTypeLinkClick);
                    let sevClass = 'badge-custom';
                    if (ev.severity === 'critical') sevClass = 'badge-expired';
                    else if (ev.severity === 'warning') sevClass = 'badge-team';
                    tbody.appendChild(Utils.el('tr', {}, [
                        Utils.el('td', { textContent: ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 19) : '' }),
                        Utils.el('td', {}, [typeLink]),
                        Utils.el('td', {}, [Utils.el('span', { className: `badge ${sevClass}`, textContent: ev.severity || '' })]),
                        Utils.el('td', { textContent: ev.outcome || '' }),
                        Utils.el('td', { textContent: ev.actor_ip || '' }),
                    ]));
                }
                if (!filtered.length) {
                    tbody.appendChild(Utils.el('tr', {}, [
                        Utils.el('td', { colSpan: 5, className: 'text-muted', textContent: 'No events.', style: 'text-align:center;padding:12px' }),
                    ]));
                }
                countMsg.textContent = `${filtered.length} event${filtered.length === 1 ? '' : 's'} loaded`;
            };

            const _loadMore = async () => {
                loadMoreBtn.disabled = true;
                loadMoreBtn.textContent = 'Loading…';
                try {
                    const result = await Api.get(
                        `${_api()}/admin/audit/logs?user_id=${encodeURIComponent(user.id)}&limit=${PAGE_SIZE}&offset=${auditOffset}`,
                    );
                    const events = result.events || [];
                    auditOffset += events.length;
                    _appendEvents(events);
                    loadMoreBtn.style.display = events.length === PAGE_SIZE ? '' : 'none';
                } catch (err) {
                    Utils.showToast('Failed to load audit events: ' + err.message, 'error');
                } finally {
                    loadMoreBtn.disabled = false;
                    loadMoreBtn.textContent = 'Load More';
                }
            };

            filterInput.addEventListener('input', () => {
                filterText = filterInput.value.trim().toLowerCase();
                _rerender();
            });
            loadMoreBtn.addEventListener('click', _loadMore);

            _loadMore();
        });

        // ---- Tab: Management ----
        _makePaneTab('Management', (pane) => {
            const errEl = Utils.el('p', { className: 'text-error', style: 'display:none;margin:4px 0 8px;font-size:var(--font-size-sm)' });
            pane.appendChild(errEl);

            const _mgmtBtn = (label, cls, desc, onClick) => {
                const btn = Utils.el('button', { className: `btn btn-sm ${cls}`, textContent: label });
                btn.addEventListener('click', _runMgmtAction.bind(null, btn, errEl, onClick));
                return Utils.el('div', { style: 'display:flex;align-items:flex-start;gap:10px;margin-bottom:10px' }, [
                    Utils.el('div', { style: 'flex:1' }, [
                        Utils.el('p', { style: 'margin:0 0 3px;font-size:var(--font-size-sm);color:var(--color-text-muted)', textContent: desc }),
                    ]),
                    btn,
                ]);
            };

            const _section = (title, isDanger, items) => {
                const border = isDanger ? '1px solid var(--color-danger,#dc2626)' : '1px solid var(--color-border)';
                const header = isDanger ? Utils.el('h6', { textContent: title, style: 'color:var(--color-danger,#dc2626);margin:0 0 10px;font-size:var(--font-size-sm);text-transform:uppercase;letter-spacing:.05em' }) : Utils.el('h6', { textContent: title, style: 'margin:0 0 10px;font-size:var(--font-size-sm);text-transform:uppercase;letter-spacing:.05em;color:var(--color-text-muted)' });
                return Utils.el('div', { style: `border:${border};border-radius:6px;padding:12px;margin-bottom:12px` }, [header, ...items]);
            };

            // Account section
            const lockItem = user.is_active
                ? _mgmtBtn('Lock Account', 'btn-danger',
                    'Deactivates the account and revokes all sessions and shares.',
                    async () => {
                        await Api.post(`${_api()}/admin/users/${user.id}/lock`, {});
                        Utils.showToast('Account locked', 'warning');
                        Utils.closeModal();
                    })
                : _mgmtBtn('Unlock Account', 'btn-secondary',
                    'Re-activates the account so the user can log in again.',
                    async () => {
                        await Api.post(`${_api()}/admin/users/${user.id}/unlock`, {});
                        Utils.showToast('Account unlocked', 'success');
                        Utils.closeModal();
                    });

            const revokeItem = _mgmtBtn('Revoke All Sessions', 'btn-secondary',
                'Logs the user out of all active sessions immediately.',
                async () => {
                    if (!confirm(`Revoke all sessions for ${user.username}? They will be logged out everywhere.`)) return;
                    const result = await Api.post(`${_api()}/admin/users/${user.id}/reset-password`, {});
                    Utils.showToast(result.message || 'Sessions revoked', 'success');
                });

            pane.appendChild(_section('Account', false, [lockItem, revokeItem]));

            // Emergency actions section
            const emergencyForm = Utils.el('div', { style: 'display:none;margin-top:10px;padding:10px;background:rgba(220,38,38,.07);border-radius:4px' });
            const reasonInput = Utils.el('input', {
                type: 'text', className: 'prompt-dialog-input',
                placeholder: 'Reason for revocation (required)',
                style: 'margin-bottom:6px;width:100%;box-sizing:border-box',
            });
            const scopeSel = Utils.el('select', { className: 'input-sm', style: 'width:100%;box-sizing:border-box;margin-bottom:6px' }, [
                Utils.el('option', { value: 'owned_only',  textContent: 'Lock owned files only' }),
                Utils.el('option', { value: 'all_access',  textContent: 'Lock all accessible files (owned + team)' }),
            ]);
            const notifyCheckId = `emergency-notify-${user.id}`;
            const notifyCheck   = Utils.el('input', { type: 'checkbox', id: notifyCheckId });
            const notifyRow     = Utils.el('div', { style: 'display:flex;align-items:center;gap:6px;margin-bottom:8px' }, [
                notifyCheck, Utils.el('label', { htmlFor: notifyCheckId, textContent: 'Notify escrow agents', style: 'font-size:var(--font-size-sm);cursor:pointer' }),
            ]);
            const confirmRevokeBtn = Utils.el('button', { className: 'btn btn-danger btn-sm', textContent: 'Confirm Emergency Revoke' });
            const cancelRevokeBtn  = Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Cancel', style: 'margin-left:6px' });
            confirmRevokeBtn.addEventListener('click', async () => {
                const reason = reasonInput.value.trim();
                if (!reason) { Utils.showToast('A reason is required', 'error'); return; }
                if (!confirm(`EMERGENCY REVOKE "${user.username}"?\n\nThis will deactivate the account, revoke all sessions and shares, and transfer-lock files. This cannot be undone.`)) return;
                confirmRevokeBtn.disabled = true;
                try {
                    const r = await Api.post(`${_api()}/admin/users/${user.id}/emergency-revoke`, {
                        reason, scope: scopeSel.value, notify_escrow: notifyCheck.checked,
                    });
                    Utils.showToast(`Emergency revoke: ${r.files_locked} file(s) locked, ${r.tokens_revoked} session(s) revoked`, 'success');
                    Utils.closeModal();
                } catch (err) {
                    Utils.showToast('Emergency revoke failed: ' + err.message, 'error');
                    confirmRevokeBtn.disabled = false;
                }
            });
            cancelRevokeBtn.addEventListener('click', () => { emergencyForm.style.display = 'none'; });
            emergencyForm.append(reasonInput, scopeSel, notifyRow, Utils.el('div', {}, [confirmRevokeBtn, cancelRevokeBtn]));

            const emergencyItem = Utils.el('div', { style: 'margin-bottom:10px' }, [
                Utils.el('div', { style: 'display:flex;align-items:flex-start;gap:10px' }, [
                    Utils.el('div', { style: 'flex:1' }, [
                        Utils.el('p', { style: 'margin:0 0 3px;font-size:var(--font-size-sm);color:var(--color-text-muted)', textContent: 'For incident response: deactivates account, revokes all sessions and shares, and transfer-locks files.' }),
                    ]),
                    Utils.el('button', {
                        className: 'btn btn-sm btn-danger',
                        textContent: 'Emergency Revoke…',
                        onClick: () => { emergencyForm.style.display = emergencyForm.style.display === 'none' ? '' : 'none'; },
                    }),
                ]),
                emergencyForm,
            ]);

            const deleteKeysItem = _mgmtBtn('Delete Asymmetric Keys', 'btn-danger',
                'Permanently deletes this user\'s asymmetric keypair. Irreversible — breaks all team cryptography for this user.',
                async () => {
                    if (!confirm(`Delete asymmetric keys for "${user.username}"?\n\nThis will break team crypto for this user and is irreversible.`)) return;
                    if (!confirm('Second confirmation: permanently delete asymmetric keys?')) return;
                    await Api.del(`${_api()}/admin/users/${user.id}/asymmetric-keys`);
                    Utils.showToast('Asymmetric keys deleted', 'warning');
                });

            pane.appendChild(_section('Emergency Actions', true, [emergencyItem, deleteKeysItem]));

            // Tools section
            const locksWrap = Utils.el('div', { style: 'margin-top:8px' });
            const locksItem = Utils.el('div', { style: 'display:flex;align-items:flex-start;gap:10px;margin-bottom:10px' }, [
                Utils.el('div', { style: 'flex:1' }, [
                    Utils.el('p', { style: 'margin:0 0 3px;font-size:var(--font-size-sm);color:var(--color-text-muted)', textContent: 'Shows all files with transfer restrictions applied to this user.' }),
                    locksWrap,
                ]),
                Utils.el('button', {
                    className: 'btn btn-sm btn-secondary',
                    textContent: 'View Transfer Locks',
                    onClick: () => _renderTransferLocks(locksWrap, user.id),
                }),
            ]);
            pane.appendChild(_section('Tools', false, [locksItem]));
        });

        // Activate Roles tab by default
        rolesTabBtn.click();
    }

    function _buildAuditTable(events) {
        const table = Utils.el('table', { className: 'admin-table' });
        table.appendChild(Utils.el('thead', {}, [
            Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Time',    style: 'width:145px; white-space:nowrap' }),
                Utils.el('th', { textContent: 'Type',    style: 'white-space:nowrap' }),
                Utils.el('th', { textContent: 'Sev',     style: 'width:70px' }),
                Utils.el('th', { textContent: 'Outcome', style: 'width:75px' }),
                Utils.el('th', { textContent: 'Path' }),
                Utils.el('th', { textContent: 'User' }),
                Utils.el('th', { textContent: 'Target' }),
            ]),
        ]));
        const tbody = Utils.el('tbody');
        table.appendChild(tbody);
        _populateAuditTable(table, events);
        return table;
    }

    function _populateAuditTable(table, events) {
        const tbody = table.querySelector('tbody');
        tbody.innerHTML = '';
        if (!events.length) {
            tbody.appendChild(Utils.el('tr', {}, [
                Utils.el('td', { colSpan: 7, className: 'text-muted', textContent: 'No events.', style: 'text-align:center; padding:12px' }),
            ]));
            return;
        }
        for (const ev of events) {
            tbody.appendChild(_buildAuditRow(ev));
        }
    }

    function _showEventDetailModal(ev) {
        function kv(label, value) {
            if (value === null || value === undefined || value === '') return null;
            return Utils.el('tr', {}, [
                Utils.el('td', { style: 'font-weight:600;padding:3px 14px 3px 0;white-space:nowrap;vertical-align:top;color:var(--color-text-muted)', textContent: label }),
                Utils.el('td', { style: 'padding:3px 0;word-break:break-all;font-family:monospace;font-size:var(--font-size-sm)', textContent: String(value) }),
            ]);
        }
        const detail = (ev.detail && typeof ev.detail === 'object') ? ev.detail : {};
        const remainingDetail = Object.fromEntries(
            Object.entries(detail).filter(([k]) => k !== 'path' && k !== 'method')
        );
        const tbody = Utils.el('tbody');
        const rows = [
            kv('Event ID',      ev.event_id),
            kv('Timestamp',     ev.timestamp),
            kv('Type',          ev.event_type),
            kv('Severity',      ev.severity),
            kv('Outcome',       ev.outcome),
            kv('Action key',    ev.action_key),
            kv('Method',        detail.method),
            kv('Path',          detail.path),
            kv('Actor',         ev.actor_username || ev.actor_user_id),
            kv('Actor user ID', ev.actor_user_id),
            kv('Actor IP',      ev.actor_ip),
            kv('Session ID',    ev.actor_session_id),
            kv('User agent',    ev.user_agent),
            kv('Target type',   ev.target_type),
            kv('Target name',   ev.target_name),
            kv('Target ID',     ev.target_id),
            kv('Admin actor',   ev.admin_actor_id),
        ];
        for (const r of rows) { if (r) tbody.appendChild(r); }
        const table = Utils.el('table', { style: 'border-collapse:collapse;width:100%' }, [tbody]);
        const wrap = Utils.el('div', { style: 'min-width:500px;max-width:700px' }, [table]);
        if (Object.keys(remainingDetail).length) {
            wrap.appendChild(Utils.el('h5', { textContent: 'Detail', style: 'margin:14px 0 6px' }));
            wrap.appendChild(Utils.el('pre', {
                style: 'background:var(--color-surface-active);color:var(--color-text);border:1px solid var(--color-border);padding:10px;border-radius:4px;overflow:auto;font-size:var(--font-size-sm);max-height:220px;margin:0',
                textContent: JSON.stringify(remainingDetail, null, 2),
            }));
        }
        Utils.showModal(`Event: ${ev.event_type}`, wrap);
    }

    function _buildAuditRow(ev) {
        let sevClass;
        if (ev.severity === 'critical') sevClass = 'badge-expired';
        else if (ev.severity === 'warning') sevClass = 'badge-team';
        else sevClass = 'badge-custom';

        const displayName = ev.actor_username || ev.actor_user_id || '';
        let actorCell;
        if (ev.actor_user_id && displayName) {
            const link = Utils.el('a', {
                textContent: displayName,
                href: '#',
                style: 'cursor:pointer',
            });
            link.addEventListener('click', (e) => {
                e.preventDefault();
                _showUserDetailModal(ev.actor_user_id, ev.actor_username);
            });
            actorCell = Utils.el('td', {}, [link]);
        } else {
            actorCell = Utils.el('td', { textContent: displayName });
        }

        const typeLink = Utils.el('a', {
            textContent: ev.event_type,
            href: '#',
            style: 'cursor:pointer',
            onClick: (e) => { e.preventDefault(); _showEventDetailModal(ev); },
        });

        const pathText = ev.detail?.path ?? '';

        return Utils.el('tr', {}, [
            Utils.el('td', { textContent: ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 19) : '', style: 'white-space:nowrap' }),
            Utils.el('td', {}, [typeLink]),
            Utils.el('td', {}, [Utils.el('span', { className: `badge ${sevClass}`, textContent: ev.severity || 'info' })]),
            Utils.el('td', { textContent: ev.outcome || '' }),
            Utils.el('td', { textContent: pathText, title: pathText, style: 'max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; font-size:var(--font-size-xs)' }),
            actorCell,
            Utils.el('td', { textContent: ev.target_name || ev.target_id || '' }),
        ]);
    }

    // --- SIEM destination management ---

    function _renderSiemList(container, destinations, filterProfiles) {
        container.innerHTML = '';
        container.appendChild(Utils.el('button', {
            className: 'btn btn-primary', style: 'margin-bottom:16px',
            textContent: '+ Add Destination',
            onClick: () => _showSiemModal(null, container, filterProfiles),
        }));

        if (!destinations.length) {
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No SIEM destinations configured. Audit events are stored locally only.' }));
            return;
        }

        const table = Utils.el('table', { className: 'admin-table' });
        table.appendChild(Utils.el('thead', {}, [
            Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Name' }),
                Utils.el('th', { textContent: 'Type' }),
                Utils.el('th', { textContent: 'Host / URL' }),
                Utils.el('th', { textContent: 'Format' }),
                Utils.el('th', { textContent: 'Filter Profile' }),
                Utils.el('th', { textContent: 'Active' }),
                Utils.el('th', { textContent: 'Actions' }),
            ]),
        ]));
        const tbody = Utils.el('tbody');
        for (const dest of destinations) {
            tbody.appendChild(_buildSiemRow(dest, container, filterProfiles));
        }
        table.appendChild(tbody);
        container.appendChild(table);
    }

    function _buildSiemRow(dest, container, filterProfiles) {
        const activeBadge = Utils.el('span', {
            className: dest.is_active ? 'badge badge-active' : 'badge badge-custom',
            textContent: dest.is_active ? 'Active' : 'Inactive',
        });
        const hostOrUrl = dest.type === 'syslog'
            ? `${dest.host || ''}:${dest.port || 514}`
            : (dest.url || '');

        const profileMeta = (filterProfiles || []).find(p => p.id === dest.filter_profile);
        const profileLabel = profileMeta ? profileMeta.label : (dest.filter_profile || 'Recommended');

        const testBtn = Utils.el('button', {
            className: 'btn btn-sm', textContent: 'Test',
            onClick: async (ev) => {
                ev.target.disabled = true;
                ev.target.textContent = 'Testing…';
                try {
                    const res = await Api.post(`${_api()}/admin/audit/siem/${dest.id}/test`);
                    Utils.showToast(res.ok ? 'Test event sent ✓' : `Test failed: ${res.error}`, res.ok ? 'success' : 'error');
                } catch (err) {
                    Utils.showToast('Test error: ' + err.message, 'error');
                } finally {
                    ev.target.disabled = false;
                    ev.target.textContent = 'Test';
                }
            },
        });

        return Utils.el('tr', {}, [
            Utils.el('td', { textContent: dest.name }),
            Utils.el('td', { textContent: dest.type }),
            Utils.el('td', { textContent: hostOrUrl }),
            Utils.el('td', { textContent: dest.syslog_format || '—' }),
            Utils.el('td', { textContent: profileLabel }),
            Utils.el('td', {}, [activeBadge]),
            Utils.el('td', { className: 'row-actions' }, [
                Utils.el('button', {
                    className: 'btn btn-sm', textContent: 'Edit',
                    onClick: () => _showSiemModal(dest, container, filterProfiles),
                }),
                testBtn,
                Utils.el('button', {
                    className: 'btn btn-sm btn-danger', textContent: 'Delete',
                    onClick: async (ev) => {
                        if (!confirm(`Delete SIEM destination "${dest.name}"?`)) return;
                        ev.target.disabled = true;
                        try {
                            await Api.del(`${_api()}/admin/audit/siem/${dest.id}`);
                            Utils.showToast('Destination deleted', 'success');
                            const data = await Api.get(`${_api()}/admin/audit/siem`);
                            _renderSiemList(container, data.destinations || [], filterProfiles);
                        } catch (err) {
                            Utils.showToast('Delete failed: ' + err.message, 'error');
                            ev.target.disabled = false;
                        }
                    },
                }),
            ]),
        ]);
    }

    function _showSiemModal(dest, listContainer, filterProfiles) {
        const isEdit = dest !== null;
        const title  = isEdit ? 'Edit SIEM Destination' : 'Add SIEM Destination';
        const body   = Utils.el('div');
        const close  = Utils.showModal(title, body);

        const nameIn   = Utils.el('input', { type: 'text',     className: 'input-sm', value: dest?.name || '',    placeholder: 'Friendly name', style: 'width:100%; margin-bottom:8px' });
        const typeSel  = Utils.el('select', { className: 'input-sm', style: 'margin-bottom:8px' });
        ['syslog', 'webhook'].forEach(t => {
            const o = Utils.el('option', { value: t, textContent: t.charAt(0).toUpperCase() + t.slice(1) });
            if (dest?.type === t) o.selected = true;
            typeSel.appendChild(o);
        });
        const activeCb = Utils.el('input', { type: 'checkbox', checked: dest?.is_active !== false });
        const activeRow = Utils.el('label', { style: 'display:flex; align-items:center; gap:8px; margin-bottom:12px; cursor:pointer' }, [
            activeCb, Utils.el('span', { textContent: 'Active' }),
        ]);

        // Syslog fields
        const hostIn   = Utils.el('input', { type: 'text',   className: 'input-sm', value: dest?.host || '',    placeholder: 'Syslog host', style: 'width:100%; margin-bottom:8px' });
        const portIn   = Utils.el('input', { type: 'number', className: 'input-sm', value: String(dest?.port || 514), style: 'width:80px; margin-bottom:8px' });
        const protoSel = Utils.el('select', { className: 'input-sm', style: 'margin-bottom:8px' });
        ['udp','tcp','tls'].forEach(p => {
            const o = Utils.el('option', { value: p, textContent: p.toUpperCase() });
            if ((dest?.protocol || 'udp') === p) o.selected = true;
            protoSel.appendChild(o);
        });
        const fmtSel   = Utils.el('select', { className: 'input-sm', style: 'margin-bottom:8px' });
        ['rfc5424','cef','leef'].forEach(f => {
            const o = Utils.el('option', { value: f, textContent: f.toUpperCase() });
            if ((dest?.syslog_format || 'rfc5424') === f) o.selected = true;
            fmtSel.appendChild(o);
        });
        const syslogFields = Utils.el('div', {}, [
            Utils.el('label', { className: 'settings-label', textContent: 'Host' }), hostIn,
            Utils.el('div', { style: 'display:flex; gap:8px; margin-bottom:8px' }, [
                Utils.el('div', {}, [Utils.el('label', { className: 'settings-label', textContent: 'Port' }), portIn]),
                Utils.el('div', {}, [Utils.el('label', { className: 'settings-label', textContent: 'Protocol' }), protoSel]),
                Utils.el('div', {}, [Utils.el('label', { className: 'settings-label', textContent: 'Format' }), fmtSel]),
            ]),
        ]);

        // Webhook fields
        const urlIn    = Utils.el('input', { type: 'url',  className: 'input-sm', value: dest?.url || '',   placeholder: 'https://siem.example.com/ingest', style: 'width:100%; margin-bottom:8px' });
        const secretIn = Utils.el('input', { type: 'password', className: 'input-sm', placeholder: isEdit ? '(leave blank to keep existing)' : 'HMAC signing secret', style: 'width:100%; margin-bottom:8px' });
        const batchIn  = Utils.el('input', { type: 'number', className: 'input-sm', value: String(dest?.batch_size || 1), min: '1', max: '100', style: 'width:80px; margin-bottom:8px' });
        const webhookFields = Utils.el('div', {}, [
            Utils.el('label', { className: 'settings-label', textContent: 'Webhook URL (HTTPS)' }), urlIn,
            Utils.el('label', { className: 'settings-label', textContent: 'HMAC Signing Secret' }), secretIn,
            Utils.el('label', { className: 'settings-label', textContent: 'Batch size (1 = real-time)' }), batchIn,
        ]);

        const fieldWrap = Utils.el('div');
        const _updateFields = () => {
            fieldWrap.innerHTML = '';
            fieldWrap.appendChild(typeSel.value === 'syslog' ? syslogFields : webhookFields);
        };
        typeSel.onchange = _updateFields;
        _updateFields();

        // --- Filter profile ---
        const profiles = filterProfiles?.length
            ? filterProfiles
            : [
                { id: 'high_security', label: 'High Security', description: 'All events including file downloads, uploads, and shares.' },
                { id: 'recommended',   label: 'Recommended',   description: 'Auth, admin actions, policy/role changes, and destructive file ops.' },
                { id: 'relaxed',       label: 'Relaxed',       description: 'Critical severity only — lockouts, emergency revocations, auth failures.' },
                { id: 'custom',        label: 'Custom',        description: 'Define your own event type glob patterns and minimum severity.' },
            ];
        const currentProfile = dest?.filter_profile || 'recommended';

        const profileSel = Utils.el('select', { className: 'input-sm', style: 'width:100%; margin-bottom:6px' });
        profiles.forEach(p => {
            const o = Utils.el('option', { value: p.id, textContent: p.label });
            if (p.id === currentProfile) o.selected = true;
            profileSel.appendChild(o);
        });

        const profileDesc = Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-sm); margin:0 0 8px' });
        const customWrap  = Utils.el('div', { style: 'display:none' });

        const customGlobsIn = Utils.el('textarea', {
            className: 'input-sm',
            placeholder: 'One glob pattern per line, e.g.:\nauth.*\nadmin.*\nfile.delete',
            style: 'width:100%; height:80px; margin-bottom:6px; font-family:monospace; font-size:var(--font-size-sm)',
        });
        const customSevSel = Utils.el('select', { className: 'input-sm', style: 'width:120px; margin-bottom:8px' });
        ['info', 'warning', 'critical'].forEach(s => {
            const o = Utils.el('option', { value: s, textContent: s.charAt(0).toUpperCase() + s.slice(1) });
            customSevSel.appendChild(o);
        });

        // Populate custom fields from existing dest if editing
        if (dest?.filter_custom_json) {
            try {
                const cfg = JSON.parse(dest.filter_custom_json);
                customGlobsIn.value = (cfg.event_type_globs || []).join('\n');
                customSevSel.value = cfg.min_severity || 'info';
            } catch { /* invalid JSON; keep default empty values */ }
        }

        customWrap.appendChild(Utils.el('label', { className: 'settings-label', textContent: 'Event type glob patterns (one per line)' }));
        customWrap.appendChild(customGlobsIn);
        customWrap.appendChild(Utils.el('label', { className: 'settings-label', textContent: 'Minimum severity' }));
        customWrap.appendChild(customSevSel);

        const _updateProfile = () => {
            const sel = profiles.find(p => p.id === profileSel.value);
            profileDesc.textContent = sel ? sel.description : '';
            customWrap.style.display = profileSel.value === 'custom' ? '' : 'none';
        };
        profileSel.onchange = _updateProfile;
        _updateProfile();

        const filterSection = Utils.el('div', { style: 'margin-top:16px' }, [
            Utils.el('label', { className: 'settings-label', textContent: 'Filter Profile' }),
            profileSel,
            profileDesc,
            customWrap,
        ]);

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary', textContent: isEdit ? 'Save' : 'Add',
            onClick: async () => {
                saveBtn.disabled = true;

                let filterCustomJson = null;
                if (profileSel.value === 'custom') {
                    const globs = customGlobsIn.value.split('\n').map(s => s.trim()).filter(Boolean);
                    if (!globs.length) {
                        Utils.showToast('Custom profile requires at least one glob pattern', 'error');
                        saveBtn.disabled = false;
                        return;
                    }
                    filterCustomJson = JSON.stringify({ event_type_globs: globs, min_severity: customSevSel.value });
                }

                const payload = {
                    name:               nameIn.value.trim(),
                    type:               typeSel.value,
                    is_active:          activeCb.checked,
                    host:               typeSel.value === 'syslog' ? hostIn.value.trim() || null : null,
                    port:               typeSel.value === 'syslog' ? Number.parseInt(portIn.value, 10) || 514 : null,
                    protocol:           typeSel.value === 'syslog' ? protoSel.value : null,
                    syslog_format:      typeSel.value === 'syslog' ? fmtSel.value : null,
                    url:                typeSel.value === 'webhook' ? urlIn.value.trim() || null : null,
                    secret:             typeSel.value === 'webhook' && secretIn.value ? secretIn.value : null,
                    batch_size:         typeSel.value === 'webhook' ? Number.parseInt(batchIn.value, 10) || 1 : 1,
                    filter_profile:     profileSel.value,
                    filter_custom_json: filterCustomJson,
                };
                try {
                    if (isEdit) {
                        await Api.put(`${_api()}/admin/audit/siem/${dest.id}`, payload);
                    } else {
                        await Api.post(`${_api()}/admin/audit/siem`, payload);
                    }
                    close();
                    Utils.showToast(isEdit ? 'Destination updated' : 'Destination added', 'success');
                    const data = await Api.get(`${_api()}/admin/audit/siem`);
                    _renderSiemList(listContainer, data.destinations || [], filterProfiles);
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                    saveBtn.disabled = false;
                }
            },
        });

        body.appendChild(Utils.el('label', { className: 'settings-label', textContent: 'Name' }));
        body.appendChild(nameIn);
        body.appendChild(Utils.el('label', { className: 'settings-label', textContent: 'Type' }));
        body.appendChild(typeSel);
        body.appendChild(activeRow);
        body.appendChild(fieldWrap);
        body.appendChild(filterSection);
        body.appendChild(Utils.el('div', { style: 'margin-top:16px; display:flex; gap:8px' }, [
            saveBtn,
            Utils.el('button', { className: 'btn btn-secondary', textContent: 'Cancel', onClick: close }),
        ]));
    }

    // =========================================================================
    // Storage section
    // =========================================================================

    async function _renderStorageSection(container) {
        container.innerHTML = '<p class="text-muted loading-msg">Loading…</p>';
        try {
            const [volumes, usage, tiers] = await Promise.all([
                Api.get(`${_api()}/admin/storage/volumes`),
                Api.get(`${_api()}/admin/storage/usage`),
                Api.get(`${_api()}/admin/storage/tiers`),
            ]);
            _renderStoragePanel(container, volumes, usage, tiers);
        } catch (err) {
            _showError(container, `Failed to load: ${err.message}`);
        }
    }

    function _renderStoragePanel(container, volumes, usage, tiers) {
        container.innerHTML = '';
        const wrap = Utils.el('div');
        container.appendChild(wrap);

        // Usage summary bar
        const usageSummary = Utils.el('div', { style: 'margin-bottom:24px' });
        const totalUsed = usage.total_used_bytes || 0;
        const totalCap  = usage.total_capacity_bytes;
        usageSummary.appendChild(Utils.el('h4', { textContent: 'Total Storage' }));
        if (totalCap) {
            const pct = Math.min(100, Math.round(totalUsed / totalCap * 100));
            usageSummary.appendChild(Utils.el('div', { className: 'quota-bar-wrap' }, [
                Utils.el('div', { className: 'quota-bar', style: `width:${pct}%` }),
            ]));
            usageSummary.appendChild(Utils.el('p', {
                className: 'text-muted',
                textContent: `${_fmtBytes(totalUsed)} used of ${_fmtBytes(totalCap)} (${pct}%)`,
            }));
        } else {
            usageSummary.appendChild(Utils.el('p', { className: 'text-muted', textContent: `${_fmtBytes(totalUsed)} used (cloud storage — total capacity not reported)` }));
        }
        wrap.appendChild(usageSummary);

        // Volumes table
        wrap.appendChild(Utils.el('h4', { textContent: 'Volumes' }));
        wrap.appendChild(Utils.el('button', {
            className: 'btn btn-primary', style: 'margin-bottom:12px',
            textContent: '+ Add Volume',
            onClick: () => _showStorageVolumeModal(null, container),
        }));

        const volUsageMap = {};
        for (const v of (usage.volumes || [])) volUsageMap[v.id] = v;

        if (volumes.length === 0) {
            wrap.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No volumes configured.' }));
        } else {
            const table = Utils.el('table', { className: 'admin-table' });
            table.appendChild(Utils.el('thead', {}, [
                Utils.el('tr', {}, [
                    Utils.el('th', { textContent: 'Name' }),
                    Utils.el('th', { textContent: 'Provider' }),
                    Utils.el('th', { textContent: 'Tier' }),
                    Utils.el('th', { textContent: 'Usage' }),
                    Utils.el('th', { textContent: 'Default' }),
                    Utils.el('th', { textContent: 'Actions' }),
                ]),
            ]));
            const tbody = Utils.el('tbody');
            for (const vol of volumes) {
                tbody.appendChild(_buildStorageVolumeRow(vol, volUsageMap[vol.id], container));
            }
            table.appendChild(tbody);
            wrap.appendChild(table);
        }

        // Tiering policy
        wrap.appendChild(Utils.el('h4', { style: 'margin-top:32px', textContent: 'Tiering Policy' }));
        const tierWrap = Utils.el('div', { className: 'settings-grid' });
        wrap.appendChild(tierWrap);

        const enabledCb = Utils.el('input', { type: 'checkbox', id: 'tier-enabled' });
        enabledCb.checked = tiers.enabled;
        tierWrap.appendChild(Utils.el('div', { className: 'settings-row' }, [
            Utils.el('label', { htmlFor: 'tier-enabled', className: 'settings-label', textContent: 'Enable tiering' }),
            enabledCb,
        ]));

        const makeInput = (id, label, value, placeholder) => {
            const inp = Utils.el('input', { type: 'text', id, value: value || '', placeholder, className: 'settings-input' });
            tierWrap.appendChild(Utils.el('div', { className: 'settings-row' }, [
                Utils.el('label', { htmlFor: id, className: 'settings-label', textContent: label }),
                inp,
            ]));
            return inp;
        };
        const hotWarmIn  = makeInput('tier-hot-warm',  'Hot → Warm after (days)', tiers.hot_to_warm_days, 'disabled');
        const warmColdIn = makeInput('tier-warm-cold', 'Warm → Cold after (days)', tiers.warm_to_cold_days, 'disabled');
        const warmVolIn  = makeInput('tier-warm-vol',  'Warm volume ID', tiers.warm_volume_id, 'volume UUID');
        const coldVolIn  = makeInput('tier-cold-vol',  'Cold volume ID', tiers.cold_volume_id, 'volume UUID');
        const autoWarmCb = Utils.el('input', { type: 'checkbox', id: 'tier-auto-warm' });
        autoWarmCb.checked = tiers.auto_warm_on_read;
        tierWrap.appendChild(Utils.el('div', { className: 'settings-row' }, [
            Utils.el('label', { htmlFor: 'tier-auto-warm', className: 'settings-label', textContent: 'Auto-warm on read' }),
            autoWarmCb,
        ]));

        // Capacity warning thresholds
        wrap.appendChild(Utils.el('h4', { style: 'margin-top:24px', textContent: 'Capacity Warning Thresholds' }));
        wrap.appendChild(Utils.el('p', { className: 'text-muted', style: 'font-size:0.85em; margin-bottom:8px', textContent: 'Triggers a warning badge on the volume when either threshold is met. Leave blank to disable that check.' }));
        const warnGrid = Utils.el('div', { className: 'settings-grid' });
        wrap.appendChild(warnGrid);
        const warnPctIn = Utils.el('input', { type: 'number', min: '0', max: '100', step: '1', className: 'settings-input', id: 'warn-pct', value: tiers.warn_pct ?? '', placeholder: 'e.g. 90 (%)' });
        warnGrid.appendChild(Utils.el('div', { className: 'settings-row' }, [
            Utils.el('label', { htmlFor: 'warn-pct', className: 'settings-label', textContent: 'Warn at % full (0–100)' }),
            warnPctIn,
        ]));
        const warnBytesIn = Utils.el('input', { type: 'number', min: '0', step: '1', className: 'settings-input', id: 'warn-bytes', value: tiers.warn_bytes_remaining ?? '', placeholder: 'e.g. 1073741824 (bytes)' });
        warnGrid.appendChild(Utils.el('div', { className: 'settings-row' }, [
            Utils.el('label', { htmlFor: 'warn-bytes', className: 'settings-label', textContent: 'Warn when free space below (bytes)' }),
            warnBytesIn,
        ]));

        const tierBtnRow = Utils.el('div', { style: 'display:flex;gap:8px;margin-top:12px;flex-wrap:wrap' });
        const triggerBtn = Utils.el('button', { className: 'btn btn-secondary', textContent: 'Trigger Tiering Now' });
        triggerBtn.addEventListener('click', async () => {
            if (!confirm('Manually trigger a tiering pass now?')) return;
            triggerBtn.disabled = true;
            try {
                const r = await Api.post(`${_api()}/admin/storage/tiering/trigger`, {});
                Utils.showToast(r.message || 'Tiering pass triggered', 'success');
            } catch (err) {
                Utils.showToast('Trigger failed: ' + err.message, 'error');
            } finally {
                triggerBtn.disabled = false;
            }
        });
        tierBtnRow.appendChild(triggerBtn);
        wrap.appendChild(tierBtnRow);

        wrap.appendChild(Utils.el('button', {
            className: 'btn btn-primary', style: 'margin-top:12px',
            textContent: 'Save Tiering Policy',
            onClick: async (ev) => {
                ev.target.disabled = true;
                try {
                    const warnPctVal   = warnPctIn.value.trim()   === '' ? null : Number.parseFloat(warnPctIn.value);
                    const warnBytesVal = warnBytesIn.value.trim() === '' ? null : Number.parseInt(warnBytesIn.value, 10);
                    await Api.put(`${_api()}/admin/storage/tiers`, {
                        enabled: enabledCb.checked,
                        hot_to_warm_days:       Number.parseInt(hotWarmIn.value, 10) || null,
                        warm_to_cold_days:      Number.parseInt(warmColdIn.value, 10) || null,
                        warm_volume_id:         warmVolIn.value.trim() || null,
                        cold_volume_id:         coldVolIn.value.trim() || null,
                        auto_warm_on_read:      autoWarmCb.checked,
                        warn_pct:               warnPctVal,
                        warn_bytes_remaining:   warnBytesVal,
                    });
                    Utils.showToast('Tiering policy saved', 'success');
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                } finally {
                    ev.target.disabled = false;
                }
            },
        }));
    }

    function _buildStorageVolumeRow(vol, volUsage, container) {
        let usageText;
        if (!volUsage) {
            usageText = '—';
        } else if (volUsage.error) {
            usageText = 'Unavailable';
        } else {
            usageText = `${_fmtBytes(volUsage.used_bytes)} / ${volUsage.total_bytes ? _fmtBytes(volUsage.total_bytes) : '∞'}`;
        }
        const usageWarning = volUsage?.warning
            ? Utils.el('span', { className: 'badge badge-team', style: 'margin-left:6px', title: volUsage.warning, textContent: '⚠ ' + volUsage.warning })
            : null;

        const actions = Utils.el('div', { className: 'row-actions' }, [
            Utils.el('button', {
                className: 'btn btn-secondary btn-sm', textContent: 'Edit',
                onClick: () => _showStorageVolumeModal(vol, container),
            }),
            Utils.el('button', {
                className: 'btn btn-secondary btn-sm', textContent: 'Test',
                onClick: async (ev) => {
                    ev.target.disabled = true;
                    ev.target.textContent = 'Testing…';
                    try {
                        const r = await Api.post(`${_api()}/admin/storage/volumes/${vol.id}/test`, {});
                        Utils.showToast(r.ok ? `OK — ${_fmtBytes(r.used_bytes)} used` : `Failed: ${r.error}`, r.ok ? 'success' : 'error');
                    } catch (err) {
                        Utils.showToast('Test failed: ' + err.message, 'error');
                    } finally {
                        ev.target.disabled = false;
                        ev.target.textContent = 'Test';
                    }
                },
            }),
            vol.is_default ? null : Utils.el('button', {
                className: 'btn btn-sm', textContent: 'Set Default',
                onClick: async (ev) => {
                    ev.target.disabled = true;
                    try {
                        await Api.post(`${_api()}/admin/storage/volumes/${vol.id}/default`, {});
                        Utils.showToast('Default volume updated', 'success');
                        await _renderStorageSection(container.closest('.admin-section-body') || container);
                    } catch (err) {
                        Utils.showToast('Failed: ' + err.message, 'error');
                        ev.target.disabled = false;
                    }
                },
            }),
            vol.is_default ? null : Utils.el('button', {
                className: 'btn btn-sm btn-danger', textContent: 'Delete',
                onClick: async (ev) => {
                    if (!confirm(`Delete volume "${vol.name}"? This cannot be undone.`)) return;
                    ev.target.disabled = true;
                    try {
                        await Api.del(`${_api()}/admin/storage/volumes/${vol.id}`);
                        Utils.showToast('Volume deleted', 'success');
                        await _renderStorageSection(container.closest('.admin-section-body') || container);
                    } catch (err) {
                        Utils.showToast('Delete failed: ' + err.message, 'error');
                        ev.target.disabled = false;
                    }
                },
            }),
        ].filter(Boolean));

        return Utils.el('tr', {}, [
            Utils.el('td', { textContent: vol.name }),
            Utils.el('td', { textContent: vol.provider }),
            Utils.el('td', { textContent: vol.tier }),
            Utils.el('td', {}, [
                Utils.el('span', { textContent: usageText }),
                usageWarning,
            ].filter(Boolean)),
            Utils.el('td', {}, [
                vol.is_default ? Utils.el('span', { className: 'badge badge-active', textContent: 'Default' }) : Utils.el('span'),
            ]),
            Utils.el('td', {}, [actions]),
        ]);
    }

    function _buildVolumeConfig(prov, configWrap, isEdit) {
        if (prov === 'local') {
            const cfg = {};
            const fd = configWrap.querySelector('#sv-files-dir')?.value.trim();
            const ud = configWrap.querySelector('#sv-uploads-dir')?.value.trim();
            if (fd) cfg.files_dir = fd;
            if (ud) cfg.uploads_dir = ud;
            return cfg;
        }
        if (prov === 'azure') {
            const connStr = configWrap.querySelector('#sv-azure-conn')?.value || '';
            const cfg = { container_name: configWrap.querySelector('#sv-azure-container')?.value.trim() };
            if (connStr) cfg.connection_string = connStr;
            return cfg;
        }
        if (prov === 'gcs') {
            const saJson = configWrap.querySelector('#sv-gcs-sa-json')?.value.trim();
            const cfg = {
                project_id:  configWrap.querySelector('#sv-gcs-project')?.value.trim(),
                bucket_name: configWrap.querySelector('#sv-gcs-bucket')?.value.trim(),
            };
            if (saJson) cfg.service_account_json = saJson;
            return cfg;
        }
        return {
            endpoint_url:      configWrap.querySelector('#sv-endpoint')?.value.trim() || null,
            bucket:            configWrap.querySelector('#sv-bucket')?.value.trim(),
            region:            configWrap.querySelector('#sv-region')?.value.trim() || 'us-east-1',
            access_key_id:     configWrap.querySelector('#sv-key-id')?.value.trim(),
            secret_access_key: configWrap.querySelector('#sv-secret')?.value || (isEdit ? '••••••••' : ''),
        };
    }

    function _showStorageVolumeModal(vol, container) {
        const isEdit = !!vol;
        const body = Utils.el('div');
        const close = () => Utils.closeModal();

        const nameIn = Utils.el('input', { type: 'text', className: 'settings-input', value: vol?.name || '', placeholder: 'Display name' });
        const provSel = Utils.el('select', { className: 'settings-input' });
        for (const p of ['local', 's3', 'b2', 'azure', 'gcs']) {
            const o = Utils.el('option', { value: p, textContent: p });
            if (vol?.provider === p) o.selected = true;
            provSel.appendChild(o);
        }
        const tierSel = Utils.el('select', { className: 'settings-input' });
        for (const t of ['hot', 'warm', 'cold']) {
            const o = Utils.el('option', { value: t, textContent: t });
            if ((vol?.tier || 'hot') === t) o.selected = true;
            tierSel.appendChild(o);
        }

        // Provider-specific config fields
        const configWrap = Utils.el('div', { style: 'margin-top:12px' });

        const localFields = Utils.el('div', {}, [
            Utils.el('label', { className: 'settings-label', textContent: 'files_dir (optional override)' }),
            Utils.el('input', { type: 'text', className: 'settings-input', id: 'sv-files-dir', value: vol?.config?.files_dir || '', placeholder: '/data/files' }),
            Utils.el('label', { className: 'settings-label', textContent: 'uploads_dir (optional override)' }),
            Utils.el('input', { type: 'text', className: 'settings-input', id: 'sv-uploads-dir', value: vol?.config?.uploads_dir || '', placeholder: '/data/uploads' }),
        ]);

        const _showS3SecurityModal = () => {
            const content = Utils.el('div', { style: 'font-size:0.9em;line-height:1.6;max-width:520px' });
            for (const [heading, text] of [
                ['IAM permissions (minimum required)',
                 'Allow only: s3:GetObject, s3:PutObject, s3:HeadObject, s3:ListBucket. ' +
                 'Explicitly deny s3:DeleteObject and s3:DeleteBucket — this limits the blast radius of compromised credentials: ' +
                 'an attacker can read and write blobs but cannot mass-delete them.'],
                ['Object Lock / Versioning',
                 'Enable S3 Object Lock (Governance mode) or bucket versioning so that even a PUT overwrite ' +
                 'cannot permanently destroy data during the lock period. This protects against ransomware even with valid credentials.'],
                ['Blob garbage collection trade-off',
                 'With s3:DeleteObject denied, the background task that purges blobs for deleted files will fail silently ' +
                 '(errors are caught). A separate privileged cleanup process (e.g. a scheduled Lambda with broader permissions) ' +
                 'is needed to garbage-collect unused blobs.'],
                ['General',
                 'Use a dedicated IAM user scoped to this bucket only. Avoid root or full-access credentials. ' +
                 'Ensure public access is blocked at the provider level.'],
            ]) {
                content.appendChild(Utils.el('p', { style: 'margin:0 0 4px;font-weight:600', textContent: heading }));
                content.appendChild(Utils.el('p', { style: 'margin:0 0 12px;color:var(--color-text-muted)', textContent: text }));
            }
            Utils.showModal('S3 Security Recommendations', content);
        };

        const s3Fields = Utils.el('div', {}, [
            Utils.el('div', {
                style: 'display:flex;align-items:center;gap:8px;font-size:0.85em;padding:6px 0;border-left:3px solid var(--color-warning,#f0ad4e);padding-left:8px;margin-bottom:8px',
            }, [
                Utils.el('span', { className: 'text-muted', textContent: 'Use a dedicated IAM user scoped to this bucket. Avoid root or full-access credentials.' }),
                Utils.el('button', {
                    type: 'button',
                    className: 'btn btn-secondary btn-sm',
                    style: 'padding:1px 8px;font-size:0.8em;flex-shrink:0;white-space:nowrap',
                    textContent: '? Recommendations',
                    onClick: _showS3SecurityModal,
                }),
            ]),
            Utils.el('label', { className: 'settings-label', textContent: 'endpoint_url (blank for AWS S3; must be https)' }),
            Utils.el('input', { type: 'text', className: 'settings-input', id: 'sv-endpoint', value: vol?.config?.endpoint_url || '' }),
            Utils.el('label', { className: 'settings-label', textContent: 'bucket' }),
            Utils.el('input', { type: 'text', className: 'settings-input', id: 'sv-bucket', value: vol?.config?.bucket || '' }),
            Utils.el('label', { className: 'settings-label', textContent: 'region' }),
            Utils.el('input', { type: 'text', className: 'settings-input', id: 'sv-region', value: vol?.config?.region || 'us-east-1' }),
            Utils.el('label', { className: 'settings-label', textContent: 'access_key_id' }),
            Utils.el('input', { type: 'text', className: 'settings-input', id: 'sv-key-id', value: vol?.config?.access_key_id || '', autocomplete: 'off' }),
            Utils.el('label', { className: 'settings-label', textContent: 'secret_access_key' }),
            Utils.el('input', { type: 'password', className: 'settings-input', id: 'sv-secret', value: '', placeholder: isEdit ? '(unchanged)' : '', autocomplete: 'new-password' }),
        ]);

        const azureFields = Utils.el('div', {}, [
            Utils.el('p', {
                className: 'text-muted',
                style: 'font-size:0.85em; padding:6px 0; border-left:3px solid var(--color-warning,#f0ad4e); padding-left:8px; margin-bottom:8px',
                textContent: 'Security: use a Storage Account with public blob access disabled. Prefer a connection string scoped to this container via a Shared Access Signature (SAS) with limited permissions.',
            }),
            Utils.el('label', { className: 'settings-label', textContent: 'connection_string' }),
            Utils.el('input', { type: 'password', className: 'settings-input', id: 'sv-azure-conn', value: '', placeholder: isEdit ? '(unchanged)' : 'DefaultEndpointsProtocol=https;AccountName=...', autocomplete: 'new-password' }),
            Utils.el('label', { className: 'settings-label', textContent: 'container_name' }),
            Utils.el('input', { type: 'text', className: 'settings-input', id: 'sv-azure-container', value: vol?.config?.container_name || '' }),
        ]);

        const gcsFields = Utils.el('div', {}, [
            Utils.el('p', {
                className: 'text-muted',
                style: 'font-size:0.85em; padding:6px 0; border-left:3px solid var(--color-warning,#f0ad4e); padding-left:8px; margin-bottom:8px',
                textContent: 'Security: create a dedicated service account with the Storage Object Admin role scoped to this bucket only. Paste the full JSON key below.',
            }),
            Utils.el('label', { className: 'settings-label', textContent: 'project_id' }),
            Utils.el('input', { type: 'text', className: 'settings-input', id: 'sv-gcs-project', value: vol?.config?.project_id || '' }),
            Utils.el('label', { className: 'settings-label', textContent: 'bucket_name' }),
            Utils.el('input', { type: 'text', className: 'settings-input', id: 'sv-gcs-bucket', value: vol?.config?.bucket_name || '' }),
            Utils.el('label', { className: 'settings-label', textContent: 'service_account_json' }),
            Utils.el('textarea', { className: 'settings-input', id: 'sv-gcs-sa-json', rows: '6', style: 'font-family:monospace; font-size:0.8em', placeholder: isEdit ? '(unchanged — paste new JSON to rotate key)' : '{ "type": "service_account", ... }' }),
        ]);

        const _updateFields = () => {
            configWrap.innerHTML = '';
            const p = provSel.value;
            if (p === 'local') configWrap.appendChild(localFields);
            else if (p === 'azure') configWrap.appendChild(azureFields);
            else if (p === 'gcs') configWrap.appendChild(gcsFields);
            else configWrap.appendChild(s3Fields);
        };
        provSel.onchange = _updateFields;
        _updateFields();

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary', textContent: isEdit ? 'Save' : 'Add',
            onClick: async () => {
                saveBtn.disabled = true;
                const cfg = _buildVolumeConfig(provSel.value, configWrap, isEdit);
                try {
                    const payload = { name: nameIn.value.trim(), provider: provSel.value, tier: tierSel.value, config: cfg };
                    if (isEdit) {
                        await Api.put(`${_api()}/admin/storage/volumes/${vol.id}`, payload);
                    } else {
                        await Api.post(`${_api()}/admin/storage/volumes`, payload);
                    }
                    close();
                    Utils.showToast(isEdit ? 'Volume updated' : 'Volume added', 'success');
                    await _renderStorageSection(container.closest('.admin-section-body') || container);
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                    saveBtn.disabled = false;
                }
            },
        });

        body.appendChild(Utils.el('label', { className: 'settings-label', textContent: 'Name' }));
        body.appendChild(nameIn);
        body.appendChild(Utils.el('label', { className: 'settings-label', textContent: 'Provider' }));
        body.appendChild(provSel);
        body.appendChild(Utils.el('label', { className: 'settings-label', textContent: 'Tier' }));
        body.appendChild(tierSel);
        body.appendChild(configWrap);
        body.appendChild(Utils.el('div', { style: 'margin-top:16px; display:flex; gap:8px' }, [
            saveBtn,
            Utils.el('button', { className: 'btn btn-secondary', textContent: 'Cancel', onClick: close }),
        ]));
        Utils.showModal(isEdit ? 'Edit Storage Volume' : 'Add Storage Volume', body);
    }

    function _fmtBytes(bytes) {
        if (bytes === 0 || bytes == null) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1);
        const val = bytes / Math.pow(1024, i);
        return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`;
    }

    // ------------------------------------------------------------------
    // Section: Notification Channels
    // ------------------------------------------------------------------

    async function _renderNotificationsSection(container) {
        container.innerHTML = '<p class="text-muted loading-msg">Loading…</p>';
        try {
            const [channelsData, settingsData] = await Promise.all([
                Api.get(`${_api()}/admin/notifications/channels`),
                Api.get(`${_api()}/admin/notifications/settings`),
            ]);
            _renderNotificationsPanel(container, channelsData.channels || [], settingsData);
        } catch (err) {
            _showError(container, `Failed to load: ${err.message}`);
        }
    }

    function _buildChannelRow(ch, container) {
        const filters = (() => { try { return JSON.parse(ch.event_filter || '[]'); } catch { return []; } })();
        const secCount = filters.filter(f => f.startsWith('security:')).length;
        const opCount  = filters.filter(f => !f.startsWith('security:')).length;
        let filterStr;
        if (!filters.length) {
            filterStr = 'all op events';
        } else {
            const parts = [];
            if (opCount)  parts.push(`${opCount} op filter${opCount > 1 ? 's' : ''}`);
            if (secCount) parts.push(`${secCount} security filter${secCount > 1 ? 's' : ''}`);
            filterStr = parts.join(', ');
        }
        let batchStr;
        if (ch.batch_size) batchStr = `${ch.batch_size} events`;
        else if (ch.batch_interval_s) batchStr = `${ch.batch_interval_s}s`;
        else batchStr = 'immediate';
        const tr = Utils.el('tr');
        tr.innerHTML = `
          <td>${Utils.escHtml(ch.name)}</td>
          <td class="td-url">${Utils.escHtml(ch.endpoint_url)}</td>
          <td class="text-sm">${Utils.escHtml(filterStr)}</td>
          <td class="text-sm">${Utils.escHtml(String(batchStr))}</td>
          <td><span class="badge ${ch.enabled ? 'badge-active' : 'badge-custom'}">${ch.enabled ? 'enabled' : 'disabled'}</span></td>
          <td></td>
        `;
        const actionsTd = tr.cells[5];
        const editBtn = Utils.el('button', { textContent: 'Edit', className: 'btn btn-secondary btn-sm', style: 'margin-right:4px' });
        editBtn.addEventListener('click', async () => {
            const full = await Api.get(`${_api()}/admin/notifications/channels/${ch.id}`);
            _showChannelModal(full, container);
        });
        const testBtn = Utils.el('button', { textContent: 'Test', className: 'btn btn-secondary btn-sm', style: 'margin-right:4px' });
        testBtn.addEventListener('click', async () => {
            try {
                const res = await Api.post(`${_api()}/admin/notifications/channels/${ch.id}/test`, {});
                Utils.showToast(res.ok ? `Test OK (HTTP 200)` : `Test failed: ${res.error || 'unknown'}`, res.ok ? 'success' : 'error');
            } catch (err) {
                Utils.showToast('Test failed: ' + err.message, 'error');
            }
        });
        const delBtn = Utils.el('button', { textContent: 'Delete', className: 'btn btn-sm btn-danger' });
        delBtn.addEventListener('click', async () => {
            if (!confirm(`Delete channel "${ch.name}"?`)) return;
            try {
                await Api.del(`${_api()}/admin/notifications/channels/${ch.id}`);
                Utils.showToast('Channel deleted.');
                await _renderNotificationsSection(container.closest('.admin-section-body') || container);
            } catch (err) {
                Utils.showToast('Delete failed: ' + err.message, 'error');
            }
        });
        actionsTd.append(editBtn, testBtn, delBtn);
        return tr;
    }

    function _renderNotificationsPanel(container, channels, settings) {
        container.innerHTML = '';
        const wrap = Utils.el('div');

        // --- Settings card ---
        const settingsCard = Utils.el('div', { className: 'policy-subsection' });
        settingsCard.appendChild(Utils.el('h3', { textContent: 'Notification Settings', style: 'margin-top:0' }));

        const fields = [
            { key: 'server_id',               label: 'Server identity tag',                  type: 'text',   placeholder: 'defaults to hostname' },
            { key: 'op_event_retention_days',  label: 'Event log retention (days)',            type: 'number', min: 1, max: 3650 },
            { key: 'api_key_expiry_warn_days', label: 'API key expiry warning (days before)', type: 'number', min: 1, max: 365 },
            { key: 'upload_quota_warn_pct',    label: 'Quota warning threshold (%)',           type: 'number', min: 1, max: 100 },
        ];

        const inputs = {};
        for (const f of fields) {
            const row = Utils.el('div', { style: 'margin-bottom:10px' });
            const lbl = Utils.el('label', { textContent: f.label, style: 'display:block;font-size:var(--font-size-sm);margin-bottom:4px' });
            const inp = Utils.el('input', { type: f.type, value: settings[f.key] ?? '', style: 'width:240px' });
            if (f.placeholder) inp.placeholder = f.placeholder;
            if (f.min != null) inp.min = f.min;
            if (f.max != null) inp.max = f.max;
            inputs[f.key] = inp;
            row.append(lbl, inp);
            settingsCard.appendChild(row);
        }

        const saveSettingsBtn = Utils.el('button', { textContent: 'Save Settings', className: 'btn btn-primary btn-sm' });
        saveSettingsBtn.addEventListener('click', async () => {
            try {
                const body = {
                    server_id:               inputs['server_id'].value.trim(),
                    op_event_retention_days:  Number.parseInt(inputs['op_event_retention_days'].value) || 30,
                    api_key_expiry_warn_days: Number.parseInt(inputs['api_key_expiry_warn_days'].value) || 30,
                    upload_quota_warn_pct:    Number.parseInt(inputs['upload_quota_warn_pct'].value) || 90,
                };
                await Api.put(`${_api()}/admin/notifications/settings`, body);
                Utils.showToast('Settings saved.');
            } catch (err) {
                Utils.showToast('Failed: ' + err.message, 'error');
            }
        });
        settingsCard.appendChild(saveSettingsBtn);
        wrap.appendChild(settingsCard);

        // --- Channels table ---
        const header = Utils.el('div', { style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:8px' });
        header.appendChild(Utils.el('h3', { textContent: 'Channels', style: 'margin:0' }));
        const addBtn = Utils.el('button', { textContent: '+ Add Channel', className: 'btn btn-primary btn-sm' });
        addBtn.addEventListener('click', () => _showChannelModal(null, container));
        header.appendChild(addBtn);
        wrap.appendChild(header);

        if (channels.length === 0) {
            wrap.appendChild(Utils.el('p', { textContent: 'No notification channels configured.', className: 'text-muted' }));
        } else {
            const table = Utils.el('table', { className: 'admin-table', style: 'width:100%' });
            const thead = Utils.el('thead');
            thead.innerHTML = '<tr><th>Name</th><th>Endpoint</th><th>Filter</th><th>Batch</th><th>Status</th><th>Actions</th></tr>';
            table.appendChild(thead);
            const tbody = Utils.el('tbody');
            for (const ch of channels) {
                tbody.appendChild(_buildChannelRow(ch, container));
            }
            table.appendChild(tbody);
            wrap.appendChild(table);
        }

        // --- Recent Events sub-panel ---
        const eventsToggle = Utils.el('details', { style: 'margin-top:20px' });
        eventsToggle.appendChild(Utils.el('summary', { textContent: 'Recent Events', style: 'cursor:pointer;font-weight:600;padding:8px 0' }));
        const eventsBody = Utils.el('div');
        eventsToggle.appendChild(eventsBody);
        eventsToggle.addEventListener('toggle', async () => {
            if (!eventsToggle.open) return;
            await _loadRecentEvents(eventsBody);
        });
        wrap.appendChild(eventsToggle);

        container.appendChild(wrap);
    }

    async function _loadRecentEvents(container) {
        container.innerHTML = '<p class="text-muted">Loading events…</p>';
        try {
            const data = await Api.get(`${_api()}/admin/notifications/events?limit=50`);
            const events = data.events || [];
            if (events.length === 0) {
                container.innerHTML = '<p class="text-muted">No events recorded.</p>';
                return;
            }
            const table = Utils.el('table', { className: 'admin-table', style: 'width:100%;font-size:var(--font-size-sm)' });
            table.innerHTML = '<thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Source</th><th>Data</th></tr></thead>';
            const tbody = Utils.el('tbody');
            for (const ev of events) {
                const tr = Utils.el('tr');
                const dataStr = JSON.stringify(ev.data || {});
                let sevBadge;
                if (ev.severity === 'error') sevBadge = 'danger';
                else if (ev.severity === 'warning') sevBadge = 'warning';
                else sevBadge = 'muted';
                tr.innerHTML = `
                  <td class="text-nowrap">${ev.created_at ? ev.created_at.slice(0, 19).replace('T', ' ') : ''}</td>
                  <td>${Utils.escHtml(ev.event_type)}</td>
                  <td><span class="badge-${sevBadge}">${Utils.escHtml(ev.severity)}</span></td>
                  <td>${Utils.escHtml(ev.source)}</td>
                  <td class="td-trunc">${Utils.escHtml(dataStr.slice(0, 120))}</td>
                `;
                tbody.appendChild(tr);
            }
            table.appendChild(tbody);
            container.innerHTML = '';
            container.appendChild(table);
        } catch (err) {
            _showError(container, `Failed to load: ${err.message}`);
        }
    }

    function _buildEventFilterUI(curFilters) {
        const filterSet = new Set(curFilters);

        function sevClass(sev) {
            if (sev === 'critical' || sev === 'error') return 'badge badge-expired';
            if (sev === 'warning') return 'badge badge-team';
            return 'badge badge-custom';
        }

        function buildGroup(grp) {
            const allActive  = filterSet.has(grp.allEntry);
            const someActive = !allActive && grp.events.some(e => filterSet.has(e.entry));

            const det = document.createElement('details');
            if (allActive || someActive) det.open = true;

            const summ = document.createElement('summary');
            summ.style.cssText = 'padding:5px 8px;cursor:pointer;user-select:none;font-size:var(--font-size-sm);font-weight:600';
            summ.textContent = grp.label;
            det.appendChild(summ);

            const body = Utils.el('div', { style: 'padding:2px 4px 8px 24px;display:flex;flex-direction:column;gap:2px' });

            // "Select All" row — tri-state: unchecked / indeterminate / checked
            const allRow = Utils.el('div', {
                style: 'display:flex;align-items:center;gap:6px;padding:2px 0 4px;border-bottom:1px solid var(--color-border,#e5e7eb);margin-bottom:4px'
            });
            const allChk = Utils.el('input', { type: 'checkbox' });
            allChk.dataset.filter   = grp.allEntry;
            allChk.dataset.groupAll = grp.allEntry;
            if (allActive)       { allChk.checked = true; }
            else if (someActive) { allChk.indeterminate = true; }
            allRow.append(
                allChk,
                Utils.el('span', {
                    textContent: 'All ' + grp.label.toLowerCase(),
                    style: 'font-size:var(--font-size-sm);font-style:italic;color:var(--color-text-muted,#6b7280)'
                })
            );
            body.appendChild(allRow);

            // Sync allChk tri-state when individual items change
            const updateAllChk = () => {
                const subs = [...body.querySelectorAll(`input[data-group="${grp.allEntry}"]`)];
                const n = subs.filter(c => c.checked).length;
                if (n === 0)             { allChk.checked = false; allChk.indeterminate = false; }
                else if (n === subs.length) { allChk.checked = true;  allChk.indeterminate = false; }
                else                     { allChk.checked = false; allChk.indeterminate = true;  }
            };

            // Clicking allChk: checked→uncheck all; unchecked/indeterminate→check all
            allChk.addEventListener('change', () => {
                const target = allChk.checked;
                body.querySelectorAll(`input[data-group="${grp.allEntry}"]`).forEach(c => { c.checked = target; });
                allChk.indeterminate = false;
            });

            for (const ev of grp.events) {
                const chk = Utils.el('input', { type: 'checkbox', checked: allActive || filterSet.has(ev.entry) });
                chk.dataset.filter = ev.entry;
                chk.dataset.group  = grp.allEntry;
                chk.addEventListener('change', updateAllChk);

                const row = Utils.el('div', { style: 'display:flex;align-items:center;gap:8px;padding:1px 0' });
                row.append(
                    chk,
                    Utils.el('span', { textContent: ev.label, style: 'font-size:var(--font-size-sm);flex:1' }),
                    Utils.el('span', { textContent: ev.sev, className: sevClass(ev.sev) })
                );
                body.appendChild(row);
            }

            if (grp.standalones?.length) {
                body.appendChild(Utils.el('div', {
                    style: 'border-top:1px solid var(--color-border,#e5e7eb);margin:4px 0 2px'
                }));
                for (const ev of grp.standalones) {
                    const chk = Utils.el('input', { type: 'checkbox', checked: filterSet.has(ev.entry) });
                    chk.dataset.filter = ev.entry;
                    const row = Utils.el('div', { style: 'display:flex;align-items:center;gap:8px;padding:1px 0' });
                    row.append(
                        chk,
                        Utils.el('span', { textContent: ev.label, style: 'font-size:var(--font-size-sm);flex:1' }),
                        Utils.el('span', { textContent: ev.sev, className: sevClass(ev.sev) })
                    );
                    body.appendChild(row);
                }
            }

            det.appendChild(body);
            return det;
        }

        const SEC_GROUPS = [
            {
                label: 'Auth Events', allEntry: 'security:auth',
                events: [
                    { entry: 'security:auth.login.success',                 label: 'Login success',             sev: 'info' },
                    { entry: 'security:auth.login.failure',                 label: 'Login failure',             sev: 'warning' },
                    { entry: 'security:auth.login.blocked',                 label: 'Login blocked',             sev: 'warning' },
                    { entry: 'security:auth.logout',                        label: 'Logout',                    sev: 'info' },
                    { entry: 'security:auth.stepup.success',                label: 'Step-up success',           sev: 'info' },
                    { entry: 'security:auth.stepup.failure',                label: 'Step-up failure',           sev: 'warning' },
                    { entry: 'security:auth.token.refreshed',               label: 'Token refreshed',           sev: 'info' },
                    { entry: 'security:auth.token.revoked',                 label: 'Token revoked',             sev: 'warning' },
                    { entry: 'security:auth.mfa.enrolled',                  label: 'MFA enrolled',              sev: 'info' },
                    { entry: 'security:auth.mfa.challenged',                label: 'MFA challenged',            sev: 'info' },
                    { entry: 'security:auth.mfa.failed',                    label: 'MFA failed',                sev: 'warning' },
                    { entry: 'security:auth.password.changed',              label: 'Password changed',          sev: 'info' },
                    { entry: 'security:auth.recovery.used',                 label: 'Recovery key used',         sev: 'warning' },
                    { entry: 'security:auth.session.force_terminated',      label: 'Session force-terminated',  sev: 'critical' },
                    { entry: 'security:auth.oidc.login',                    label: 'OIDC login',                sev: 'info' },
                    { entry: 'security:auth.ldap.login',                    label: 'LDAP login',                sev: 'info' },
                    { entry: 'security:auth.service_account.authenticated', label: 'Service account auth',      sev: 'info' },
                    { entry: 'security:auth.service_account.rejected',      label: 'Service account rejected',  sev: 'warning' },
                    { entry: 'security:auth.unauthorized',                  label: '401 Unauthorized',          sev: 'warning' },
                    { entry: 'security:auth.forbidden',                     label: '403 Forbidden',             sev: 'warning' },
                    { entry: 'security:auth.probe_404',                     label: 'Endpoint probe (404)',       sev: 'info' },
                    { entry: 'security:auth.probe_405',                     label: 'Method probe (405)',         sev: 'info' },
                    { entry: 'security:auth.rate_limited',                  label: 'Rate limited (429)',         sev: 'warning' },
                ],
            },
            {
                label: 'File Events', allEntry: 'security:file',
                events: [
                    { entry: 'security:file.upload.started',     label: 'Upload started',     sev: 'info' },
                    { entry: 'security:file.upload.completed',   label: 'Upload completed',   sev: 'info' },
                    { entry: 'security:file.upload.aborted',     label: 'Upload aborted',     sev: 'info' },
                    { entry: 'security:file.download.started',   label: 'Download started',   sev: 'info' },
                    { entry: 'security:file.download.completed', label: 'Download completed', sev: 'info' },
                    { entry: 'security:file.download.aborted',   label: 'Download aborted',   sev: 'info' },
                    { entry: 'security:file.delete',             label: 'File deleted',       sev: 'warning' },
                    { entry: 'security:file.move',               label: 'File moved',         sev: 'info' },
                    { entry: 'security:file.rename',             label: 'File renamed',       sev: 'info' },
                    { entry: 'security:file.share.created',      label: 'Share created',      sev: 'info' },
                    { entry: 'security:file.share.revoked',      label: 'Share revoked',      sev: 'warning' },
                    { entry: 'security:file.share.accessed',     label: 'Share accessed',     sev: 'info' },
                    { entry: 'security:file.lock.applied',       label: 'File lock applied',  sev: 'info' },
                    { entry: 'security:file.lock.cleared',       label: 'File lock cleared',  sev: 'info' },
                ],
            },
            {
                label: 'Admin Events', allEntry: 'security:admin',
                events: [
                    { entry: 'security:admin.user.suspended',              label: 'User suspended',         sev: 'warning' },
                    { entry: 'security:admin.user.activated',              label: 'User activated',         sev: 'info' },
                    { entry: 'security:admin.user.role_changed',           label: 'Role changed',           sev: 'info' },
                    { entry: 'security:admin.emergency_revocation',        label: 'Emergency revocation',   sev: 'critical' },
                    { entry: 'security:admin.policy.changed',              label: 'Policy changed',         sev: 'warning' },
                    { entry: 'security:admin.team.member_added',           label: 'Team member added',      sev: 'info' },
                    { entry: 'security:admin.team.member_removed',         label: 'Team member removed',    sev: 'warning' },
                    { entry: 'security:admin.team_key.rotation_started',   label: 'Key rotation started',   sev: 'info' },
                    { entry: 'security:admin.team_key.rotation_completed', label: 'Key rotation completed', sev: 'info' },
                    { entry: 'security:admin.siem.config_changed',         label: 'SIEM config changed',    sev: 'warning' },
                    { entry: 'security:admin.bootstrap.completed',         label: 'Bootstrap completed',    sev: 'info' },
                ],
                standalones: [
                    { entry: 'security:user.registered', label: 'New user registered', sev: 'info' },
                ],
            },
        ];

        const OP_GROUPS = [
            {
                label: 'System', allEntry: 'system',
                events: [
                    { entry: 'system.startup',               label: 'Server startup',        sev: 'info' },
                    { entry: 'system.api_key.expiring_soon', label: 'API key expiring soon', sev: 'warning' },
                    { entry: 'system.api_key.expired',       label: 'API key expired',       sev: 'warning' },
                ],
            },
            {
                label: 'Storage', allEntry: 'storage',
                events: [
                    { entry: 'storage.volume.capacity_warning', label: 'Volume capacity warning',  sev: 'warning' },
                    { entry: 'storage.volume.capacity_ok',      label: 'Volume capacity OK',       sev: 'info' },
                    { entry: 'storage.migration.failed',        label: 'Storage migration failed', sev: 'error' },
                ],
            },
            {
                label: 'Upload / Quota', allEntry: 'upload',
                events: [
                    { entry: 'upload.quota.warning', label: 'Quota warning', sev: 'warning' },
                    { entry: 'upload.quota.ok',      label: 'Quota OK',      sev: 'info' },
                ],
            },
            {
                label: 'AV Scanning', allEntry: 'file',
                events: [
                    { entry: 'file.av.infected', label: 'Infected file detected', sev: 'critical' },
                ],
            },
        ];

        const wrap = Utils.el('div', {
            style: 'border:1px solid var(--color-border,#e5e7eb);border-radius:6px;max-height:360px;overflow-y:auto;overflow-x:hidden'
        });

        const secHdr = Utils.el('div', {
            style: 'padding:5px 8px;font-size:var(--font-size-sm);font-weight:700;background:var(--color-surface-active,#f3f4f6);border-bottom:1px solid var(--color-border,#e5e7eb);position:sticky;top:0;z-index:1'
        });
        secHdr.textContent = 'Security Events';
        wrap.appendChild(secHdr);

        const secDiv = Utils.el('div', { style: 'border-bottom:2px solid var(--color-border,#e5e7eb)' });
        for (const grp of SEC_GROUPS) secDiv.appendChild(buildGroup(grp));
        wrap.appendChild(secDiv);

        const opHdr = Utils.el('div', {
            style: 'padding:5px 8px;font-size:var(--font-size-sm);font-weight:700;background:var(--color-surface-active,#f3f4f6);border-bottom:1px solid var(--color-border,#e5e7eb);position:sticky;top:0;z-index:1'
        });
        opHdr.textContent = 'Operational Events';
        wrap.appendChild(opHdr);

        const opDiv = Utils.el('div');
        for (const grp of OP_GROUPS) opDiv.appendChild(buildGroup(grp));
        wrap.appendChild(opDiv);

        return wrap;
    }

    function _readEventFilterUI(filterGrid) {
        const result = [];
        filterGrid.querySelectorAll('input[data-filter]').forEach(inp => {
            if (inp.dataset.groupAll) {
                // Group "Select All" — include prefix only if checked
                if (inp.checked) result.push(inp.dataset.filter);
            } else if (inp.dataset.group) {
                // Individual event — skip if its group-all is checked (prefix already covers it)
                const allChk = filterGrid.querySelector(`input[data-group-all="${inp.dataset.group}"]`);
                if (!allChk?.checked && inp.checked) result.push(inp.dataset.filter);
            } else {
                // Standalone (no group)
                if (inp.checked) result.push(inp.dataset.filter);
            }
        });
        return result;
    }

    function _showChannelModal(channel, refreshContainer) {
        const isEdit = !!channel;
        const modal = Utils.el('div', { className: 'modal-overlay' });
        const box   = Utils.el('div', { className: 'modal', style: 'max-width:680px;width:calc(100% - 32px)' });
        box.appendChild(Utils.el('h3', { textContent: isEdit ? 'Edit Channel' : 'Add Channel', style: 'margin-top:0' }));

        const mkField = (label, inp) => {
            const row = Utils.el('div', { style: 'margin-bottom:10px' });
            row.appendChild(Utils.el('label', { textContent: label, style: 'display:block;font-size:var(--font-size-sm);margin-bottom:4px' }));
            row.appendChild(inp);
            return row;
        };

        const nameInp   = Utils.el('input', { type: 'text', value: channel?.name || '', style: 'width:100%', placeholder: 'e.g. Slack alerts' });
        const urlInp    = Utils.el('input', { type: 'text', value: channel?.endpoint_url || '', style: 'width:100%', placeholder: 'https://...' });
        const secretInp = Utils.el('input', { type: 'password', style: 'width:100%', placeholder: isEdit ? '(unchanged)' : '(leave blank for unsigned)' });
        const secretWarn = Utils.el('p', { style: 'font-size:var(--font-size-sm);color:var(--color-warning,#d97706);margin:4px 0 0;display:none' });
        if (!isEdit) {
            secretWarn.textContent = 'No signing secret — deliveries will be unsigned JSON. Recommended: set a secret.';
            secretWarn.style.display = '';
            secretInp.addEventListener('input', () => { secretWarn.style.display = secretInp.value ? 'none' : ''; });
        }
        const secretField = mkField('Signing secret', secretInp);
        secretField.appendChild(secretWarn);

        box.append(mkField('Name', nameInp), mkField('Endpoint URL (must be https://)', urlInp), secretField);

        const curFilters = (() => {
            try { return JSON.parse(channel?.event_filter || '[]'); } catch { return []; }
        })();
        const filterWrap = Utils.el('div', { style: 'margin-bottom:10px' });
        filterWrap.appendChild(Utils.el('label', {
            textContent: 'Event filters',
            style: 'display:block;font-size:var(--font-size-sm);margin-bottom:4px;font-weight:600'
        }));
        const filterGrid = _buildEventFilterUI(curFilters);
        filterWrap.appendChild(filterGrid);
        box.appendChild(filterWrap);

        const batchSizeInp = Utils.el('input', { type: 'number', value: channel?.batch_size ?? '', style: 'width:120px', placeholder: 'e.g. 20' });
        const intervalInp  = Utils.el('input', { type: 'number', value: channel?.batch_interval_s ?? '', style: 'width:120px', placeholder: 'e.g. 86400' });
        const enabledChk   = Utils.el('input', { type: 'checkbox', checked: channel ? !!channel.enabled : true });

        box.append(
            mkField('Batch size (blank = immediate)', batchSizeInp),
            mkField('Flush interval (seconds, blank = disabled)', intervalInp),
        );
        const enabledRow = Utils.el('div', { style: 'margin-bottom:16px;display:flex;align-items:center;gap:8px' });
        enabledRow.append(enabledChk, Utils.el('label', { textContent: 'Enabled' }));
        box.appendChild(enabledRow);

        const errEl = Utils.el('p', { className: 'error-text', style: 'display:none;margin-bottom:8px' });
        box.appendChild(errEl);

        const btns = Utils.el('div', { style: 'display:flex;gap:8px;justify-content:flex-end' });
        const cancelBtn = Utils.el('button', { textContent: 'Cancel', className: 'btn btn-secondary btn-sm' });
        cancelBtn.addEventListener('click', () => modal.remove());
        const saveBtn = Utils.el('button', { textContent: isEdit ? 'Save Changes' : 'Add Channel', className: 'btn btn-primary btn-sm' });
        saveBtn.addEventListener('click', async () => {
            const body = {
                name:                nameInp.value.trim(),
                endpoint_url:        urlInp.value.trim(),
                secret:              secretInp.value || null,
                event_filter:        _readEventFilterUI(filterGrid),
                batch_size:          batchSizeInp.value ? Number.parseInt(batchSizeInp.value) : null,
                batch_interval_s:    intervalInp.value ? Number.parseInt(intervalInp.value) : null,
                enabled:             enabledChk.checked,
            };
            try {
                if (isEdit) {
                    await Api.put(`${_api()}/admin/notifications/channels/${channel.id}`, body);
                } else {
                    await Api.post(`${_api()}/admin/notifications/channels`, body);
                }
                modal.remove();
                await _renderNotificationsSection(refreshContainer.closest('.admin-section-body') || refreshContainer);
            } catch (err) {
                errEl.textContent = err.message;
                errEl.style.display = '';
            }
        });
        btns.append(cancelBtn, saveBtn);
        box.appendChild(btns);
        modal.appendChild(box);
        document.body.appendChild(modal);
    }

    // ------------------------------------------------------------------
    // Section: API Keys
    // ------------------------------------------------------------------

    async function _renderApiKeysSection(container) {
        container.innerHTML = '<p class="text-muted loading-msg">Loading…</p>';
        try {
            const data = await Api.get(`${_api()}/admin/api-keys`);
            _renderApiKeysPanel(container, data.keys || []);
        } catch (err) {
            _showError(container, `Failed to load: ${err.message}`);
        }
    }

    const _KEY_SCOPES = [
        { value: 'audit_read', label: 'Security Audit Log', desc: 'Read-only access to the security event log. Suits SIEM integrations, compliance exports, and log analysis tools.' },
        { value: 'ops_read',   label: 'Operational Events', desc: 'Read live operational events (storage warnings, quota alerts, system events). Suits monitoring dashboards and alerting scripts.' },
    ];

    function _buildApiKeyRow(k, container) {
        const scopes = (() => { try { return JSON.parse(k.scopes || '[]'); } catch { return []; } })();
        const filterParts = [];
        if (k.filter_event_types)  filterParts.push(`types: ${k.filter_event_types}`);
        if (k.filter_min_severity) filterParts.push(`sev≥${k.filter_min_severity}`);
        const tr = Utils.el('tr');
        tr.innerHTML = `
          <td>${Utils.escHtml(k.name)}</td>
          <td class="text-sm">${Utils.escHtml(scopes.join(', '))}</td>
          <td class="text-muted-xs">${Utils.escHtml(filterParts.join(' · ') || '—')}</td>
          <td class="text-sm">${k.created_at ? k.created_at.slice(0, 10) : ''}</td>
          <td class="text-sm">${k.last_used_at ? k.last_used_at.slice(0, 10) : 'never'}</td>
          <td class="text-sm">${k.expires_at ? k.expires_at.slice(0, 10) : 'never'}</td>
          <td class="text-nowrap"></td>
        `;
        const actionsCell = tr.cells[6];
        const rotateBtn = Utils.el('button', { textContent: 'Rotate', className: 'btn btn-sm', style: 'margin-right:4px' });
        rotateBtn.addEventListener('click', async () => {
            if (!confirm(`Rotate key "${k.name}"? The current key will stop working immediately.`)) return;
            try {
                const result = await Api.post(`${_api()}/admin/api-keys/${k.id}/rotate`, {});
                _showApiKeyReveal(result.key, result.name, container);
            } catch (err) {
                Utils.showToast('Rotate failed: ' + err.message, 'error');
            }
        });
        const revokeBtn = Utils.el('button', { textContent: 'Revoke', className: 'btn btn-sm btn-danger' });
        revokeBtn.addEventListener('click', async () => {
            if (!confirm(`Revoke API key "${k.name}"? This cannot be undone.`)) return;
            try {
                await Api.del(`${_api()}/admin/api-keys/${k.id}`);
                Utils.showToast('API key revoked.');
                await _renderApiKeysSection(container.closest('.admin-section-body') || container);
            } catch (err) {
                Utils.showToast('Revoke failed: ' + err.message, 'error');
            }
        });
        actionsCell.append(rotateBtn, revokeBtn);
        return tr;
    }

    function _renderApiKeysPanel(container, keys) {
        container.innerHTML = '';
        const wrap = Utils.el('div');

        const header = Utils.el('div', { style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:8px' });
        header.appendChild(Utils.el('h3', { textContent: 'API Keys', style: 'margin:0' }));
        const createBtn = Utils.el('button', { textContent: '+ Create API Key', className: 'btn btn-primary btn-sm' });
        createBtn.addEventListener('click', () => _showApiKeyModal(container));
        header.appendChild(createBtn);
        wrap.appendChild(header);
        wrap.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'font-size:var(--font-size-sm);margin-bottom:16px',
            textContent: 'API keys authenticate machine-to-machine access — for example, SIEM log ingestion or custom monitoring integrations. '
                + 'Browser sessions use JWT cookies and do not need API keys. '
                + 'Scope each key to the minimum required access.',
        }));

        if (keys.length === 0) {
            wrap.appendChild(Utils.el('p', { textContent: 'No API keys.', className: 'text-muted' }));
        } else {
            const table = Utils.el('table', { className: 'admin-table', style: 'width:100%' });
            table.innerHTML = '<thead><tr><th>Name</th><th>Scopes</th><th>Filters</th><th>Created</th><th>Last used</th><th>Expires</th><th>Actions</th></tr></thead>';
            const tbody = Utils.el('tbody');
            for (const k of keys) {
                tbody.appendChild(_buildApiKeyRow(k, container));
            }
            table.appendChild(tbody);
            wrap.appendChild(table);
        }

        container.appendChild(wrap);
    }

    function _showApiKeyModal(refreshContainer) {
        const modal = Utils.el('div', { className: 'modal-overlay' });
        const box   = Utils.el('div', { className: 'modal', style: 'max-width:480px;width:calc(100% - 32px)' });
        box.appendChild(Utils.el('h3', { textContent: 'Create API Key', style: 'margin-top:0' }));
        box.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'font-size:var(--font-size-sm);margin-bottom:14px',
            textContent: 'API keys authenticate programmatic read access to logs and event streams — for SIEM integrations, monitoring scripts, or compliance tools. Browser sessions use JWT cookies and do not need API keys.',
        }));

        const mkField = (label, inp, hint) => {
            const row = Utils.el('div', { style: 'margin-bottom:10px' });
            row.appendChild(Utils.el('label', { textContent: label, style: 'display:block;font-size:var(--font-size-sm);margin-bottom:4px' }));
            row.appendChild(inp);
            if (hint) row.appendChild(Utils.el('p', { textContent: hint, style: 'font-size:var(--font-size-sm);color:var(--color-muted,#888);margin:2px 0 0' }));
            return row;
        };

        const nameInp        = Utils.el('input', { type: 'text',  style: 'width:100%',  placeholder: 'e.g. Grafana SIEM' });
        const expiryInp      = Utils.el('input', { type: 'date',  style: 'width:200px' });
        const filterTypesInp = Utils.el('input', { type: 'text',  style: 'width:100%',  placeholder: 'e.g. auth.*,admin.* (blank = all events)' });

        box.appendChild(mkField('Name', nameInp));

        // Scope checkboxes
        const scopeWrap = Utils.el('div', { style: 'margin-bottom:10px' });
        scopeWrap.appendChild(Utils.el('label', { textContent: 'Access scope', style: 'display:block;font-size:var(--font-size-sm);margin-bottom:6px' }));
        const scopeChecks = {};
        for (const s of _KEY_SCOPES) {
            const row = Utils.el('div', {
                style: 'display:flex;align-items:flex-start;gap:8px;margin-bottom:6px;padding:8px;border:1px solid var(--color-border,#e5e7eb);border-radius:4px'
            });
            const chk = Utils.el('input', { type: 'checkbox', style: 'margin-top:2px;flex-shrink:0' });
            scopeChecks[s.value] = chk;
            const labelWrap = Utils.el('div');
            labelWrap.appendChild(Utils.el('span', { textContent: s.label, style: 'font-size:var(--font-size-sm);font-weight:600;display:block' }));
            labelWrap.appendChild(Utils.el('span', { textContent: s.desc,  style: 'font-size:var(--font-size-sm);color:var(--color-text-muted,#6b7280)' }));
            row.append(chk, labelWrap);
            scopeWrap.appendChild(row);
        }
        box.appendChild(scopeWrap);

        box.append(
            mkField('Expiry date (optional)', expiryInp),
            mkField('Filter event types (optional)', filterTypesInp, 'Comma-separated glob patterns. Limits which events are visible through this key. Leave blank to allow all.'),
        );

        const errEl = Utils.el('p', { className: 'error-text', style: 'display:none;margin-bottom:8px' });
        box.appendChild(errEl);

        const btns = Utils.el('div', { style: 'display:flex;gap:8px;justify-content:flex-end' });
        const cancelBtn = Utils.el('button', { textContent: 'Cancel', className: 'btn btn-secondary btn-sm' });
        cancelBtn.addEventListener('click', () => modal.remove());
        const createBtn = Utils.el('button', { textContent: 'Create Key', className: 'btn btn-primary btn-sm' });
        createBtn.addEventListener('click', async () => {
            const scopes = _KEY_SCOPES.map(s => s.value).filter(v => scopeChecks[v].checked);
            if (!nameInp.value.trim()) {
                errEl.textContent = 'Name is required.';
                errEl.style.display = '';
                return;
            }
            if (!scopes.length) {
                errEl.textContent = 'Select at least one access scope.';
                errEl.style.display = '';
                return;
            }
            const body = {
                name:               nameInp.value.trim(),
                scopes,
                expires_at:         expiryInp.value ? expiryInp.value + 'T00:00:00Z' : null,
                filter_event_types: filterTypesInp.value.trim() || null,
            };
            try {
                const result = await Api.post(`${_api()}/admin/api-keys`, body);
                modal.remove();
                _showApiKeyReveal(result.key, result.name, refreshContainer);
            } catch (err) {
                errEl.textContent = err.message;
                errEl.style.display = '';
            }
        });
        btns.append(cancelBtn, createBtn);
        box.appendChild(btns);
        modal.appendChild(box);
        document.body.appendChild(modal);
    }

    function _showApiKeyReveal(rawKey, keyName, refreshContainer) {
        const modal = Utils.el('div', { className: 'modal-overlay' });
        const box   = Utils.el('div', { className: 'modal', style: 'max-width:500px' });
        box.appendChild(Utils.el('h3', { textContent: 'API Key Created', style: 'margin-top:0' }));
        box.appendChild(Utils.el('p', { textContent: `Copy this key now — it will not be shown again.`, style: 'color:var(--color-warning,#d97706)' }));
        box.appendChild(Utils.el('p', { textContent: keyName, style: 'font-weight:600;margin-bottom:6px' }));

        const codeWrap = Utils.el('div', { style: 'display:flex;gap:8px;align-items:center;margin-bottom:16px' });
        const code = Utils.el('code', { textContent: rawKey, style: 'word-break:break-all;background:var(--color-surface,#f5f5f5);padding:8px;border-radius:4px;flex:1;font-size:var(--font-size-sm)' });
        const copyBtn = Utils.el('button', { textContent: 'Copy', className: 'btn btn-sm' });
        copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(rawKey).then(() => { copyBtn.textContent = 'Copied!'; });
        });
        codeWrap.append(code, copyBtn);
        box.appendChild(codeWrap);

        const doneBtn = Utils.el('button', { textContent: 'Done', className: 'btn btn-primary btn-sm' });
        doneBtn.addEventListener('click', async () => {
            modal.remove();
            await _renderApiKeysSection(refreshContainer.closest('.admin-section-body') || refreshContainer);
        });
        box.appendChild(doneBtn);
        modal.appendChild(box);
        document.body.appendChild(modal);
    }

    // ------------------------------------------------------------------
    // Antivirus section
    // ------------------------------------------------------------------

    async function _renderAntivirusSection(container) {
        container.innerHTML = '';

        // --- Always-visible OS AV documentation ---
        const infoCard = Utils.el('div', { className: 'policy-subsection' });
        infoCard.appendChild(Utils.el('h4', { textContent: 'How antivirus scanning works', style: 'margin-top:0' }));
        const _avP1 = Utils.el('p');
        _avP1.innerHTML = '<strong>Client-side (always active):</strong> All files are decrypted by the client\'s browser at download time. The decrypted file is saved to the browser\'s download folder via the standard browser download mechanism, where OS real-time AV will scan it automatically. No additional configuration needed.';
        const _avP2 = Utils.el('p');
        _avP2.innerHTML = '<strong>OPFS partial-download window:</strong> During an interrupted or in-progress download, incomplete encrypted chunks exist in OPFS (origin-private storage, sandboxed, invisible to OS AV). These chunks are partial and not independently usable as malware. OS AV fires on the final write when the download completes or resumes. Recommend real-time AV with filesystem monitoring on endpoints.';
        const _avP3 = Utils.el('p');
        _avP3.innerHTML = '<strong>Server-side scanning (optional):</strong> When <code>TUSSHARE_ESCROW_PRIVATE_KEY</code> is configured, files uploaded after that point can be decrypted and scanned server-side via a configurable AV webhook. The server sends plaintext to your AV endpoint; the webhook returns a verdict.';
        infoCard.append(_avP1, _avP2, _avP3);
        container.appendChild(infoCard);

        // Check if escrow is configured (server exposes escrow public key endpoint)
        let escrowConfigured = false;
        try {
            await Api.get(`${Config.app.apiPrefix}/uploads/escrow-key`);
            escrowConfigured = true;
        } catch { /* 404 = not configured */ }

        // --- Server-side webhook configuration (only shown when escrow key is present) ---
        if (!escrowConfigured) {
            container.appendChild(Utils.el('p', {
                className: 'text-muted',
                textContent: 'Server-side AV webhook is not available: TUSSHARE_ESCROW_PRIVATE_KEY is not configured.',
            }));
            return;
        }

        // Load current settings
        const settingsData = await Api.get(`${Config.app.apiPrefix}/admin/settings`);
        const s = settingsData.settings || {};

        const _mkAvLabel = (text) => Utils.el('label', {
            textContent: text,
            style: 'display:block;font-size:var(--font-size-sm);font-weight:600;margin-bottom:var(--space-1)',
        });

        const form = Utils.el('div', { className: 'policy-subsection' });
        form.appendChild(Utils.el('h4', { textContent: 'Server-side AV webhook', style: 'margin-top:0' }));

        // Endpoint
        form.appendChild(_mkAvLabel('Webhook endpoint URL'));
        const endpointInput = Utils.el('input', {
            type: 'text',
            placeholder: 'https://av.example.com/scan',
            value: s.av_scan_endpoint || '',
            style: 'width:100%;max-width:420px;margin-bottom:var(--space-3)',
        });
        form.appendChild(endpointInput);

        // Secret
        form.appendChild(_mkAvLabel('Webhook secret (HMAC-SHA256)'));
        const secretInput = Utils.el('input', {
            type: 'password',
            placeholder: 'Signing secret (leave blank to keep current)',
            value: '',
            style: 'width:100%;max-width:420px;margin-bottom:var(--space-3)',
        });
        form.appendChild(secretInput);

        // require_clean toggle
        const requireCheck = Utils.el('input', { type: 'checkbox', id: 'av-require-clean' });
        requireCheck.checked = s.av_require_clean === 'true';
        form.appendChild(Utils.el('div', { className: 'policy-strict-row', style: 'margin-bottom:var(--space-3)' }, [
            requireCheck,
            Utils.el('label', {
                htmlFor: 'av-require-clean',
                textContent: 'Block download and batch-move for files not yet confirmed clean (av_require_clean)',
            }),
        ]));

        // Retry attempts
        form.appendChild(_mkAvLabel('Retry attempts on webhook failure'));
        const retryInput = Utils.el('input', {
            type: 'number',
            min: '1', max: '10',
            value: s.av_scan_retry_attempts || '3',
            style: 'width:80px;margin-bottom:var(--space-3)',
        });
        form.appendChild(retryInput);

        // Save button
        const saveBtn = Utils.el('button', { textContent: 'Save AV Settings', className: 'btn btn-primary btn-sm' });
        saveBtn.addEventListener('click', async () => {
            const update = {
                av_scan_endpoint:       endpointInput.value.trim(),
                av_require_clean:       requireCheck.checked ? 'true' : 'false',
                av_scan_retry_attempts: retryInput.value || '3',
            };
            if (secretInput.value.trim()) {
                update.av_scan_secret = secretInput.value.trim();
            }
            saveBtn.disabled = true;
            try {
                await Api.put(`${Config.app.apiPrefix}/admin/settings`, { settings: update });
                Utils.showToast('AV settings saved', 'success');
                secretInput.value = '';
            } catch (err) {
                Utils.showToast('Save failed: ' + err.message, 'error');
            } finally {
                saveBtn.disabled = false;
            }
        });
        form.appendChild(saveBtn);
        container.appendChild(form);

        // --- File status summary ---
        const statusCard = Utils.el('div', { className: 'policy-subsection' });

        async function _refreshStatus() {
            statusCard.innerHTML = '<h4 style="margin-top:0">File AV status</h4><p class="text-muted">Loading…</p>';
            try {
                const counts = await Api.get(`${Config.app.apiPrefix}/admin/files/av-status`);
                statusCard.innerHTML = '<h4 style="margin-top:0">File AV status</h4>';
                const table = Utils.el('table', { className: 'admin-table', style: 'width:100%;margin-bottom:var(--space-3)' });
                const thead = Utils.el('thead');
                thead.innerHTML = '<tr><th>Status</th><th>Count</th></tr>';
                const tbody = Utils.el('tbody');
                for (const [k, v] of Object.entries(counts)) {
                    const tr = Utils.el('tr');
                    tr.append(Utils.el('td', { textContent: k }), Utils.el('td', { textContent: String(v) }));
                    tbody.appendChild(tr);
                }
                table.appendChild(thead);
                table.appendChild(tbody);
                statusCard.appendChild(table);

                const rescanBtn = Utils.el('button', {
                    textContent: 'Bulk rescan (null + error files)',
                    className: 'btn btn-secondary btn-sm',
                });
                rescanBtn.addEventListener('click', async () => {
                    rescanBtn.disabled = true;
                    try {
                        const r = await Api.post(`${Config.app.apiPrefix}/admin/files/av-rescan`, {});
                        Utils.showToast(`Queued ${r.queued} file(s) for rescan`, 'success');
                        setTimeout(_refreshStatus, 2000);
                    } catch (err) {
                        Utils.showToast('Rescan failed: ' + err.message, 'error');
                    } finally {
                        rescanBtn.disabled = false;
                    }
                });
                statusCard.appendChild(rescanBtn);
            } catch (err) {
                statusCard.innerHTML = '<h4 style="margin-top:0">File AV status</h4>';
                statusCard.appendChild(Utils.el('p', { className: 'text-error', textContent: err.message }));
            }
        }

        await _refreshStatus();
        container.appendChild(statusCard);
    }

    // -----------------------------------------------------------------------
    // Escrow by Default
    // -----------------------------------------------------------------------

    function _buildEscrowPickerTable(items, onRemove) {
        if (!items.length) {
            return Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-xs);margin:var(--space-2) 0 0', textContent: 'None configured.' });
        }
        const table = Utils.el('table', { className: 'admin-table admin-table-sm', style: 'margin-top:var(--space-2)' });
        const tbody = Utils.el('tbody');
        for (const item of items) {
            const tr = Utils.el('tr');
            tr.appendChild(Utils.el('td', { textContent: item.label }));
            tr.appendChild(Utils.el('td', { style: 'width:1px;white-space:nowrap' }, [
                Utils.el('button', {
                    className: 'btn btn-xs btn-danger',
                    textContent: 'Remove',
                    onClick: () => { onRemove(item.id); tr.remove(); },
                }),
            ]));
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        return table;
    }

    async function _renderEscrowSection(container) {
        container.innerHTML = '';

        let esData;
        try {
            esData = await Api.get(`${Config.app.apiPrefix}/admin/escrow/settings`);
        } catch (err) {
            container.appendChild(Utils.el('p', { className: 'text-error', textContent: 'Failed to load escrow settings: ' + err.message }));
            await _renderEscrowFolderPolicies(container);
            await _renderEscrowCoverageReport(container);
            return;
        }

        // --- Org-Level Escrow Defaults ---
        const settingsSec = Utils.el('div', { className: 'policy-subsection' });
        settingsSec.appendChild(Utils.el('div', { className: 'policy-sub-header' }, [
            Utils.el('h4', { textContent: 'Org-Level Escrow Defaults' }),
        ]));

        // Require coverage toggle
        const reqCheck = Utils.el('input', { type: 'checkbox', id: 'escrow-require-coverage' });
        reqCheck.checked = !!esData.escrow_require_coverage;
        settingsSec.appendChild(Utils.el('div', { className: 'policy-strict-row', style: 'margin-bottom:var(--space-4)' }, [
            reqCheck,
            Utils.el('label', { htmlFor: 'escrow-require-coverage', textContent: 'Require escrow coverage — block team creation when no escrow agents are resolved' }),
        ]));

        if (esData.is_locked) {
            settingsSec.appendChild(Utils.el('p', {
                className: 'text-muted',
                style: 'font-size:var(--font-size-xs);margin-bottom:var(--space-3)',
                textContent: `Settings locked (requires tier ${esData.locked_min_tier} or higher to change).`,
            }));
        }

        // --- Default Escrow Roles ---
        const roleItems = (esData.escrow_default_role_ids || []).map(id => ({ id, label: id }));
        const rolesSec = Utils.el('div', { style: 'margin-bottom:var(--space-5)' });
        rolesSec.appendChild(Utils.el('p', { style: 'font-weight:600;font-size:var(--font-size-sm);margin-bottom:var(--space-2)', textContent: 'Default Escrow Roles' }));
        rolesSec.appendChild(Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-xs);margin-bottom:var(--space-2)', textContent: 'Roles whose members automatically act as escrow agents for all teams.' }));
        const rolesTableWrap = Utils.el('div');
        rolesTableWrap.appendChild(_buildEscrowPickerTable(roleItems, id => {
            const i = roleItems.findIndex(r => r.id === id);
            if (i !== -1) roleItems.splice(i, 1);
        }));
        const addRoleBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: '+ Add Role',
            style: 'margin-top:var(--space-2)',
            onClick: async () => {
                let roles;
                try {
                    const rd = await Api.get(`${_api()}/admin/roles`);
                    roles = rd.roles || [];
                } catch (err) {
                    Utils.showToast('Failed to load roles: ' + err.message, 'error'); return;
                }
                const available = roles.filter(r => !roleItems.find(ri => ri.id === r.id));
                if (!available.length) { Utils.showToast('All roles are already added.', 'info'); return; }
                const modalBody = Utils.el('div', { style: 'min-width:320px' });
                const tbl = Utils.el('table', { className: 'admin-table' });
                const tbody = Utils.el('tbody');
                for (const r of available) {
                    const tr = Utils.el('tr', { style: 'cursor:pointer' });
                    tr.appendChild(Utils.el('td', { textContent: r.name || r.id }));
                    tr.appendChild(Utils.el('td', { className: 'text-muted', style: 'font-size:var(--font-size-xs)', textContent: r.description || '' }));
                    tr.addEventListener('click', () => {
                        roleItems.push({ id: r.id, label: r.name || r.id });
                        rolesTableWrap.innerHTML = '';
                        rolesTableWrap.appendChild(_buildEscrowPickerTable(roleItems, id => {
                            const i = roleItems.findIndex(ri => ri.id === id);
                            if (i !== -1) roleItems.splice(i, 1);
                        }));
                        Utils.closeModal();
                    });
                    tbody.appendChild(tr);
                }
                tbl.appendChild(tbody);
                modalBody.appendChild(tbl);
                Utils.showModal('Select Role', modalBody);
            },
        });
        rolesSec.appendChild(rolesTableWrap);
        rolesSec.appendChild(addRoleBtn);
        settingsSec.appendChild(rolesSec);

        // --- Default Escrow Users ---
        const userItems = (esData.escrow_default_user_ids || []).map(id => ({ id, label: id }));
        const usersSec = Utils.el('div', { style: 'margin-bottom:var(--space-5)' });
        usersSec.appendChild(Utils.el('p', { style: 'font-weight:600;font-size:var(--font-size-sm);margin-bottom:var(--space-2)', textContent: 'Default Escrow Users' }));
        usersSec.appendChild(Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-xs);margin-bottom:var(--space-2)', textContent: 'Specific users who automatically act as escrow agents for all teams.' }));
        const usersTableWrap = Utils.el('div');
        usersTableWrap.appendChild(_buildEscrowPickerTable(userItems, id => {
            const i = userItems.findIndex(u => u.id === id);
            if (i !== -1) userItems.splice(i, 1);
        }));
        const addUserBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: '+ Add User',
            style: 'margin-top:var(--space-2)',
            onClick: async () => {
                let users;
                try {
                    const ud = await Api.get(`${_api()}/admin/users?limit=200`);
                    users = ud.users || [];
                } catch (err) {
                    Utils.showToast('Failed to load users: ' + err.message, 'error'); return;
                }
                const available = users.filter(u => !userItems.find(ui => ui.id === u.id));
                const modalBody = Utils.el('div', { style: 'min-width:320px' });
                const searchIn = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'Search users…', style: 'width:100%;margin-bottom:var(--space-3)' });
                const tbl = Utils.el('table', { className: 'admin-table' });
                const tbody = Utils.el('tbody');
                function _populateUserRows(filter) {
                    tbody.innerHTML = '';
                    const filtered = filter ? available.filter(u => u.username.toLowerCase().includes(filter)) : available;
                    for (const u of filtered) {
                        const tr = Utils.el('tr', { style: 'cursor:pointer' });
                        tr.appendChild(Utils.el('td', { textContent: u.username }));
                        tr.addEventListener('click', () => {
                            userItems.push({ id: u.id, label: u.username });
                            usersTableWrap.innerHTML = '';
                            usersTableWrap.appendChild(_buildEscrowPickerTable(userItems, id => {
                                const i = userItems.findIndex(ui => ui.id === id);
                                if (i !== -1) userItems.splice(i, 1);
                            }));
                            Utils.closeModal();
                        });
                        tbody.appendChild(tr);
                    }
                    if (!filtered.length) tbody.appendChild(Utils.el('tr', {}, [Utils.el('td', { className: 'text-muted', textContent: 'No users found.' })]));
                }
                searchIn.addEventListener('input', () => _populateUserRows(searchIn.value.toLowerCase()));
                _populateUserRows('');
                tbl.appendChild(tbody);
                modalBody.appendChild(searchIn);
                modalBody.appendChild(tbl);
                Utils.showModal('Select User', modalBody);
            },
        });
        usersSec.appendChild(usersTableWrap);
        usersSec.appendChild(addUserBtn);
        settingsSec.appendChild(usersSec);

        // Save button at the bottom of settings section
        const saveBtn = Utils.el('button', { className: 'btn btn-primary btn-sm', textContent: 'Save Escrow Settings', style: 'margin-top:var(--space-2)' });
        saveBtn.addEventListener('click', async () => {
            saveBtn.disabled = true;
            try {
                await Api.put(`${Config.app.apiPrefix}/admin/escrow/settings`, {
                    escrow_require_coverage: reqCheck.checked,
                    escrow_default_role_ids: roleItems.map(r => r.id),
                    escrow_default_user_ids: userItems.map(u => u.id),
                });
                Utils.showToast('Escrow settings saved', 'success');
                _renderEscrowSection(container);
            } catch (err) {
                Utils.showToast('Save failed: ' + err.message, 'error');
                saveBtn.disabled = false;
            }
        });
        settingsSec.appendChild(saveBtn);
        container.appendChild(settingsSec);

        await _renderEscrowFolderPolicies(container);
        await _renderEscrowCoverageReport(container);
    }

    async function _renderEscrowFolderPolicies(container) {
        const sec = Utils.el('div', { className: 'policy-subsection' });
        sec.appendChild(Utils.el('div', { className: 'policy-sub-header' }, [
            Utils.el('h4', { textContent: 'Folder Escrow Overrides' }),
        ]));
        container.appendChild(sec);

        let data;
        try {
            data = await Api.get(`${Config.app.apiPrefix}/admin/escrow/folder-policies`);
        } catch (err) {
            sec.appendChild(Utils.el('p', { className: 'text-error', textContent: 'Failed to load policies: ' + err.message }));
            return;
        }

        const policies = data.policies || [];
        if (policies.length === 0) {
            sec.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No folder-level overrides configured.' }));
        } else {
            const table = Utils.el('table', { className: 'admin-table' });
            table.innerHTML = '<thead><tr><th>Folder</th><th>Mode</th><th>Agents</th><th>Locked</th><th></th></tr></thead>';
            const tbody = Utils.el('tbody');
            for (const p of policies) {
                const tr = Utils.el('tr');
                tr.appendChild(Utils.el('td', { textContent: p.folder_name || p.folder_id }));
                tr.appendChild(Utils.el('td', { textContent: p.override_mode }));
                tr.appendChild(Utils.el('td', { textContent: String(p.agent_count) }));
                tr.appendChild(Utils.el('td', { textContent: p.policy_locked ? `Yes (tier ≤${p.locked_min_tier})` : 'No' }));
                const delBtn = Utils.el('button', { className: 'btn btn-danger btn-xs', textContent: 'Delete' });
                delBtn.addEventListener('click', async () => {
                    if (!confirm(`Delete escrow override for folder "${p.folder_name}"?`)) return;
                    delBtn.disabled = true;
                    try {
                        await Api.del(`${Config.app.apiPrefix}/admin/escrow/folder-policies/${p.folder_id}`);
                        Utils.showToast('Policy deleted', 'success');
                        tr.remove();
                    } catch (err) {
                        Utils.showToast('Delete failed: ' + err.message, 'error');
                        delBtn.disabled = false;
                    }
                });
                const td = Utils.el('td');
                td.appendChild(delBtn);
                tr.appendChild(td);
                tbody.appendChild(tr);
            }
            table.appendChild(tbody);
            sec.appendChild(table);
        }
    }

    async function _renderEscrowCoverageReport(container) {
        const sec = Utils.el('div', { className: 'policy-subsection' });
        sec.appendChild(Utils.el('div', { className: 'policy-sub-header' }, [
            Utils.el('h4', { textContent: 'Coverage Report — Teams Without Escrow' }),
        ]));
        container.appendChild(sec);

        let data;
        try {
            data = await Api.get(`${Config.app.apiPrefix}/admin/escrow/coverage-report`);
        } catch (err) {
            sec.appendChild(Utils.el('p', { className: 'text-error', textContent: 'Failed to load coverage report: ' + err.message }));
            return;
        }

        const teams = data.teams || [];
        if (teams.length === 0) {
            sec.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'All teams have at least one escrow agent.' }));
            return;
        }

        sec.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:var(--space-3)',
            textContent: `${data.total} team(s) have no escrow agent key slot filled.`,
        }));

        const table = Utils.el('table', { className: 'admin-table' });
        table.innerHTML = '<thead><tr><th>Team</th><th>Owner</th><th>Created</th><th></th></tr></thead>';
        const tbody = Utils.el('tbody');
        for (const t of teams) {
            const tr = Utils.el('tr');
            tr.appendChild(Utils.el('td', { textContent: t.team_name }));
            tr.appendChild(Utils.el('td', { textContent: t.owner_username }));
            tr.appendChild(Utils.el('td', { textContent: new Date(t.created_at).toLocaleDateString() }));
            const grantBtn = Utils.el('button', {
                className: 'btn btn-secondary btn-xs',
                textContent: 'View team',
                onClick: () => globalThis.location.hash = `#/teams/${t.team_id}`,
            });
            const td = Utils.el('td');
            td.appendChild(grantBtn);
            tr.appendChild(td);
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        sec.appendChild(table);
    }

    // -----------------------------------------------------------------------
    // Sharing Restrictions
    // -----------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Section: Rate Limiting
    // ------------------------------------------------------------------

    async function _renderRateLimits(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let s;
        try {
            const data = await Api.get(`${_api()}/admin/settings`);
            s = data.settings;
        } catch (err) {
            _showError(container, 'Failed to load settings: ' + err.message);
            return;
        }

        const _iv = (key, def = 0) => String(Number.parseInt(s[key]?.value ?? s[key] ?? def, 10));

        const fldLogin    = Utils.el('input', { type: 'number', min: '1', max: '1000',  className: 'input-sm', value: _iv('rate_limit_login', 5) });
        const fldApi      = Utils.el('input', { type: 'number', min: '1', max: '10000', className: 'input-sm', value: _iv('rate_limit_api', 60) });
        const fldShare    = Utils.el('input', { type: 'number', min: '1', max: '1000',  className: 'input-sm', value: _iv('rate_limit_share_create', 5) });
        const fldUpload   = Utils.el('input', { type: 'number', min: '1', max: '10000', className: 'input-sm', value: _iv('rate_limit_upload', 300) });
        const fldMgmt     = Utils.el('input', { type: 'number', min: '1', max: '10000', className: 'input-sm', value: _iv('rate_limit_management', 120) });

        const fldErrThresh  = Utils.el('input', { type: 'number', min: '0', max: '100', className: 'input-sm', value: _iv('rate_limit_error_threshold', 5) });
        const fldErrWindow  = Utils.el('input', { type: 'number', min: '1', max: '3600', className: 'input-sm', value: _iv('rate_limit_error_window', 60) });
        const fldEscMax     = Utils.el('input', { type: 'number', min: '1', max: '1000', className: 'input-sm', value: _iv('rate_limit_escalated_max', 1) });
        const fldEscWindow  = Utils.el('input', { type: 'number', min: '1', max: '60',   className: 'input-sm', value: _iv('rate_limit_escalated_window', 1) });
        const fldEscDur     = Utils.el('input', { type: 'number', min: '1', max: '86400', className: 'input-sm', value: _iv('rate_limit_escalated_duration', 300) });

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Save Rate Limits',
            onClick: async () => {
                saveBtn.disabled = true;
                try {
                    await Api.put(`${_api()}/admin/settings`, {
                        settings: {
                            rate_limit_login:              String(Number.parseInt(fldLogin.value, 10)),
                            rate_limit_api:                String(Number.parseInt(fldApi.value, 10)),
                            rate_limit_share_create:       String(Number.parseInt(fldShare.value, 10)),
                            rate_limit_upload:             String(Number.parseInt(fldUpload.value, 10)),
                            rate_limit_management:         String(Number.parseInt(fldMgmt.value, 10)),
                            rate_limit_error_threshold:    String(Number.parseInt(fldErrThresh.value, 10)),
                            rate_limit_error_window:       String(Number.parseInt(fldErrWindow.value, 10)),
                            rate_limit_escalated_max:      String(Number.parseInt(fldEscMax.value, 10)),
                            rate_limit_escalated_window:   String(Number.parseInt(fldEscWindow.value, 10)),
                            rate_limit_escalated_duration: String(Number.parseInt(fldEscDur.value, 10)),
                        },
                    });
                    Utils.showToast('Rate limits saved', 'success');
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                } finally {
                    saveBtn.disabled = false;
                }
            },
        });

        container.innerHTML = '';
        container.appendChild(Utils.el('div', { className: 'settings-form' }, [
            Utils.el('h4', { textContent: 'Standard Limits', style: 'margin:0 0 10px;font-size:var(--font-size-sm);text-transform:uppercase;color:var(--color-muted,#888);letter-spacing:.05em' }),
            _row('Login / register', 'requests per 15 min per IP', fldLogin),
            _row('API (general)', 'requests per minute per user', fldApi),
            _row('Share creation', 'requests per minute per user', fldShare),
            _row('Upload initiation', 'requests per minute per user — increase for high-volume automation', fldUpload),
            _row('Folder / share management', 'requests per minute per user', fldMgmt),
            Utils.el('div', { className: 'settings-divider', style: 'margin:16px 0 12px;border-top:1px solid var(--color-border);' }),
            Utils.el('h4', { textContent: 'Error Escalation', style: 'margin:0 0 4px;font-size:var(--font-size-sm);text-transform:uppercase;color:var(--color-muted,#888);letter-spacing:.05em' }),
            Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-sm);margin:0 0 10px', textContent: 'IPs that accumulate ≥ threshold non-429 errors within the window are throttled to escalated-max reqs per escalated-window for escalated-duration seconds. Set threshold to 0 to disable.' }),
            _row('Error threshold', 'errors before escalation (0 = disabled)', fldErrThresh),
            _row('Error window (seconds)', 'window over which errors are counted', fldErrWindow),
            _row('Escalated max requests', 'max requests allowed per escalated window', fldEscMax),
            _row('Escalated window (seconds)', 'seconds per escalated request slot', fldEscWindow),
            _row('Escalated duration (seconds)', 'how long the IP stays throttled', fldEscDur),
            Utils.el('div', { className: 'settings-actions' }, [saveBtn]),
        ]));
    }

    // ------------------------------------------------------------------
    // Section: Session & Auth Policy
    // ------------------------------------------------------------------

    async function _renderSessionPolicy(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let s;
        try {
            const data = await Api.get(`${_api()}/admin/settings`);
            s = data.settings;
        } catch (err) {
            _showError(container, 'Failed to load settings: ' + err.message);
            return;
        }

        const _iv = (key, def = 0) => String(Number.parseInt(s[key]?.value ?? s[key] ?? def, 10));

        const fldAccess       = Utils.el('input', { type: 'number', min: '1', max: '60',    className: 'input-sm', value: _iv('access_token_expire_minutes', 5) });
        const fldRefresh      = Utils.el('input', { type: 'number', min: '1', max: '365',   className: 'input-sm', value: _iv('refresh_token_expire_days', 7) });
        const fldIdle         = Utils.el('input', { type: 'number', min: '1', max: '1440',  className: 'input-sm', value: _iv('session_idle_timeout_minutes', 10) });
        const fldShareSess    = Utils.el('input', { type: 'number', min: '1', max: '168',   className: 'input-sm', value: _iv('share_session_expire_hours', 2) });
        const fldPublicDev    = Utils.el('input', { type: 'number', min: '1', max: '1440',  className: 'input-sm', value: _iv('public_device_refresh_minutes', 60) });
        const fldMfaTtl       = Utils.el('input', { type: 'number', min: '10', max: '600',  className: 'input-sm', value: _iv('mfa_pending_token_ttl', 90) });
        const fldStepUpWindow = Utils.el('input', { type: 'number', min: '0', max: '86400', className: 'input-sm', value: _iv('step_up_window_seconds', 300) });
        const fldStepUpFail   = Utils.el('input', { type: 'number', min: '1', max: '20',    className: 'input-sm', value: _iv('step_up_max_failures', 3) });

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Save Session Policy',
            onClick: async () => {
                saveBtn.disabled = true;
                try {
                    await Api.put(`${_api()}/admin/settings`, {
                        settings: {
                            access_token_expire_minutes:   String(Number.parseInt(fldAccess.value, 10)),
                            refresh_token_expire_days:     String(Number.parseInt(fldRefresh.value, 10)),
                            session_idle_timeout_minutes:  String(Number.parseInt(fldIdle.value, 10)),
                            share_session_expire_hours:    String(Number.parseInt(fldShareSess.value, 10)),
                            public_device_refresh_minutes: String(Number.parseInt(fldPublicDev.value, 10)),
                            mfa_pending_token_ttl:         String(Number.parseInt(fldMfaTtl.value, 10)),
                            step_up_window_seconds:        String(Number.parseInt(fldStepUpWindow.value, 10)),
                            step_up_max_failures:          String(Number.parseInt(fldStepUpFail.value, 10)),
                        },
                    });
                    Utils.showToast('Session policy saved', 'success');
                } catch (err) {
                    Utils.showToast('Save failed: ' + err.message, 'error');
                } finally {
                    saveBtn.disabled = false;
                }
            },
        });

        container.innerHTML = '';
        container.appendChild(Utils.el('div', { className: 'settings-form' }, [
            Utils.el('h4', { textContent: 'Token Lifetimes', style: 'margin:0 0 4px;font-size:var(--font-size-sm);text-transform:uppercase;color:var(--color-muted,#888);letter-spacing:.05em' }),
            Utils.el('p', { className: 'text-muted', style: 'font-size:var(--font-size-sm);margin:0 0 10px', textContent: 'TTL changes apply to new sessions only — existing sessions keep their current expiry.' }),
            _row('Access token (minutes)', 'Short-lived JWT lifetime; lower = more frequent silent refresh', fldAccess),
            _row('Refresh token (days)', 'How long a logged-in session lasts without activity', fldRefresh),
            _row('Session idle timeout (minutes)', 'Inactivity window before a session is automatically revoked', fldIdle),
            _row('Share session (hours)', 'Lifetime of the IP-bound JWT issued for public share access', fldShareSess),
            _row('Public device session (minutes)', 'Shorter TTL when the user checks "Public Device" at login', fldPublicDev),
            Utils.el('div', { className: 'settings-divider', style: 'margin:16px 0 12px;border-top:1px solid var(--color-border);' }),
            Utils.el('h4', { textContent: 'MFA & Step-Up', style: 'margin:0 0 10px;font-size:var(--font-size-sm);text-transform:uppercase;color:var(--color-muted,#888);letter-spacing:.05em' }),
            _row('MFA pending token TTL (seconds)', 'Window between login/finish and MFA challenge completion', fldMfaTtl),
            _row('Step-up sudo window (seconds)', '0 = single-use (each action needs re-auth); >0 = grants cover any sensitive action within the window', fldStepUpWindow),
            _row('Step-up max failures', 'Failed attempts before the session is revoked', fldStepUpFail),
            Utils.el('div', { className: 'settings-actions' }, [saveBtn]),
        ]));
    }

    const _SHARING_OPERATORS = [
        'eq', 'neq', 'contains', 'not_contains', 'starts_with', 'ends_with',
        'in', 'not_in', 'matches_re', 'cross_eq', 'cross_neq',
    ];

    async function _renderLinkShareSettings(container) {
        const wrap = Utils.el('div', { className: 'policy-subsection', style: 'margin-bottom:24px' });
        wrap.appendChild(Utils.el('h4', { textContent: 'Link Share Settings' }));

        let currentVal = 0;
        try {
            const data = await Api.get(`${_api()}/admin/settings`);
            const raw = data.settings?.link_share_max_expiry_days;
            currentVal = Number.parseInt(raw, 10) || 0;
        } catch (e) {
            console.error('Failed to load link share settings:', e);
        }

        const row = Utils.el('div', { style: 'display:flex;align-items:center;gap:8px;margin-bottom:8px' });
        const label = Utils.el('label', {
            textContent: 'Maximum link share duration (days):',
            style: 'margin:0;white-space:nowrap',
        });
        const inp = Utils.el('input', {
            type: 'number',
            className: 'input-sm',
            style: 'width:90px',
            min: '0',
            step: '1',
            value: String(currentVal),
        });
        const hint = Utils.el('span', {
            className: 'text-muted',
            textContent: '(0 = no limit)',
            style: 'font-size:0.85em',
        });
        row.appendChild(label);
        row.appendChild(inp);
        row.appendChild(hint);
        wrap.appendChild(row);

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Save',
        });
        saveBtn.addEventListener('click', async () => {
            const v = Number.parseInt(inp.value, 10);
            if (Number.isNaN(v) || v < 0) { Utils.showToast('Enter a non-negative integer', 'error'); return; }
            saveBtn.disabled = true;
            try {
                await Api.put(`${_api()}/admin/settings`, { settings: { link_share_max_expiry_days: String(v) } });
                Utils.showToast('Link share settings saved', 'success');
            } catch (err) {
                Utils.showToast('Save failed: ' + err.message, 'error');
            } finally {
                saveBtn.disabled = false;
            }
        });
        wrap.appendChild(saveBtn);
        container.appendChild(wrap);
    }

    async function _renderSharingSection(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let data;
        try {
            data = await Api.get(`${_api()}/admin/sharing/rules`);
        } catch (err) {
            container.innerHTML = '';
            _showError(container, 'Failed to load sharing rules: ' + err.message);
            _renderSharingTestPanel(container);
            return;
        }
        container.innerHTML = '';

        // Link share settings sub-section
        await _renderLinkShareSettings(container);

        // Header + create button
        const createBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Create Rule',
            onClick: () => _showSharingRuleModal(null, () => _renderSharingSection(container)),
        });
        container.appendChild(Utils.el('div', { className: 'policy-sub-header' }, [
            Utils.el('div', { style: 'display:flex;align-items:center;gap:8px' }, [
                Utils.el('h4', { textContent: 'Sharing Rules', style: 'margin:0' }),
                createBtn,
            ]),
            Utils.el('p', {
                className: 'text-muted policy-sub-hint',
                textContent: 'Rules are evaluated in priority order (lowest number first). The first matching deny wins; an explicit allow overrides earlier denies.',
            }),
            Utils.el('p', {
                className: 'text-muted',
                textContent: 'These rules dictate how users may or may not share files or folders. For example, blocking OIDC users from sharing outside of your @example.com domain.',
            }),
        ]));

        const rules = data.rules || [];
        if (rules.length === 0) {
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No sharing rules configured. By default all shares are permitted.' }));
        } else {
            const list = Utils.el('div', { className: 'policy-list' });
            for (const rule of rules) {
                list.appendChild(_buildSharingRuleCard(rule, () => _renderSharingSection(container)));
            }
            container.appendChild(list);
        }

        _renderSharingAttributeRef(container);
        _renderSharingTestPanel(container);
    }

    function _buildSharingRuleCard(rule, refreshFn) {
        const body = Utils.el('div', { className: 'policy-card-body', style: 'display:none' });
        let loaded = false;

        const effectBadge = Utils.el('span', {
            className: `badge ${rule.effect === 'deny' ? 'badge-expired' : 'badge-active'}`,
            textContent: rule.effect,
        });
        const subjectBadge = Utils.el('span', {
            className: 'badge badge-custom',
            textContent: rule.subject,
        });
        const typeBadge = rule.applies_to_share_type ? Utils.el('span', {
            className: 'badge badge-internal',
            textContent: rule.applies_to_share_type,
        }) : null;
        const activeBadge = Utils.el('span', {
            className: `badge ${rule.is_active ? 'badge-admin' : 'badge-custom'}`,
            textContent: rule.is_active ? 'active' : 'inactive',
        });
        const lockedBadge = rule.is_locked ? Utils.el('span', {
            className: 'badge badge-team',
            textContent: `locked ≤tier${rule.locked_min_tier ?? '?'}`,
        }) : null;
        const priorityTag = Utils.el('span', {
            className: 'text-muted',
            textContent: `P${rule.priority}`,
            style: 'font-size:0.8em;margin-right:6px',
        });

        const toggleBtn = Utils.el('button', {
            className: 'policy-card-toggle collapsed',
            onClick: () => {
                const open = body.style.display !== 'none';
                body.style.display = open ? 'none' : '';
                toggleBtn.classList.toggle('collapsed', open);
                if (!open && !loaded) {
                    loaded = true;
                    _populateSharingRuleBody(body, rule, refreshFn);
                }
            },
        });
        const badgeRow = Utils.el('span', { style: 'display:flex;align-items:center;gap:2px;flex-wrap:wrap' }, [
            priorityTag, effectBadge, subjectBadge,
            ...(typeBadge ? [typeBadge] : []),
            activeBadge,
            ...(lockedBadge ? [lockedBadge] : []),
        ]);
        toggleBtn.appendChild(Utils.el('span', { textContent: rule.name, style: 'margin-right:8px' }));
        toggleBtn.appendChild(badgeRow);

        const deleteBtn = Utils.el('button', {
            className: 'btn btn-danger btn-xs policy-card-delete',
            textContent: 'Delete',
            onClick: async (e) => {
                e.stopPropagation();
                if (!confirm(`Delete sharing rule "${rule.name}"?`)) return;
                try {
                    await Api.del(`${_api()}/admin/sharing/rules/${rule.id}`);
                    Utils.showToast('Rule deleted', 'success');
                    refreshFn();
                } catch (err) {
                    Utils.showToast('Delete failed: ' + err.message, 'error');
                }
            },
        });

        const editBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-xs',
            style: 'margin-right:var(--space-1)',
            textContent: 'Edit',
            onClick: (e) => {
                e.stopPropagation();
                _showSharingRuleModal(rule, refreshFn);
            },
        });

        return Utils.el('div', { className: 'policy-card' }, [
            Utils.el('div', { className: 'policy-card-header' }, [toggleBtn, editBtn, deleteBtn]),
            body,
        ]);
    }

    function _populateSharingRuleBody(container, rule, refreshFn) {
        if (rule.description) {
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: rule.description }));
        }

        // Toggle active
        const activeToggle = Utils.el('button', {
            className: `btn btn-sm ${rule.is_active ? 'btn-secondary' : 'btn-primary'}`,
            style: 'margin-bottom:var(--space-4)',
            textContent: rule.is_active ? 'Deactivate rule' : 'Activate rule',
            onClick: async () => {
                activeToggle.disabled = true;
                try {
                    await Api.put(`${_api()}/admin/sharing/rules/${rule.id}`, {
                        is_active: !rule.is_active,
                    });
                    Utils.showToast(rule.is_active ? 'Rule deactivated' : 'Rule activated', 'success');
                    refreshFn();
                } catch (err) {
                    Utils.showToast('Update failed: ' + err.message, 'error');
                    activeToggle.disabled = false;
                }
            },
        });
        container.appendChild(activeToggle);

        // Conditions table
        const condHeader = Utils.el('h5', { className: 'policy-body-section-title', textContent: 'Conditions' });
        container.appendChild(condHeader);

        if (!rule.conditions || rule.conditions.length === 0) {
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No conditions — rule matches all shares of the specified type.' }));
        } else {
            const table = Utils.el('table', { className: 'policy-table' });
            table.innerHTML = `<thead><tr>
                <th>Attribute</th><th>Operator</th><th>Value</th><th>Block if missing</th>
            </tr></thead>`;
            const tbody = Utils.el('tbody');
            for (const cond of rule.conditions) {
                const path = cond.attribute_path + (cond.attribute_path2 ? ` ↔ ${cond.attribute_path2}` : '');
                const tr = Utils.el('tr', {}, [
                    Utils.el('td', {}, [Utils.el('code', { textContent: path })]),
                    Utils.el('td', { textContent: cond.operator }),
                    Utils.el('td', { textContent: cond.value ?? '—' }),
                    Utils.el('td', { textContent: cond.block_on_missing_attribute ? 'Yes' : 'No' }),
                ]);
                tbody.appendChild(tr);
            }
            table.appendChild(tbody);
            container.appendChild(table);
        }
    }

    function _showSharingRuleModal(existing, refreshFn) {
        const isEdit = !!existing;

        const nameEl = Utils.el('input', {
            type: 'text', className: 'input-sm', maxlength: '200',
            placeholder: 'Rule name',
            value: existing?.name ?? '',
        });
        const descEl = Utils.el('input', {
            type: 'text', className: 'input-sm',
            placeholder: 'Description (optional)',
            value: existing?.description ?? '',
        });
        const priorityEl = Utils.el('input', {
            type: 'number', className: 'input-sm', min: '1', max: '10000',
            value: String(existing?.priority ?? 100),
        });

        const subjectSel = Utils.el('select', { className: 'input-sm' });
        ['sender', 'recipient', 'cross'].forEach(v => {
            const opt = Utils.el('option', { value: v, textContent: v });
            if (existing?.subject === v) opt.selected = true;
            subjectSel.appendChild(opt);
        });

        const typeSel = Utils.el('select', { className: 'input-sm' });
        [['', '(any share type)'], ['link', 'link'], ['user', 'user']].forEach(([v, label]) => {
            const opt = Utils.el('option', { value: v, textContent: label });
            if ((existing?.applies_to_share_type ?? '') === v) opt.selected = true;
            typeSel.appendChild(opt);
        });

        const effectSel = Utils.el('select', { className: 'input-sm' });
        ['deny', 'allow'].forEach(v => {
            const opt = Utils.el('option', { value: v, textContent: v });
            if ((existing?.effect ?? 'deny') === v) opt.selected = true;
            effectSel.appendChild(opt);
        });

        const activeCheck = Utils.el('input', { type: 'checkbox' });
        activeCheck.checked = existing?.is_active ?? true;

        // Conditions editor
        const conditions = (existing?.conditions ?? []).map(c => ({ ...c }));
        const condTable = Utils.el('div');

        function _renderCondTable() {
            condTable.innerHTML = '';
            if (conditions.length === 0) {
                condTable.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No conditions yet — rule matches all shares.' }));
            } else {
                const table = Utils.el('table', { className: 'policy-table' });
                table.innerHTML = '<thead><tr><th>Attribute</th><th>Operator</th><th>Value</th><th>Block if missing</th><th></th></tr></thead>';
                const tbody = Utils.el('tbody');
                conditions.forEach((cond, idx) => { // NOSONAR — closures over cond/idx; unavoidable nesting
                    const pathEl = Utils.el('input', {
                        type: 'text', className: 'input-sm', value: cond.attribute_path ?? '',
                        placeholder: 'e.g. internal.email',
                        style: 'width:150px',
                    });
                    pathEl.addEventListener('input', () => { conditions[idx].attribute_path = pathEl.value; }); // NOSONAR

                    const opSel = Utils.el('select', { className: 'input-sm' });
                    _SHARING_OPERATORS.forEach(op => { // NOSONAR — closure over cond/opSel
                        const opt = Utils.el('option', { value: op, textContent: op });
                        if (cond.operator === op) opt.selected = true;
                        opSel.appendChild(opt);
                    });
                    opSel.addEventListener('change', () => { conditions[idx].operator = opSel.value; }); // NOSONAR

                    const valEl = Utils.el('input', {
                        type: 'text', className: 'input-sm', value: cond.value ?? '',
                        placeholder: 'value',
                        style: 'width:120px',
                    });
                    valEl.addEventListener('input', () => { conditions[idx].value = valEl.value || null; }); // NOSONAR

                    const blockCheck = Utils.el('input', { type: 'checkbox', checked: cond.block_on_missing_attribute !== false });
                    blockCheck.addEventListener('change', () => { conditions[idx].block_on_missing_attribute = blockCheck.checked; }); // NOSONAR

                    const delBtn = Utils.el('button', {
                        className: 'btn btn-danger btn-xs',
                        textContent: '×',
                        type: 'button',
                        onClick: () => { // NOSONAR — closure required; nesting depth unavoidable in sharing-rule condition editor
                            conditions.splice(idx, 1);
                            _renderCondTable();
                        },
                    });

                    const tr = Utils.el('tr', {}, [
                        Utils.el('td', {}, [pathEl]),
                        Utils.el('td', {}, [opSel]),
                        Utils.el('td', {}, [valEl]),
                        Utils.el('td', {}, [blockCheck]),
                        Utils.el('td', {}, [delBtn]),
                    ]);
                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                condTable.appendChild(table);
            }
            const addBtn = Utils.el('button', {
                className: 'btn btn-sm btn-secondary',
                style: 'margin-top:var(--space-2)',
                textContent: '+ Add Condition',
                type: 'button',
                onClick: () => {
                    conditions.push({
                        attribute_path: '',
                        attribute_path2: null,
                        operator: 'eq',
                        value: null,
                        block_on_missing_attribute: true,
                    });
                    _renderCondTable();
                },
            });
            condTable.appendChild(addBtn);
        }
        _renderCondTable();

        const _row = (label, el) => Utils.el('div', { className: 'policy-strict-row' }, [
            Utils.el('label', { textContent: label }),
            el,
        ]);

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            style: 'margin-top:var(--space-4)',
            textContent: isEdit ? 'Save Changes' : 'Create Rule',
            type: 'button',
            onClick: async () => {
                saveBtn.disabled = true;
                const payload = {
                    name: nameEl.value.trim(),
                    description: descEl.value.trim() || null,
                    priority: Number.parseInt(priorityEl.value, 10) || 100,
                    subject: subjectSel.value,
                    applies_to_share_type: typeSel.value || null,
                    effect: effectSel.value,
                    is_active: activeCheck.checked,
                    conditions: conditions.filter(c => c.attribute_path),
                };
                try {
                    if (isEdit) {
                        await Api.put(`${_api()}/admin/sharing/rules/${existing.id}`, payload);
                        Utils.showToast('Rule updated', 'success');
                    } else {
                        await Api.post(`${_api()}/admin/sharing/rules`, payload);
                        Utils.showToast('Rule created', 'success');
                    }
                    Utils.closeModal?.();
                    refreshFn();
                } catch (err) {
                    Utils.showToast((isEdit ? 'Update' : 'Create') + ' failed: ' + err.message, 'error');
                    saveBtn.disabled = false;
                }
            },
        });

        const form = Utils.el('div', { className: 'policy-modal-form' }, [
            _row('Name', nameEl),
            _row('Description', descEl),
            _row('Priority (1–10000, lower = first)', priorityEl),
            _row('Subject', subjectSel),
            _row('Applies to share type', typeSel),
            _row('Effect', effectSel),
            Utils.el('div', { className: 'policy-strict-row' }, [
                Utils.el('label', { textContent: 'Active' }),
                activeCheck,
            ]),
            Utils.el('h5', { textContent: 'Conditions', style: 'margin-top:16px' }),
            Utils.el('p', {
                className: 'text-muted',
                style: 'font-size:0.8em;margin:0 0 6px',
                textContent: 'Attribute paths: internal.{username|email|display_name|created_at}, ldap.{attr}, oidc.{claim}. See Attribute Reference below for available keys.',
            }),
            condTable,
            saveBtn,
        ]);

        Utils.showModal(isEdit ? `Edit Rule — ${existing.name}` : 'Create Sharing Rule', form);
    }

    const _INTERNAL_ATTRS = [
        { path: 'internal.username',     desc: 'Username of the user' },
        { path: 'internal.email',        desc: 'Email address' },
        { path: 'internal.display_name', desc: 'Display name' },
        { path: 'internal.created_at',   desc: 'Account creation timestamp (ISO 8601 string)' },
    ];

    function _renderSharingAttributeRef(container) {
        const wrap = Utils.el('div', { className: 'policy-subsection', style: 'margin-top:24px' });
        const body = Utils.el('div', { style: 'display:none' });
        let loaded = false;

        const toggle = Utils.el('button', {
            className: 'btn btn-sm btn-secondary',
            style: 'margin-bottom:8px',
            textContent: 'Attribute Reference ▾',
            onClick: () => {
                const open = body.style.display !== 'none';
                body.style.display = open ? 'none' : '';
                toggle.textContent = open ? 'Attribute Reference ▾' : 'Attribute Reference ▴';
                if (!open && !loaded) {
                    loaded = true;
                    _loadSharingAttributeRef(body);
                }
            },
        });

        wrap.appendChild(Utils.el('h4', { textContent: 'Attribute Reference', style: 'margin-bottom:4px' }));
        wrap.appendChild(Utils.el('p', {
            className: 'text-muted policy-sub-hint',
            textContent: 'Attribute paths available for sharing rule conditions, grouped by source.',
        }));
        wrap.appendChild(toggle);
        wrap.appendChild(body);
        container.appendChild(wrap);
    }

    async function _loadSharingAttributeRef(body) {
        body.innerHTML = '<p class="text-muted">Loading…</p>';

        // Built-in attributes table
        const internalTable = Utils.el('table', { className: 'policy-table', style: 'margin-bottom:16px' });
        internalTable.innerHTML = `<thead><tr><th>Attribute path</th><th>Description</th></tr></thead>`;
        const internalTbody = Utils.el('tbody');
        for (const a of _INTERNAL_ATTRS) {
            internalTbody.appendChild(Utils.el('tr', {}, [
                Utils.el('td', {}, [Utils.el('code', { textContent: a.path })]),
                Utils.el('td', { textContent: a.desc }),
            ]));
        }
        internalTable.appendChild(internalTbody);

        body.innerHTML = '';
        body.appendChild(Utils.el('h5', { textContent: 'Built-in (internal.*)', style: 'margin-bottom:6px' }));
        body.appendChild(internalTable);

        // IdP-observed attributes from backend
        try {
            const data = await Api.get(`${_api()}/admin/sharing/attributes`);
            const observed = data.observed || {};

            if (Object.keys(observed).length === 0) {
                body.appendChild(Utils.el('p', {
                    className: 'text-muted',
                    textContent: 'No LDAP or OIDC users found — IdP attribute keys will appear here once users have authenticated via an identity provider.',
                }));
            } else {
                for (const [source, keys] of Object.entries(observed)) {
                    body.appendChild(Utils.el('h5', {
                        textContent: source === 'ldap' ? 'LDAP attributes (ldap.*)' : 'OIDC claims (oidc.*)',
                        style: 'margin:12px 0 6px',
                    }));
                    if (keys.length === 0) {
                        body.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No attributes observed yet.' }));
                        continue;
                    }
                    const idpTable = Utils.el('table', { className: 'policy-table' });
                    idpTable.innerHTML = `<thead><tr><th>Attribute path</th><th>Notes</th></tr></thead>`;
                    const idpTbody = Utils.el('tbody');
                    for (const key of keys) {
                        idpTbody.appendChild(Utils.el('tr', {}, [
                            Utils.el('td', {}, [Utils.el('code', { textContent: `${source}.${key}` })]),
                            Utils.el('td', { className: 'text-muted', textContent: 'Observed in user claims cache' }),
                        ]));
                    }
                    idpTable.appendChild(idpTbody);
                    body.appendChild(idpTable);
                }
            }
        } catch {
            body.appendChild(Utils.el('p', {
                className: 'text-muted',
                textContent: 'IdP attributes could not be loaded. LDAP attributes use ldap.{attr} and OIDC claims use oidc.{claim}.',
            }));
        }
    }

    function _renderSharingTestPanel(container) {
        const wrap = Utils.el('div', { className: 'policy-subsection', style: 'margin-top:24px' });
        wrap.appendChild(Utils.el('h4', { textContent: 'Test Rules (dry run)' }));
        wrap.appendChild(Utils.el('p', {
            className: 'text-muted policy-sub-hint',
            textContent: 'Evaluate sharing rules for a specific user pair without making any changes.',
        }));

        const senderEl = Utils.el('input', {
            type: 'text', className: 'input-sm', placeholder: 'Sender user ID (UUID)',
            style: 'width:300px',
        });
        const recipientEl = Utils.el('input', {
            type: 'text', className: 'input-sm', placeholder: 'Recipient user ID (optional)',
            style: 'width:300px',
        });
        const stypeSel = Utils.el('select', { className: 'input-sm' });
        ['link', 'user'].forEach(v => stypeSel.appendChild(Utils.el('option', { value: v, textContent: v })));

        const resultBox = Utils.el('div', { style: 'margin-top:12px' });

        const testBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Test',
            onClick: async () => {
                testBtn.disabled = true;
                resultBox.innerHTML = '';
                try {
                    const payload = {
                        sender_user_id: senderEl.value.trim(),
                        share_type: stypeSel.value,
                    };
                    if (recipientEl.value.trim()) payload.recipient_user_id = recipientEl.value.trim();
                    const res = await Api.post(`${_api()}/admin/sharing/rules/test`, payload);
                    const outcomeEl = Utils.el('p', {
                        textContent: `Outcome: ${res.outcome.toUpperCase()}`,
                        style: `font-weight:bold;color:${res.outcome === 'deny' ? 'var(--color-error)' : 'var(--color-ok, #2d7a36)'}`,
                    });
                    resultBox.appendChild(outcomeEl);
                    if (res.matching_rules.length === 0) {
                        resultBox.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No rules matched.' }));
                    } else {
                        const ul = Utils.el('ul');
                        for (const r of res.matching_rules) {
                            ul.appendChild(Utils.el('li', { textContent: `[${r.effect}] P${r.priority} "${r.name}"` }));
                        }
                        resultBox.appendChild(ul);
                    }
                } catch (err) {
                    resultBox.appendChild(Utils.el('p', { className: 'text-danger', textContent: 'Test failed: ' + err.message }));
                } finally {
                    testBtn.disabled = false;
                }
            },
        });

        const _row2 = (label, el) => Utils.el('div', { style: 'margin-bottom:8px' }, [
            Utils.el('label', { textContent: label, style: 'display:block;font-size:0.85em;margin-bottom:2px' }),
            el,
        ]);

        wrap.appendChild(Utils.el('div', {}, [
            _row2('Sender user ID', senderEl),
            _row2('Recipient user ID (leave blank for link shares)', recipientEl),
            _row2('Share type', stypeSel),
            testBtn,
            resultBox,
        ]));
        container.appendChild(wrap);
    }

    // ------------------------------------------------------------------
    // Service Accounts section
    // ------------------------------------------------------------------

    async function _renderServiceAccountsSection(container) {
        container.innerHTML = '<p class="text-muted loading-msg">Loading…</p>';
        try {
            const data = await Api.get(`${_api()}/admin/service-accounts`);
            _renderServiceAccountsPanel(container, data.service_accounts || []);
        } catch (err) {
            _showError(container, `Failed to load: ${err.message}`);
        }
    }

    function _buildServiceAccountRow(sa, container) {
        const statusBadge = sa.is_active
            ? '<span class="text-success">active</span>'
            : '<span class="text-danger">inactive</span>';
        const tr = Utils.el('tr');
        tr.innerHTML = `
          <td>${Utils.escHtml(sa.username)}</td>
          <td class="text-muted-sm">${Utils.escHtml(sa.description || '—')}</td>
          <td class="text-sm">${statusBadge}</td>
          <td class="text-mono-sm">${Utils.escHtml(sa.key_prefix || '—')}</td>
          <td class="text-sm">${sa.last_used_at ? sa.last_used_at.slice(0, 10) : 'never'}</td>
          <td class="text-sm">${sa.key_expires_at ? sa.key_expires_at.slice(0, 10) : 'never'}</td>
          <td class="text-nowrap"></td>
        `;
        const actionsCell = tr.cells[6];
        const rotateBtn = Utils.el('button', { textContent: 'Rotate Key', className: 'btn btn-sm', style: 'margin-right:4px' });
        rotateBtn.addEventListener('click', async () => {
            if (!confirm(`Rotate the key for "${sa.username}"? The current key will stop working immediately.`)) return;
            try {
                const result = await Api.post(`${_api()}/admin/service-accounts/${sa.id}/rotate-key`, {});
                _showSaKeyReveal(result.key, sa.username, container);
            } catch (err) {
                Utils.showToast('Rotate failed: ' + err.message, 'error');
            }
        });
        const toggleBtn = Utils.el('button', {
            textContent: sa.is_active ? 'Deactivate' : 'Activate',
            className: 'btn btn-sm' + (sa.is_active ? ' btn-secondary' : ' btn-primary'),
            style: 'margin-right:4px',
        });
        toggleBtn.addEventListener('click', async () => {
            const action = sa.is_active ? 'Deactivate' : 'Activate';
            if (!confirm(`${action} service account "${sa.username}"?`)) return;
            try {
                await Api.patch(`${_api()}/admin/service-accounts/${sa.id}`, { is_active: !sa.is_active });
                Utils.showToast(`${action}d "${sa.username}".`);
                await _renderServiceAccountsSection(container.closest('.admin-section-body') || container);
            } catch (err) {
                Utils.showToast(`${action} failed: ` + err.message, 'error');
            }
        });
        const deleteBtn = Utils.el('button', { textContent: 'Delete', className: 'btn btn-sm btn-danger' });
        deleteBtn.addEventListener('click', async () => {
            if (!confirm(`Permanently delete service account "${sa.username}"? This cannot be undone.`)) return;
            try {
                await Api.del(`${_api()}/admin/service-accounts/${sa.id}`);
                Utils.showToast(`Service account "${sa.username}" deleted.`);
                await _renderServiceAccountsSection(container.closest('.admin-section-body') || container);
            } catch (err) {
                Utils.showToast('Delete failed: ' + err.message, 'error');
            }
        });
        const rolesBtn = Utils.el('button', { textContent: 'Roles', className: 'btn btn-sm', style: 'margin-right:4px' });
        rolesBtn.addEventListener('click', () => _showUserDetailModal(sa.id, sa.username));
        actionsCell.append(rotateBtn, rolesBtn, toggleBtn, deleteBtn);
        return tr;
    }

    function _renderServiceAccountsPanel(container, accounts) {
        container.innerHTML = '';
        const wrap = Utils.el('div');

        const header = Utils.el('div', { style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:12px' });
        header.appendChild(Utils.el('h3', { textContent: 'Service Accounts', style: 'margin:0' }));
        const createBtn = Utils.el('button', { textContent: '+ Create Service Account', className: 'btn btn-primary btn-sm' });
        createBtn.addEventListener('click', () => _showCreateServiceAccountModal(container));
        header.appendChild(createBtn);
        wrap.appendChild(header);

        wrap.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'font-size:var(--font-size-sm);margin-bottom:12px',
            textContent: 'Service accounts are machine identities that authenticate via bearer token. They receive no permissions by default — assign roles after creation.',
        }));

        if (accounts.length === 0) {
            wrap.appendChild(Utils.el('p', { textContent: 'No service accounts.', className: 'text-muted' }));
        } else {
            const table = Utils.el('table', { className: 'admin-table', style: 'width:100%' });
            table.innerHTML = '<thead><tr><th>Name</th><th>Description</th><th>Status</th><th>Key prefix</th><th>Last used</th><th>Expires</th><th>Actions</th></tr></thead>';
            const tbody = Utils.el('tbody');
            for (const sa of accounts) {
                tbody.appendChild(_buildServiceAccountRow(sa, container));
            }
            table.appendChild(tbody);
            wrap.appendChild(table);
        }

        container.appendChild(wrap);
    }

    function _showCreateServiceAccountModal(refreshContainer) {
        const modal = Utils.el('div', { className: 'modal-overlay' });
        const box   = Utils.el('div', { className: 'modal', style: 'max-width:460px' });
        box.appendChild(Utils.el('h3', { textContent: 'Create Service Account', style: 'margin-top:0' }));

        const nameInp  = Utils.el('input', { type: 'text', style: 'width:100%', placeholder: 'e.g. backup-agent' });
        const descInp  = Utils.el('input', { type: 'text', style: 'width:100%', placeholder: 'Optional description' });
        const expiryInp = Utils.el('input', { type: 'date', style: 'width:200px' });

        const mkField = _mkField;

        box.append(
            mkField('Name', nameInp, 'Lowercase, no spaces recommended. Used as the bearer token identity.'),
            mkField('Description (optional)', descInp),
            mkField('Key expiry (optional)', expiryInp, 'Leave blank for a non-expiring key.'),
        );

        box.appendChild(Utils.el('p', {
            style: 'font-size:var(--font-size-sm);color:var(--color-muted,#888);margin-bottom:8px',
            textContent: 'The service account will be created with no roles. Assign roles via the Roles & Permissions section after creation.',
        }));

        const errEl = Utils.el('p', { className: 'error-text', style: 'display:none;margin-bottom:8px' });
        box.appendChild(errEl);

        const btns = Utils.el('div', { style: 'display:flex;gap:8px;justify-content:flex-end' });
        const cancelBtn = Utils.el('button', { textContent: 'Cancel', className: 'btn btn-secondary btn-sm' });
        cancelBtn.addEventListener('click', () => modal.remove());

        const createBtn = Utils.el('button', { textContent: 'Create', className: 'btn btn-primary btn-sm' });
        createBtn.addEventListener('click', async () => {
            errEl.style.display = 'none';
            const body = {
                username:    nameInp.value.trim(),
                description: descInp.value.trim() || null,
                expires_at:  expiryInp.value ? expiryInp.value + 'T00:00:00Z' : null,
            };
            if (!body.username) {
                errEl.textContent = 'Name is required.';
                errEl.style.display = '';
                return;
            }
            createBtn.disabled = true;
            try {
                const result = await Api.post(`${_api()}/admin/service-accounts`, body);
                modal.remove();
                _showSaKeyReveal(result.key, result.username, refreshContainer);
            } catch (err) {
                errEl.textContent = err.message;
                errEl.style.display = '';
                createBtn.disabled = false;
            }
        });

        btns.append(cancelBtn, createBtn);
        box.appendChild(btns);
        modal.appendChild(box);
        document.body.appendChild(modal);
        nameInp.focus();
    }

    function _showSaKeyReveal(rawKey, username, refreshContainer) {
        const modal = Utils.el('div', { className: 'modal-overlay' });
        const box   = Utils.el('div', { className: 'modal', style: 'max-width:520px' });
        box.appendChild(Utils.el('h3', { textContent: 'Service Account Key', style: 'margin-top:0' }));
        box.appendChild(Utils.el('p', { textContent: 'Copy this key now — it will not be shown again.', style: 'color:var(--color-warning,#d97706);font-weight:600' }));
        box.appendChild(Utils.el('p', { textContent: username, style: 'font-weight:600;margin-bottom:6px' }));

        const codeWrap = Utils.el('div', { style: 'display:flex;gap:8px;align-items:center;margin-bottom:8px' });
        const code = Utils.el('code', { textContent: rawKey, style: 'word-break:break-all;background:var(--color-surface,#f5f5f5);padding:8px;border-radius:4px;flex:1;font-size:var(--font-size-sm)' });
        const copyBtn = Utils.el('button', { textContent: 'Copy', className: 'btn btn-sm' });
        copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(rawKey).then(() => { copyBtn.textContent = 'Copied!'; });
        });
        codeWrap.append(code, copyBtn);
        box.appendChild(codeWrap);

        box.appendChild(Utils.el('p', {
            style: 'font-size:var(--font-size-sm);color:var(--color-muted,#888);margin-bottom:16px',
            textContent: 'Pass this as a Bearer token: Authorization: Bearer <key>',
        }));

        const doneBtn = Utils.el('button', { textContent: 'Done', className: 'btn btn-primary btn-sm' });
        doneBtn.addEventListener('click', async () => {
            modal.remove();
            await _renderServiceAccountsSection(refreshContainer.closest('.admin-section-body') || refreshContainer);
        });
        box.appendChild(doneBtn);
        modal.appendChild(box);
        document.body.appendChild(modal);
    }

    // ------------------------------------------------------------------
    // Settings Profile section
    // ------------------------------------------------------------------

    async function _renderProfilesSection(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let profilesData;
        try {
            profilesData = await Api.get(`${_api()}/admin/settings/profiles`);
        } catch (err) {
            container.innerHTML = '';
            _showError(container, 'Failed to load profiles: ' + err.message);
            return;
        }
        container.innerHTML = '';

        const profiles = profilesData.profiles || [];

        // ---- Apply built-in profile ------------------------------------------
        const applySection = Utils.el('div', { style: 'margin-bottom:24px' });
        applySection.appendChild(Utils.el('h5', { textContent: 'Apply Built-in Profile', style: 'margin-bottom:8px' }));
        applySection.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:12px',
            textContent: 'Apply a pre-defined security profile to configure sharing restrictions, escrow settings, and lock states in one step.',
        }));

        const profileCards = Utils.el('div', { style: 'display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px' });
        let selectedProfile = profiles[0]?.id || 'recommended';

        for (const p of profiles) {
            const card = Utils.el('div', {
                style: [
                    'flex:1;min-width:180px;padding:12px;border-radius:6px;cursor:pointer',
                    'border:2px solid var(--color-border,#dee2e6);background:var(--color-surface,#fff)',
                ].join(';'),
                dataset: { profileId: p.id },
            });
            card.appendChild(Utils.el('div', { textContent: p.name, style: 'font-weight:600;margin-bottom:4px' }));
            card.appendChild(Utils.el('div', { textContent: p.description, className: 'text-muted', style: 'font-size:var(--font-size-sm)' }));
            card.addEventListener('click', () => {
                selectedProfile = p.id;
                profileCards.querySelectorAll('[data-profile-id]').forEach(c => {
                    c.style.borderColor = c.dataset.profileId === p.id
                        ? 'var(--color-primary,#0d6efd)'
                        : 'var(--color-border,#dee2e6)';
                });
            });
            if (p.id === selectedProfile) card.style.borderColor = 'var(--color-primary,#0d6efd)';
            profileCards.appendChild(card);
        }
        applySection.appendChild(profileCards);

        const applyBtn = Utils.el('button', { className: 'btn btn-primary btn-sm', textContent: 'Preview & Apply' });
        applyBtn.addEventListener('click', () => _showApplyProfileModal(selectedProfile, () => _renderProfilesSection(container)));
        applySection.appendChild(applyBtn);
        container.appendChild(applySection);

        container.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'font-size:var(--font-size-sm);margin-top:8px',
            textContent: 'To export or import full configuration (roles, policies, integrations, etc.) use the Import / Export tab.',
        }));
    }

    // ------------------------------------------------------------------
    // Import / Export tab
    // ------------------------------------------------------------------

    const _EXPORT_CATEGORIES = [
        { id: 'security_profile', label: 'Security Profile',       desc: 'Sharing restrictions, escrow settings, and sharing flags for role_user.' },
        { id: 'roles',            label: 'Roles & Permissions',    desc: 'All roles (system and custom) with their permission flag values.' },
        { id: 'admin_settings',   label: 'Admin Settings',         desc: 'MFA policy, registration, file size limits, audit retention, etc. (credentials excluded).' },
        { id: 'policies',         label: 'Policies (org-scoped)',  desc: 'Org-level policy engine policies and conditions. Effects (team/folder grants) are excluded — re-add after import.' },
        { id: 'policy_fields',    label: 'Custom Policy Fields',   desc: 'Custom LDAP/OIDC attribute definitions added to the policy field registry.' },
        { id: 'siem',             label: 'SIEM Destinations',      desc: 'Syslog and webhook SIEM destinations. Signing secrets excluded — reconfigure after import.' },
        { id: 'notifications',    label: 'Notification Channels',  desc: 'Outbound webhook notification channels. Signing secrets excluded — reconfigure after import.' },
        { id: 'storage',          label: 'Storage Providers',      desc: 'Storage volume metadata (name, provider, tier). Credentials excluded — reconfigure after import. Always merged, never deleted.' },
    ];

    async function _renderExportSection(container) {
        container.innerHTML = '';
        const wrap = Utils.el('div', { style: 'padding:4px 0' });

        // ---- Export -----------------------------------------------------------
        const exportDiv = Utils.el('div', { style: 'margin-bottom:32px' });
        exportDiv.appendChild(Utils.el('h5', { textContent: 'Export', style: 'margin-bottom:6px' }));
        exportDiv.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:14px',
            textContent: 'Select the categories to include in the export file. Credentials and instance-specific IDs (user IDs, file IDs) are always excluded.',
        }));

        const checks = {};
        const checkList = Utils.el('div', { style: 'margin-bottom:14px' });
        for (const cat of _EXPORT_CATEGORIES) {
            const row = Utils.el('div', { style: 'display:flex;align-items:flex-start;gap:10px;margin-bottom:8px' });
            const cb  = Utils.el('input', { type: 'checkbox', checked: true, style: 'margin-top:2px;width:15px;height:15px;flex-shrink:0;cursor:pointer' });
            const lbl = Utils.el('div', { style: 'cursor:pointer' });
            lbl.appendChild(Utils.el('span', { textContent: cat.label, style: 'font-weight:600;font-size:var(--font-size-sm);display:block' }));
            lbl.appendChild(Utils.el('span', { textContent: cat.desc, className: 'text-muted', style: 'font-size:var(--font-size-sm)' }));
            lbl.addEventListener('click', () => { cb.checked = !cb.checked; });
            checks[cat.id] = cb;
            row.append(cb, lbl);
            checkList.appendChild(row);
        }
        exportDiv.appendChild(checkList);

        const exportErrEl = Utils.el('p', { className: 'text-danger', style: 'display:none;font-size:var(--font-size-sm);margin-bottom:8px' });
        exportDiv.appendChild(exportErrEl);

        const exportBtn = Utils.el('button', { className: 'btn btn-primary btn-sm', textContent: 'Export Selected →' });
        exportBtn.addEventListener('click', async () => {
            const cats = _EXPORT_CATEGORIES.map(c => c.id).filter(id => checks[id].checked);
            if (!cats.length) { exportErrEl.textContent = 'Select at least one category.'; exportErrEl.style.display = ''; return; }
            exportErrEl.style.display = 'none';
            exportBtn.disabled = true;
            exportBtn.textContent = 'Exporting…';
            try {
                const data = await Api.get(`${_api()}/admin/settings/full-export?categories=${encodeURIComponent(cats.join(','))}`);
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url  = URL.createObjectURL(blob);
                const a    = document.createElement('a');
                a.href     = url;
                a.download = `filexfer-export-${new Date().toISOString().slice(0, 10)}.json`;
                a.click();
                URL.revokeObjectURL(url);
            } catch (err) {
                exportErrEl.textContent = 'Export failed: ' + err.message;
                exportErrEl.style.display = '';
            } finally {
                exportBtn.disabled = false;
                exportBtn.textContent = 'Export Selected →';
            }
        });
        exportDiv.appendChild(exportBtn);
        wrap.appendChild(exportDiv);

        // ---- Divider -----------------------------------------------------------
        wrap.appendChild(Utils.el('hr', { style: 'border-color:var(--color-border);margin:0 0 28px' }));

        // ---- Import -----------------------------------------------------------
        const importDiv = Utils.el('div');
        importDiv.appendChild(Utils.el('h5', { textContent: 'Import', style: 'margin-bottom:6px' }));
        importDiv.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:14px',
            textContent: 'Import a previously exported configuration file. Only categories present in the file and checked below will be applied.',
        }));

        let _parsedImport = null;
        let _importCategories = [];

        const fileInp = Utils.el('input', { type: 'file', accept: '.json', style: 'display:block;margin-bottom:8px' });
        const fileStatus = Utils.el('p', { style: 'font-size:var(--font-size-sm);margin:0 0 10px' });
        importDiv.append(fileInp, fileStatus);

        const importCatWrap = Utils.el('div', { style: 'display:none;margin-bottom:12px' });
        const importCatList = Utils.el('div', { style: 'margin-bottom:10px' });
        importCatWrap.appendChild(Utils.el('p', { textContent: 'Categories in file:', style: 'font-weight:600;font-size:var(--font-size-sm);margin-bottom:6px' }));
        importCatWrap.appendChild(importCatList);
        importDiv.appendChild(importCatWrap);

        const modeRow = Utils.el('div', { style: 'display:flex;align-items:center;gap:10px;margin-bottom:12px' });
        modeRow.appendChild(Utils.el('label', { textContent: 'Mode:', style: 'font-weight:600;margin:0;font-size:var(--font-size-sm);white-space:nowrap' }));
        const modeSel = Utils.el('select', { className: 'input-sm', style: 'width:auto' }, [
            Utils.el('option', { value: 'replace', textContent: 'Replace — wipe and overwrite each selected category' }),
            Utils.el('option', { value: 'merge',   textContent: 'Merge — add or update, keep existing entries not in file' }),
        ]);
        modeRow.appendChild(modeSel);
        importDiv.appendChild(modeRow);

        const importErrEl  = Utils.el('p', { className: 'text-danger',  style: 'display:none;font-size:var(--font-size-sm);margin-bottom:8px' });
        const importOkEl   = Utils.el('p', { className: 'text-success', style: 'display:none;font-size:var(--font-size-sm);margin-bottom:8px' });
        importDiv.append(importErrEl, importOkEl);

        const importBtn = Utils.el('button', { className: 'btn btn-danger btn-sm', textContent: 'Apply Import', disabled: true });
        importDiv.appendChild(importBtn);

        const importCatChecks = {};

        fileInp.addEventListener('change', async () => {
            _parsedImport = null;
            _importCategories = [];
            importCatWrap.style.display = 'none';
            importCatList.innerHTML = '';
            importBtn.disabled = true;
            importErrEl.style.display = 'none';
            importOkEl.style.display = 'none';
            if (!fileInp.files[0]) return;
            try {
                const text = await fileInp.files[0].text();
                _parsedImport = JSON.parse(text);
                const meta = _parsedImport._meta || {};
                const fmtVer = meta.format_version || '?';
                const cats   = meta.categories || Object.keys(_parsedImport).filter(k => !k.startsWith('_'));
                _importCategories = cats;

                fileStatus.style.color = 'var(--color-success)';
                fileStatus.textContent = `✓ Loaded (format v${fmtVer}, exported ${meta.exported_at ? meta.exported_at.slice(0,10) : '?'})`;

                // Build category checkboxes
                importCatList.innerHTML = '';
                for (const catId of cats) {
                    const catMeta = _EXPORT_CATEGORIES.find(c => c.id === catId);
                    const row = Utils.el('div', { style: 'display:flex;align-items:center;gap:8px;margin-bottom:6px' });
                    const cb  = Utils.el('input', { type: 'checkbox', checked: true, style: 'width:15px;height:15px;cursor:pointer' });
                    const lbl = Utils.el('span', { textContent: catMeta ? catMeta.label : catId, style: 'font-size:var(--font-size-sm);cursor:pointer' });
                    lbl.addEventListener('click', () => { cb.checked = !cb.checked; });
                    importCatChecks[catId] = cb;
                    row.append(cb, lbl);
                    importCatList.appendChild(row);
                }

                if (_parsedImport._warnings?.length) {
                    const warnBox = Utils.el('div', { style: 'background:var(--color-warning-muted,#fff3cd);border:1px solid var(--color-warning,#ffc107);border-radius:4px;padding:8px;margin-top:8px' });
                    for (const w of _parsedImport._warnings) {
                        warnBox.appendChild(Utils.el('p', { textContent: w, style: 'font-size:var(--font-size-sm);margin:2px 0' }));
                    }
                    importCatList.appendChild(warnBox);
                }

                importCatWrap.style.display = '';
                importBtn.disabled = false;
            } catch {
                fileStatus.style.color = 'var(--color-danger)';
                fileStatus.textContent = '✗ Could not parse file — confirm it is valid JSON';
            }
        });

        importBtn.addEventListener('click', async () => {
            if (!_parsedImport) return;
            const selCats = _importCategories.filter(id => importCatChecks[id]?.checked);
            if (!selCats.length) { importErrEl.textContent = 'Select at least one category.'; importErrEl.style.display = ''; return; }
            const mode = modeSel.value;
            const confirmMsg = mode === 'replace'
                ? `Replace selected categories (${selCats.join(', ')}) with data from the file?\n\nThis will overwrite existing entries for these categories. Continue?`
                : `Merge selected categories (${selCats.join(', ')}) from file into current config?\n\nExisting entries not in the file are kept.`;
            if (!confirm(confirmMsg)) return;
            importBtn.disabled = true;
            importBtn.textContent = 'Applying…';
            importErrEl.style.display = 'none';
            importOkEl.style.display = 'none';
            try {
                const result = await Api.post(`${_api()}/admin/settings/full-import`, {
                    data: _parsedImport,
                    categories: selCats,
                    mode,
                });
                const summary = Object.entries(result.items_applied || {})
                    .map(([k, v]) => `${k}: ${v}`)
                    .join(', ');
                importOkEl.textContent = `✓ Import applied. Items: ${summary || 'none'}`;
                importOkEl.style.display = '';
            } catch (err) {
                importErrEl.textContent = 'Import failed: ' + err.message;
                importErrEl.style.display = '';
            } finally {
                importBtn.disabled = false;
                importBtn.textContent = 'Apply Import';
            }
        });

        wrap.appendChild(importDiv);
        container.appendChild(wrap);
    }

    function _showApplyProfileModal(profileId, refreshFn) {
        const modal = Utils.el('div', { style: 'position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:2000;display:flex;align-items:center;justify-content:center' });
        const box   = Utils.el('div', { style: 'background:var(--color-bg,#fff);border-radius:8px;padding:24px;width:640px;max-width:95vw;max-height:80vh;overflow-y:auto' });

        box.appendChild(Utils.el('h4', { textContent: `Apply Profile: ${profileId.replaceAll('_', ' ')}`, style: 'margin-bottom:16px' }));

        const modeRow = Utils.el('div', { style: 'display:flex;gap:12px;margin-bottom:16px;align-items:center' });
        modeRow.appendChild(Utils.el('label', { textContent: 'Mode:', style: 'font-weight:600;margin:0' }));
        const modeSelect = Utils.el('select', { className: 'input-sm', style: 'width:auto' }, [
            Utils.el('option', { value: 'replace', textContent: 'Replace all' }),
            Utils.el('option', { value: 'merge',   textContent: 'Merge' }),
        ]);
        modeRow.appendChild(modeSelect);
        box.appendChild(modeRow);

        const diffArea = Utils.el('div', { style: 'margin-bottom:16px' });
        box.appendChild(diffArea);

        const confirmRow = Utils.el('div', { style: 'display:none;margin-bottom:12px' });
        const confirmInp = Utils.el('input', { type: 'text', className: 'input-sm', style: 'width:100%', placeholder: 'Type REPLACE to confirm' });
        confirmRow.appendChild(Utils.el('p', { style: 'color:var(--color-danger,#dc3545);margin-bottom:4px', textContent: 'This will replace all sharing rules and security settings. Type REPLACE to confirm.' }));
        confirmRow.appendChild(confirmInp);
        box.appendChild(confirmRow);

        const btnRow   = Utils.el('div', { style: 'display:flex;gap:8px' });
        const previewBtn = Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Preview diff' });
        const applyBtn   = Utils.el('button', { className: 'btn btn-primary btn-sm', textContent: 'Apply', disabled: true });
        const cancelBtn  = Utils.el('button', { className: 'btn btn-secondary btn-sm', textContent: 'Cancel' });
        btnRow.append(previewBtn, applyBtn, cancelBtn);
        box.appendChild(btnRow);

        cancelBtn.addEventListener('click', () => modal.remove());

        let diffData = null;

        async function loadDiff() {
            previewBtn.disabled = true;
            diffArea.textContent = 'Loading diff…';
            try {
                const resp = await Api.post(`${_api()}/admin/settings/apply-profile`, {
                    profile: profileId, mode: modeSelect.value, confirm: false,
                });
                diffData = resp.diff || [];
                _renderDiffTable(diffArea, diffData, modeSelect.value);
                applyBtn.disabled = false;
                if (modeSelect.value === 'replace') confirmRow.style.display = '';
                else confirmRow.style.display = 'none';
            } catch (err) {
                diffArea.textContent = 'Error loading diff: ' + err.message;
            } finally {
                previewBtn.disabled = false;
            }
        }

        previewBtn.addEventListener('click', loadDiff);
        modeSelect.addEventListener('change', () => { applyBtn.disabled = true; diffArea.textContent = ''; confirmRow.style.display = 'none'; });

        applyBtn.addEventListener('click', async () => {
            const mode = modeSelect.value;
            const confirmText = mode === 'replace' ? confirmInp.value : 'REPLACE';
            if (mode === 'replace' && confirmInp.value !== 'REPLACE') {
                alert('Type REPLACE to confirm replacement of all settings.');
                return;
            }
            applyBtn.disabled = true;
            applyBtn.textContent = 'Applying…';
            try {
                const decisions = {};
                if (mode === 'merge') {
                    diffArea.querySelectorAll('[data-decision-key]').forEach(sel => {
                        decisions[sel.dataset.decisionKey] = sel.value;
                    });
                }
                await Api.post(`${_api()}/admin/settings/apply-profile`, {
                    profile: profileId, mode, confirm: true,
                    confirmation_text: confirmText, decisions,
                });
                modal.remove();
                refreshFn();
            } catch (err) {
                _showError(box, 'Apply failed: ' + err.message);
                applyBtn.disabled = false;
                applyBtn.textContent = 'Apply';
            }
        });

        modal.appendChild(box);
        document.body.appendChild(modal);
    }

    function _renderDiffTable(container, diff, mode) {
        container.innerHTML = '';
        if (!diff.length) {
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No differences — current settings already match the profile.' }));
            return;
        }
        const same    = diff.filter(d => !d.changed);
        if (same.length) {
            container.appendChild(Utils.el('p', {
                className: 'text-muted',
                style: 'font-size:var(--font-size-sm)',
                textContent: `${same.length} setting(s) already match — shown below.`,
            }));
        }

        const table = Utils.el('table', { className: 'admin-table', style: 'font-size:var(--font-size-sm);width:100%' });
        const thead = Utils.el('thead');
        thead.appendChild(Utils.el('tr', {}, [
            Utils.el('th', { textContent: 'Setting' }),
            Utils.el('th', { textContent: 'Current' }),
            Utils.el('th', { textContent: 'Proposed' }),
            ...(mode === 'merge' ? [Utils.el('th', { textContent: 'Use' })] : []),
        ]));
        table.appendChild(thead);

        const tbody = Utils.el('tbody');
        for (const d of diff) {
            const tr = Utils.el('tr', { style: d.changed ? 'background:rgba(255,243,205,.4)' : '' });
            tr.appendChild(Utils.el('td', { textContent: d.label }));
            tr.appendChild(Utils.el('td', { textContent: d.current == null ? '(not set)' : JSON.stringify(d.current), style: 'word-break:break-all' }));
            tr.appendChild(Utils.el('td', { textContent: JSON.stringify(d.proposed), style: 'word-break:break-all' }));
            if (mode === 'merge') {
                const sel = Utils.el('select', { className: 'input-sm', style: 'width:auto', dataset: { decisionKey: d.key } }, [
                    Utils.el('option', { value: 'proposed', textContent: 'Proposed', selected: true }),
                    Utils.el('option', { value: 'current',  textContent: 'Keep current' }),
                ]);
                if (!d.changed) sel.value = 'current';
                tr.appendChild(Utils.el('td', {}, [sel]));
            }
            tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        container.appendChild(table);
    }

    return { renderAdminPage };
})();
