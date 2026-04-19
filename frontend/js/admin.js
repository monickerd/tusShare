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

    function renderAdminPage(container) {
        container.innerHTML = '';

        const page = Utils.el('div', { className: 'admin-page' }, [
            Utils.el('h2', { className: 'admin-title', textContent: 'Admin Dashboard' }),
        ]);

        const sections = [
            _buildSection('settings',  'System Settings',   _renderSettings),
            _buildSection('disk',      'Disk Usage',         _renderDiskUsage),
            _buildSection('users',     'User Management',    _renderUsers),
            _buildSection('invites',   'Invites',            _renderInvites),
            _buildSection('mfa',       'MFA Policy',         _renderMfaAdmin),
            _buildSection('idp',       'Identity Providers', _renderIdpSection),
            _buildSection('theme',     'Theme & Branding',   _renderTheme),
            _buildSection('roles',     'Roles & Permissions',_renderRoles),
            _buildSection('policy',    'Policy Engine',      _renderPolicySection),
            _buildSection('audit',         'Audit & SIEM',          _renderAuditSection),
            _buildSection('storage',       'Storage',               _renderStorageSection),
            _buildSection('notifications', 'Notification Channels', _renderNotificationsSection),
            _buildSection('api-keys',      'API Keys',              _renderApiKeysSection),
            _buildSection('antivirus',     'Antivirus',             _renderAntivirusSection),
        ];
        sections.forEach(s => page.appendChild(s));
        container.appendChild(page);
    }

    // ------------------------------------------------------------------
    // Section scaffold — collapsible wrapper
    // ------------------------------------------------------------------

    function _buildSection(id, title, renderFn) {
        let loaded = false;
        const body = Utils.el('div', { className: 'admin-section-body' });

        const toggle = Utils.el('button', {
            className: 'admin-section-toggle',
            textContent: title,
            onClick: () => {
                const open = body.style.display !== 'none';
                body.style.display = open ? 'none' : '';
                toggle.classList.toggle('collapsed', open);
                if (!open && !loaded) {
                    loaded = true;
                    renderFn(body);
                }
            },
        });

        const section = Utils.el('div', { className: 'admin-section', id: `admin-${id}` }, [
            Utils.el('div', { className: 'admin-section-header' }, [toggle]),
            body,
        ]);

        // Open the first section by default
        if (id === 'settings') {
            body.style.display = '';
            toggle.classList.remove('collapsed');
            renderFn(body);
            loaded = true;
        } else {
            body.style.display = 'none';
            toggle.classList.add('collapsed');
        }

        return section;
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
            const raw = parseInt(s[key] || '0', 10);
            return divisor > 1 ? Math.round(raw / divisor) : raw;
        };

        // Helper: labelled row
        const _row = (label, hint, input) => Utils.el('div', { className: 'settings-row' }, [
            Utils.el('label', { className: 'settings-label', textContent: label }),
            Utils.el('div', { className: 'settings-input-wrap' }, [
                input,
                hint ? Utils.el('span', { className: 'settings-hint', textContent: hint }) : null,
            ].filter(Boolean)),
        ]);

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

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Save Settings',
            onClick: async () => {
                const chunkMb = parseInt(fldChunkSize.value, 10);
                if (isNaN(chunkMb) || chunkMb < 1) {
                    Utils.showToast('Default chunk size must be at least 1 MB', 'error');
                    return;
                }
                const payload = {
                    global_max_file_size:   String(parseInt(fldMaxFileSize.value, 10) * _MB),
                    global_bandwidth_limit: String(parseInt(fldBandwidth.value, 10)   * _MB),
                    disk_warning_threshold: String(parseInt(fldDiskWarn.value, 10)),
                    default_chunk_size:     String(chunkMb * _MB),
                    open_registration:      fldOpenReg.checked ? 'true' : 'false',
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
            _row('Default chunk size (MB)', 'Informational — clients use their own config value', fldChunkSize),
            _row('Open registration', 'Allow anyone to register without an invite', fldOpenReg),
            Utils.el('div', { className: 'settings-actions' }, [saveBtn]),
        ]));
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
        fsLine.textContent = data.filesystem_total > 0
            ? `${_fmtBytes(data.filesystem_total - data.filesystem_free)} used of ${_fmtBytes(data.filesystem_total)} (${pct}%)${warn ? ' ⚠ above warning threshold' : ''}`
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
                    textContent: uPct !== null ? `${uPct}%` : '—',
                    className: uPct !== null && uPct >= 90 ? 'text-warn' : '',
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

        const thead = Utils.el('thead', {}, [
            Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Username' }),
                Utils.el('th', { textContent: 'Roles' }),
                Utils.el('th', { textContent: 'Disk Used' }),
                Utils.el('th', { textContent: 'Quota (MB)' }),
                Utils.el('th', { textContent: 'BW Limit (MB/s)' }),
                Utils.el('th', { textContent: 'File Limit (MB)' }),
                Utils.el('th', { textContent: 'Active' }),
                Utils.el('th', { textContent: 'Actions' }),
            ]),
        ]);

        const tbody = Utils.el('tbody');
        const currentUser = Auth.getCurrentUser();

        for (const u of data.users) {
            tbody.appendChild(_buildUserRow(u, currentUser, () => _renderUsers(container)));
        }

        container.innerHTML = '';
        container.appendChild(Utils.el('table', { className: 'admin-table admin-users-table' }, [thead, tbody]));
    }

    function _buildUserRow(u, currentUser, refreshFn) {
        const isSelf = u.id === currentUser.id;

        // Editable number input (0 = no limit; blank also treated as 0)
        const _numInput = (val, divisor = 1) => Utils.el('input', {
            type: 'number', min: '0', className: 'input-xs',
            value: val != null ? String(Math.round(val / divisor)) : '',
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
                    const n = parseInt(input.value, 10);
                    return isNaN(n) || n === 0 ? null : n * _MB;
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
                if (fldQuota.value === '' || parseInt(fldQuota.value, 10) === 0) payload.disk_quota = null;
                if (fldBw.value    === '' || parseInt(fldBw.value,    10) === 0) payload.bandwidth_limit = null;
                if (fldMax.value   === '' || parseInt(fldMax.value,   10) === 0) payload.max_file_size = null;
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

        const deleteBtn = isSelf ? null : Utils.el('button', {
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

        const actions = Utils.el('td', { className: 'admin-actions' }, [
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

        // Pending invites only in main list; used invites shown in a collapsed sub-section
        const pending = data.invites.filter(i => !i.used_at);
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
                    Utils.el('td', { textContent: i.used_at    ? i.used_at.slice(0, 16).replace('T', ' ') : '—' }),
                    Utils.el('td', { textContent: i.used_by_ip || '—' }),
                ]));
            });
            return Utils.el('details', { className: 'admin-used-invites' }, [
                Utils.el('summary', { textContent: `${used.length} used invite${used.length !== 1 ? 's' : ''}` }),
                Utils.el('table', { className: 'admin-table admin-table-sm' }, [
                    Utils.el('thead', {}, [
                        Utils.el('tr', {}, [
                            Utils.el('th', { textContent: 'Created' }),
                            Utils.el('th', { textContent: 'Expired' }),
                            Utils.el('th', { textContent: 'Used At' }),
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
        const expiresDate = invite.expires_at ? invite.expires_at.slice(0, 16).replace('T', ' ') : '—';
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
            Utils.el('span', { className: 'invite-meta', textContent: `Created ${createdDate} · Expires ${expiresDate} UTC` }),
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

        const inviteUrl = `${window.location.origin}/register/${data.token}`;

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
                    shortLinkInput.value = `${window.location.origin}/${sl.slug}`;
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

    // Category display order and labels
    const _FLAG_CATEGORIES = [
        { key: 'admin',        label: 'Administration' },
        { key: 'roles',        label: 'Role Management' },
        { key: 'observability',label: 'Observability' },
        { key: 'audit',        label: 'Audit Trail' },
        { key: 'integrations', label: 'Integrations' },
        { key: 'policy',       label: 'Policy Engine' },
        { key: 'files',        label: 'File Access' },
    ];

    async function _renderRoles(container) {
        container.innerHTML = '<p class="text-muted">Loading…</p>';
        let data;
        try {
            data = await Api.get(`${_api()}/admin/roles`);
        } catch (err) {
            _showError(container, 'Failed to load roles: ' + err.message);
            return;
        }

        const { roles, flags } = data;

        // Index flags by category for grouped rendering
        const flagsByCategory = {};
        for (const f of flags) {
            (flagsByCategory[f.category] = flagsByCategory[f.category] || []).push(f);
        }

        const createBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Create Custom Role',
            onClick: () => _showCreateRoleModal(flags, () => _renderRoles(container)),
        });

        const roleList = Utils.el('div', { className: 'roles-list' });
        for (const role of roles) {
            roleList.appendChild(_buildRoleCard(role, flags, flagsByCategory, () => _renderRoles(container)));
        }

        container.innerHTML = '';
        container.appendChild(Utils.el('div', { className: 'roles-header' }, [createBtn]));
        container.appendChild(roleList);
    }

    function _buildRoleCard(role, flags, flagsByCategory, refreshFn) {
        const body = Utils.el('div', { className: 'role-card-body', style: 'display:none' });
        let bodyLoaded = false;

        const toggleBtn = Utils.el('button', {
            className: 'role-card-toggle collapsed',
            onClick: () => {
                const open = body.style.display !== 'none';
                body.style.display = open ? 'none' : '';
                toggleBtn.classList.toggle('collapsed', open);
                if (!open && !bodyLoaded) {
                    bodyLoaded = true;
                    _populateRoleCardBody(body, role, flags, flagsByCategory, refreshFn);
                }
            },
        });
        toggleBtn.appendChild(Utils.el('span', { className: 'role-card-name', textContent: role.name }));
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

    function _populateRoleCardBody(container, role, flags, flagsByCategory, refreshFn) {
        // Description row
        const descEl = Utils.el('p', { className: 'role-desc text-muted', textContent: role.description || '(no description)' });

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

        const deleteBtn = role.is_system ? null : Utils.el('button', {
            className: 'btn btn-danger btn-sm',
            textContent: 'Delete Role',
            onClick: async () => {
                if (!confirm(`Delete role "${role.name}"? All users currently holding this role will lose it.`)) return;
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
        const flagInputs = {};   // flag → checkbox element
        const flagSections = _FLAG_CATEGORIES
            .filter(cat => flagsByCategory[cat.key])
            .map(cat => {
                const rows = (flagsByCategory[cat.key] || []).map(f => {
                    const currentVal = (role.permissions || {})[f.flag] || '0';
                    const chk = Utils.el('input', {
                        type: 'checkbox',
                        checked: currentVal === '1',
                        title: f.is_sensitive ? 'Sensitive — requires Server Admin or Org Admin to activate' : '',
                    });
                    flagInputs[f.flag] = chk;
                    return Utils.el('div', { className: 'flag-row' + (f.is_sensitive ? ' flag-sensitive' : '') }, [
                        Utils.el('label', { className: 'flag-label' }, [
                            chk,
                            Utils.el('span', { className: 'flag-name', textContent: f.flag }),
                            f.is_sensitive ? Utils.el('span', { className: 'flag-sensitive-badge', textContent: 'sensitive' }) : null,
                        ].filter(Boolean)),
                        Utils.el('span', { className: 'flag-desc', textContent: f.description }),
                    ]);
                });
                return Utils.el('div', { className: 'flag-category' }, [
                    Utils.el('h5', { className: 'flag-category-label', textContent: cat.label }),
                    ...rows,
                ]);
            });

        const saveFlagsBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Save Permissions',
            onClick: async () => {
                const permissions = {};
                for (const [flag, chk] of Object.entries(flagInputs)) {
                    permissions[flag] = chk.checked ? '1' : '0';
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

        container.innerHTML = '';
        container.appendChild(Utils.el('div', { className: 'role-card-content' }, [
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

    function _showCreateRoleModal(flags, refreshFn) {
        // Reuse the existing modal infrastructure — build a form in a dialog
        const flagsByCategory = {};
        for (const f of flags) {
            (flagsByCategory[f.category] = flagsByCategory[f.category] || []).push(f);
        }

        const fldId   = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'e.g. finance_reviewer' });
        const fldName = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'Role display name' });
        const fldDesc = Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'Optional description' });

        const flagInputs = {};
        const flagSections = _FLAG_CATEGORIES
            .filter(cat => flagsByCategory[cat.key])
            .map(cat => {
                const rows = (flagsByCategory[cat.key] || []).map(f => {
                    const chk = Utils.el('input', {
                        type: 'checkbox',
                        title: f.is_sensitive ? 'Sensitive — only Server/Org Admin may activate' : '',
                    });
                    flagInputs[f.flag] = chk;
                    return Utils.el('div', { className: 'flag-row' + (f.is_sensitive ? ' flag-sensitive' : '') }, [
                        Utils.el('label', { className: 'flag-label' }, [
                            chk,
                            Utils.el('span', { className: 'flag-name', textContent: f.flag }),
                            f.is_sensitive ? Utils.el('span', { className: 'flag-sensitive-badge', textContent: 'sensitive' }) : null,
                        ].filter(Boolean)),
                        Utils.el('span', { className: 'flag-desc', textContent: f.description }),
                    ]);
                });
                return Utils.el('div', { className: 'flag-category' }, [
                    Utils.el('h5', { className: 'flag-category-label', textContent: cat.label }),
                    ...rows,
                ]);
            });

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
                        await Api.delete(`${_api()}/admin/policy-fields/${f.name}`);
                        Utils.showToast('Field deleted', 'success');
                        refreshFn();
                    } catch (err) {
                        Utils.showToast('Delete failed: ' + err.message, 'error');
                    }
                },
            });
            const tr = Utils.el('tr');
            tr.innerHTML = `
                <td><code>${f.name}</code></td>
                <td>${f.display_label}</td>
                <td><span class="badge badge-${f.source}">${f.source}</span></td>
                <td>${f.data_type}</td>
                <td>${f.claim_path || '—'}</td>
            `;
            const actionTd = Utils.el('td');
            if (deleteBtn) actionTd.appendChild(deleteBtn);
            tr.appendChild(actionTd);
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
            (byHolder[key] = byHolder[key] || { holder_type: c.holder_type, holder_id: c.holder_id, conds: [] }).conds.push(c);
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
                                await Api.delete(`${_api()}/admin/scopes/conditions/${c.id}`);
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

        // E4b: escrow badge + toggle button in header
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
                    await Api.delete(`${_api()}/admin/policies/${policy.id}`);
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

    function _populatePolicyBody(container, policy, fields, refreshFn) {
        container.innerHTML = '';

        // ── Conditions ──────────────────────────────────────────────────
        const condHeader = Utils.el('h5', { className: 'policy-body-section-title', textContent: 'Conditions' });
        container.appendChild(condHeader);

        if (!policy.conditions.length) {
            container.appendChild(Utils.el('p', { className: 'text-muted', textContent: 'No conditions yet. Add at least one condition for this policy to match users.' }));
        } else {
            const table = Utils.el('table', { className: 'policy-table' });
            table.innerHTML = `<thead><tr>
                <th>Field</th><th>Operator</th><th>Value</th><th>Strict</th><th>Inherited</th><th></th>
            </tr></thead>`;
            const tbody = Utils.el('tbody');
            for (const cond of policy.conditions) {
                const isInherited = cond.inherited_scope_id !== null;
                const isDetached  = cond.scope_detached;
                const deleteCondBtn = isInherited ? null : Utils.el('button', {
                    className: 'btn btn-danger btn-xs',
                    textContent: 'Remove',
                    onClick: async () => {
                        try {
                            await Api.delete(`${_api()}/admin/policies/${policy.id}/conditions/${cond.id}`);
                            Utils.showToast('Condition removed', 'success');
                            refreshFn();
                        } catch (err) {
                            Utils.showToast('Failed: ' + err.message, 'error');
                        }
                    },
                });

                const inheritedCell = isInherited
                    ? (isDetached
                        ? Utils.el('span', { className: 'text-warn', textContent: 'detached' })
                        : Utils.el('span', { className: 'text-muted', textContent: 'locked' }))
                    : Utils.el('span', { textContent: '—' });

                const tr = Utils.el('tr', { className: isDetached ? 'cond-row-detached' : '' });
                tr.innerHTML = `
                    <td><code>${cond.field}</code></td>
                    <td>${cond.operator}</td>
                    <td>${cond.value}</td>
                    <td>${cond.strict ? 'yes' : 'no'}</td>
                `;
                const inheritedTd = Utils.el('td');
                inheritedTd.appendChild(inheritedCell);
                const actionTd = Utils.el('td');
                if (deleteCondBtn) actionTd.appendChild(deleteCondBtn);
                tr.appendChild(inheritedTd);
                tr.appendChild(actionTd);
                tbody.appendChild(tr);
            }
            table.appendChild(tbody);
            container.appendChild(table);
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
            wrap.innerHTML = `<span class="text-error">Failed to load effects: ${err.message}</span>`;
        }
    }

    function _renderEffects(wrap, policy, effects, refreshFn) {
        wrap.innerHTML = '';

        if (!effects.length) {
            wrap.appendChild(Utils.el('p', { className: 'text-muted policy-effects-empty', textContent: 'No effects yet. Add an effect to define what this policy grants.' }));
        } else {
            const table = Utils.el('table', { className: 'policy-table' });
            table.innerHTML = `<thead><tr>
                <th>Type</th><th>Target ID</th><th>Details</th><th></th>
            </tr></thead>`;
            const tbody = Utils.el('tbody');
            for (const eff of effects) {
                const badgeClass = eff.effect_type === 'team_member' ? 'team'
                    : eff.effect_type === 'team_escrow' ? 'escrow'
                    : 'folder';
                const typeBadge = Utils.el('span', {
                    className: `badge badge-effect-${badgeClass}`,
                    textContent: eff.effect_type,
                });
                let detailText;
                if (eff.effect_type === 'team_member') {
                    detailText = `role: ${eff.role_level}`;
                } else if (eff.effect_type === 'team_escrow') {
                    detailText = eff.escrow_override === 1 ? 'force-on'
                        : eff.escrow_override === 0 ? 'force-off'
                        : 'override';
                } else {
                    detailText = `${eff.permission}${eff.recursive ? ', recursive' : ''}`;
                }

                const deleteBtn = Utils.el('button', {
                    className: 'btn btn-danger btn-xs',
                    textContent: 'Remove',
                    onClick: async () => {
                        if (!confirm('Remove this effect? Policy-sourced grants for this effect will be revoked for all users.')) return;
                        try {
                            await Api.delete(`${_api()}/admin/policies/${policy.id}/effects/${eff.id}`);
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
                targetTd.innerHTML = `<code class="policy-uuid-cell">${eff.target_id}</code>`;
                const detailTd = Utils.el('td', { className: 'text-muted', textContent: detailText });
                const actionTd = Utils.el('td');
                actionTd.appendChild(deleteBtn);
                tr.appendChild(typeTd);
                tr.appendChild(targetTd);
                tr.appendChild(detailTd);
                tr.appendChild(actionTd);
                tbody.appendChild(tr);
            }
            table.appendChild(tbody);
            wrap.appendChild(table);
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
                    payload.escrow_override = parseInt(escrowOverrideEl.value, 10);
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
            Utils.el('label', { textContent: 'Team ID' }),
            Utils.el('input', { type: 'text', className: 'input-sm', placeholder: 'Team UUID', id: 'new-policy-scope-id' }),
        ]);
        scopeTypeEl.addEventListener('change', () => {
            scopeIdWrap.style.display = scopeTypeEl.value === 'team' ? '' : 'none';
        });
        // E4b: escrow_enabled toggle
        const escrowEl = Utils.el('input', { type: 'checkbox' });
        const escrowRow = Utils.el('div', { className: 'policy-strict-row' }, [
            escrowEl,
            Utils.el('label', { textContent: ' Enable key escrow (escrow agents receive sk_team for all covered teams)' }),
        ]);
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
                        scope_id:       scopeTypeEl.value === 'team' ? (scopeIdInput ? scopeIdInput.value.trim() : null) : null,
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

        const _row = (label, hint, input) => Utils.el('div', { className: 'settings-row' }, [
            Utils.el('label', { className: 'settings-label', textContent: label }),
            Utils.el('div', { className: 'settings-input-wrap' }, [
                input,
                hint ? Utils.el('span', { className: 'settings-hint', textContent: hint }) : null,
            ].filter(Boolean)),
        ]);

        const currentEnforcement = s['mfa_enforcement'] || 'off';
        const selEnforcement = Utils.el('select', { className: 'input-sm' });
        for (const [val, label] of [['off', 'Off — MFA not required'], ['optional', 'Optional — encourage but don\'t require'], ['required', 'Required — block access until enrolled']]) {
            selEnforcement.appendChild(Utils.el('option', { value: val, textContent: label, selected: val === currentEnforcement }));
        }

        let currentMethods = ['totp', 'webauthn'];
        try { currentMethods = JSON.parse(s['mfa_allowed_methods'] || '["totp","webauthn"]'); } catch {}
        const cbTotp = Utils.el('input', { type: 'checkbox', checked: currentMethods.includes('totp') });
        const cbWebAuthn = Utils.el('input', { type: 'checkbox', checked: currentMethods.includes('webauthn') });
        const cbEmailOtp = Utils.el('input', { type: 'checkbox', checked: currentMethods.includes('email_otp'), disabled: true, title: 'Email OTP not yet available' });

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
            Utils.el('label', { style: 'display:flex;gap:4px;align-items:center;opacity:0.5' }, [cbEmailOtp, Utils.el('span', { textContent: 'Email OTP (future)' })]),
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

        const thead = Utils.el('thead', {}, [
            Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Username' }),
                Utils.el('th', { textContent: 'MFA Credentials' }),
                Utils.el('th', { textContent: 'Actions' }),
            ]),
        ]);
        const tbody = Utils.el('tbody');

        for (const u of users) {
            const mfaCell = Utils.el('td', { textContent: '…', className: 'text-muted' });
            const actionsCell = Utils.el('td', { className: 'admin-actions' });

            // Load per-user MFA info async
            Api.get(`${_api()}/admin/users/${u.id}/mfa`).then(mfaData => {
                const creds = mfaData.credentials || [];
                mfaCell.textContent = creds.length === 0 ? 'None' : creds.map(c => c.method).join(', ');

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
            }).catch(() => {
                mfaCell.textContent = '(error)';
            });

            tbody.appendChild(Utils.el('tr', {}, [
                Utils.el('td', { textContent: u.username }),
                mfaCell,
                actionsCell,
            ]));
        }

        container.innerHTML = '';
        container.appendChild(Utils.el('h4', { textContent: 'Per-User MFA Status', style: 'margin-bottom:8px' }));
        container.appendChild(Utils.el('table', { className: 'admin-table' }, [thead, tbody]));
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
    // Identity Providers section (E6)
    // ------------------------------------------------------------------

    async function _renderIdpSection(container) {
        container.innerHTML = '<p class="text-muted" style="padding:16px">Loading…</p>';
        try {
            const data = await Api.get(`${_api()}/admin/identity-providers`);
            _renderIdpList(container, data.providers || []);
        } catch (err) {
            container.innerHTML = `<p class="error-text" style="padding:16px">Failed to load: ${err.message}</p>`;
        }
    }

    function _renderIdpList(container, providers) {
        container.innerHTML = '';
        const wrap = Utils.el('div', { style: 'padding:16px' });
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
            className: prov.is_active ? 'badge badge-success' : 'badge badge-neutral',
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
                        await Api.delete(`${_api()}/admin/identity-providers/${prov.id}`);
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
        const dialog = Utils.el('div', { className: 'modal-dialog', style: 'max-width:560px' });
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
                Utils.el('input', { type: 'url', id: 'oidc-redirect-uri', value: cfg.redirect_uri || (window.location.origin + '/api/v1/auth/oidc/callback') }),
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
        const dialog = Utils.el('div', { className: 'modal-dialog', style: 'max-width:640px' });
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
            body.innerHTML = `<p class="error-text">Failed to load wizard: ${err.message}</p>`;
        }
    }

    // ------------------------------------------------------------------
    // Section: Audit & SIEM
    // ------------------------------------------------------------------

    async function _renderAuditSection(container) {
        container.innerHTML = '<p class="text-muted" style="padding:16px">Loading…</p>';
        try {
            const [logsData, siemData, settingsData] = await Promise.all([
                Api.get(`${_api()}/admin/audit/logs?limit=50`),
                Api.get(`${_api()}/admin/audit/siem`),
                Api.get(`${_api()}/admin/settings`),
            ]);
            _renderAudit(container, logsData.events || [], siemData.destinations || [], settingsData.settings || {});
        } catch (err) {
            container.innerHTML = `<p class="error-text" style="padding:16px">Failed to load: ${err.message}</p>`;
        }
    }

    function _renderAudit(container, events, destinations, settings) {
        container.innerHTML = '';
        const wrap = Utils.el('div', { style: 'padding:16px' });
        container.appendChild(wrap);

        // --- Retention setting ---
        const retentionDays = parseInt(settings['audit_retention_days'] || '365', 10);
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

        // --- Live stream toggle ---
        let _streamSource = null;
        const streamStatus = Utils.el('span', { className: 'badge badge-neutral', textContent: 'Disconnected', style: 'margin-left:8px' });
        const streamBtn = Utils.el('button', {
            className: 'btn btn-sm', textContent: 'Connect',
            onClick: () => {
                if (_streamSource) {
                    _streamSource.close();
                    _streamSource = null;
                    streamBtn.textContent = 'Connect';
                    streamStatus.className = 'badge badge-neutral';
                    streamStatus.textContent = 'Disconnected';
                    return;
                }
                const token = Auth.getToken ? Auth.getToken() : '';
                const url = `${_api()}/admin/audit/logs/stream`;
                _streamSource = new EventSource(url);
                streamBtn.textContent = 'Disconnect';
                streamStatus.className = 'badge badge-info';
                streamStatus.textContent = 'Connecting…';
                _streamSource.onopen = () => {
                    streamStatus.className = 'badge badge-success';
                    streamStatus.textContent = 'Connected';
                };
                _streamSource.onerror = () => {
                    streamStatus.className = 'badge badge-error';
                    streamStatus.textContent = 'Error';
                };
                _streamSource.addEventListener('message', ev => {
                    try { _prependStreamEvent(liveTable, JSON.parse(ev.data)); } catch {}
                });
                // Listen on all event type names is handled by the catch-all above
            },
        });
        wrap.appendChild(Utils.el('div', { style: 'margin-bottom:12px; display:flex; align-items:center; gap:8px' }, [
            Utils.el('strong', { textContent: 'Live stream:' }),
            streamBtn,
            streamStatus,
        ]));

        // --- Live stream table (populated by SSE) ---
        const liveTable = _buildAuditTable([]);
        liveTable.style.marginBottom = '24px';
        wrap.appendChild(Utils.el('h4', { textContent: 'Recent events (live)', style: 'margin:0 0 8px' }));
        wrap.appendChild(liveTable);

        // --- Historical log query ---
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

        const filterRow = Utils.el('div', { style: 'display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px; align-items:center' }, [
            etInput, sevSel, uidInput,
            Utils.el('span', { textContent: 'From:', style: 'font-size:.85em' }), sinceIn,
            Utils.el('span', { textContent: 'To:',   style: 'font-size:.85em' }), untilIn,
            queryBtn, exportBtn,
        ]);
        wrap.appendChild(filterRow);

        const histTable = _buildAuditTable(events);
        wrap.appendChild(histTable);

        const _buildQs = () => {
            const p = new URLSearchParams();
            if (etInput.value.trim())  p.set('event_types', etInput.value.trim());
            if (sevSel.value !== 'info') p.set('severity', sevSel.value);
            if (uidInput.value.trim()) p.set('user_id', uidInput.value.trim());
            if (sinceIn.value) p.set('since', sinceIn.value.replace('T', ' '));
            if (untilIn.value) p.set('until', untilIn.value.replace('T', ' '));
            return p.toString();
        };

        queryBtn.onclick = async () => {
            queryBtn.disabled = true;
            try {
                const data = await Api.get(`${_api()}/admin/audit/logs?limit=200&${_buildQs()}`);
                _populateAuditTable(histTable, data.events || []);
            } catch (e) {
                Utils.showToast('Query failed: ' + e.message, 'error');
            } finally {
                queryBtn.disabled = false;
            }
        };

        exportBtn.onclick = () => {
            window.location = `${_api()}/admin/audit/logs/export?${_buildQs()}`;
        };

        // --- SIEM destinations ---
        wrap.appendChild(Utils.el('hr', { style: 'margin:24px 0' }));
        wrap.appendChild(Utils.el('h4', { textContent: 'SIEM Destinations', style: 'margin:0 0 12px' }));

        const siemWrap = Utils.el('div');
        wrap.appendChild(siemWrap);
        _renderSiemList(siemWrap, destinations);
    }

    // --- Audit table helpers ---

    function _buildAuditTable(events) {
        const table = Utils.el('table', { className: 'admin-table' });
        table.appendChild(Utils.el('thead', {}, [
            Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Time' }),
                Utils.el('th', { textContent: 'Type' }),
                Utils.el('th', { textContent: 'Sev' }),
                Utils.el('th', { textContent: 'Outcome' }),
                Utils.el('th', { textContent: 'Actor' }),
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
                Utils.el('td', { colSpan: 6, className: 'text-muted', textContent: 'No events.', style: 'text-align:center; padding:12px' }),
            ]));
            return;
        }
        for (const ev of events) {
            tbody.appendChild(_buildAuditRow(ev));
        }
    }

    function _prependStreamEvent(table, ev) {
        const tbody = table.querySelector('tbody');
        const emptyRow = tbody.querySelector('td[colspan]');
        if (emptyRow) emptyRow.closest('tr').remove();
        tbody.insertBefore(_buildAuditRow(ev), tbody.firstChild);
        // Cap live table at 100 rows
        while (tbody.children.length > 100) tbody.removeChild(tbody.lastChild);
    }

    function _buildAuditRow(ev) {
        const sevClass = ev.severity === 'critical' ? 'badge-error' : ev.severity === 'warning' ? 'badge-warning' : 'badge-neutral';
        return Utils.el('tr', {}, [
            Utils.el('td', { textContent: ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 19) : '' }),
            Utils.el('td', { textContent: ev.event_type }),
            Utils.el('td', {}, [Utils.el('span', { className: `badge ${sevClass}`, textContent: ev.severity || 'info' })]),
            Utils.el('td', { textContent: ev.outcome || '' }),
            Utils.el('td', { textContent: ev.actor_user_id || ev.actor_username || '' }),
            Utils.el('td', { textContent: ev.target_name || ev.target_id || '' }),
        ]);
    }

    // --- SIEM destination management ---

    function _renderSiemList(container, destinations) {
        container.innerHTML = '';
        container.appendChild(Utils.el('button', {
            className: 'btn btn-primary', style: 'margin-bottom:16px',
            textContent: '+ Add Destination',
            onClick: () => _showSiemModal(null, container),
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
                Utils.el('th', { textContent: 'Active' }),
                Utils.el('th', { textContent: 'Actions' }),
            ]),
        ]));
        const tbody = Utils.el('tbody');
        for (const dest of destinations) {
            tbody.appendChild(_buildSiemRow(dest, container));
        }
        table.appendChild(tbody);
        container.appendChild(table);
    }

    function _buildSiemRow(dest, container) {
        const activeBadge = Utils.el('span', {
            className: dest.is_active ? 'badge badge-success' : 'badge badge-neutral',
            textContent: dest.is_active ? 'Active' : 'Inactive',
        });
        const hostOrUrl = dest.type === 'syslog'
            ? `${dest.host || ''}:${dest.port || 514}`
            : (dest.url || '');

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
            Utils.el('td', {}, [activeBadge]),
            Utils.el('td', { className: 'row-actions' }, [
                Utils.el('button', {
                    className: 'btn btn-sm', textContent: 'Edit',
                    onClick: () => _showSiemModal(dest, container),
                }),
                testBtn,
                Utils.el('button', {
                    className: 'btn btn-sm btn-danger', textContent: 'Delete',
                    onClick: async (ev) => {
                        if (!confirm(`Delete SIEM destination "${dest.name}"?`)) return;
                        ev.target.disabled = true;
                        try {
                            await Api.delete(`${_api()}/admin/audit/siem/${dest.id}`);
                            Utils.showToast('Destination deleted', 'success');
                            const data = await Api.get(`${_api()}/admin/audit/siem`);
                            _renderSiemList(container, data.destinations || []);
                        } catch (err) {
                            Utils.showToast('Delete failed: ' + err.message, 'error');
                            ev.target.disabled = false;
                        }
                    },
                }),
            ]),
        ]);
    }

    function _showSiemModal(dest, listContainer) {
        const isEdit = dest !== null;
        const title  = isEdit ? 'Edit SIEM Destination' : 'Add SIEM Destination';
        const { modal, body, close } = Utils.openModal(title);

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

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary', textContent: isEdit ? 'Save' : 'Add',
            onClick: async () => {
                saveBtn.disabled = true;
                const payload = {
                    name:          nameIn.value.trim(),
                    type:          typeSel.value,
                    is_active:     activeCb.checked,
                    host:          typeSel.value === 'syslog' ? hostIn.value.trim() || null : null,
                    port:          typeSel.value === 'syslog' ? parseInt(portIn.value, 10) || 514 : null,
                    protocol:      typeSel.value === 'syslog' ? protoSel.value : null,
                    syslog_format: typeSel.value === 'syslog' ? fmtSel.value : null,
                    url:           typeSel.value === 'webhook' ? urlIn.value.trim() || null : null,
                    secret:        typeSel.value === 'webhook' && secretIn.value ? secretIn.value : null,
                    batch_size:    typeSel.value === 'webhook' ? parseInt(batchIn.value, 10) || 1 : 1,
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
                    _renderSiemList(listContainer, data.destinations || []);
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
        body.appendChild(Utils.el('div', { style: 'margin-top:16px; display:flex; gap:8px' }, [
            saveBtn,
            Utils.el('button', { className: 'btn btn-secondary', textContent: 'Cancel', onClick: close }),
        ]));
    }

    // =========================================================================
    // Storage section
    // =========================================================================

    async function _renderStorageSection(container) {
        container.innerHTML = '<p class="text-muted" style="padding:16px">Loading…</p>';
        try {
            const [volumes, usage, tiers] = await Promise.all([
                Api.get(`${_api()}/admin/storage/volumes`),
                Api.get(`${_api()}/admin/storage/usage`),
                Api.get(`${_api()}/admin/storage/tiers`),
            ]);
            _renderStoragePanel(container, volumes, usage, tiers);
        } catch (err) {
            container.innerHTML = `<p class="error-text" style="padding:16px">Failed to load: ${err.message}</p>`;
        }
    }

    function _renderStoragePanel(container, volumes, usage, tiers) {
        container.innerHTML = '';
        const wrap = Utils.el('div', { style: 'padding:16px' });
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

        wrap.appendChild(Utils.el('button', {
            className: 'btn btn-primary', style: 'margin-top:12px',
            textContent: 'Save Tiering Policy',
            onClick: async (ev) => {
                ev.target.disabled = true;
                try {
                    const warnPctVal  = warnPctIn.value.trim()   !== '' ? parseFloat(warnPctIn.value)  : null;
                    const warnBytesVal = warnBytesIn.value.trim() !== '' ? parseInt(warnBytesIn.value, 10) : null;
                    await Api.put(`${_api()}/admin/storage/tiers`, {
                        enabled: enabledCb.checked,
                        hot_to_warm_days:       parseInt(hotWarmIn.value, 10) || null,
                        warm_to_cold_days:      parseInt(warmColdIn.value, 10) || null,
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
        const usageText = volUsage
            ? (volUsage.error ? 'Unavailable' : `${_fmtBytes(volUsage.used_bytes)} / ${volUsage.total_bytes ? _fmtBytes(volUsage.total_bytes) : '∞'}`)
            : '—';
        const usageWarning = volUsage?.warning
            ? Utils.el('span', { className: 'badge badge-warning', style: 'margin-left:6px', title: volUsage.warning, textContent: '⚠ ' + volUsage.warning })
            : null;

        const actions = Utils.el('div', { className: 'row-actions' }, [
            Utils.el('button', {
                className: 'btn btn-sm', textContent: 'Edit',
                onClick: () => _showStorageVolumeModal(vol, container),
            }),
            Utils.el('button', {
                className: 'btn btn-sm', textContent: 'Test',
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
                        await Api.delete(`${_api()}/admin/storage/volumes/${vol.id}`);
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
                vol.is_default ? Utils.el('span', { className: 'badge badge-success', textContent: 'Default' }) : Utils.el('span'),
            ]),
            Utils.el('td', {}, [actions]),
        ]);
    }

    function _showStorageVolumeModal(vol, container) {
        const isEdit = !!vol;
        const { modal, body, close } = Utils.createModal(isEdit ? 'Edit Storage Volume' : 'Add Storage Volume');

        const nameIn = Utils.el('input', { type: 'text', className: 'settings-input', value: vol?.name || '', placeholder: 'Display name' });
        const provSel = Utils.el('select', { className: 'settings-input' });
        for (const p of ['local', 's3', 'b2']) {
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

        const s3Fields = Utils.el('div', {}, [
            Utils.el('p', {
                className: 'text-muted',
                style: 'font-size:0.85em; padding:6px 0; border-left:3px solid var(--color-warning,#f0ad4e); padding-left:8px; margin-bottom:8px',
                textContent: 'Security: use a dedicated IAM user scoped to this bucket only (s3:GetObject, s3:PutObject, s3:DeleteObject, s3:ListBucket). Avoid root or full-access credentials. Ensure the bucket has public access blocked at the provider level.',
            }),
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

        const _updateFields = () => {
            configWrap.innerHTML = '';
            if (provSel.value === 'local') configWrap.appendChild(localFields);
            else configWrap.appendChild(s3Fields);
        };
        provSel.onchange = _updateFields;
        _updateFields();

        const saveBtn = Utils.el('button', {
            className: 'btn btn-primary', textContent: isEdit ? 'Save' : 'Add',
            onClick: async () => {
                saveBtn.disabled = true;
                let cfg = {};
                if (provSel.value === 'local') {
                    const fd = configWrap.querySelector('#sv-files-dir')?.value.trim();
                    const ud = configWrap.querySelector('#sv-uploads-dir')?.value.trim();
                    if (fd) cfg.files_dir = fd;
                    if (ud) cfg.uploads_dir = ud;
                } else {
                    cfg = {
                        endpoint_url:      configWrap.querySelector('#sv-endpoint')?.value.trim() || null,
                        bucket:            configWrap.querySelector('#sv-bucket')?.value.trim(),
                        region:            configWrap.querySelector('#sv-region')?.value.trim() || 'us-east-1',
                        access_key_id:     configWrap.querySelector('#sv-key-id')?.value.trim(),
                        secret_access_key: configWrap.querySelector('#sv-secret')?.value || (isEdit ? '••••••••' : ''),
                    };
                }
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
    }

    function _fmtBytes(bytes) {
        if (bytes === 0 || bytes == null) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1);
        const val = bytes / Math.pow(1024, i);
        return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`;
    }

    // ------------------------------------------------------------------
    // Section: Notification Channels (G1)
    // ------------------------------------------------------------------

    async function _renderNotificationsSection(container) {
        container.innerHTML = '<p class="text-muted" style="padding:16px">Loading…</p>';
        try {
            const [channelsData, settingsData] = await Promise.all([
                Api.get(`${_api()}/admin/notifications/channels`),
                Api.get(`${_api()}/admin/notifications/settings`),
            ]);
            _renderNotificationsPanel(container, channelsData.channels || [], settingsData);
        } catch (err) {
            container.innerHTML = `<p class="error-text" style="padding:16px">Failed to load: ${err.message}</p>`;
        }
    }

    function _renderNotificationsPanel(container, channels, settings) {
        container.innerHTML = '';
        const wrap = Utils.el('div', { style: 'padding:16px' });

        // --- Settings card ---
        const settingsCard = Utils.el('div', { className: 'card', style: 'margin-bottom:16px' });
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
            const lbl = Utils.el('label', { textContent: f.label, style: 'display:block;font-size:13px;margin-bottom:4px' });
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
                    op_event_retention_days:  parseInt(inputs['op_event_retention_days'].value) || 30,
                    api_key_expiry_warn_days: parseInt(inputs['api_key_expiry_warn_days'].value) || 30,
                    upload_quota_warn_pct:    parseInt(inputs['upload_quota_warn_pct'].value) || 90,
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
                const tr = Utils.el('tr');
                const filters = (() => { try { return JSON.parse(ch.event_filter || '[]'); } catch { return []; } })();
                const filterStr = filters.length ? filters.join(', ') : '(all)';
                const batchStr  = ch.batch_size ? `${ch.batch_size} events` : (ch.batch_interval_s ? `${ch.batch_interval_s}s` : 'immediate');
                tr.innerHTML = `
                  <td>${Utils.escHtml(ch.name)}</td>
                  <td style="font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${Utils.escHtml(ch.endpoint_url)}</td>
                  <td style="font-size:12px">${Utils.escHtml(filterStr)}</td>
                  <td style="font-size:12px">${batchStr}</td>
                  <td><span class="${ch.enabled ? 'badge-success' : 'badge-muted'}">${ch.enabled ? 'enabled' : 'disabled'}</span></td>
                  <td></td>
                `;
                const actionsTd = tr.cells[5];
                const editBtn = Utils.el('button', { textContent: 'Edit', className: 'btn btn-sm', style: 'margin-right:4px' });
                editBtn.addEventListener('click', async () => {
                    const full = await Api.get(`${_api()}/admin/notifications/channels/${ch.id}`);
                    _showChannelModal(full, container);
                });
                const testBtn = Utils.el('button', { textContent: 'Test', className: 'btn btn-sm', style: 'margin-right:4px' });
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
                tbody.appendChild(tr);
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
            const table = Utils.el('table', { className: 'admin-table', style: 'width:100%;font-size:12px' });
            table.innerHTML = '<thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Source</th><th>Data</th></tr></thead>';
            const tbody = Utils.el('tbody');
            for (const ev of events) {
                const tr = Utils.el('tr');
                const dataStr = JSON.stringify(ev.data || {});
                tr.innerHTML = `
                  <td style="white-space:nowrap">${ev.created_at ? ev.created_at.slice(0, 19).replace('T', ' ') : ''}</td>
                  <td>${Utils.escHtml(ev.event_type)}</td>
                  <td><span class="badge-${ev.severity === 'error' ? 'danger' : ev.severity === 'warning' ? 'warning' : 'muted'}">${ev.severity}</span></td>
                  <td>${Utils.escHtml(ev.source)}</td>
                  <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${Utils.escHtml(dataStr.slice(0, 120))}</td>
                `;
                tbody.appendChild(tr);
            }
            table.appendChild(tbody);
            container.innerHTML = '';
            container.appendChild(table);
        } catch (err) {
            container.innerHTML = `<p class="error-text">Failed to load: ${err.message}</p>`;
        }
    }

    function _showChannelModal(channel, refreshContainer) {
        const isEdit = !!channel;
        const modal = Utils.el('div', { className: 'modal-overlay' });
        const box   = Utils.el('div', { className: 'modal-box', style: 'max-width:480px' });
        box.appendChild(Utils.el('h3', { textContent: isEdit ? 'Edit Channel' : 'Add Channel', style: 'margin-top:0' }));

        const mkField = (label, inp) => {
            const row = Utils.el('div', { style: 'margin-bottom:10px' });
            row.appendChild(Utils.el('label', { textContent: label, style: 'display:block;font-size:13px;margin-bottom:4px' }));
            row.appendChild(inp);
            return row;
        };

        const nameInp    = Utils.el('input', { type: 'text', value: channel?.name || '', style: 'width:100%', placeholder: 'e.g. Slack alerts' });
        const urlInp     = Utils.el('input', { type: 'text', value: channel?.endpoint_url || '', style: 'width:100%', placeholder: 'https://...' });
        const secretInp  = Utils.el('input', { type: 'password', style: 'width:100%', placeholder: isEdit ? '(unchanged)' : '(leave blank for unsigned)' });
        const filterInp  = Utils.el('textarea', { style: 'width:100%;height:80px;font-size:12px', placeholder: 'One prefix per line. Blank = all operational events.\nPrefix with security: for security events.' });
        if (channel?.event_filter) {
            try {
                filterInp.value = JSON.parse(channel.event_filter).join('\n');
            } catch { filterInp.value = ''; }
        }
        const batchSizeInp = Utils.el('input', { type: 'number', value: channel?.batch_size ?? '', style: 'width:120px', placeholder: 'e.g. 20' });
        const intervalInp  = Utils.el('input', { type: 'number', value: channel?.batch_interval_s ?? '', style: 'width:120px', placeholder: 'e.g. 86400' });
        const enabledChk   = Utils.el('input', { type: 'checkbox', checked: channel ? !!channel.enabled : true });

        if (!secretInp.value && !isEdit) {
            const warn = Utils.el('p', { style: 'font-size:12px;color:var(--color-warning,#d97706);margin:4px 0 0' });
            warn.textContent = 'No signing secret — deliveries will be unsigned JSON. Recommended: set a secret.';
            secretInp.addEventListener('input', () => { warn.style.display = secretInp.value ? 'none' : ''; });
            // append after building
        }

        box.append(
            mkField('Name', nameInp),
            mkField('Endpoint URL (must be https://)', urlInp),
            mkField('Signing secret', secretInp),
            mkField('Event filter (one prefix per line)', filterInp),
            mkField('Batch size (blank = immediate)', batchSizeInp),
            mkField('Flush interval (seconds, blank = disabled)', intervalInp),
        );

        const enabledRow = Utils.el('div', { style: 'margin-bottom:16px;display:flex;align-items:center;gap:8px' });
        enabledRow.append(enabledChk, Utils.el('label', { textContent: 'Enabled' }));
        box.appendChild(enabledRow);

        const errEl = Utils.el('p', { className: 'error-text', style: 'display:none;margin-bottom:8px' });
        box.appendChild(errEl);

        const btns = Utils.el('div', { style: 'display:flex;gap:8px;justify-content:flex-end' });
        const cancelBtn = Utils.el('button', { textContent: 'Cancel', className: 'btn btn-sm' });
        cancelBtn.addEventListener('click', () => document.body.removeChild(modal));
        const saveBtn = Utils.el('button', { textContent: isEdit ? 'Save Changes' : 'Add Channel', className: 'btn btn-primary btn-sm' });
        saveBtn.addEventListener('click', async () => {
            const filters = filterInp.value.trim()
                ? filterInp.value.trim().split('\n').map(s => s.trim()).filter(Boolean)
                : [];
            const body = {
                name:             nameInp.value.trim(),
                endpoint_url:     urlInp.value.trim(),
                secret:           secretInp.value || null,
                event_filter:     filters,
                batch_size:       batchSizeInp.value ? parseInt(batchSizeInp.value) : null,
                batch_interval_s: intervalInp.value ? parseInt(intervalInp.value) : null,
                enabled:          enabledChk.checked,
            };
            try {
                if (isEdit) {
                    await Api.put(`${_api()}/admin/notifications/channels/${channel.id}`, body);
                } else {
                    await Api.post(`${_api()}/admin/notifications/channels`, body);
                }
                document.body.removeChild(modal);
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
    // Section: API Keys (G1)
    // ------------------------------------------------------------------

    async function _renderApiKeysSection(container) {
        container.innerHTML = '<p class="text-muted" style="padding:16px">Loading…</p>';
        try {
            const data = await Api.get(`${_api()}/admin/api-keys`);
            _renderApiKeysPanel(container, data.keys || []);
        } catch (err) {
            container.innerHTML = `<p class="error-text" style="padding:16px">Failed to load: ${err.message}</p>`;
        }
    }

    function _renderApiKeysPanel(container, keys) {
        container.innerHTML = '';
        const wrap = Utils.el('div', { style: 'padding:16px' });

        const header = Utils.el('div', { style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:12px' });
        header.appendChild(Utils.el('h3', { textContent: 'API Keys', style: 'margin:0' }));
        const createBtn = Utils.el('button', { textContent: '+ Create API Key', className: 'btn btn-primary btn-sm' });
        createBtn.addEventListener('click', () => _showApiKeyModal(container));
        header.appendChild(createBtn);
        wrap.appendChild(header);

        if (keys.length === 0) {
            wrap.appendChild(Utils.el('p', { textContent: 'No API keys.', className: 'text-muted' }));
        } else {
            const table = Utils.el('table', { className: 'admin-table', style: 'width:100%' });
            table.innerHTML = '<thead><tr><th>Name</th><th>Scopes</th><th>Created</th><th>Last used</th><th>Expires</th><th>Actions</th></tr></thead>';
            const tbody = Utils.el('tbody');
            for (const k of keys) {
                const tr = Utils.el('tr');
                const scopes = (() => { try { return JSON.parse(k.scopes || '[]'); } catch { return []; } })();
                tr.innerHTML = `
                  <td>${Utils.escHtml(k.name)}</td>
                  <td style="font-size:12px">${Utils.escHtml(scopes.join(', '))}</td>
                  <td style="font-size:12px">${k.created_at ? k.created_at.slice(0, 10) : ''}</td>
                  <td style="font-size:12px">${k.last_used_at ? k.last_used_at.slice(0, 10) : 'never'}</td>
                  <td style="font-size:12px">${k.expires_at ? k.expires_at.slice(0, 10) : 'never'}</td>
                  <td></td>
                `;
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
                tr.cells[5].appendChild(revokeBtn);
                tbody.appendChild(tr);
            }
            table.appendChild(tbody);
            wrap.appendChild(table);
        }

        container.appendChild(wrap);
    }

    function _showApiKeyModal(refreshContainer) {
        const modal = Utils.el('div', { className: 'modal-overlay' });
        const box   = Utils.el('div', { className: 'modal-box', style: 'max-width:420px' });
        box.appendChild(Utils.el('h3', { textContent: 'Create API Key', style: 'margin-top:0' }));

        const nameInp   = Utils.el('input', { type: 'text', style: 'width:100%', placeholder: 'e.g. Grafana dashboard' });
        const expiryInp = Utils.el('input', { type: 'date', style: 'width:200px' });
        // Scope checkboxes
        const eventsChk = Utils.el('input', { type: 'checkbox', checked: true });
        const scopeRow  = Utils.el('div', { style: 'display:flex;align-items:center;gap:8px;margin-bottom:10px' });
        scopeRow.append(eventsChk, Utils.el('label', { textContent: 'events.read' }));

        const mkField = (label, inp) => {
            const row = Utils.el('div', { style: 'margin-bottom:10px' });
            row.appendChild(Utils.el('label', { textContent: label, style: 'display:block;font-size:13px;margin-bottom:4px' }));
            row.appendChild(inp);
            return row;
        };

        box.append(
            mkField('Name', nameInp),
            Utils.el('label', { textContent: 'Scopes', style: 'display:block;font-size:13px;margin-bottom:4px' }),
            scopeRow,
            mkField('Expiry date (optional)', expiryInp),
        );

        const errEl = Utils.el('p', { className: 'error-text', style: 'display:none;margin-bottom:8px' });
        box.appendChild(errEl);

        const btns = Utils.el('div', { style: 'display:flex;gap:8px;justify-content:flex-end' });
        const cancelBtn = Utils.el('button', { textContent: 'Cancel', className: 'btn btn-sm' });
        cancelBtn.addEventListener('click', () => document.body.removeChild(modal));
        const createBtn = Utils.el('button', { textContent: 'Create Key', className: 'btn btn-primary btn-sm' });
        createBtn.addEventListener('click', async () => {
            const scopes = eventsChk.checked ? ['events.read'] : [];
            const body = {
                name:       nameInp.value.trim(),
                scopes,
                expires_at: expiryInp.value ? expiryInp.value + 'T00:00:00Z' : null,
            };
            try {
                const result = await Api.post(`${_api()}/admin/api-keys`, body);
                document.body.removeChild(modal);
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
        const box   = Utils.el('div', { className: 'modal-box', style: 'max-width:500px' });
        box.appendChild(Utils.el('h3', { textContent: 'API Key Created', style: 'margin-top:0' }));
        box.appendChild(Utils.el('p', { textContent: `Copy this key now — it will not be shown again.`, style: 'color:var(--color-warning,#d97706)' }));
        box.appendChild(Utils.el('p', { textContent: keyName, style: 'font-weight:600;margin-bottom:6px' }));

        const codeWrap = Utils.el('div', { style: 'display:flex;gap:8px;align-items:center;margin-bottom:16px' });
        const code = Utils.el('code', { textContent: rawKey, style: 'word-break:break-all;background:var(--color-surface,#f5f5f5);padding:8px;border-radius:4px;flex:1;font-size:13px' });
        const copyBtn = Utils.el('button', { textContent: 'Copy', className: 'btn btn-sm' });
        copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(rawKey).then(() => { copyBtn.textContent = 'Copied!'; });
        });
        codeWrap.append(code, copyBtn);
        box.appendChild(codeWrap);

        const doneBtn = Utils.el('button', { textContent: 'Done', className: 'btn btn-primary btn-sm' });
        doneBtn.addEventListener('click', async () => {
            document.body.removeChild(modal);
            await _renderApiKeysSection(refreshContainer.closest('.admin-section-body') || refreshContainer);
        });
        box.appendChild(doneBtn);
        modal.appendChild(box);
        document.body.appendChild(modal);
    }

    // ------------------------------------------------------------------
    // Antivirus section (F5)
    // ------------------------------------------------------------------

    async function _renderAntivirusSection(container) {
        container.innerHTML = '';

        // --- Always-visible OS AV documentation card ---
        const infoCard = Utils.el('div', { className: 'card mb-3' });
        infoCard.innerHTML = `
            <div class="card-body">
                <h5 class="card-title">How antivirus scanning works</h5>
                <p><strong>Client-side (always active):</strong> All files are decrypted by the
                client's browser at download time. The decrypted file is saved to the browser's
                download folder via the standard browser download mechanism, where OS real-time AV
                will scan it automatically. No additional configuration needed.</p>
                <p><strong>OPFS partial-download window:</strong> During an interrupted or in-progress
                download, incomplete encrypted chunks exist in OPFS (origin-private storage, sandboxed,
                invisible to OS AV). These chunks are partial and not independently usable as malware.
                OS AV fires on the final write when the download completes or resumes. Recommend
                real-time AV with filesystem monitoring on endpoints.</p>
                <p><strong>Server-side scanning (optional):</strong> When
                <code>TUSSHARE_ESCROW_PRIVATE_KEY</code> is configured, files uploaded after that
                point can be decrypted and scanned server-side via a configurable AV webhook.
                The server sends plaintext to your AV endpoint; the webhook returns a verdict.</p>
            </div>
        `;
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

        const form = Utils.el('div', { className: 'card mb-3' });
        form.innerHTML = '<div class="card-body"><h5 class="card-title">Server-side AV webhook</h5></div>';
        const body = form.querySelector('.card-body');

        // Endpoint
        body.appendChild(Utils.el('label', { textContent: 'Webhook endpoint URL', className: 'form-label' }));
        const endpointInput = Utils.el('input', {
            type: 'text', className: 'form-control mb-2',
            placeholder: 'https://av.example.com/scan',
            value: s.av_scan_endpoint || '',
        });
        body.appendChild(endpointInput);

        // Secret
        body.appendChild(Utils.el('label', { textContent: 'Webhook secret (HMAC-SHA256)', className: 'form-label' }));
        const secretInput = Utils.el('input', {
            type: 'password', className: 'form-control mb-2',
            placeholder: 'Signing secret (leave blank to keep current)',
            value: '',
        });
        body.appendChild(secretInput);

        // require_clean toggle
        const requireRow = Utils.el('div', { className: 'form-check mb-2' });
        const requireCheck = Utils.el('input', {
            type: 'checkbox', className: 'form-check-input', id: 'av-require-clean',
        });
        requireCheck.checked = s.av_require_clean === 'true';
        requireRow.appendChild(requireCheck);
        requireRow.appendChild(Utils.el('label', {
            htmlFor: 'av-require-clean', className: 'form-check-label',
            textContent: 'Block download and batch-move for files not yet confirmed clean (av_require_clean)',
        }));
        body.appendChild(requireRow);

        // Retry attempts
        body.appendChild(Utils.el('label', { textContent: 'Retry attempts on webhook failure', className: 'form-label' }));
        const retryInput = Utils.el('input', {
            type: 'number', className: 'form-control mb-3',
            min: '1', max: '10',
            value: s.av_scan_retry_attempts || '3',
        });
        body.appendChild(retryInput);

        // Save button
        const saveBtn = Utils.el('button', { textContent: 'Save AV Settings', className: 'btn btn-primary btn-sm me-2' });
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
        body.appendChild(saveBtn);
        container.appendChild(form);

        // --- File status summary ---
        const statusCard = Utils.el('div', { className: 'card mb-3' });
        const statusBody = Utils.el('div', { className: 'card-body' });
        statusCard.appendChild(statusBody);

        async function _refreshStatus() {
            statusBody.innerHTML = '<h5 class="card-title">File AV status</h5><p class="text-muted">Loading…</p>';
            try {
                const counts = await Api.get(`${Config.app.apiPrefix}/admin/files/av-status`);
                statusBody.innerHTML = '<h5 class="card-title">File AV status</h5>';
                const table = Utils.el('table', { className: 'table table-sm table-bordered' });
                const thead = Utils.el('thead');
                thead.innerHTML = '<tr><th>Status</th><th>Count</th></tr>';
                const tbody = Utils.el('tbody');
                for (const [k, v] of Object.entries(counts)) {
                    const tr = Utils.el('tr');
                    tr.innerHTML = `<td>${k}</td><td>${v}</td>`;
                    tbody.appendChild(tr);
                }
                table.appendChild(thead);
                table.appendChild(tbody);
                statusBody.appendChild(table);

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
                statusBody.appendChild(rescanBtn);
            } catch (err) {
                statusBody.innerHTML = `<h5 class="card-title">File AV status</h5><p class="text-danger">${err.message}</p>`;
            }
        }

        await _refreshStatus();
        container.appendChild(statusCard);
    }

    return { renderAdminPage };
})();
