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
            _buildSection('theme',     'Theme & Branding',   _renderTheme),
            _buildSection('roles',     'Roles & Permissions',_renderRoles),
            _buildSection('policy',    'Policy Engine',      _renderPolicySection),
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
    // Helpers
    // ------------------------------------------------------------------

    function _showError(container, msg) {
        container.innerHTML = '';
        const p = Utils.el('p', { className: 'text-error' });
        p.textContent = msg;
        container.appendChild(p);
    }

    function _fmtBytes(bytes) {
        if (bytes === 0 || bytes == null) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1);
        const val = bytes / Math.pow(1024, i);
        return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`;
    }

    return { renderAdminPage };
})();
