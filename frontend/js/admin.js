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
            _buildSection('settings',  'System Settings',  _renderSettings),
            _buildSection('disk',      'Disk Usage',        _renderDiskUsage),
            _buildSection('users',     'User Management',   _renderUsers),
            _buildSection('invites',   'Invites',           _renderInvites),
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
