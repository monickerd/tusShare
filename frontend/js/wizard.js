/**
 * tusShare — First-run setup wizard.
 *
 * Rendered at #/setup when first_run_completed is absent or '0'.
 *
 * Screens:
 *   1. Org Identity    — brand name + logo upload
 *   2. Hardware Scan   — hw_scan recommendations + manual settings panel
 *   3. Security Profile — profile selector, Advanced accordion, Import
 *   4. Escrow Agents   (conditional — only if escrow coverage required)
 *   5. Done
 */
const Wizard = (() => {
    const _api = () => Config.app.apiPrefix;

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    let _state = {};

    function _resetState() {
        _state = {
            brandName:         '',
            logoUploaded:      false,
            hwScanResults:     null,
            profileSelected:   'recommended',
            profileImportJson: null,
            advancedValues:    null,
            requiresEscrow:    false,
        };
    }

    // -----------------------------------------------------------------------
    // Built-in profile defaults (mirrors backend _PROFILES for Advanced panel)
    // -----------------------------------------------------------------------

    const _PROFILE_ADVANCED = {
        high_security: {
            escrow_require_coverage:     true,
            notify_escrow_on_revocation: true,
            can_create_link_shares:      false,
            can_create_user_shares:      true,
            can_create_upload_grants:    true,
            can_share_folders:           false,
        },
        recommended: {
            escrow_require_coverage:     false,
            notify_escrow_on_revocation: true,
            can_create_link_shares:      true,
            can_create_user_shares:      true,
            can_create_upload_grants:    true,
            can_share_folders:           true,
        },
        open: {
            escrow_require_coverage:     false,
            notify_escrow_on_revocation: false,
            can_create_link_shares:      true,
            can_create_user_shares:      true,
            can_create_upload_grants:    true,
            can_share_folders:           true,
        },
    };

    const _PROFILE_LABELS = {
        high_security: {
            name: 'High Security',
            desc: 'Mandatory escrow; link & folder shares blocked; all security settings locked at tier 1 (server_admin only).',
        },
        recommended: {
            name: 'Recommended',
            desc: 'Sensible defaults for most deployments. Sharing enabled; escrow encouraged; settings locked at tier 2 (org_admin).',
        },
        open: {
            name: 'Open',
            desc: 'All sharing on, no restrictions, no locks. For dev, internal tooling, or environments with a separate policy layer.',
        },
    };

    // -----------------------------------------------------------------------
    // Shared UI helpers
    // -----------------------------------------------------------------------

    function _buildStepBar(currentStep, labels) {
        const n = labels.length;
        const bar = Utils.el('div', { style: 'display:flex;align-items:center;margin-bottom:28px' });
        for (let i = 0; i < n; i++) {
            const done   = i < currentStep;
            const active = i === currentStep;
            const dot = Utils.el('div', {
                style: [
                    'width:28px;height:28px;border-radius:50%;flex-shrink:0',
                    'display:flex;align-items:center;justify-content:center',
                    'font-size:12px;font-weight:700',
                    active ? 'background:var(--color-primary);color:#fff'
                    : done  ? 'background:var(--color-success);color:#fff'
                    : 'background:var(--color-surface-active);color:var(--color-text-muted)',
                ].join(';'),
                textContent: done ? '✓' : String(i + 1),
            });
            bar.appendChild(dot);
            const lbl = Utils.el('span', {
                style: `font-size:11px;margin:0 6px;white-space:nowrap;color:${active ? 'var(--color-text)' : 'var(--color-text-muted)'}`,
                textContent: labels[i],
            });
            bar.appendChild(lbl);
            if (i < n - 1) {
                bar.appendChild(Utils.el('div', {
                    style: `flex:1;height:2px;background:${done ? 'var(--color-success)' : 'var(--color-border)'};min-width:16px`,
                }));
            }
        }
        return bar;
    }

    function _navRow({ onPrev, onNext, nextLabel, onSkip, skipLabel } = {}) {
        const row = Utils.el('div', { style: 'display:flex;gap:8px;margin-top:28px;align-items:center' });
        if (onPrev) {
            row.appendChild(Utils.el('button', {
                className: 'btn btn-secondary btn-sm',
                textContent: '← Back',
                onClick: onPrev,
            }));
        }
        row.appendChild(Utils.el('div', { style: 'flex:1' }));
        let nextBtn = null;
        if (onSkip) {
            row.appendChild(Utils.el('button', {
                className: 'btn btn-light btn-sm',
                textContent: skipLabel || 'Skip',
                onClick: onSkip,
            }));
        }
        if (onNext) {
            nextBtn = Utils.el('button', {
                className: 'btn btn-primary btn-sm',
                textContent: nextLabel || 'Next →',
                onClick: onNext,
            });
            row.appendChild(nextBtn);
        }
        return { row, nextBtn };
    }

    function _errEl() {
        return Utils.el('div', { style: 'color:var(--color-danger);font-size:13px;margin-top:8px;display:none' });
    }

    function _showErr(el, msg) {
        el.textContent = msg;
        el.style.display = '';
    }

    function _hideErr(el) {
        el.style.display = 'none';
    }

    function _setSaving(btn, label) {
        btn.disabled = true;
        btn.textContent = label;
    }

    function _clearSaving(btn, label) {
        btn.disabled = false;
        btn.textContent = label;
    }

    // -----------------------------------------------------------------------
    // Screen 1: Org Identity
    // -----------------------------------------------------------------------

    async function _screen1(wrapper, navigate) {
        wrapper.innerHTML = '';

        const steps = ['Org Identity', 'Hardware', 'Security', 'Done'];
        wrapper.appendChild(_buildStepBar(0, steps));
        wrapper.appendChild(Utils.el('h3', { textContent: 'Organisation Identity', style: 'margin-bottom:4px' }));
        wrapper.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:24px',
            textContent: 'Set a brand name and logo for this deployment. Both can be updated later from Admin → System → Theme & Branding.',
        }));

        // Brand name
        const nameGrp = Utils.el('div', { style: 'margin-bottom:20px' });
        nameGrp.appendChild(Utils.el('label', {
            textContent: 'Brand Name',
            style: 'display:block;font-weight:600;margin-bottom:6px',
        }));
        const nameInp = Utils.el('input', {
            type: 'text',
            className: 'form-control form-control-sm',
            style: 'max-width:360px',
            maxLength: '64',
            placeholder: 'tusShare',
            value: _state.brandName || '',
        });
        nameGrp.appendChild(nameInp);
        nameGrp.appendChild(Utils.el('p', {
            className: 'settings-hint',
            textContent: 'Shown in the browser tab and page header. Leave blank to keep the default "tusShare".',
        }));
        wrapper.appendChild(nameGrp);

        // Logo upload
        const logoGrp = Utils.el('div', { style: 'margin-bottom:24px' });
        logoGrp.appendChild(Utils.el('label', {
            textContent: 'Logo',
            style: 'display:block;font-weight:600;margin-bottom:6px',
        }));
        const logoInp = Utils.el('input', {
            type: 'file',
            accept: 'image/png,image/jpeg,image/gif,image/svg+xml,image/webp',
            style: 'display:block;margin-bottom:4px',
        });
        logoGrp.appendChild(logoInp);
        logoGrp.appendChild(Utils.el('p', {
            className: 'settings-hint',
            textContent: 'PNG, JPEG, GIF, SVG, or WebP · max 2 MB. Replaces the text brand name in the header.',
        }));
        wrapper.appendChild(logoGrp);

        const err = _errEl();
        wrapper.appendChild(err);

        const { row, nextBtn } = _navRow({
            onNext: async () => {
                _hideErr(err);
                _setSaving(nextBtn, 'Saving…');
                try {
                    const brand = nameInp.value.trim();
                    if (brand) {
                        await Api.patch(`${_api()}/admin/theme`, { brand_name: brand });
                        _state.brandName = brand;
                        if (document.title) document.title = brand;
                    }
                    if (logoInp.files[0]) {
                        const csrf = Api.getCsrfToken();
                        const fd = new FormData();
                        fd.append('file', logoInp.files[0]);
                        const resp = await fetch(`${_api()}/admin/theme/logo`, {
                            method: 'POST',
                            headers: { 'X-CSRF-Token': csrf },
                            body: fd,
                            credentials: 'same-origin',
                        });
                        if (!resp.ok) {
                            const body = await resp.json().catch(() => ({}));
                            throw new Error(body.detail || `HTTP ${resp.status}`);
                        }
                        _state.logoUploaded = true;
                    }
                    navigate(2);
                } catch (e) {
                    _showErr(err, 'Save failed: ' + e.message);
                    _clearSaving(nextBtn, 'Next →');
                }
            },
            onSkip: () => navigate(2),
            skipLabel: 'Skip — use defaults',
        });
        wrapper.appendChild(row);
    }

    // -----------------------------------------------------------------------
    // Screen 2: Hardware Scan
    // -----------------------------------------------------------------------

    async function _screen2(wrapper, navigate) {
        wrapper.innerHTML = '';

        const steps = ['Org Identity', 'Hardware', 'Security', 'Done'];
        wrapper.appendChild(_buildStepBar(1, steps));
        wrapper.appendChild(Utils.el('h3', { textContent: 'Hardware & Capacity', style: 'margin-bottom:4px' }));
        wrapper.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:24px',
            textContent: 'Run a hardware scan for server recommendations, or configure capacity settings manually.',
        }));

        // Scan area
        const scanBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: '⚡ Run Hardware Scan',
            style: 'margin-bottom:12px',
        });
        const scanResults = Utils.el('div', { style: 'margin-bottom:16px' });
        wrapper.appendChild(scanBtn);
        wrapper.appendChild(scanResults);

        // Manual settings (collapsible)
        const manualToggle = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: '▶ Manual Configuration',
            style: 'width:100%;text-align:left;padding:10px 14px;margin-bottom:6px',
        });
        const manualPanel = Utils.el('div', {
            style: 'display:none;padding:16px;background:var(--color-surface-hover);border-radius:6px;margin-bottom:16px',
        });
        manualToggle.addEventListener('click', () => {
            const open = manualPanel.style.display !== 'none';
            manualPanel.style.display = open ? 'none' : '';
            manualToggle.textContent = (open ? '▶' : '▼') + ' Manual Configuration';
        });

        // Settings fields (stored in MB; API stores bytes)
        const _MB = 1048576;

        function _field(label, key, defaultVal, hint, min, max) {
            const grp = Utils.el('div', { style: 'margin-bottom:14px' });
            grp.appendChild(Utils.el('label', {
                textContent: label,
                style: 'display:block;font-weight:600;margin-bottom:4px;font-size:13px',
            }));
            const inp = Utils.el('input', {
                type: 'number',
                className: 'form-control form-control-sm',
                style: 'max-width:160px',
                value: String(defaultVal),
                min: String(min),
                max: String(max),
            });
            grp.appendChild(inp);
            if (hint) grp.appendChild(Utils.el('p', { className: 'settings-hint', textContent: hint }));
            return { grp, inp };
        }

        const { grp: chunkGrp, inp: chunkInp } = _field('Upload Chunk Size (MB)', 'default_chunk_size', 5, 'Larger = better throughput on fast links. Smaller = better reliability on slow links.', 1, 100);
        const { grp: maxGrp,   inp: maxInp   } = _field('Max File Size (MB)',        'global_max_file_size', 0, '0 = no limit.', 0, 1000000);
        const { grp: bwGrp,    inp: bwInp    } = _field('Bandwidth Limit (MB/s)',    'global_bandwidth_limit', 0, '0 = no limit. Applies per connection to uploads and downloads.', 0, 10000);
        manualPanel.append(chunkGrp, maxGrp, bwGrp);

        scanBtn.addEventListener('click', async () => {
            _setSaving(scanBtn, 'Scanning…');
            scanResults.innerHTML = '<p class="text-muted" style="font-size:13px">Running hardware probes — takes 1–3 seconds…</p>';
            try {
                const r = await Api.get(`${_api()}/admin/hw-scan`);
                _state.hwScanResults = r;

                const rec    = r.recommendations || {};
                const cpu    = r.cpu || {};
                const ram    = r.ram || {};
                const pbkdf2 = r.pbkdf2 || {};
                const disk   = r.disk || [];

                const _gb = bytes => bytes ? (bytes / 1073741824).toFixed(1) + ' GB' : '?';

                const tbl = Utils.el('table', { style: 'border-collapse:collapse;width:100%;font-size:13px;margin-top:4px' });

                function _row(label, value, note) {
                    const tr = Utils.el('tr');
                    tr.appendChild(Utils.el('td', { textContent: label, style: 'padding:5px 10px 5px 0;font-weight:600;color:var(--color-text-muted);white-space:nowrap;width:160px' }));
                    tr.appendChild(Utils.el('td', { textContent: String(value), style: 'padding:5px 8px;font-family:monospace' }));
                    tr.appendChild(Utils.el('td', { textContent: note || '', style: 'padding:5px 0 5px 8px;color:var(--color-text-muted);font-size:12px' }));
                    tbl.appendChild(tr);
                }

                _row('CPU cores',       cpu.logical_cores ?? '?',                  `Recommended thread pool: ${rec.thread_pool_size ?? '?'}`);
                _row('RAM',             `${_gb(ram.total_bytes)} total`,            `${_gb(ram.available_bytes)} available · ${ram.used_pct ?? '?'}% in use`);
                _row('PBKDF2 iters',    (rec.pbkdf2_iterations ?? '?').toLocaleString?.() ?? rec.pbkdf2_iterations ?? '?',
                    `~${pbkdf2.expected_ms ?? '?'} ms/login (target ${pbkdf2.target_ms ?? 200} ms)${pbkdf2.floored ? ' — OWASP floor applied' : ''}`);
                _row('PRE batch size',  rec.pre_batch_size ?? '?',                  'Re-encryption ops per DB transaction');

                for (const v of disk) {
                    _row(`Disk: ${v.volume_name}`, v.error || `${_gb(v.free_bytes)} free`,
                        v.error ? '' : `${_gb(v.used_bytes)} used · ${v.path || ''}`);
                }

                scanResults.innerHTML = '';
                scanResults.appendChild(Utils.el('p', {
                    style: 'font-weight:600;color:var(--color-success);font-size:13px;margin-bottom:8px',
                    textContent: '✓ Scan complete — results are informational. Adjust Manual Configuration below if needed.',
                }));
                scanResults.appendChild(tbl);

                // Auto-expand manual panel
                manualPanel.style.display = '';
                manualToggle.textContent = '▼ Manual Configuration';
            } catch (e) {
                scanResults.innerHTML = '';
                scanResults.appendChild(Utils.el('p', {
                    style: 'color:var(--color-danger);font-size:13px',
                    textContent: 'Scan failed: ' + e.message,
                }));
            } finally {
                _clearSaving(scanBtn, '⚡ Run Hardware Scan');
            }
        });

        wrapper.appendChild(manualToggle);
        wrapper.appendChild(manualPanel);

        const err = _errEl();
        wrapper.appendChild(err);

        const { row, nextBtn } = _navRow({
            onPrev: () => navigate(1),
            onNext: async () => {
                _hideErr(err);
                const settings = {};
                const chunk = parseInt(chunkInp.value, 10);
                if (!isNaN(chunk) && chunk >= 1) settings.default_chunk_size = String(chunk);
                const maxMb = parseInt(maxInp.value, 10);
                if (!isNaN(maxMb) && maxMb >= 0) settings.global_max_file_size = String(maxMb * _MB);
                const bwMbs = parseInt(bwInp.value, 10);
                if (!isNaN(bwMbs) && bwMbs >= 0) settings.global_bandwidth_limit = String(bwMbs * _MB);
                if (!Object.keys(settings).length) { navigate(3); return; }
                _setSaving(nextBtn, 'Saving…');
                try {
                    await Api.put(`${_api()}/admin/settings`, { settings });
                    navigate(3);
                } catch (e) {
                    _showErr(err, 'Failed to save settings: ' + e.message);
                    _clearSaving(nextBtn, 'Next →');
                }
            },
            onSkip: () => navigate(3),
            skipLabel: 'Skip',
        });
        wrapper.appendChild(row);
    }

    // -----------------------------------------------------------------------
    // Screen 3: Security Profile
    // -----------------------------------------------------------------------

    async function _screen3(wrapper, navigate) {
        wrapper.innerHTML = '';

        const steps = ['Org Identity', 'Hardware', 'Security', 'Done'];
        wrapper.appendChild(_buildStepBar(2, steps));
        wrapper.appendChild(Utils.el('h3', { textContent: 'Security Profile', style: 'margin-bottom:4px' }));
        wrapper.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:4px',
            textContent: 'Choose a security profile. This sets sharing restrictions, escrow behaviour, and which settings are locked for lower-tier admins.',
        }));
        wrapper.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:24px;font-size:12px',
            textContent: 'Unlocked settings can be adjusted any time from Admin → Security → Settings Profile.',
        }));

        // Profile selector row
        const selRow = Utils.el('div', { style: 'display:flex;align-items:center;gap:10px;margin-bottom:6px' });
        selRow.appendChild(Utils.el('label', { textContent: 'Profile:', style: 'font-weight:600;margin:0;white-space:nowrap' }));

        const profileSel = Utils.el('select', { className: 'form-select form-select-sm', style: 'max-width:260px' }, [
            Utils.el('option', { value: 'high_security', textContent: 'High Security' }),
            Utils.el('option', { value: 'recommended',   textContent: 'Recommended' }),
            Utils.el('option', { value: 'open',          textContent: 'Open' }),
            Utils.el('option', { value: 'import',        textContent: 'Import from file…' }),
            Utils.el('option', { value: 'custom',        textContent: 'Custom', disabled: true }),
        ]);
        profileSel.value = (_state.profileSelected && _state.profileSelected !== 'custom')
            ? _state.profileSelected : 'recommended';
        selRow.appendChild(profileSel);
        wrapper.appendChild(selRow);

        const descEl = Utils.el('p', { className: 'text-muted', style: 'font-size:13px;margin-bottom:14px;min-height:1.4em' });
        wrapper.appendChild(descEl);

        function _updateDesc() {
            const v = profileSel.value;
            descEl.textContent = _PROFILE_LABELS[v]?.desc ?? '';
        }
        _updateDesc();

        // Import area (shown when "Import from file…" selected)
        const importArea = Utils.el('div', {
            style: 'display:none;margin-bottom:12px;padding:12px;background:var(--color-surface-hover);border-radius:6px',
        });
        const importFileInp = Utils.el('input', {
            type: 'file', accept: '.json', style: 'display:block;margin-bottom:6px',
        });
        const importStatusEl = Utils.el('p', { style: 'font-size:12px;margin:0' });
        importArea.append(
            Utils.el('label', { textContent: 'Profile JSON file:', style: 'display:block;font-weight:600;margin-bottom:6px;font-size:13px' }),
            importFileInp,
            importStatusEl,
        );
        wrapper.appendChild(importArea);

        // Advanced accordion
        const advToggle = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: '▶ Advanced',
            style: 'width:100%;text-align:left;padding:10px 14px;margin-bottom:6px',
        });
        const advPanel = Utils.el('div', {
            style: 'display:none;padding:16px;background:var(--color-surface-hover);border-radius:6px;margin-bottom:14px',
        });
        advToggle.addEventListener('click', () => {
            const open = advPanel.style.display !== 'none';
            advPanel.style.display = open ? 'none' : '';
            advToggle.textContent = (open ? '▶' : '▼') + ' Advanced';
        });
        wrapper.appendChild(advToggle);
        wrapper.appendChild(advPanel);

        // Advanced state — mirrors the selected profile's defaults
        let _adv = { ...(_PROFILE_ADVANCED[profileSel.value] ?? _PROFILE_ADVANCED.recommended) };
        if (_state.advancedValues) _adv = { ..._state.advancedValues };

        let _importWarnings = [];
        let _advInputs = {};

        function _buildToggle(label, key, hint) {
            const r = Utils.el('div', { style: 'display:flex;align-items:flex-start;gap:10px;margin-bottom:10px' });
            const cb = Utils.el('input', { type: 'checkbox', checked: !!_adv[key], style: 'margin-top:2px;width:15px;height:15px;flex-shrink:0' });
            cb.addEventListener('change', () => {
                _adv[key] = cb.checked;
                _adv._modified = true;
                // Switch dropdown to Custom
                let customOpt = profileSel.querySelector('option[value="custom"]');
                if (customOpt) { customOpt.disabled = false; }
                profileSel.value = 'custom';
                _state.profileSelected = 'custom';
                _updateDesc();
            });
            _advInputs[key] = cb;
            const lbl = Utils.el('div');
            lbl.appendChild(Utils.el('span', { textContent: label, style: 'font-weight:600;font-size:13px' }));
            if (hint) lbl.appendChild(Utils.el('div', { textContent: hint, style: 'color:var(--color-text-muted);font-size:12px' }));
            lbl.addEventListener('click', () => cb.click());
            r.append(cb, lbl);
            return r;
        }

        function _renderAdv() {
            advPanel.innerHTML = '';
            advPanel.appendChild(Utils.el('p', {
                style: 'font-size:12px;color:var(--color-text-muted);margin-bottom:12px',
                textContent: 'Editing any value sets the profile to "Custom". Selecting a named profile from the dropdown resets these values to that profile\'s defaults.',
            }));

            const esc = Utils.el('div', { style: 'margin-bottom:14px' });
            esc.appendChild(Utils.el('strong', { textContent: 'Escrow', style: 'display:block;margin-bottom:8px;font-size:13px' }));
            esc.appendChild(_buildToggle('Require escrow coverage', 'escrow_require_coverage',
                'Teams cannot be created without an assigned escrow agent'));
            esc.appendChild(_buildToggle('Notify escrow agent on emergency revocation', 'notify_escrow_on_revocation', ''));
            advPanel.appendChild(esc);

            advPanel.appendChild(Utils.el('hr', { style: 'margin:8px 0 12px;border-color:var(--color-border)' }));

            const sh = Utils.el('div');
            sh.appendChild(Utils.el('strong', { textContent: 'Sharing (role_user defaults)', style: 'display:block;margin-bottom:8px;font-size:13px' }));
            sh.appendChild(_buildToggle('Allow link shares',   'can_create_link_shares',   'Publicly accessible share links'));
            sh.appendChild(_buildToggle('Allow user shares',   'can_create_user_shares',   'Direct file shares to specific users'));
            sh.appendChild(_buildToggle('Allow upload grants', 'can_create_upload_grants', 'Let others upload into a user\'s folder'));
            sh.appendChild(_buildToggle('Allow folder shares', 'can_share_folders',         'Share entire folder trees'));
            advPanel.appendChild(sh);
        }
        _renderAdv();

        // Parse imported JSON and load into Advanced
        function _loadImportIntoAdv(json) {
            const s = json.admin_settings || {};
            const f = json.role_flag_overrides?.role_user || {};
            _adv = {
                escrow_require_coverage:     (s.escrow_require_coverage?.value     ?? '0') !== '0',
                notify_escrow_on_revocation: (s.notify_escrow_on_revocation?.value ?? '1') !== '0',
                can_create_link_shares:   f.can_create_link_shares?.value   !== false && f.can_create_link_shares?.value   !== '0',
                can_create_user_shares:   f.can_create_user_shares?.value   !== false && f.can_create_user_shares?.value   !== '0',
                can_create_upload_grants: f.can_create_upload_grants?.value !== false && f.can_create_upload_grants?.value !== '0',
                can_share_folders:        f.can_share_folders?.value        !== false && f.can_share_folders?.value        !== '0',
            };
            _renderAdv();
        }

        importFileInp.addEventListener('change', async () => {
            const f = importFileInp.files[0];
            if (!f) return;
            try {
                const parsed = JSON.parse(await f.text());
                _state.profileImportJson = parsed;
                _importWarnings = parsed._warnings || [];
                importStatusEl.style.color = 'var(--color-success)';
                importStatusEl.textContent = `✓ Loaded: ${f.name}` + (_importWarnings.length ? ` · ${_importWarnings.length} warning(s)` : '');
                _loadImportIntoAdv(parsed);
                // Auto-expand Advanced so admin can review
                advPanel.style.display = '';
                advToggle.textContent = '▼ Advanced';
            } catch {
                importStatusEl.style.color = 'var(--color-danger)';
                importStatusEl.textContent = '✗ Could not parse file — confirm it is valid JSON';
                _state.profileImportJson = null;
            }
        });

        profileSel.addEventListener('change', () => {
            const v = profileSel.value;
            _state.profileSelected = v;
            _updateDesc();
            importArea.style.display = v === 'import' ? '' : 'none';
            if (_PROFILE_ADVANCED[v]) {
                // Named profile selected — reset Advanced to that profile's defaults
                _adv = { ..._PROFILE_ADVANCED[v] };
                _renderAdv();
            }
        });

        // Import warnings area (shown before applying)
        const warnArea = Utils.el('div', { style: 'display:none;margin-bottom:10px' });
        wrapper.appendChild(warnArea);

        const err = _errEl();
        wrapper.appendChild(err);

        const { row, nextBtn } = _navRow({
            onPrev: () => navigate(2),
            nextLabel: 'Apply & Continue →',
            onNext: async () => {
                _hideErr(err);
                const sel = profileSel.value;

                if (sel === 'import' && !_state.profileImportJson) {
                    _showErr(err, 'Select a profile JSON file first.');
                    return;
                }

                // Show import warnings before proceeding
                if (sel === 'import' && _importWarnings.length) {
                    warnArea.innerHTML = '';
                    warnArea.style.display = '';
                    const box = Utils.el('div', {
                        style: 'background:var(--color-warning-muted);border-radius:6px;padding:12px;margin-bottom:8px',
                    });
                    box.appendChild(Utils.el('strong', { textContent: '⚠ Import Warnings', style: 'display:block;margin-bottom:6px' }));
                    for (const w of _importWarnings) {
                        box.appendChild(Utils.el('p', { textContent: w, style: 'font-size:12px;margin:3px 0' }));
                    }
                    warnArea.appendChild(box);
                }

                _setSaving(nextBtn, 'Applying…');
                try {
                    if (sel === 'import') {
                        await Api.post(`${_api()}/admin/settings/import`, {
                            profile_json: _state.profileImportJson,
                            mode: 'replace',
                            confirm: true,
                            confirmation_text: 'REPLACE',
                        });
                        await Api.put(`${_api()}/admin/settings`, { settings: { first_run_completed: '1' } });
                    } else if (sel === 'custom') {
                        // Use 'open' as the unlocked base, then patch escrow/sharing overrides
                        await Api.post(`${_api()}/admin/settings/apply-profile`, {
                            profile: 'open', mode: 'replace', confirm: true,
                            confirmation_text: 'REPLACE', mark_first_run: false,
                        });
                        await Api.put(`${_api()}/admin/settings`, {
                            settings: {
                                first_run_completed:     '1',
                                escrow_require_coverage: _adv.escrow_require_coverage ? '1' : '0',
                                notify_escrow_on_revocation: _adv.notify_escrow_on_revocation ? '1' : '0',
                            },
                        });
                    } else {
                        await Api.post(`${_api()}/admin/settings/apply-profile`, {
                            profile: sel, mode: 'replace', confirm: true,
                            confirmation_text: 'REPLACE', mark_first_run: true,
                        });
                    }

                    _state.advancedValues = { ..._adv };
                    _state.requiresEscrow = !!_adv.escrow_require_coverage;
                    navigate(_state.requiresEscrow ? 4 : 5);
                } catch (e) {
                    _showErr(err, 'Failed to apply profile: ' + e.message);
                    _clearSaving(nextBtn, 'Apply & Continue →');
                }
            },
        });
        wrapper.appendChild(row);
    }

    // -----------------------------------------------------------------------
    // Screen 4 (conditional): Escrow Agents
    // -----------------------------------------------------------------------

    async function _screen4(wrapper, navigate) {
        wrapper.innerHTML = '';

        const steps = ['Org Identity', 'Hardware', 'Security', 'Escrow Agents', 'Done'];
        wrapper.appendChild(_buildStepBar(3, steps));
        wrapper.appendChild(Utils.el('h3', { textContent: 'Escrow Agents', style: 'margin-bottom:4px' }));
        wrapper.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:4px',
            textContent: 'The chosen profile requires escrow coverage. Assign at least one escrow agent now to avoid blocking team creation.',
        }));
        wrapper.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:24px;font-size:12px',
            textContent: 'Escrow agents hold decryption keys for team recovery. Only assign trusted administrators. More can be added later from Admin → Security → Escrow.',
        }));

        const listArea = Utils.el('div', { style: 'margin-bottom:16px' });
        listArea.innerHTML = '<p class="text-muted" style="font-size:13px">Loading users…</p>';
        wrapper.appendChild(listArea);

        const err = _errEl();
        wrapper.appendChild(err);

        const { row, nextBtn } = _navRow({
            onPrev: () => navigate(3),
            nextLabel: 'Finish Setup →',
            onSkip: () => navigate(5),
            skipLabel: 'Configure escrow later',
            onNext: async () => {
                _hideErr(err);
                const selected = Array.from(
                    listArea.querySelectorAll('input[type=checkbox]:checked'),
                ).map(cb => cb.dataset.userId);
                if (!selected.length) {
                    _showErr(err, 'Select at least one user, or click "Configure escrow later" to skip.');
                    return;
                }
                _setSaving(nextBtn, 'Assigning…');
                try {
                    for (const uid of selected) {
                        await Api.post(`${_api()}/admin/users/${uid}/roles/escrow_agent`);
                    }
                    navigate(5);
                } catch (e) {
                    _showErr(err, 'Failed to assign escrow role: ' + e.message);
                    _clearSaving(nextBtn, 'Finish Setup →');
                }
            },
        });
        wrapper.appendChild(row);

        // Load users asynchronously (after nav row is in DOM)
        try {
            const { users } = await Api.get(`${_api()}/admin/users`);
            listArea.innerHTML = '';
            const me = Auth.getCurrentUser();
            const eligible = (users || []).filter(u => u.auth_method !== 'service');
            if (!eligible.length) {
                listArea.appendChild(Utils.el('p', { className: 'text-muted', style: 'font-size:13px', textContent: 'No users found.' }));
                return;
            }
            for (const u of eligible) {
                const r = Utils.el('div', { style: 'display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--color-border)' });
                const cb = Utils.el('input', {
                    type: 'checkbox',
                    dataset: { userId: u.id },
                    style: 'width:15px;height:15px',
                    checked: u.id === me?.id,  // pre-select self
                });
                r.appendChild(cb);
                r.appendChild(Utils.el('span', {
                    textContent: u.username,
                    style: 'flex:1;font-weight:' + (u.id === me?.id ? '600' : '400'),
                }));
                if (u.id === me?.id) {
                    r.appendChild(Utils.el('span', { textContent: '(you)', style: 'font-size:12px;color:var(--color-text-muted)' }));
                }
                listArea.appendChild(r);
            }
        } catch (e) {
            listArea.innerHTML = '';
            listArea.appendChild(Utils.el('p', {
                style: 'color:var(--color-danger);font-size:13px',
                textContent: 'Failed to load users: ' + e.message,
            }));
        }
    }

    // -----------------------------------------------------------------------
    // Screen 5: Done
    // -----------------------------------------------------------------------

    function _screen5(wrapper) {
        wrapper.innerHTML = '';

        const labels = _state.requiresEscrow
            ? ['Org Identity', 'Hardware', 'Security', 'Escrow Agents', 'Done']
            : ['Org Identity', 'Hardware', 'Security', 'Done'];
        wrapper.appendChild(_buildStepBar(labels.length - 1, labels));

        const card = Utils.el('div', { style: 'text-align:center;padding:40px 24px' });
        card.appendChild(Utils.el('div', {
            textContent: '✓',
            style: 'font-size:52px;color:var(--color-success);margin-bottom:12px',
        }));
        card.appendChild(Utils.el('h3', { textContent: 'Setup Complete', style: 'margin-bottom:8px' }));
        card.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'margin-bottom:28px',
            textContent: 'Your deployment is ready. All settings can be adjusted from the Admin panel at any time.',
        }));
        card.appendChild(Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Go to Admin Panel →',
            onClick: () => { window.location.hash = '#/admin'; },
        }));
        wrapper.appendChild(card);
    }

    // -----------------------------------------------------------------------
    // Public entry point
    // -----------------------------------------------------------------------

    function renderSetupWizard(container) {
        _resetState();

        const wrapper = Utils.el('div', {
            style: [
                'max-width:680px;margin:48px auto;padding:32px',
                'background:var(--color-surface);border-radius:12px',
                'box-shadow:var(--shadow-modal)',
            ].join(';'),
        });
        container.innerHTML = '';
        container.appendChild(wrapper);

        function navigate(screenNum) {
            switch (screenNum) {
                case 1: _screen1(wrapper, navigate); break;
                case 2: _screen2(wrapper, navigate); break;
                case 3: _screen3(wrapper, navigate); break;
                case 4: _screen4(wrapper, navigate); break;
                case 5: _screen5(wrapper);           break;
            }
        }

        navigate(1);
    }

    return { renderSetupWizard };
})();
