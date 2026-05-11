/**
 * tusShare — File browser UI.
 *
 * Renders folder tree, file list, breadcrumbs, drag-drop zone.
 * Full implementation in Phase 2. Stub here for importability.
 */
const Files = (() => {
    let _currentFolderId = null;
    let _currentFolder = null;
    let _isSharedView = false;
    let _isTeamView = false;
    let _currentTeamId = null;    // non-null when browsing a team folder tree
    let _currentTeamPK = null;    // base64 team public key, cached alongside _currentTeamId
    const _pageSize = Config.ui.paginationDefaultLimit;

    // Live update state — one EventSource per viewed folder/root
    let _liveSource = null;
    let _liveReloadTimer = null;

    // Active uploads being managed in this page session: uploadId → { pct: number }.
    // Used to inject a live "uploading" row during folder re-renders so the file
    // stays visible while a TransferManager row shows real-time progress.
    const _activeUploads = new Map();

    function _startLive(folderId) {
        _stopLive();
        const url = folderId
            ? `${Config.app.apiPrefix}/events?folder_id=${encodeURIComponent(folderId)}`
            : `${Config.app.apiPrefix}/events`;
        const source = new EventSource(url, { withCredentials: true });
        source.onmessage = () => {
            // Debounce rapid bursts (e.g. multiple files uploaded at once)
            clearTimeout(_liveReloadTimer);
            _liveReloadTimer = setTimeout(() => _reloadCurrentView(), 500);
        };
        _liveSource = source;
    }

    function _stopLive() {
        if (_liveSource) {
            _liveSource.close();
            _liveSource = null;
        }
        clearTimeout(_liveReloadTimer);
        _liveReloadTimer = null;
    }

    /**
     * @param {HTMLElement} container
     * @param {{ shared?: boolean }} opts
     */
    function renderFileBrowser(container, opts = {}) {
        _stopLive();
        _isSharedView  = !!opts.shared;
        _isTeamView    = !!opts.teamView;
        _currentTeamId = null;
        _currentTeamPK = null;
        _clearContainer(container);

        const main = Utils.el('main', { className: 'files-main' }, [
            Utils.el('div', { className: 'files-toolbar', id: 'files-toolbar' }, [
                Utils.el('div', { id: 'breadcrumbs', className: 'breadcrumbs' }),
                Utils.el('div', { className: 'toolbar-actions' }, [
                    Utils.el('input', {
                        type: 'text',
                        id: 'file-list-filter',
                        className: 'input-sm',
                        placeholder: 'Filter by name…',
                        style: 'width:200px;margin-right:12px',
                        onInput: (e) => {
                            const term = e.target.value.toLowerCase();
                            const listEl = document.getElementById('file-list');
                            if (!listEl) return;
                            for (const row of listEl.querySelectorAll('tr.row-file, tr.row-folder')) {
                                const name = (row.dataset.name || '').toLowerCase();
                                row.style.display = !term || name.includes(term) ? '' : 'none';
                            }
                        },
                    }),
                    Utils.el('button', {
                        className: 'btn btn-secondary btn-sm',
                        textContent: 'New Folder',
                        onClick: () => _promptNewFolder(),
                    }),
                    Utils.el('button', {
                        className: 'btn btn-primary btn-sm',
                        textContent: 'Upload',
                        onClick: () => _triggerUpload(),
                    }),
                ]),
            ]),
            Utils.el('div', {
                id: 'file-list',
                className: 'file-list drop-zone',
                textContent: 'Loading...',
            }),
        ]);

        container.appendChild(main);
        if (!_isSharedView) {
            if (opts.initialFolderId) {
                loadFolder(opts.initialFolderId);
            } else {
                _loadRootFolders();
            }
        }

        // Wire up drag-and-drop on the file list area
        const dropZone = main.querySelector('.drop-zone');
        if (dropZone) _initDropZone(dropZone);
    }

    async function _loadRootFolders() {
        _currentFolderId = null;
        _currentFolder = null;
        _currentTeamId = null;
        _currentTeamPK = null;
        const listEl = document.getElementById('file-list');
        if (!listEl) return;
        // Show root breadcrumb
        _renderBreadcrumbs([], null);
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/folders`);
            _renderFolderContents(listEl, data.folders, data.files || [], data.pending_uploads || []);
            _startLive(null);
        } catch (err) {
            listEl.textContent = 'Failed to load files: ' + err.message;
        }
    }

    function _createTreeNode(folder) {
        const li = Utils.el('li', { className: 'tree-node' });

        const row = Utils.el('div', { className: 'tree-row' });
        const toggle = Utils.el('span', {
            className: 'tree-toggle',
            textContent: '\u25B6',
            onClick: (e) => {
                e.stopPropagation();
                _toggleTreeNode(li, folder.id, toggle);
            },
        });
        const label = Utils.el('a', {
            href: `#/files/${folder.id}`,
            className: 'tree-label',
            textContent: folder.name,
        });
        row.appendChild(toggle);
        row.appendChild(label);
        li.appendChild(row);
        return li;
    }

    async function _toggleTreeNode(li, folderId, toggle) {
        const existing = li.querySelector(':scope > .tree-list');
        if (existing) {
            // Collapse
            existing.remove();
            toggle.textContent = '\u25B6';
            toggle.classList.remove('expanded');
            return;
        }

        // Expand — fetch children
        toggle.textContent = '\u23F3';
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/folders/${folderId}`);
            const childFolders = data.child_folders || [];
            toggle.classList.add('expanded');
            if (childFolders.length === 0) {
                toggle.textContent = '\u2022';
                return;
            }
            toggle.textContent = '\u25BC';
            const sublist = Utils.el('ul', { className: 'tree-list' });
            for (const child of childFolders) {
                sublist.appendChild(_createTreeNode(child));
            }
            li.appendChild(sublist);
        } catch {
            toggle.textContent = '\u25B6';
        }
    }

    async function loadFolder(folderId) {
        _currentFolderId = folderId;
        const listEl = document.getElementById('file-list');
        if (!listEl) return;
        listEl.textContent = 'Loading...';
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/folders/${folderId}`);
            _currentFolder = data.folder || null;

            // Cache team context so uploads and moves can use it without an extra round-trip
            if (data.team_id && data.team_id !== _currentTeamId) {
                _currentTeamId = data.team_id;
                _currentTeamPK = null; // will be fetched on demand
                try {
                    const teamData = await Api.get(`${Config.app.apiPrefix}/teams/${data.team_id}`);
                    _currentTeamPK = teamData.team?.pre_public_key || null;
                } catch { /* best-effort; uploads will fall back to no team key */ }
            } else if (!data.team_id) {
                _currentTeamId = null;
                _currentTeamPK = null;
            }

            _renderBreadcrumbs(data.breadcrumbs || [], data.folder);
            _renderFolderContents(listEl, data.child_folders, data.files, data.pending_uploads || []);
            _startLive(folderId);
        } catch (err) {
            listEl.textContent = 'Failed to load folder: ' + err.message;
        }
    }

    function _renderBreadcrumbs(ancestors, currentFolder) {
        const el = document.getElementById('breadcrumbs');
        if (!el) return;
        _clearContainer(el);

        // Root link
        let rootLabel, rootHash;
        if (_isTeamView) {
            rootLabel = 'Team Folders';
            rootHash  = '#/team-folders';
        } else if (_isSharedView) {
            rootLabel = 'Shared Folder';
            rootHash  = '#/shared';
        } else {
            rootLabel = 'My Files';
            rootHash  = '#/files';
        }

        // "Go up one level" button (shown when inside a folder)
        if (currentFolder) {
            let parentHash = rootHash;
            if (ancestors.length > 0) {
                const lastAnc = ancestors[ancestors.length - 1];
                parentHash = _isTeamView ? `#/team-folders/${lastAnc.id}` : `#/files/${lastAnc.id}`;
            }
            el.appendChild(Utils.el('a', {
                href: parentHash,
                className: 'breadcrumb-up',
                title: 'Go up one level',
                textContent: '↑',
            }));
        }

        el.appendChild(Utils.el('a', {
            href: rootHash,
            className: 'breadcrumb-tile',
            textContent: rootLabel,
        }));

        // Collapse deep paths: show root → /…/ → parent → current
        const COLLAPSE_DEPTH = 3;
        const crumbHash = (crumb) => _isTeamView ? `#/team-folders/${crumb.id}` : `#/files/${crumb.id}`;

        if (ancestors.length > COLLAPSE_DEPTH) {
            // Show first ancestor, then ellipsis, then last ancestor
            el.appendChild(Utils.el('span', { className: 'breadcrumb-sep', textContent: ' / ' }));
            el.appendChild(Utils.el('a', {
                href: crumbHash(ancestors[0]),
                className: 'breadcrumb-tile',
                textContent: ancestors[0].name,
            }));
            el.appendChild(Utils.el('span', { className: 'breadcrumb-sep breadcrumb-ellipsis', textContent: ' / … / ' }));
            const parent = ancestors[ancestors.length - 1];
            el.appendChild(Utils.el('a', {
                href: crumbHash(parent),
                className: 'breadcrumb-tile',
                textContent: parent.name,
            }));
        } else {
            for (const crumb of ancestors) {
                el.appendChild(Utils.el('span', { className: 'breadcrumb-sep', textContent: ' / ' }));
                el.appendChild(Utils.el('a', {
                    href: crumbHash(crumb),
                    className: 'breadcrumb-tile',
                    textContent: crumb.name,
                }));
            }
        }

        // Current folder (plain non-clickable text)
        if (currentFolder) {
            el.appendChild(Utils.el('span', { className: 'breadcrumb-sep', textContent: ' / ' }));
            el.appendChild(Utils.el('span', {
                className: 'breadcrumb-current',
                textContent: currentFolder.name,
            }));

            // Star icon at end of breadcrumb trail (add to Favourites)
            const pinBtn = Utils.el('button', {
                className: 'breadcrumb-pin-btn',
                title: 'Add to Favourites',
                textContent: '☆',
            });
            pinBtn.addEventListener('click', () => {
                const hash = _isTeamView
                    ? `#/team-folders/${currentFolder.id}`
                    : `#/files/${currentFolder.id}`;
                if (typeof App !== 'undefined' && App.pinCurrentFolder) {
                    App.pinCurrentFolder(currentFolder.id, currentFolder.name, hash);
                    Utils.showToast(`Added "${currentFolder.name}" to Favourites`, 'success');
                }
            });
            el.appendChild(pinBtn);
        }
    }

    function _renderFolderContents(container, folders, files, pendingUploads = []) {
        _clearContainer(container);

        const hasActiveInFolder = [..._activeUploads.values()].some(e => e.folderId === _currentFolderId);
        if (folders.length === 0 && files.length === 0 && pendingUploads.length === 0 && !hasActiveInFolder) {
            container.appendChild(Utils.el('div', {
                className: 'empty-state',
                textContent: 'This folder is empty. Upload files or create a subfolder.',
            }));
            return;
        }

        const table = Utils.el('table', { className: 'file-table' }, [
            Utils.el('thead', {}, [
                Utils.el('tr', {}, [
                    Utils.el('th', { className: 'col-check' }, [
                        Utils.el('input', { type: 'checkbox', className: 'select-all' }),
                    ]),
                    Utils.el('th', { textContent: 'Name' }),
                    Utils.el('th', { textContent: 'Size' }),
                    Utils.el('th', { textContent: 'Modified' }),
                    Utils.el('th', { textContent: '' }),
                ]),
            ]),
        ]);

        const tbody = Utils.el('tbody');

        for (const folder of folders) {
            tbody.appendChild(_createFolderRow(folder));
        }

        // Paginate files — show first page, add "Load more" if needed
        const visibleFiles = files.slice(0, _pageSize);
        for (const file of visibleFiles) {
            tbody.appendChild(_createFileRow(file));
        }

        for (const upload of pendingUploads) {
            const row = _createPendingUploadRow(upload);
            if (row) tbody.appendChild(row);
        }

        // Inject rows for active uploads not yet reflected in server response.
        // This closes the timing gap: if the user navigated away before the server
        // had the upload in pending_uploads, the upload still appears immediately.
        const serverPendingIds = new Set(pendingUploads.map(u => u.upload_id));
        for (const [uploadId, entry] of _activeUploads) {
            if (entry.folderId === _currentFolderId && !serverPendingIds.has(uploadId)) {
                tbody.appendChild(Utils.el('tr', { className: 'row-pending' }, [
                    Utils.el('td'),
                    Utils.el('td', {}, [
                        Utils.el('div', { className: 'pending-name' }, [
                            Utils.el('span', { className: 'pending-icon', textContent: '↑' }),
                            Utils.el('span', { textContent: entry.originalName }),
                        ]),
                    ]),
                    Utils.el('td', { textContent: `${entry.pct}% — uploading…` }),
                    Utils.el('td', { textContent: '' }),
                    Utils.el('td'),
                ]));
            }
        }

        table.appendChild(tbody);
        container.appendChild(table);

        // Wire up select-all checkbox
        const selectAll = table.querySelector('.select-all');
        if (selectAll) {
            selectAll.addEventListener('change', () => {
                const cbs = tbody.querySelectorAll('input[type="checkbox"]');
                for (const cb of cbs) cb.checked = selectAll.checked;
                _updateBulkActions();
            });
            // Update bulk bar on individual checkbox change
            tbody.addEventListener('change', (e) => {
                if (e.target.type === 'checkbox') _updateBulkActions();
            });
        }

        // "Load more" button if there are more files than the first page
        if (files.length > _pageSize) {
            let shown = _pageSize;
            const loadMore = Utils.el('button', {
                className: 'btn btn-secondary btn-full',
                textContent: `Show more (${files.length - shown} remaining)`,
                onClick: () => {
                    const nextBatch = files.slice(shown, shown + _pageSize);
                    for (const file of nextBatch) {
                        tbody.appendChild(_createFileRow(file));
                    }
                    shown += nextBatch.length;
                    if (shown >= files.length) {
                        loadMore.remove();
                    } else {
                        loadMore.textContent = `Show more (${files.length - shown} remaining)`;
                    }
                },
            });
            container.appendChild(loadMore);
        }
    }

    function _createFolderRow(folder) {
        const folderHash = _isTeamView ? `#/team-folders/${folder.id}` : `#/files/${folder.id}`;
        return Utils.el('tr', { className: 'row-folder', dataset: { name: folder.name } }, [
            Utils.el('td', {}, [Utils.el('input', { type: 'checkbox', dataset: { type: 'folder', id: folder.id, name: folder.name } })]),
            Utils.el('td', {}, [
                Utils.el('a', {
                    href: folderHash,
                    className: 'folder-link',
                    textContent: folder.name,
                }),
            ]),
            Utils.el('td', { textContent: '--' }),
            Utils.el('td', { textContent: Utils.timeAgo(folder.updated_at) }),
            Utils.el('td', { className: 'row-actions' }, [
                _createContextButton([
                    { label: 'Share', action: () => Shares.openFolderShareDialog(folder) },
                    { label: 'Move/Copy', action: () => _openMoveCopyModal([{ type: 'folder', id: folder.id, name: folder.name }]) },
                    { label: 'Rename', action: () => _renameFolder(folder) },
                    folder.user_can_manage ? {
                        label: folder.restrict_permissions ? '✓ Block inherited permissions' : 'Block inherited permissions',
                        action: () => _toggleFolderInheritance(folder),
                    } : null,
                    { label: 'Delete', action: () => _deleteFolder(folder), danger: true },
                ].filter(Boolean)),
            ]),
        ]);
    }

    function _createFileRow(file) {
        const nameLink = Utils.el('a', {
            href: '#',
            className: 'file-name-link',
            textContent: file.original_name,
        });
        nameLink.addEventListener('click', (e) => {
            e.preventDefault();
            _downloadFile(file);
        });
        return Utils.el('tr', { className: 'row-file', dataset: { name: file.original_name } }, [
            Utils.el('td', {}, [Utils.el('input', { type: 'checkbox', dataset: { type: 'file', id: file.id, name: file.original_name } })]),
            Utils.el('td', {}, [nameLink]),
            Utils.el('td', { textContent: Utils.formatBytes(file.size_bytes) }),
            Utils.el('td', { textContent: Utils.timeAgo(file.created_at) }),
            Utils.el('td', { className: 'row-actions' }, [
                _createContextButton(() => _fileContextItems(file)),
            ]),
        ]);
    }

    async function _fileContextItems(file) {
        const fileForPicker = { type: 'file', id: file.id, name: file.original_name, encrypted_file_key: file.encrypted_file_key, key_iv: file.key_iv };
        const items = [
            { label: 'Download', action: () => _downloadFile(file) },
            { label: 'Share', action: () => _openCombinedShareDialog(file) },
            { label: 'Move/Copy', action: () => _openMoveCopyModal([fileForPicker]) },
            { label: 'More Info', action: () => _openFileInfoModal(file) },
            { label: 'Rename', action: () => _renameFile(file) },
            { label: 'Delete', action: () => _deleteFile(file), danger: true },
        ];

        const partials = await Download.listPartialDownloads().catch(() => []);
        const partial  = partials.find(p => p.fileId === file.id);
        if (partial && partial.doneCount > 0) {
            const pct = Math.round((partial.doneCount / partial.totalChunks) * 100);
            items[0] = { label: `Resume download (${pct}%)`, action: () => _downloadFile(file) };
            items.push({ label: 'Discard partial download', action: () => _discardPartialDownload(file), danger: true });
        }

        return items;
    }

    function _openCombinedShareDialog(file) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }
        const files = [file].filter(f => f.encrypted_file_key && f.key_iv);
        if (!files.length) {
            Utils.showToast('File is not shareable (missing encryption keys).', 'info');
            return;
        }

        const overlay = Utils.el('div', { className: 'modal-overlay' });
        overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

        const tabLink = Utils.el('button', { className: 'tab-btn tab-active', textContent: 'Link' });
        const tabUser = Utils.el('button', { className: 'tab-btn', textContent: 'User' });
        const tabBar  = Utils.el('div', { style: 'display:flex;border-bottom:1px solid var(--color-border);margin-bottom:12px' }, [tabLink, tabUser]);

        const contentWrap = Utils.el('div');
        const cancelBtn   = Utils.el('button', { className: 'btn btn-secondary', textContent: 'Cancel' });
        cancelBtn.addEventListener('click', () => overlay.remove());
        const actionsRow  = Utils.el('div', { className: 'modal-actions' }, [cancelBtn]);

        let _currentActionBtn = null;

        function _switchTab(type) {
            tabLink.classList.toggle('tab-active', type === 'link');
            tabUser.classList.toggle('tab-active', type === 'user');
            contentWrap.innerHTML = '';
            if (_currentActionBtn) _currentActionBtn.remove();
            cancelBtn.textContent = 'Cancel';

            const onSuccess = () => { cancelBtn.textContent = 'Close'; };
            const { contentEl, actionBtn } = type === 'link'
                ? Shares.buildLinkShareContent(files, masterKey, null, onSuccess)
                : Shares.buildUserShareContent(files, masterKey, onSuccess);

            contentWrap.appendChild(contentEl);
            actionsRow.appendChild(actionBtn);
            _currentActionBtn = actionBtn;
        }

        tabLink.addEventListener('click', () => _switchTab('link'));
        tabUser.addEventListener('click', () => _switchTab('user'));

        overlay.appendChild(Utils.el('div', { className: 'modal share-dialog' }, [
            Utils.el('h3', { textContent: `Share: ${file.original_name}`, style: 'margin-top:0' }),
            tabBar,
            contentWrap,
            actionsRow,
        ]));
        document.body.appendChild(overlay);
        _switchTab('link');
    }

    async function _openFileInfoModal(file) {
        Utils.showModal(`Info: ${file.original_name}`, Utils.el('p', { textContent: 'Loading…' }));
        let info;
        try {
            info = await Api.get(`${Config.app.apiPrefix}/files/${file.id}/info`);
        } catch (e) {
            Utils.showModal(`Info: ${file.original_name}`, Utils.el('p', { className: 'text-error', textContent: 'Failed to load: ' + e.message }));
            return;
        }

        const _esc = (s) => {
            if (s == null) return '—';
            return String(s).replace(/[^a-zA-Z0-9 .\-_]/g, c => '%' + c.codePointAt(0).toString(16).padStart(2, '0'));
        };

        const wrap = Utils.el('div', { style: 'min-width:400px' });
        const grid = Utils.el('div', { style: 'display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:13px;margin-bottom:14px' });
        const _row = (label, val) => {
            grid.appendChild(Utils.el('span', { textContent: label + ':', style: 'font-weight:600;color:var(--color-text-muted)' }));
            grid.appendChild(Utils.el('span', { textContent: _esc(val) }));
        };
        _row('File Name', info.name);
        _row('Size', Utils.formatBytes(info.size_bytes));
        _row('Created', info.created_at ? info.created_at.replace('T', ' ').slice(0, 19) : '—');
        _row('Creator', info.creator);
        _row('Downloads', String(info.download_count));
        wrap.appendChild(grid);

        if (info.audit?.length) {
            wrap.appendChild(Utils.el('h5', { textContent: 'Recent Access', style: 'margin:0 0 6px' }));
            const tbl = Utils.el('table', { className: 'admin-table', style: 'font-size:12px;width:100%' });
            tbl.appendChild(Utils.el('thead', {}, [Utils.el('tr', {}, [
                Utils.el('th', { textContent: 'Time' }),
                Utils.el('th', { textContent: 'User' }),
                Utils.el('th', { textContent: 'Action' }),
                Utils.el('th', { textContent: 'IP' }),
            ])]));
            const tbody = Utils.el('tbody');
            for (const e of info.audit) {
                tbody.appendChild(Utils.el('tr', {}, [
                    Utils.el('td', { textContent: e.timestamp ? e.timestamp.replace('T', ' ').slice(0, 19) : '' }),
                    Utils.el('td', { textContent: _esc(e.user) }),
                    Utils.el('td', { textContent: _esc(e.action) }),
                    Utils.el('td', { textContent: _esc(e.ip) }),
                ]));
            }
            tbl.appendChild(tbody);
            wrap.appendChild(tbl);
        }

        Utils.showModal(`Info: ${_esc(info.name)}`, wrap);
    }

    async function _discardPartialDownload(file) {
        await Download.clearPartialDownload(file.id);
        Utils.showToast(`Partial download for "${file.original_name}" discarded.`, 'info');
    }

    async function _downloadFile(file) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        // Notify user when resuming an interrupted download
        try {
            const partials = await Download.listPartialDownloads();
            const partial  = partials.find(p => p.fileId === file.id);
            if (partial && partial.doneCount > 0) {
                const pct = Math.round((partial.doneCount / partial.totalChunks) * 100);
                Utils.showToast(`Resuming download — ${pct}% already done`, 'info');
            }
        } catch { /* non-critical */ }

        const abortCtrl    = new AbortController();
        const abortDownload = () => abortCtrl.abort();
        const overlay      = _showUploadOverlay(file.original_name);
        const transfer     = TransferManager.start(file.original_name, 'download', {
            onStop:   abortDownload,
            onLogout: abortDownload,
        });
        try {
            await Download.downloadFile(file.id, masterKey, (done, total) => {
                const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                overlay.update(pct, file.original_name);
                transfer.update(pct);
            }, abortCtrl.signal);
            overlay.remove();
            transfer.complete();
            Utils.showToast(`"${file.original_name}" downloaded`, 'success');
        } catch (err) {
            overlay.remove();
            if (err.name === 'AbortError') {
                transfer.cancelled();
            } else {
                transfer.fail();
                Utils.showToast(`Download failed: ${err.message}`, 'error');
            }
        }
    }

    function _createPendingUploadRow(upload) {
        const activeEntry = _activeUploads.get(upload.upload_id);
        if (activeEntry) {
            // Re-inject a live "uploading" row so the file stays visible during re-renders.
            // Progress comes from in-memory state, which is more current than the server offset.
            const pct = activeEntry.pct;
            return Utils.el('tr', { className: 'row-pending' }, [
                Utils.el('td'),
                Utils.el('td', {}, [
                    Utils.el('div', { className: 'pending-name' }, [
                        Utils.el('span', { className: 'pending-icon', textContent: '↑' }),
                        Utils.el('span', { textContent: upload.original_name }),
                    ]),
                ]),
                Utils.el('td', { textContent: `${pct}% — uploading…` }),
                Utils.el('td', { textContent: '' }),
                Utils.el('td'),
            ]);
        }

        const pct = upload.total_size > 0
            ? Math.round((upload.current_offset / upload.total_size) * 100)
            : 0;
        const progress = `${pct}% — ${Utils.formatBytes(upload.current_offset)} of ${Utils.formatBytes(upload.total_size)}`;
        const expiresLabel = `Expires ${Utils.timeAgo(upload.expires_at)}`;

        return Utils.el('tr', { className: 'row-pending' }, [
            Utils.el('td'),   // no checkbox — pending rows aren't selectable
            Utils.el('td', {}, [
                Utils.el('div', { className: 'pending-name' }, [
                    Utils.el('span', { className: 'pending-icon', textContent: '↺' }),
                    Utils.el('span', { textContent: upload.original_name }),
                ]),
            ]),
            Utils.el('td', { textContent: progress }),
            Utils.el('td', { textContent: expiresLabel }),
            Utils.el('td', { className: 'row-actions' }, [
                _createContextButton([
                    { label: 'Resume', action: () => _resumePendingUpload(upload) },
                    { label: 'Cancel', action: () => _cancelPendingUpload(upload), danger: true },
                ]),
            ]),
        ]);
    }

    async function _resumePendingUpload(upload) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        const input = document.createElement('input');
        input.type = 'file';
        input.addEventListener('change', async () => {
            const selectedFile = input.files[0];
            input.remove();
            if (!selectedFile) return;

            if (selectedFile.name !== upload.original_name || selectedFile.size !== upload.size_bytes) {
                Utils.showToast(
                    `File does not match: expected "${upload.original_name}" (${Utils.formatBytes(upload.size_bytes)}).`,
                    'error'
                );
                return;
            }

            let fileKey;
            try {
                fileKey = await Crypto.decryptFileKey(upload.encrypted_file_key, upload.key_iv, masterKey);
            } catch {
                Utils.showToast('Upload cannot be resumed — the folder\'s encryption keys were rotated (likely due to a membership change). Please re-upload the file.', 'error');
                return;
            }

            const location = `${Config.app.apiPrefix}/uploads/${upload.upload_id}`;
            const ctrl     = _makeUploadCtrl(_currentFolderId, upload.original_name);
            ctrl.onCreated(upload.upload_id); // ID is already known — register immediately
            const overlay  = _showUploadOverlay(upload.original_name);
            const transfer = TransferManager.start(upload.original_name, 'upload', {
                onPause:  () => { ctrl.pause();  transfer.setPaused(true);  },
                onResume: () => { ctrl.resume(); transfer.setPaused(false); },
                onStop:   () => ctrl.stop(true),
                onLogout: () => ctrl.stop(false),
            });

            try {
                const result = await Upload.resumeUpload(location, selectedFile, fileKey, (done, total) => {
                    const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                    overlay.update(pct, upload.original_name);
                    transfer.update(pct);
                    const _ae = ctrl.uploadId ? _activeUploads.get(ctrl.uploadId) : null;
                    if (_ae) _ae.pct = pct;
                }, ctrl);
                overlay.remove();
                transfer.complete();
                await _registerTeamFileKey(result.fileId, result.fileKeyBytes).catch(
                    teamKeyErr => console.warn('Failed to register team file key for', result.fileId, teamKeyErr),
                );
                Utils.showToast(`"${upload.original_name}" uploaded`, 'success');
            } catch (err) {
                overlay.remove();
                if (err instanceof Upload.AbortedError) {
                    transfer.cancelled();
                    if (ctrl.shouldDeleteOnAbort()) {
                        Api.del(err.location).catch(() => {});
                        Utils.showToast(`"${upload.original_name}" upload cancelled`, 'info');
                    }
                } else {
                    transfer.fail();
                    Utils.showToast(`Resume failed: ${err.message}`, 'error');
                }
            } finally {
                ctrl.cleanup();
            }

            _reloadCurrentView();
        });
        input.click();
    }

    async function _cancelPendingUpload(upload) {
        try {
            await Api.del(`${Config.app.apiPrefix}/uploads/${upload.upload_id}`);
            Utils.showToast('Upload cancelled', 'success');
        } catch (err) {
            Utils.showToast(`Could not cancel upload: ${err.message}`, 'error');
        }
        _reloadCurrentView();
    }

    // itemsOrFn may be a plain array or an async function returning an array.
    // The async form is used for context menus that need to query IndexedDB
    // before showing (e.g. to add a "Resume download" item conditionally).
    function _createContextButton(itemsOrFn) {
        const btn = Utils.el('button', {
            className: 'btn-context',
            textContent: '\u22EE',
            onClick: async (e) => {
                e.stopPropagation();
                const items = typeof itemsOrFn === 'function' ? await itemsOrFn() : itemsOrFn;
                _showContextMenu(btn, items);
            },
        });
        return btn;
    }

    let _activeMenu = null;

    function _showContextMenu(anchor, items) {
        _dismissContextMenu();
        const menu = Utils.el('div', { className: 'context-menu' });
        for (const item of items) {
            menu.appendChild(Utils.el('button', {
                className: 'context-menu-item' + (item.danger ? ' danger' : ''),
                textContent: item.label,
                onClick: (e) => {
                    e.stopPropagation();
                    _dismissContextMenu();
                    item.action();
                },
            }));
        }

        // Attach to body with position:fixed so the menu escapes table stacking
        // contexts — otherwise the next row's :hover fires through the menu,
        // making Resume/Cancel unclickable when rows are densely packed.
        menu.style.position = 'fixed';
        menu.style.zIndex = '9999';
        document.body.appendChild(menu);

        // Position below-right of the anchor button
        const rect = anchor.getBoundingClientRect();
        const menuWidth = 160; // approximate before layout; adjusted after paint
        const spaceRight = window.innerWidth - rect.right;
        menu.style.left = spaceRight >= menuWidth
            ? `${rect.right - menu.offsetWidth || rect.left}px`
            : `${rect.left - (menu.offsetWidth || menuWidth)}px`;
        menu.style.top = `${rect.bottom}px`;

        // After the element is in the DOM, snap to correct position
        requestAnimationFrame(() => {
            const mw = menu.offsetWidth;
            if (rect.right + mw <= window.innerWidth) {
                menu.style.left = `${rect.left}px`;
            } else {
                menu.style.left = `${rect.right - mw}px`;
            }
        });

        _activeMenu = { menu, dismiss: _onDocClickDismiss };
        document.addEventListener('click', _onDocClickDismiss, { once: true });
    }

    function _onDocClickDismiss() {
        _dismissContextMenu();
    }

    function _dismissContextMenu() {
        if (_activeMenu) {
            if (_activeMenu.menu.parentNode) _activeMenu.menu.remove();
            document.removeEventListener('click', _activeMenu.dismiss);
            _activeMenu = null;
        }
    }

    async function _renameFolder(folder) {
        const name = prompt('New name:', folder.name);
        if (!name || name === folder.name) return;
        try {
            await Api.put(`${Config.app.apiPrefix}/folders/${folder.id}`, { name });
            Utils.showToast('Folder renamed', 'success');
            _reloadCurrentView();
        } catch (err) {
            Utils.showToast(err.message, 'error');
        }
    }

    async function _toggleFolderInheritance(folder) {
        const newVal = !folder.restrict_permissions;
        const msg = newVal
            ? 'Block inherited permissions on this folder? Users will need explicit access grants here.'
            : 'Remove the inheritance block? This folder will inherit permissions from its ancestors again.';
        if (!confirm(msg)) return;
        try {
            await Api.put(`${Config.app.apiPrefix}/folders/${folder.id}`, { restrict_permissions: newVal });
            Utils.showToast(
                newVal ? 'Inheritance blocked — access to this folder is now self-contained.' : 'Inheritance restored.',
                'success',
            );
            _reloadCurrentView();
        } catch (err) {
            Utils.showToast(err.message, 'error');
        }
    }

    function _previewFilenameSanitize(name) {
        const blacklist = Config.file.nameBlacklistChars;
        const removed = [];
        let cleaned = '';
        for (const ch of name) {
            const code = ch.codePointAt(0);
            if ((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f) || blacklist.has(ch)) {
                if (!removed.includes(ch)) removed.push(ch);
            } else {
                cleaned += ch;
            }
        }
        return { cleaned, removed };
    }

    async function _renameFile(file) {
        const name = prompt('New name:', file.original_name);
        if (!name || name === file.original_name) return;

        // Client-side preview: warn before submitting if chars will be stripped
        const preview = _previewFilenameSanitize(name);
        if (preview.removed.length) {
            const chars = preview.removed.map(c => c === ' ' ? '(space)' : c).join('  ');
            const ok = await Utils.showConfirm(
                `The following characters will be removed: ${chars}\n\nResult: "${preview.cleaned}"\n\nContinue?`
            );
            if (!ok) return;
        }

        try {
            const res = await Api.put(`${Config.app.apiPrefix}/files/${file.id}`, { original_name: name });
            if (res.removed_chars?.length) {
                const chars = res.removed_chars.map(c => c === ' ' ? '(space)' : c).join('  ');
                Utils.showToast(`File renamed. Removed invalid characters: ${chars}`, 'warning');
            } else {
                Utils.showToast('File renamed', 'success');
            }
            _reloadCurrentView();
        } catch (err) {
            Utils.showToast(err.message, 'error');
        }
    }

    async function _deleteFolder(folder) {
        const ok = await Utils.showConfirm(`Delete folder "${folder.name}" and all its contents?`);
        if (!ok) return;
        try {
            await Api.del(`${Config.app.apiPrefix}/folders/${folder.id}`);
            Utils.showToast('Folder deleted', 'success');
            _reloadCurrentView();
        } catch (err) {
            Utils.showToast(err.message, 'error');
        }
    }

    async function _deleteFile(file) {
        const ok = await Utils.showConfirm(`Delete "${file.original_name}"?`);
        if (!ok) return;
        try {
            await Api.del(`${Config.app.apiPrefix}/files/${file.id}`);
            Utils.showToast('File deleted', 'success');
            _reloadCurrentView();
        } catch (err) {
            Utils.showToast(err.message, 'error');
        }
    }

    function _reloadCurrentView() {
        if (_currentFolderId) {
            loadFolder(_currentFolderId);
        } else if (!_isSharedView) {
            _loadRootFolders();
        }
    }

    function _updateBulkActions() {
        const selected = getSelectedItems();
        let bar = document.getElementById('bulk-actions');

        if (selected.length === 0) {
            if (bar) bar.remove();
            return;
        }

        if (!bar) {
            bar = Utils.el('div', { id: 'bulk-actions', className: 'bulk-actions' });
            const toolbar = document.getElementById('files-toolbar');
            if (toolbar) toolbar.after(bar);
        }
        _clearContainer(bar);
        bar.appendChild(Utils.el('span', {
            className: 'bulk-count',
            textContent: `${selected.length} selected`,
        }));
        bar.appendChild(Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Download selected',
            onClick: () => _bulkDownload(selected),
        }));
        bar.appendChild(Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Share selected',
            onClick: () => _bulkShare(selected),
        }));
        bar.appendChild(Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Move/Copy selected',
            onClick: () => _openMoveCopyModal(selected),
        }));
        bar.appendChild(Utils.el('button', {
            className: 'btn btn-danger btn-sm',
            textContent: 'Delete selected',
            onClick: () => _bulkDelete(selected),
        }));
    }

    async function _bulkDownload(items) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Session expired — please log in again', 'error');
            return;
        }

        // Annotate each item with the current folder as parentFolderId
        const annotated = items.map(item => ({
            ...item,
            parentFolderId: _currentFolderId,
        }));

        // Deselect checkboxes so the user can make a new selection while download runs
        document.querySelectorAll('#file-list input[type="checkbox"]:checked').forEach(cb => {
            cb.checked = false;
        });
        _updateBulkActions();

        if (annotated.length === 1 && annotated[0].type === 'file') {
            // Single file — use regular single-file download (no ZIP)
            const file = { id: annotated[0].id, original_name: annotated[0].name };
            return _downloadFile(file);
        }

        const abortCtrl = new AbortController();
        const abortDownload = () => abortCtrl.abort();

        const label = annotated.length === 1
            ? `${annotated[0].name} (ZIP)`
            : `${annotated.length} items (ZIP)`;

        const transfer = TransferManager.start(label, 'download', {
            onStop:   abortDownload,
            onLogout: abortDownload,
        });

        try {
            await Download.downloadBatch(
                annotated,
                masterKey,
                (done, total) => {
                    transfer.update(Math.round(done / total * 100));
                },
                abortCtrl.signal,
            );
            transfer.complete();
            Utils.showToast(`${annotated.length} ${annotated.length === 1 ? 'item' : 'items'} downloaded`, 'success');
        } catch (err) {
            if (err.name === 'AbortError') {
                transfer.cancelled();
            } else {
                transfer.fail();
                Utils.showToast(`Batch download failed: ${err.message}`, 'error');
            }
        }
    }

    async function _bulkDelete(items) {
        const ok = await Utils.showConfirm(`Delete ${items.length} item(s)? This cannot be undone.`);
        if (!ok) return;

        let errors = 0;
        for (const item of items) {
            try {
                const endpoint = item.type === 'folder'
                    ? `${Config.app.apiPrefix}/folders/${item.id}`
                    : `${Config.app.apiPrefix}/files/${item.id}`;
                await Api.del(endpoint);
            } catch {
                errors++;
            }
        }

        if (errors > 0) {
            Utils.showToast(`Deleted with ${errors} error(s)`, 'warning');
        } else {
            Utils.showToast(`${items.length} item(s) deleted`, 'success');
        }
        _reloadCurrentView();
    }

    async function _bulkShare(items) {
        const folderItems = items.filter(i => i.type === 'folder');
        const fileItems   = items.filter(i => i.type === 'file');

        // Single folder selected — use folder share dialog
        if (folderItems.length === 1 && fileItems.length === 0) {
            Shares.openFolderShareDialog({ id: folderItems[0].id, name: '(selected folder)' });
            return;
        }

        // Multiple folders or mixed — not supported
        if (folderItems.length > 0) {
            Utils.showToast('To share a folder, use its context menu. Bulk share works with files only.', 'info');
            return;
        }

        // Files only — fetch full metadata (we need encrypted_file_key + key_iv)
        const files = [];
        for (const item of fileItems) {
            try {
                const data = await Api.get(`${Config.app.apiPrefix}/files/${item.id}`);
                if (data.file) files.push(data.file);
            } catch (err) {
                Utils.showToast(`Failed to load file ${item.id}: ${err.message}`, 'error');
                return;
            }
        }

        Shares.openShareDialog(files);
    }

    // ── Move files / folders ──────────────────────────────────────────────────

    async function _openMoveCopyModal(items) {
        const files = items.filter(i => i.type === 'file');
        if (items.length === 0) return;

        const sourceIsTeam = _isTeamView;
        let selectedDest = null;
        let currentSelectedEl = null;

        const moveBtn = Utils.el('button', {
            className: 'btn btn-primary btn-sm',
            textContent: 'Move',
            disabled: true,
        });
        const copyBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Copy',
            disabled: true,
        });

        function _selectDest(optionEl, dest) {
            if (currentSelectedEl) currentSelectedEl.classList.remove('selected');
            optionEl.classList.add('selected');
            currentSelectedEl = optionEl;
            selectedDest = dest;
            moveBtn.disabled = false;
            copyBtn.disabled = files.length === 0;
        }

        const filterInput = Utils.el('input', {
            type: 'text',
            className: 'input-sm',
            placeholder: 'Filter destinations…',
            style: 'width:100%;margin-bottom:8px;box-sizing:border-box',
        });

        const pickerList = Utils.el('ul', { className: 'folder-picker' });

        Utils.inlineFilter(filterInput, () => pickerList.querySelectorAll('li.folder-picker-item'), row => row.querySelector('.picker-folder-name')?.textContent || '');

        const overlay = Utils.el('div', {
            className: 'modal-overlay',
            onClick: (e) => { if (e.target === overlay) overlay.remove(); },
        });

        const title = items.length === 1
            ? `Move / Copy "${items[0].name}"`
            : `Move / Copy ${items.length} items`;

        overlay.appendChild(Utils.el('div', { className: 'modal move-modal' }, [
            Utils.el('h3', { textContent: title }),
            filterInput,
            pickerList,
            Utils.el('div', { className: 'modal-actions', style: 'justify-content:space-between' }, [
                Utils.el('button', {
                    className: 'btn btn-secondary',
                    textContent: 'Cancel',
                    onClick: () => overlay.remove(),
                }),
                Utils.el('div', { style: 'display:flex;gap:8px' }, [copyBtn, moveBtn]),
            ]),
        ]));
        document.body.appendChild(overlay);

        moveBtn.addEventListener('click', async () => {
            overlay.remove();
            await _confirmAndExecuteMoves(items, selectedDest, sourceIsTeam);
        });
        copyBtn.addEventListener('click', async () => {
            overlay.remove();
            await _executeCopies(files, selectedDest);
        });

        // Personal root
        pickerList.appendChild(Utils.el('li', { className: 'folder-picker-section', textContent: 'My Files' }));
        const rootRow = Utils.el('div', { className: 'folder-picker-option' }, [
            Utils.el('span', { className: 'picker-folder-name', textContent: 'My Files (root)' }),
        ]);
        rootRow.addEventListener('click', () => _selectDest(rootRow, { id: null, label: 'My Files (root)', isTeam: false }));
        pickerList.appendChild(Utils.el('li', { className: 'folder-picker-item' }, [rootRow]));

        const loadingLi = Utils.el('li', { className: 'folder-picker-loading', textContent: 'Loading…' });
        pickerList.appendChild(loadingLi);

        try {
            const [foldersData, teamsData] = await Promise.all([
                Api.get(`${Config.app.apiPrefix}/folders`),
                Api.get(`${Config.app.apiPrefix}/teams`),
            ]);
            loadingLi.remove();

            for (const folder of (foldersData.folders || [])) {
                pickerList.appendChild(_createPickerFolderNode(folder, 0, _selectDest, false));
            }

            const teams = teamsData.teams || [];
            const visibleTeams = teams.slice(0, 3);
            const hiddenTeams  = teams.slice(3);

            for (const team of visibleTeams) {
                pickerList.appendChild(Utils.el('li', { className: 'folder-picker-section', textContent: team.name }));
                await _appendTeamFolders(pickerList, team, _selectDest);
            }

            if (hiddenTeams.length > 0) {
                const loadMoreLi = Utils.el('li', { className: 'folder-picker-item' });
                const loadMoreBtn = Utils.el('button', {
                    className: 'btn btn-secondary btn-sm',
                    textContent: `Load more (${hiddenTeams.length} more team${hiddenTeams.length > 1 ? 's' : ''})…`,
                    style: 'width:100%;margin:4px 0',
                });
                loadMoreBtn.addEventListener('click', async () => {
                    loadMoreLi.remove();
                    pickerList.style.maxHeight = '340px';
                    pickerList.style.overflowY = 'auto';
                    for (const team of hiddenTeams) {
                        pickerList.appendChild(Utils.el('li', { className: 'folder-picker-section', textContent: team.name }));
                        await _appendTeamFolders(pickerList, team, _selectDest);
                    }
                });
                loadMoreLi.appendChild(loadMoreBtn);
                pickerList.appendChild(loadMoreLi);
            }
        } catch {
            if (loadingLi.parentNode) loadingLi.textContent = 'Failed to load destinations';
        }
    }

    async function _appendTeamFolders(pickerList, team, selectDest) {
        try {
            const tfData = await Api.get(`${Config.app.apiPrefix}/teams/${team.id}/folders`);
            const teamFolders = tfData.folders || [];
            if (teamFolders.length === 0) {
                pickerList.appendChild(Utils.el('li', { className: 'folder-picker-loading', textContent: 'No folders in this team' }));
            } else {
                for (const tf of teamFolders) {
                    pickerList.appendChild(_createPickerFolderNode(
                        { id: tf.folder_id, name: tf.folder_name }, 0, selectDest, true,
                    ));
                }
            }
        } catch {
            pickerList.appendChild(Utils.el('li', { className: 'folder-picker-error', textContent: 'Failed to load folders' }));
        }
    }


    /**
     * Build a lazily-expandable folder node for the move picker.
     * isTeam: true if this node is in a team context (propagated to children).
     */
    function _createPickerFolderNode(folder, depth, onSelect, isTeam) {
        const li = Utils.el('li', { className: 'folder-picker-item' });
        let expanded = false;

        const expandBtn = Utils.el('span', { className: 'picker-expand', textContent: '\u25B6' });
        expandBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (expanded) {
                const sub = li.querySelector(':scope > ul');
                if (sub) sub.remove();
                expanded = false;
                expandBtn.textContent = '\u25B6';
                return;
            }
            expanded = true;
            expandBtn.textContent = '\u2026';
            try {
                const data = await Api.get(`${Config.app.apiPrefix}/folders/${folder.id}`);
                const children = data.child_folders || [];
                if (children.length === 0) {
                    expandBtn.textContent = '\u00B7';
                } else {
                    expandBtn.textContent = '\u25BC';
                    const sublist = Utils.el('ul');
                    for (const child of children) {
                        sublist.appendChild(_createPickerFolderNode(child, depth + 1, onSelect, isTeam));
                    }
                    li.appendChild(sublist);
                }
            } catch {
                expanded = false;
                expandBtn.textContent = '\u25B6';
            }
        });

        const indentPx = 12 + depth * 20;
        const row = Utils.el('div', {
            className: 'folder-picker-option',
            style: `padding-left: ${indentPx}px`,
        }, [
            expandBtn,
            Utils.el('span', { className: 'picker-folder-name', textContent: folder.name }),
        ]);
        row.addEventListener('click', () => onSelect(row, { id: folder.id, label: folder.name, isTeam }));

        li.appendChild(row);
        return li;
    }

    /** Resolve destination team id + PRE public key. Throws on API error. */
    async function _resolveDestTeamInfo(destination) {
        const destId = destination.id;
        if (!destination.isTeam || !destId) return { destTeamId: null, destTeamPK: null };
        const folderData = await Api.get(`${Config.app.apiPrefix}/folders/${destId}`);
        const destTeamId = folderData.team_id || null;
        if (!destTeamId) return { destTeamId: null, destTeamPK: null };
        const teamData = await Api.get(`${Config.app.apiPrefix}/teams/${destTeamId}`);
        return { destTeamId, destTeamPK: teamData.team?.pre_public_key || null };
    }

    /** Returns false if the user cancels after being warned about active shares. */
    async function _warnIfActiveShares(items) {
        const allIds = items.map(i => i.id);
        let idsWithShares = [];
        try {
            const res = await Api.post(
                `${Config.app.apiPrefix}/shares/active-for-items`,
                { resource_ids: allIds },
            );
            idsWithShares = res.ids_with_shares || [];
        } catch { /* best-effort */ }
        if (idsWithShares.length === 0) return true;
        const shareMsg = idsWithShares.length === 1
            ? `One of the selected items has an active share link. Recipients of that link may lose access after the move.`
            : `${idsWithShares.length} of the selected items have active share links. Recipients of those links may lose access after the move.`;
        return Utils.showConfirm(shareMsg + '\n\nProceed anyway?');
    }

    /** Returns false if the user cancels after being warned about a team-boundary crossing. */
    async function _warnIfBoundary(items, sourceIsTeam, destination) {
        if (sourceIsTeam === destination.isTeam) return true;
        const noun = items.length === 1 ? 'this item' : 'these items';
        const boundaryMsg = !sourceIsTeam && destination.isTeam
            ? `Warning: By moving to "${destination.label}", you will be sharing ${noun} with everyone who has access to that folder.`
            : `Warning: By moving to your personal files, team members will lose access to ${noun}.`;
        return Utils.showConfirm(boundaryMsg + '\n\nProceed?');
    }

    /**
     * Run pre-move checks (active shares, cross-boundary warning) then execute.
     * destination: { id: string|null, label: string, isTeam: boolean }
     */
    async function _confirmAndExecuteMoves(items, destination, sourceIsTeam) {
        if (!await _warnIfActiveShares(items)) return;
        if (!await _warnIfBoundary(items, sourceIsTeam, destination)) return;
        await _executeMoves(items, destination);
    }

    /**
     * Move folders in the items list to destId, updating the overlay.
     * Returns { done, errors } counts (done = number of folders processed).
     */
    async function _executeFolderMoves(folders, destId, destTeamPK, folderNeedsCrypto, overlay, total, isCancelled) {
        let done = 0;
        let errors = 0;
        for (const folder of folders) {
            if (isCancelled()) break;
            overlay.update(done, total, `Moving "${folder.name}"…`);
            try {
                if (folderNeedsCrypto) {
                    await _moveFolderAcrossTeamBoundary(
                        folder, destId, destTeamPK,
                        (label) => overlay.update(done, total, label),
                        isCancelled,
                    );
                } else {
                    await Api.put(`${Config.app.apiPrefix}/folders/${folder.id}`,
                        destId === null ? { move_to_root: true } : { parent_id: destId });
                }
            } catch { errors++; }
            done++;
            overlay.update(done, total);
        }
        return { done, errors };
    }

    /**
     * Build the batch-move payload for one chunk of files.
     * For team destinations, fetches missing crypto metadata and encrypts a team_key.
     * Returns { items: Array, failed: number }.
     */
    async function _buildFileMoveItems(batch, destTeamPK, masterKey) {
        const items = [];
        let failed = 0;
        for (const file of batch) {
            try {
                let teamKey = null;
                if (destTeamPK) {
                    let fileData = file;
                    if (!file.encrypted_file_key) {
                        const fetched = await Api.get(`${Config.app.apiPrefix}/files/${file.id}`);
                        fileData = fetched.file || fetched;
                    }
                    const fileKeyBytes = await _resolveFileKeyBytes(fileData, masterKey);
                    teamKey = await Teams.encryptFileKeyForTeam(fileKeyBytes, destTeamPK); // NOSONAR — async function accessed via Teams module export
                }
                items.push({ id: file.id, team_key: teamKey });
            } catch { failed++; }
        }
        return { items, failed };
    }

    async function _moveFileBatches(files, destId, destTeamPK, overlay, initialDone, total, isCancelled) {
        const masterKey = destTeamPK ? Auth.getMasterKeyObj() : null;
        let done = initialDone;
        let errors = 0;
        for (const batch of _chunk(files, 50)) {
            if (isCancelled()) break;
            overlay.update(done, total, 'Moving files…');
            const { items: batchItems, failed } = await _buildFileMoveItems(batch, destTeamPK, masterKey);
            errors += failed;
            if (batchItems.length > 0) {
                try {
                    const result = await Api.post(
                        `${Config.app.apiPrefix}/files/batch-move`,
                        { files: batchItems, destination_folder_id: destId },
                    );
                    errors += (result.failed || []).length;
                } catch { errors += batchItems.length; }
            }
            done += batch.length;
            overlay.update(done, total);
        }
        return { done, errors };
    }

    /**
     * Execute moves for a list of items to a destination (no confirmation).
     * destination: { id: string|null, label: string, isTeam: boolean }
     */
    async function _executeMoves(items, destination) {
        const destId = destination.id;

        let destTeamId = null;
        let destTeamPK = null;
        try {
            ({ destTeamId, destTeamPK } = await _resolveDestTeamInfo(destination));
        } catch {
            Utils.showToast('Failed to resolve destination team — move cancelled', 'error');
            return;
        }
        if (destination.isTeam && destId && !destTeamPK) {
            Utils.showToast('Destination folder is not part of a team — move cancelled', 'error');
            return;
        }

        const srcTeamId = _currentTeamId || null;
        const folderNeedsCrypto = srcTeamId !== destTeamId;  // null !== null is false ✓

        const folders = items.filter(i => i.type === 'folder');
        const files   = items.filter(i => i.type === 'file');
        const total   = items.length;

        let cancelled = false;
        const initialLabel = items.length === 1
            ? `Moving "${items[0].name}"…`
            : `Moving ${items.length} items…`;
        const overlay = _showMoveOverlay(initialLabel);
        overlay.onCancel(() => { cancelled = true; });

        let { done, errors } = await _executeFolderMoves(
            folders, destId, destTeamPK, folderNeedsCrypto, overlay, total,
            () => cancelled,
        );

        if (files.length > 0 && !cancelled) {
            const fileResult = await _moveFileBatches(files, destId, destTeamPK, overlay, done, total, () => cancelled);
            done = fileResult.done;
            errors += fileResult.errors;
        }

        overlay.remove();

        if (cancelled) {
            Utils.showToast(
                `Move cancelled — ${done - errors} of ${total} item${total === 1 ? '' : 's'} moved`,
                'warning',
            );
        } else {
            _finishMoveToast(items, destination, errors);
        }
        _reloadCurrentView();
    }


    /**
     * Load source team SK, file key map, and optionally the rk scalar for cross-team copies.
     * Returns { skSrcBigInt, srcTeamFileKeyMap, rkBigInt }.
     */
    async function _loadCopySourceTeamKeys(srcTeamId, destTeamId) {
        const asymKeys = Auth.getAsymmetricKeys();
        if (!asymKeys) throw new Error('Asymmetric keys not available');
        const srcMyKey = await Api.get(`${Config.app.apiPrefix}/teams/${srcTeamId}/my-key`);
        const srcKeyResult = await Teams.unwrapTeamKey( // NOSONAR — async function accessed via Teams module export
            srcMyKey, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
        );
        const skSrcBigInt = srcKeyResult.sk_bigint;
        const skSrcBytes  = srcKeyResult.sk_bytes;

        const fkData = await Api.get(`${Config.app.apiPrefix}/teams/${srcTeamId}/file-keys`);
        const srcTeamFileKeyMap = new Map((fkData.file_keys || []).map(fk => [fk.file_id, fk]));

        let rkBigInt = null;
        if (destTeamId && destTeamId !== srcTeamId) {
            const destMyKey = await Api.get(`${Config.app.apiPrefix}/teams/${destTeamId}/my-key`);
            const destKeyResult = await Teams.unwrapTeamKey( // NOSONAR — async function accessed via Teams module export
                destMyKey, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
            );
            rkBigInt = Teams.computeRKScalar(skSrcBytes, destKeyResult.sk_bytes);
        }
        return { skSrcBigInt, srcTeamFileKeyMap, rkBigInt };
    }

    /**
     * Build the batch-copy payload item for a single file.
     * ctx: { srcTeamId, destTeamId, destTeamPK, masterKey, skSrcBigInt, rkBigInt, srcTeamFileKeyMap }
     */
    async function _buildFileCopyItem(file, ctx) {
        const { srcTeamId, destTeamId, destTeamPK, masterKey, skSrcBigInt, rkBigInt, srcTeamFileKeyMap } = ctx;
        const item = { file_id: file.id };

        if (srcTeamId === destTeamId) {
            // Path 1 (personal→personal) or Path 2 (same-team): server handles everything

        } else if (!srcTeamId && destTeamId) {
            // Path 4: Personal → Team — encrypt DEK for team
            let fileData = file;
            if (!fileData.encrypted_file_key) {
                const fetched = await Api.get(`${Config.app.apiPrefix}/files/${file.id}`);
                fileData = fetched.file || fetched;
            }
            const fileKeyBytes = await _resolveFileKeyBytes(fileData, masterKey);
            const teamKey = await Teams.encryptFileKeyForTeam(fileKeyBytes, destTeamPK); // NOSONAR — async function accessed via Teams module export
            item.pre_c1 = teamKey.pre_c1;
            item.encrypted_file_key = teamKey.encrypted_file_key;
            item.key_iv = teamKey.key_iv;

        } else if (srcTeamId && !destTeamId) {
            // Path 5: Team → Personal — decrypt DEK from team, re-wrap under personal KEK
            const fk = srcTeamFileKeyMap?.get(file.id);
            if (!fk) throw new Error(`Team file key not found for ${file.id}`);
            const dekKey = await Teams.decryptFileKeyFromTeam( // NOSONAR — async function accessed via Teams module export
                fk.pre_c1, fk.encrypted_file_key, fk.key_iv, skSrcBigInt
            );
            const { encryptedKeyB64, ivB64 } = await Crypto.encryptFileKey(dekKey, masterKey);
            item.encrypted_file_key = encryptedKeyB64;
            item.key_iv = ivB64;

        } else {
            // Path 3: Cross-Team — apply re-encryption key to C1
            const fk = srcTeamFileKeyMap?.get(file.id);
            if (!fk) throw new Error(`Team file key not found for ${file.id}`);
            item.pre_c1 = await Teams.applyPRERotation(fk.pre_c1, rkBigInt); // NOSONAR — async function accessed via Teams module export
        }

        return item;
    }

    async function _copyFileBatches(files, destId, ctx, overlay, total) {
        let done = 0;
        let errors = 0;
        for (const batch of _chunk(files, 50)) {
            overlay.update(done, total, 'Copying files…');
            const batchItems = [];
            for (const file of batch) {
                try {
                    batchItems.push(await _buildFileCopyItem(file, ctx));
                } catch { errors++; }
            }
            if (batchItems.length > 0) {
                try {
                    const result = await Api.post(
                        `${Config.app.apiPrefix}/files/batch-copy`,
                        { files: batchItems, destination_folder_id: destId },
                    );
                    errors += (result.failed || []).length;
                } catch { errors += batchItems.length; }
            }
            done += batch.length;
            overlay.update(done, total);
        }
        return { done, errors };
    }

    /**
     * Execute copies for a list of file items to a destination folder.
     * Determines the crypto path per file and calls POST /files/batch-copy.
     * destination: { id: string|null, label: string, isTeam: boolean }
     */
    async function _executeCopies(files, destination) {
        const destId = destination.id;
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Session expired — please log in again', 'error');
            return;
        }

        let destTeamId = null;
        let destTeamPK = null;
        try {
            ({ destTeamId, destTeamPK } = await _resolveDestTeamInfo(destination));
        } catch {
            Utils.showToast('Failed to resolve destination team — copy cancelled', 'error');
            return;
        }

        const srcTeamId = _currentTeamId || null;
        let srcTeamFileKeyMap = null;
        let skSrcBigInt = null;
        let rkBigInt = null;

        if (srcTeamId && srcTeamId !== destTeamId) {
            try {
                ({ skSrcBigInt, srcTeamFileKeyMap, rkBigInt } = await _loadCopySourceTeamKeys(srcTeamId, destTeamId));
            } catch (e) {
                Utils.showToast(`Failed to load team key: ${e.message}`, 'error');
                return;
            }
        }

        const total = files.length;
        let errors = 0;
        const initialLabel = files.length === 1
            ? `Copying "${files[0].name}"…`
            : `Copying ${files.length} files…`;
        const overlay = _showMoveOverlay(initialLabel);
        const ctx = { srcTeamId, destTeamId, destTeamPK, masterKey, skSrcBigInt, rkBigInt, srcTeamFileKeyMap };

        ({ errors } = await _copyFileBatches(files, destId, ctx, overlay, total));

        overlay.remove();

        const label = destination.label || 'selected folder';
        if (errors === 0) {
            Utils.showToast(
                files.length === 1
                    ? `"${files[0].name}" copied to ${label}`
                    : `${files.length} files copied to ${label}`,
                'success',
            );
        } else {
            Utils.showToast(`${errors} of ${total} files failed to copy`, 'error');
        }
        _reloadCurrentView();
    }

    /**
     * Move a folder across a team boundary by recreating its structure at the
     * destination and batch-moving all contained files page by page.
     *
     * onProgress(label) — optional; called with a status string for the outer overlay.
     * isCancelled()     — optional; returns true if the user cancelled.
     */
    async function _moveFolderAcrossTeamBoundary(folder, destParentId, destTeamPK, onProgress, isCancelled) {
        const masterKey = Auth.getMasterKeyObj();

        // Create mirror folder at destination.
        // The subtree endpoint returns a flat file list; all files land in this one folder.
        let newFolderId = destParentId;
        try {
            const created = await Api.post(`${Config.app.apiPrefix}/folders`, {
                name: folder.name,
                parent_id: destParentId,
            });
            newFolderId = created.folder.id;
        } catch {
            throw new Error(`Failed to create destination folder "${folder.name}"`);
        }

        // Paginated enumeration — process each page as it arrives
        await _enumerateFolderFiles(folder.id, async (pageFiles, doneSoFar, totalFiles) => {
            if (isCancelled?.()) return;
            onProgress?.(`Moving "${folder.name}" — ${doneSoFar} / ${totalFiles} files…`);

            for (const batch of _chunk(pageFiles, 50)) {
                if (isCancelled?.()) break;
                const { items: batchItems } = await _buildFileMoveItems(batch, destTeamPK, masterKey);
                if (batchItems.length > 0) {
                    await Api.post(
                        `${Config.app.apiPrefix}/files/batch-move`,
                        { files: batchItems, destination_folder_id: newFolderId },
                    );
                }
            }
        });

        // Delete the now-empty source folder
        await Api.del(`${Config.app.apiPrefix}/folders/${folder.id}`);
    }

    /**
     * Recover raw file key bytes for a file owned by the current user.
     *
     * The personal copy (encrypted_file_key / key_iv) is always present for
     * files the user owns, regardless of whether the file is in a team folder.
     * file must have encrypted_file_key and key_iv fields (present in all
     * folder listing and /folders/{id}/files responses).
     */
    async function _resolveFileKeyBytes(file, masterKey) {
        const fileKey = await Crypto.decryptFileKey(
            file.encrypted_file_key, file.key_iv, masterKey
        );
        return new Uint8Array(await crypto.subtle.exportKey('raw', fileKey));
    }

    /** Split an array into chunks of at most `size`. */
    function _chunk(arr, size) {
        const out = [];
        for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
        return out;
    }

    /**
     * Paginated fetch of all files in a folder subtree.
     * Calls onPage(files, doneSoFar, total) for each page as it arrives.
     * doneSoFar is the cumulative file count after this page.
     */
    async function _enumerateFolderFiles(folderId, onPage) {
        const pageSize = 500;
        let offset = 0;
        let total = Infinity;
        while (offset < total) {
            const data = await Api.get(
                `${Config.app.apiPrefix}/folders/${folderId}/files?limit=${pageSize}&offset=${offset}`
            );
            total = data.total;
            offset += data.files.length;
            await onPage(data.files, offset, total);
            if (data.files.length < pageSize) break;
        }
    }

    function _finishMoveToast(items, destination, errors) {
        if (errors > 0) {
            Utils.showToast(`Moved with ${errors} error(s)`, 'warning');
        } else {
            Utils.showToast(
                items.length === 1
                    ? `"${items[0].name}" moved to ${destination.label}`
                    : `${items.length} items moved to ${destination.label}`,
                'success'
            );
        }
    }

    function _promptNewFolder() {
        Utils.showPrompt('New Folder', 'Folder name').then((name) => {
            if (!name) return;
            Api.post(`${Config.app.apiPrefix}/folders`, { name, parent_id: _currentFolderId })
                .then(() => {
                    Utils.showToast('Folder created', 'success');
                    if (_currentFolderId) loadFolder(_currentFolderId);
                    else _loadRootFolders();
                })
                .catch(err => Utils.showToast(err.message, 'error'));
        });
    }

    function _triggerUpload() {
        const input = document.createElement('input');
        input.type = 'file';
        input.multiple = true;
        input.addEventListener('change', () => {
            if (input.files.length > 0) {
                _uploadFiles(Array.from(input.files));
            }
            input.remove();
        });
        input.click();
    }

    /** Register a team file key after upload; no-op when not in a team context. */
    async function _registerTeamFileKey(fileId, fileKeyBytes) {
        if (!_currentTeamId || !_currentTeamPK || !fileId || !fileKeyBytes) return;
        const teamKey = await Teams.encryptFileKeyForTeam(fileKeyBytes, _currentTeamPK); // NOSONAR — async function accessed via Teams module export
        await Api.post(
            `${Config.app.apiPrefix}/teams/${_currentTeamId}/file-keys`,
            { file_keys: [{ file_id: fileId, ...teamKey }] },
        );
    }

    async function _initStandaloneUploadCtx(fileCount) {
        if (fileCount > Config.upload.bulkWarnThreshold) {
            const confirmed = await _showBulkUploadWarning(fileCount);
            if (!confirmed) return null;
        }
        return {
            results: { ok: 0, failed: [], firstName: null },
            conflictState: { decisionDifferent: null, decisionIdentical: null },
            fileCache: new Map(),
            lastUploadMs: null,
        };
    }

    function _reportUploadResults(ctx) {
        if (ctx.results.ok === 1) Utils.showToast(`"${ctx.results.firstName}" uploaded`, 'success');
        else if (ctx.results.ok > 1) Utils.showToast(`${ctx.results.ok} files uploaded`, 'success');
        if (ctx.results.failed.length > 0) Utils.showToast(`${ctx.results.failed.length} item(s) failed to upload`, 'error');
    }

    /**
     * Upload an array of File objects sequentially, showing a progress overlay.
     * Requires Auth.getMasterKeyObj() to return a valid CryptoKey.
     */
    async function _uploadFiles(files, targetFolderId, _ctx = null) {
        const folderId = targetFolderId === undefined ? _currentFolderId : targetFolderId;
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        const isStandalone = _ctx === null;
        if (isStandalone) {
            _ctx = await _initStandaloneUploadCtx(files.length);
            if (!_ctx) return;
        }

        const existingFiles = await _getExistingFiles(folderId, _ctx.fileCache);
        const existingByName = new Map(existingFiles.map(f => [f.original_name.toLowerCase(), f]));

        for (let i = 0; i < files.length; i++) {
            const conflict = await _processFileConflict(files[i], existingByName, _ctx);
            if (conflict.skip) continue;

            await _paceUploadIfNeeded(_ctx);
            _ctx.lastUploadMs = Date.now();

            const outcome = await _executeFileUpload(conflict.file, folderId, masterKey, _ctx, files, i, conflict.deletedForReplace);
            if (outcome === 'aborted' || outcome === 'error') break;
        }

        if (isStandalone) _reportUploadResults(_ctx);
        _reloadCurrentView();
    }

    /**
     * Render a small progress bar in the toolbar.
     * Returns { update(pct, label), remove() }.
     */
    /**
     * Show a progress bar below the toolbar for a move operation.
     * Returns { update(done, total, label?), remove(), onCancel(fn) }.
     * done/total are file counts; label replaces the text when provided.
     */
    function _showMoveOverlay(initialLabel) {
        let onCancelFn = null;

        const cancelBtn = Utils.el('button', {
            className: 'btn btn-secondary btn-sm upload-progress-cancel',
            textContent: 'Cancel',
            onClick: () => { if (onCancelFn) onCancelFn(); },
        });

        const bar = Utils.el('div', { className: 'upload-progress' }, [
            Utils.el('span', { className: 'upload-progress-label', textContent: initialLabel }),
            Utils.el('div', { className: 'upload-progress-track' }, [
                Utils.el('div', { className: 'upload-progress-fill', style: 'width:0%' }),
            ]),
            Utils.el('span', { className: 'upload-progress-pct', textContent: '' }),
            cancelBtn,
        ]);

        const toolbar = document.getElementById('files-toolbar');
        if (toolbar) toolbar.after(bar);

        return {
            update(done, total, label) {
                const labelEl = bar.querySelector('.upload-progress-label');
                const fillEl  = bar.querySelector('.upload-progress-fill');
                const pctEl   = bar.querySelector('.upload-progress-pct');
                if (label !== undefined && labelEl) labelEl.textContent = label;
                if (total > 0) {
                    const pct = Math.round((done / total) * 100);
                    if (fillEl) fillEl.style.width = `${pct}%`;
                    if (pctEl)  pctEl.textContent  = `${done} / ${total}`;
                }
            },
            remove() {
                if (bar.parentNode) bar.remove();
            },
            onCancel(fn) { onCancelFn = fn; },
        };
    }

    function _showUploadOverlay(initialLabel) {
        const bar = Utils.el('div', { className: 'upload-progress' }, [
            Utils.el('span', { className: 'upload-progress-label', textContent: initialLabel }),
            Utils.el('div', { className: 'upload-progress-track' }, [
                Utils.el('div', { className: 'upload-progress-fill', style: 'width:0%' }),
            ]),
            Utils.el('span', { className: 'upload-progress-pct', textContent: '0%' }),
        ]);

        const toolbar = document.getElementById('files-toolbar');
        if (toolbar) toolbar.after(bar);

        return {
            update(pct, label) {
                const labelEl = bar.querySelector('.upload-progress-label');
                const fillEl  = bar.querySelector('.upload-progress-fill');
                const pctEl   = bar.querySelector('.upload-progress-pct');
                if (labelEl) labelEl.textContent = label;
                if (fillEl)  fillEl.style.width = `${pct}%`;
                if (pctEl)   pctEl.textContent  = `${pct}%`;
            },
            remove() {
                if (bar.parentNode) bar.remove();
            },
        };
    }

    function _initDropZone(zone) {
        let dragCounter = 0;

        zone.addEventListener('dragenter', (e) => {
            e.preventDefault();
            dragCounter++;
            zone.classList.add('drag-over');
        });

        zone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            dragCounter--;
            if (dragCounter <= 0) {
                dragCounter = 0;
                zone.classList.remove('drag-over');
            }
        });

        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'copy';
        });

        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            dragCounter = 0;
            zone.classList.remove('drag-over');

            // Use the DataTransfer items API so we can detect folders and
            // traverse them recursively.  Fall back to files if unavailable.
            const items = e.dataTransfer?.items;
            if (items && items.length > 0) {
                const entries = [];
                for (const item of items) {
                    const entry = item.getAsEntry?.() ?? item.webkitGetAsEntry?.();
                    if (entry) entries.push(entry);
                }
                if (entries.length > 0) {
                    _uploadEntries(entries, _currentFolderId);
                    return;
                }
            }
            // Fallback: plain file list (no folder support)
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                _uploadFiles(Array.from(files));
            }
        });
    }

    async function _getExistingFiles(folderId, cache) {
        const key = folderId ?? '__root__';
        if (cache.has(key)) return cache.get(key);
        let files;
        try {
            if (folderId) {
                const data = await Api.get(`${Config.app.apiPrefix}/folders/${folderId}`);
                files = data.files || [];
            } else {
                const data = await Api.get(`${Config.app.apiPrefix}/folders`);
                files = data.files || [];
            }
        } catch {
            files = [];
        }
        cache.set(key, files);
        return files;
    }

    async function _paceUploadIfNeeded(ctx) {
        if (ctx.lastUploadMs === null) return;
        const rateLimit = Auth.getCurrentUser()?.upload_rate_limit;
        if (rateLimit > 0) {
            const minGapMs = 60000 / rateLimit;
            const elapsed = Date.now() - ctx.lastUploadMs;
            if (elapsed < minGapMs) await _sleep(minGapMs - elapsed);
        }
    }

    async function _getConflictResolution(file, existingFile, isIdentical, ctx) {
        if (!isIdentical && ctx.conflictState.decisionDifferent !== null)
            return { action: ctx.conflictState.decisionDifferent };
        if (isIdentical && ctx.conflictState.decisionIdentical !== null)
            return { action: ctx.conflictState.decisionIdentical };
        const resolution = await _showConflictModal(file, existingFile, isIdentical);
        if (resolution.applyToAll) {
            if (isIdentical) ctx.conflictState.decisionIdentical = resolution.action;
            else             ctx.conflictState.decisionDifferent = resolution.action;
        }
        return resolution;
    }

    async function _processFileConflict(file, existingByName, ctx) {
        const existingFile = existingByName.get(file.name.toLowerCase());
        if (!existingFile) return { skip: false, file, deletedForReplace: false };

        const isIdentical = existingFile.last_modified_ms != null
                         && existingFile.last_modified_ms === file.lastModified
                         && existingFile.size_bytes === file.size;

        const resolution = await _getConflictResolution(file, existingFile, isIdentical, ctx);

        if (resolution.action === 'skip') return { skip: true, file, deletedForReplace: false };

        if (resolution.action === 'replace') {
            try {
                await Api.del(`${Config.app.apiPrefix}/files/${existingFile.id}`);
                existingByName.delete(file.name.toLowerCase());
                return { skip: false, file, deletedForReplace: true };
            } catch (delErr) {
                Utils.showToast(`Failed to replace "${file.name}": ${delErr.message}`, 'error');
                ctx.results.failed.push(file.name);
                return { skip: true, file, deletedForReplace: false };
            }
        }

        if (resolution.action === 'rename') {
            file = _renameWithSuffix(file, existingByName);
        }
        return { skip: false, file, deletedForReplace: false };
    }

    async function _executeFileUpload(file, folderId, masterKey, ctx, files, i, deletedForReplace) {
        const label = files.length > 1 ? `${file.name} (${i + 1}/${files.length})` : file.name;
        const ctrl = _makeUploadCtrl(folderId, file.name);
        const overlay = _showUploadOverlay(label);
        const transfer = TransferManager.start(label, 'upload', {
            onPause:  () => { ctrl.pause();  transfer.setPaused(true);  },
            onResume: () => { ctrl.resume(); transfer.setPaused(false); },
            onStop:   () => ctrl.stop(true),
            onLogout: () => ctrl.stop(false),
        });

        try {
            const result = await Upload.uploadFile(file, folderId, masterKey, (done, total) => {
                const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                overlay.update(pct, label);
                transfer.update(pct);
                const _ae = ctrl.uploadId ? _activeUploads.get(ctrl.uploadId) : null;
                if (_ae) _ae.pct = pct;
            }, ctrl);
            overlay.remove();
            transfer.complete();
            await _registerTeamFileKey(result.fileId, result.fileKeyBytes).catch(
                teamKeyErr => console.warn('Failed to register team file key for', result.fileId, teamKeyErr),
            );
            ctx.results.ok++;
            if (!ctx.results.firstName) ctx.results.firstName = file.name;
            ctrl.cleanup();
            return 'ok';
        } catch (err) {
            overlay.remove();
            ctrl.cleanup();
            if (err instanceof Upload.AbortedError) {
                transfer.cancelled();
                if (ctrl.shouldDeleteOnAbort()) {
                    Api.del(err.location).catch(() => {});
                    Utils.showToast(`"${file.name}" upload cancelled`, 'info');
                }
                return 'aborted';
            }
            transfer.fail();
            if (deletedForReplace) {
                Utils.showToast(`Original deleted but upload failed — "${file.name}" lost. Re-upload manually.`, 'error');
            } else {
                ctx.results.failed.push(file.name);
            }
            return 'error';
        }
    }

    function _renameWithSuffix(file, existingByName) {
        const lastDot = file.name.lastIndexOf('.');
        const base = lastDot > 0 ? file.name.slice(0, lastDot) : file.name;
        const ext  = lastDot > 0 ? file.name.slice(lastDot) : '';
        let n = 1;
        let newName;
        do {
            newName = `${base} (${n})${ext}`;
            n++;
        } while (existingByName.has(newName.toLowerCase()));
        return new File([file], newName, { type: file.type });
    }

    function _wrapModalDismiss(resolve) {
        let overlay = Utils.el('div', { className: 'modal-overlay' });
        const dismiss = (action, applyToAll) => {
            if (overlay?.parentNode) overlay.remove();
            overlay = null;
            resolve({ action, applyToAll });
        };
        return { overlay, dismiss };
    }

    function _showConflictModal(file, existingFile, isIdentical) {
        return new Promise((resolve) => {
            const { overlay, dismiss } = _wrapModalDismiss(resolve);
            const checkbox = Utils.el('input', { type: 'checkbox' });
            const checkboxRow = Utils.el('label', {
                style: 'display:flex; align-items:center; gap:8px; margin-top: var(--space-3); cursor:pointer;',
            }, [checkbox, isIdentical ? ' Do this for all conflicts (identical files)' : ' Do this for all conflicts (different files)']);

            const fmtDate = (val) => new Date(val).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
            const nameStyle = 'overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:100%;';
            const metaStyle = 'color:var(--text-muted); font-size:.875rem; margin:2px 0 var(--space-3);';

            const bodyContent = isIdentical
                ? Utils.el('p', { textContent: `"${file.name}" appears identical to a file already in this folder (same size and date).` })
                : Utils.el('div', {}, [
                    Utils.el('p', { textContent: 'Existing:', style: 'font-weight:600; margin-bottom:4px;' }),
                    Utils.el('div', { textContent: existingFile.original_name, style: nameStyle }),
                    Utils.el('p', { textContent: `Size: ${Utils.formatBytes(existingFile.size_bytes)} · Uploaded: ${fmtDate(existingFile.created_at)}`, style: metaStyle }),
                    Utils.el('p', { textContent: 'New file:', style: 'font-weight:600; margin-bottom:4px;' }),
                    Utils.el('div', { textContent: file.name, style: nameStyle }),
                    Utils.el('p', { textContent: `Size: ${Utils.formatBytes(file.size)} · Modified: ${fmtDate(file.lastModified)}`, style: metaStyle }),
                ]);

            const dialog = Utils.el('div', { className: 'modal confirm-dialog' }, [
                Utils.el('h3', { textContent: 'File already exists', style: 'margin-top:0;' }),
                bodyContent,
                checkboxRow,
                Utils.el('div', { className: 'modal-actions' }, [
                    Utils.el('button', { className: 'btn btn-secondary', textContent: 'Skip',    onClick: () => dismiss('skip',    checkbox.checked) }),
                    Utils.el('button', { className: 'btn btn-secondary', textContent: 'Replace', onClick: () => dismiss('replace', checkbox.checked) }),
                    Utils.el('button', { className: 'btn btn-primary',   textContent: 'Rename',  onClick: () => dismiss('rename',  checkbox.checked) }),
                ]),
            ]);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);
        });
    }

    function _sleep(ms) { return new Promise(res => setTimeout(res, ms)); }

    function _readEntriesBatch(reader) {
        return new Promise((res, rej) => reader.readEntries(res, rej));
    }

    async function _readAllDirEntries(reader) {
        const all = [];
        let batch;
        do {
            batch = await _readEntriesBatch(reader);
            all.push(...batch);
        } while (batch.length > 0);
        return all;
    }

    async function _countEntries(entries) {
        let count = 0;
        for (const entry of entries) {
            count++;
            if (entry.isDirectory) {
                const children = await _readAllDirEntries(entry.createReader());
                count += await _countEntries(children);
            }
        }
        return count;
    }

    function _showBulkUploadWarning(count) {
        return new Promise((resolve) => {
            let overlay = Utils.el('div', { className: 'modal-overlay' });
            const dismiss = (confirmed) => {
                if (overlay?.parentNode) overlay.remove();
                overlay = null;
                resolve(confirmed);
            };
            const dialog = Utils.el('div', { className: 'modal confirm-dialog' }, [
                Utils.el('p', { textContent: `Warning: Large operation! You are about to upload ${count} items. Continue?` }),
                Utils.el('div', { className: 'modal-actions' }, [
                    Utils.el('button', {
                        className: 'btn btn-secondary',
                        textContent: 'Cancel',
                        onClick: () => dismiss(false),
                    }),
                    Utils.el('button', {
                        className: 'btn btn-primary',
                        textContent: 'Upload',
                        onClick: () => dismiss(true),
                    }),
                ]),
            ]);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);
        });
    }

    function _showFolderMergeModal(folderName) {
        return new Promise((resolve) => {
            const { overlay, dismiss } = _wrapModalDismiss(resolve);
            const checkbox = Utils.el('input', { type: 'checkbox' });
            const checkboxRow = Utils.el('label', {
                style: 'display:flex; align-items:center; gap:8px; margin-top: var(--space-3); cursor:pointer;',
            }, [checkbox, ' Do this for all folder conflicts']);
            const dialog = Utils.el('div', { className: 'modal confirm-dialog' }, [
                Utils.el('p', { textContent: `"${folderName}" already exists here. Merge new files into it, or skip this folder?` }),
                checkboxRow,
                Utils.el('div', { className: 'modal-actions' }, [
                    Utils.el('button', {
                        className: 'btn btn-secondary',
                        textContent: 'Skip',
                        onClick: () => dismiss('skip', checkbox.checked),
                    }),
                    Utils.el('button', {
                        className: 'btn btn-primary',
                        textContent: 'Merge',
                        onClick: () => dismiss('merge', checkbox.checked),
                    }),
                ]),
            ]);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);
        });
    }

    /**
     * Recursively upload a list of FileSystemEntry objects (files and/or folders).
     * Folders are created on the server first, then their contents are uploaded.
     */
    async function _resolveNewFolderId(entry, parentFolderId, ctx) {
        try {
            const created = await Api.post(`${Config.app.apiPrefix}/folders`, {
                name: entry.name,
                parent_id: parentFolderId || null,
            });
            return created.folder.id;
        } catch (err) {
            if (err.status === 409 && err.existingFolderId) {
                let action = ctx.mergeState.decision;
                if (!action) {
                    const choice = await _showFolderMergeModal(entry.name);
                    if (choice.applyToAll) ctx.mergeState.decision = choice.action;
                    action = choice.action;
                }
                return action === 'merge' ? err.existingFolderId : null;
            }
            ctx.results.failed.push(entry.name);
            return null;
        }
    }

    async function _initEntriesUploadCtx(entries) {
        const totalCount = await _countEntries(entries);
        if (totalCount > Config.upload.bulkWarnThreshold) {
            const confirmed = await _showBulkUploadWarning(totalCount);
            if (!confirmed) return null;
        }
        return {
            results: { ok: 0, failed: [], firstName: null },
            mergeState: { decision: null },
            conflictState: { decisionDifferent: null, decisionIdentical: null },
            fileCache: new Map(),
            lastUploadMs: null,
        };
    }

    async function _uploadEntries(entries, parentFolderId, _ctx = null) {
        const isTopLevel = _ctx === null;
        if (isTopLevel) {
            _ctx = await _initEntriesUploadCtx(entries);
            if (!_ctx) return;
        }

        for (const entry of entries) {
            if (entry.isFile) {
                const file = await new Promise((res, rej) => entry.file(res, rej));
                await _uploadFiles([file], parentFolderId, _ctx);
            } else if (entry.isDirectory) {
                const newFolderId = await _resolveNewFolderId(entry, parentFolderId, _ctx);
                if (newFolderId === null) continue;
                const children = await _readAllDirEntries(entry.createReader());
                if (children.length > 0) await _uploadEntries(children, newFolderId, _ctx);
            }
        }

        if (isTopLevel) _reportUploadResults(_ctx);
    }

    /**
     * Create a pause/stop controller for a single upload.
     *
     * Exposes the duck-typed shape that Upload.uploadFile / resumeUpload accept
     * as their `ctrl` parameter, plus wiring points for TransferManager buttons.
     *
     * Call ctrl.onCreated(uploadId) is invoked by uploadFile after the server
     * creates the upload resource; it registers the ID so pending-upload rows
     * are suppressed while the live TransferManager row is active.
     */
    function _makeUploadCtrl(folderId = null, originalName = '') {
        let _paused        = false;
        let _stopped       = false;
        let _deleteOnAbort = true;   // false when stopped by logout (leave partial for resume)
        let _uploadId      = null;
        let _resumeResolvers = [];

        const ctrl = {
            get uploadId() { return _uploadId; },

            onCreated(id) {
                _uploadId = id;
                _activeUploads.set(id, { pct: 0, folderId, originalName });
            },

            pause() {
                _paused = true;
            },

            resume() {
                _paused = false;
                const rs = _resumeResolvers.splice(0);
                rs.forEach(r => r());
            },

            /** @param {boolean} [deleteOnAbort=true] - false for logout (leave partial on server). */
            stop(deleteOnAbort = true) {
                _deleteOnAbort = deleteOnAbort;
                _stopped = true;
                // Unblock waitIfPaused so the upload loop can detect the stop flag
                if (_paused) ctrl.resume();
            },

            async waitIfPaused() {
                while (_paused) { // NOSONAR — _paused is set by resume() via the controller closure
                    await new Promise(resolve => _resumeResolvers.push(resolve));
                }
            },

            isStopped() { return _stopped; },

            /** Whether the catch block should DELETE the partial upload from the server. */
            shouldDeleteOnAbort() { return _deleteOnAbort; },

            cleanup() {
                if (_uploadId) _activeUploads.delete(_uploadId);
            },
        };

        return ctrl;
    }

    /** Remove all child nodes properly instead of innerHTML = '' */
    function _clearContainer(el) {
        while (el.firstChild) {
            el.firstChild.remove();
        }
    }

    function getSelectedItems() {
        const checkboxes = document.querySelectorAll('#file-list input[type="checkbox"]:checked:not(.select-all)');
        return Array.from(checkboxes).map(cb => ({
            type: cb.dataset.type,
            id: cb.dataset.id,
            name: cb.dataset.name || '',
        }));
    }

    function downloadFileById(_id, file) {
        return _downloadFile(file);
    }

    return {
        renderFileBrowser,
        loadFolder,
        downloadFileById,
        getSelectedItems,
        stopLive: _stopLive,
    };
})();
