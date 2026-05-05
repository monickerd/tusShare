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
            _loadFolderTree();
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

    async function _loadFolderTree() {
        const treeEl = document.getElementById('folder-tree');
        if (!treeEl) return;
        _clearContainer(treeEl);
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/folders`);
            if (data.folders.length === 0) {
                treeEl.appendChild(Utils.el('div', {
                    className: 'tree-empty',
                    textContent: 'No folders yet',
                }));
                return;
            }
            const list = Utils.el('ul', { className: 'tree-list' });
            for (const folder of data.folders) {
                list.appendChild(_createTreeNode(folder));
            }
            treeEl.appendChild(list);
        } catch {
            // Silently fail — tree is supplementary navigation
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
        el.appendChild(Utils.el('a', {
            href: rootHash,
            className: 'breadcrumb-link',
            textContent: rootLabel,
        }));

        // Ancestor folders
        for (const crumb of ancestors) {
            el.appendChild(Utils.el('span', { className: 'breadcrumb-sep', textContent: ' / ' }));
            el.appendChild(Utils.el('a', {
                href: `#/files/${crumb.id}`,
                className: 'breadcrumb-link',
                textContent: crumb.name,
            }));
        }

        // Current folder
        if (currentFolder) {
            el.appendChild(Utils.el('span', { className: 'breadcrumb-sep', textContent: ' / ' }));
            el.appendChild(Utils.el('span', {
                className: 'breadcrumb-current',
                textContent: currentFolder.name,
            }));
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
        return Utils.el('tr', { className: 'row-folder' }, [
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
                    { label: 'Move', action: () => _openMoveModal([{ type: 'folder', id: folder.id, name: folder.name }]) },
                    { label: 'Rename', action: () => _renameFolder(folder) },
                    { label: 'Delete', action: () => _deleteFolder(folder), danger: true },
                ]),
            ]),
        ]);
    }

    function _createFileRow(file) {
        return Utils.el('tr', { className: 'row-file' }, [
            Utils.el('td', {}, [Utils.el('input', { type: 'checkbox', dataset: { type: 'file', id: file.id, name: file.original_name } })]),
            Utils.el('td', { textContent: file.original_name }),
            Utils.el('td', { textContent: Utils.formatBytes(file.size_bytes) }),
            Utils.el('td', { textContent: Utils.timeAgo(file.created_at) }),
            Utils.el('td', { className: 'row-actions' }, [
                _createContextButton(() => _fileContextItems(file)),
            ]),
        ]);
    }

    async function _fileContextItems(file) {
        const items = [
            { label: 'Download', action: () => _downloadFile(file) },
            { label: 'Share (link)', action: () => Shares.openShareDialog([file]) },
            { label: 'Share with user', action: () => Shares.openUserShareDialog([file]) },
            { label: 'Add to Team', action: () => Teams.openAddToTeamDialog([file]) },
            { label: 'Move', action: () => _openMoveModal([{ type: 'file', id: file.id, name: file.original_name }]) },
            { label: 'Copy to…', action: () => _openCopyModal([{ type: 'file', id: file.id, name: file.original_name, encrypted_file_key: file.encrypted_file_key, key_iv: file.key_iv }]) },
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
                await Upload.resumeUpload(location, selectedFile, fileKey, (done, total) => {
                    const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                    overlay.update(pct, upload.original_name);
                    transfer.update(pct);
                    const _ae = ctrl.uploadId ? _activeUploads.get(ctrl.uploadId) : null;
                    if (_ae) _ae.pct = pct;
                }, ctrl);
                overlay.remove();
                transfer.complete();
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

    function _previewFilenameSanitize(name) {
        const blacklist = Config.file.nameBlacklistChars;
        const removed = [];
        let cleaned = '';
        for (const ch of name) {
            const code = ch.charCodeAt(0);
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
        if (!_isSharedView) _loadFolderTree();
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
            textContent: 'Add to Team',
            onClick: () => _bulkAddToTeam(selected),
        }));
        bar.appendChild(Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Move selected',
            onClick: () => _openMoveModal(selected),
        }));
        bar.appendChild(Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Copy selected',
            onClick: () => _openCopyModal(selected.filter(i => i.type === 'file')),
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

    async function _bulkAddToTeam(items) {
        const fileItems = items.filter(i => i.type === 'file');
        if (fileItems.length === 0) {
            Utils.showToast('Select files to add to a team', 'info');
            return;
        }

        // Fetch full file metadata (need encrypted_file_key + key_iv)
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

        Teams.openAddToTeamDialog(files);
    }

    // ── Move files / folders ──────────────────────────────────────────────────

    /**
     * Open the move-destination picker modal.
     * items: [{ type: 'file'|'folder', id: string, name: string }]
     * sourceIsTeam derived from _isTeamView at call time.
     */
    async function _openMoveModal(items) {
        if (items.length === 0) return;

        const sourceIsTeam = _isTeamView;
        let selectedDest = null; // { id: string|null, label: string, isTeam: boolean }
        let currentSelectedEl = null;

        const moveBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Move here',
            disabled: true,
            onClick: async () => {
                overlay.remove();
                await _confirmAndExecuteMoves(items, selectedDest, sourceIsTeam);
            },
        });

        function _selectDest(optionEl, dest) {
            if (currentSelectedEl) currentSelectedEl.classList.remove('selected');
            optionEl.classList.add('selected');
            currentSelectedEl = optionEl;
            selectedDest = dest;
            moveBtn.disabled = false;
        }

        const pickerList = Utils.el('ul', { className: 'folder-picker' });

        // Personal section header
        pickerList.appendChild(Utils.el('li', { className: 'folder-picker-section', textContent: 'My Files' }));

        // My Files root option
        const rootRow = Utils.el('div', { className: 'folder-picker-option' }, [
            Utils.el('span', { className: 'picker-folder-name', textContent: 'My Files (root)' }),
        ]);
        rootRow.addEventListener('click', () => _selectDest(rootRow, { id: null, label: 'My Files (root)', isTeam: false }));
        pickerList.appendChild(Utils.el('li', { className: 'folder-picker-item' }, [rootRow]));

        const loadingLi = Utils.el('li', { className: 'folder-picker-loading', textContent: 'Loading…' });
        pickerList.appendChild(loadingLi);

        const overlay = Utils.el('div', {
            className: 'modal-overlay',
            onClick: (e) => { if (e.target === overlay) overlay.remove(); },
        });

        const title = items.length === 1
            ? `Move "${items[0].name}"`
            : `Move ${items.length} items`;

        overlay.appendChild(Utils.el('div', { className: 'modal move-modal' }, [
            Utils.el('h3', { textContent: title }),
            pickerList,
            Utils.el('div', { className: 'modal-actions' }, [
                Utils.el('button', {
                    className: 'btn btn-secondary',
                    textContent: 'Cancel',
                    onClick: () => overlay.remove(),
                }),
                moveBtn,
            ]),
        ]));
        document.body.appendChild(overlay);

        // Load personal folders and teams in parallel, then team folders sequentially
        try {
            const [foldersData, teamsData] = await Promise.all([
                Api.get(`${Config.app.apiPrefix}/folders`),
                Api.get(`${Config.app.apiPrefix}/teams`),
            ]);
            loadingLi.remove();

            // Personal folders
            for (const folder of (foldersData.folders || [])) {
                pickerList.appendChild(_createPickerFolderNode(folder, 0, _selectDest, false));
            }

            // One section per team with its root-level team folders
            for (const team of (teamsData.teams || [])) {
                pickerList.appendChild(Utils.el('li', {
                    className: 'folder-picker-section',
                    textContent: team.name,
                }));
                try {
                    const tfData = await Api.get(`${Config.app.apiPrefix}/teams/${team.id}/folders`);
                    const teamFolders = tfData.folders || [];
                    if (teamFolders.length === 0) {
                        pickerList.appendChild(Utils.el('li', {
                            className: 'folder-picker-loading',
                            textContent: 'No folders in this team',
                        }));
                    } else {
                        for (const tf of teamFolders) {
                            // TeamFolder shape: { folder_id, folder_name, ... }
                            pickerList.appendChild(_createPickerFolderNode(
                                { id: tf.folder_id, name: tf.folder_name },
                                0, _selectDest, true,
                            ));
                        }
                    }
                } catch {
                    pickerList.appendChild(Utils.el('li', {
                        className: 'folder-picker-error',
                        textContent: 'Failed to load folders',
                    }));
                }
            }
        } catch {
            if (loadingLi.parentNode) loadingLi.textContent = 'Failed to load folders';
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

    /**
     * Run pre-move checks (active shares, cross-boundary warning) then execute.
     * destination: { id: string|null, label: string, isTeam: boolean }
     */
    async function _confirmAndExecuteMoves(items, destination, sourceIsTeam) {
        // 1. Active share check — warn if any item has a live share link
        const allIds = items.map(i => i.id);
        let idsWithShares = [];
        try {
            const res = await Api.post(
                `${Config.app.apiPrefix}/shares/active-for-items`,
                { resource_ids: allIds },
            );
            idsWithShares = res.ids_with_shares || [];
        } catch {
            // Best-effort; skip the check if the endpoint fails
        }

        if (idsWithShares.length > 0) {
            const shareMsg = idsWithShares.length === 1
                ? `One of the selected items has an active share link. Recipients of that link may lose access after the move.`
                : `${idsWithShares.length} of the selected items have active share links. Recipients of those links may lose access after the move.`;
            const ok = await Utils.showConfirm(shareMsg + '\n\nProceed anyway?');
            if (!ok) return;
        }

        // 2. Cross-boundary warning
        const destIsTeam = destination.isTeam;
        if (sourceIsTeam !== destIsTeam) {
            let boundaryMsg;
            if (!sourceIsTeam && destIsTeam) {
                boundaryMsg = `Warning: By moving to "${destination.label}", you will be sharing ${items.length === 1 ? 'this item' : 'these items'} with everyone who has access to that folder.`;
            } else {
                boundaryMsg = `Warning: By moving to your personal files, team members will lose access to ${items.length === 1 ? 'this item' : 'these items'}.`;
            }
            const ok = await Utils.showConfirm(boundaryMsg + '\n\nProceed?');
            if (!ok) return;
        }

        await _executeMoves(items, destination);
    }

    /**
     * Execute moves for a list of items to a destination (no confirmation).
     * destination: { id: string|null, label: string, isTeam: boolean }
     */
    async function _executeMoves(items, destination) {
        const destId = destination.id;

        // Resolve destination team (if any)
        let destTeamPK = null;
        let destTeamId = null;
        if (destination.isTeam && destId) {
            try {
                const folderData = await Api.get(`${Config.app.apiPrefix}/folders/${destId}`);
                destTeamId = folderData.team_id || null;
                if (destTeamId) {
                    const teamData = await Api.get(`${Config.app.apiPrefix}/teams/${destTeamId}`);
                    destTeamPK = teamData.team?.pre_public_key || null;
                }
            } catch {
                Utils.showToast('Failed to resolve destination team — move cancelled', 'error');
                return;
            }
            if (!destTeamPK) {
                Utils.showToast('Destination folder is not part of a team — move cancelled', 'error');
                return;
            }
        }

        // Cross-team folder moves require re-encryption; same-team/personal use a simple PATCH.
        const srcTeamId = _currentTeamId || null;
        const folderNeedsCrypto = srcTeamId !== destTeamId;  // null !== null is false ✓

        const folders = items.filter(i => i.type === 'folder');
        const files   = items.filter(i => i.type === 'file');

        let errors = 0;
        let done = 0;
        const total = items.length;
        let cancelled = false;

        const initialLabel = items.length === 1
            ? `Moving "${items[0].name}"…`
            : `Moving ${items.length} items…`;
        const overlay = _showMoveOverlay(initialLabel);
        overlay.onCancel(() => { cancelled = true; });

        // --- Folder moves ---
        for (const folder of folders) {
            if (cancelled) break;
            overlay.update(done, total, `Moving "${folder.name}"…`);
            try {
                if (folderNeedsCrypto) {
                    await _moveFolderAcrossTeamBoundary(
                        folder, destId, destTeamPK,
                        (label) => overlay.update(done, total, label),
                        () => cancelled,
                    );
                } else {
                    await Api.put(`${Config.app.apiPrefix}/folders/${folder.id}`,
                        destId === null ? { move_to_root: true } : { parent_id: destId });
                }
            } catch { errors++; }
            done++;
            overlay.update(done, total);
        }

        // --- File moves — always use batch-move ---
        // For team destinations: fetch full metadata (encrypted_file_key + key_iv) per file
        // if not already present, then encrypt a team_key via PRE.
        // For personal destinations: team_key is null — no crypto needed.
        if (files.length > 0 && !cancelled) {
            const masterKey = destTeamPK ? Auth.getMasterKeyObj() : null;
            const batches = _chunk(files, 50);
            for (const batch of batches) {
                if (cancelled) break;
                overlay.update(done, total, `Moving files…`);
                const batchItems = [];
                for (const file of batch) {
                    try {
                        let teamKey = null;
                        if (destTeamPK) {
                            // Items from the file list only carry { type, id, name };
                            // fetch full metadata to get the crypto fields.
                            let fileData = file;
                            if (!file.encrypted_file_key) {
                                const fetched = await Api.get(`${Config.app.apiPrefix}/files/${file.id}`);
                                fileData = fetched.file || fetched;
                            }
                            const fileKeyBytes = await _resolveFileKeyBytes(fileData, masterKey);
                            teamKey = await Teams.encryptFileKeyForTeam(fileKeyBytes, destTeamPK);
                        }
                        batchItems.push({ id: file.id, team_key: teamKey });
                    } catch { errors++; }
                }
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
        }

        overlay.remove();

        if (cancelled) {
            const moved = done - errors;
            Utils.showToast(
                `Move cancelled — ${moved} of ${total} item${total === 1 ? '' : 's'} moved`,
                'warning',
            );
        } else {
            _finishMoveToast(items, destination, errors);
        }
        _reloadCurrentView();
    }

    /**
     * Open the folder-picker modal for a copy operation.
     * Only file items are copied (folder items are silently filtered out).
     */
    function _openCopyModal(items) {
        const files = items.filter(i => i.type === 'file');
        if (files.length === 0) {
            Utils.showToast('Only files can be copied — select at least one file.', 'warning');
            return;
        }

        let selectedDest = null;
        let currentSelectedEl = null;

        const copyBtn = Utils.el('button', {
            className: 'btn btn-primary',
            textContent: 'Copy here',
            disabled: true,
            onClick: async () => {
                overlay.remove();
                await _executeCopies(files, selectedDest);
            },
        });

        function _selectDest(optionEl, dest) {
            if (currentSelectedEl) currentSelectedEl.classList.remove('selected');
            optionEl.classList.add('selected');
            currentSelectedEl = optionEl;
            selectedDest = dest;
            copyBtn.disabled = false;
        }

        const pickerList = Utils.el('ul', { className: 'folder-picker' });
        pickerList.appendChild(Utils.el('li', { className: 'folder-picker-section', textContent: 'My Files' }));

        const rootRow = Utils.el('div', { className: 'folder-picker-option' }, [
            Utils.el('span', { className: 'picker-folder-name', textContent: 'My Files (root)' }),
        ]);
        rootRow.addEventListener('click', () => _selectDest(rootRow, { id: null, label: 'My Files (root)', isTeam: false }));
        pickerList.appendChild(Utils.el('li', { className: 'folder-picker-item' }, [rootRow]));

        const loadingLi = Utils.el('li', { className: 'folder-picker-loading', textContent: 'Loading…' });
        pickerList.appendChild(loadingLi);

        const overlay = Utils.el('div', {
            className: 'modal-overlay',
            onClick: (e) => { if (e.target === overlay) overlay.remove(); },
        });

        const title = files.length === 1
            ? `Copy "${files[0].name}"`
            : `Copy ${files.length} files`;

        overlay.appendChild(Utils.el('div', { className: 'modal move-modal' }, [
            Utils.el('h3', { textContent: title }),
            pickerList,
            Utils.el('div', { className: 'modal-actions' }, [
                Utils.el('button', {
                    className: 'btn btn-secondary',
                    textContent: 'Cancel',
                    onClick: () => overlay.remove(),
                }),
                copyBtn,
            ]),
        ]));
        document.body.appendChild(overlay);

        Promise.all([
            Api.get(`${Config.app.apiPrefix}/folders`),
            Api.get(`${Config.app.apiPrefix}/teams`),
        ]).then(async ([foldersData, teamsData]) => {
            loadingLi.remove();
            for (const folder of (foldersData.folders || [])) {
                pickerList.appendChild(_createPickerFolderNode(folder, 0, _selectDest, false));
            }
            for (const team of (teamsData.teams || [])) {
                pickerList.appendChild(Utils.el('li', { className: 'folder-picker-section', textContent: team.name }));
                try {
                    const tfData = await Api.get(`${Config.app.apiPrefix}/teams/${team.id}/folders`);
                    const teamFolders = tfData.folders || [];
                    if (teamFolders.length === 0) {
                        pickerList.appendChild(Utils.el('li', { className: 'folder-picker-loading', textContent: 'No folders in this team' }));
                    } else {
                        for (const tf of teamFolders) {
                            pickerList.appendChild(_createPickerFolderNode(
                                { id: tf.folder_id, name: tf.folder_name }, 0, _selectDest, true
                            ));
                        }
                    }
                } catch {
                    pickerList.appendChild(Utils.el('li', { className: 'folder-picker-error', textContent: 'Failed to load folders' }));
                }
            }
        }).catch(() => {
            if (loadingLi.parentNode) loadingLi.textContent = 'Failed to load folders';
        });
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

        // Resolve destination team info
        let destTeamId = null;
        let destTeamPK = null;
        if (destination.isTeam && destId) {
            try {
                const folderData = await Api.get(`${Config.app.apiPrefix}/folders/${destId}`);
                destTeamId = folderData.team_id || null;
                if (destTeamId) {
                    const teamData = await Api.get(`${Config.app.apiPrefix}/teams/${destTeamId}`);
                    destTeamPK = teamData.team?.pre_public_key || null;
                }
            } catch {
                Utils.showToast('Failed to resolve destination team — copy cancelled', 'error');
                return;
            }
        }

        const srcTeamId = _currentTeamId || null;

        // Pre-fetch source team file keys and my team SK when needed for cross-boundary paths
        let srcTeamFileKeyMap = null; // Map<file_id, {pre_c1, encrypted_file_key, key_iv}>
        let skSrcBigInt = null;
        let skSrcBytes = null;
        let skDestBytes = null;
        let rkBigInt = null;

        const needsSourceTeamKey = srcTeamId && srcTeamId !== destTeamId;

        if (needsSourceTeamKey) {
            try {
                const asymKeys = Auth.getAsymmetricKeys();
                if (!asymKeys) throw new Error('Asymmetric keys not available');
                const srcMyKey = await Api.get(`${Config.app.apiPrefix}/teams/${srcTeamId}/my-key`);
                const srcKeyResult = await Teams.unwrapTeamKey(
                    srcMyKey, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
                );
                skSrcBigInt = srcKeyResult.sk_bigint;
                skSrcBytes  = srcKeyResult.sk_bytes;

                // Fetch all file keys for this source team once
                const fkData = await Api.get(`${Config.app.apiPrefix}/teams/${srcTeamId}/file-keys`);
                srcTeamFileKeyMap = new Map((fkData.file_keys || []).map(fk => [fk.file_id, fk]));

                // Cross-team (path 3): also unwrap dest team SK to compute rk
                if (destTeamId && destTeamId !== srcTeamId) {
                    const destMyKey = await Api.get(`${Config.app.apiPrefix}/teams/${destTeamId}/my-key`);
                    const destKeyResult = await Teams.unwrapTeamKey(
                        destMyKey, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
                    );
                    skDestBytes = destKeyResult.sk_bytes;
                    rkBigInt = Teams.computeRKScalar(skSrcBytes, skDestBytes);
                }
            } catch (e) {
                Utils.showToast(`Failed to load team key: ${e.message}`, 'error');
                return;
            }
        }

        const total = files.length;
        let errors = 0;
        let done = 0;

        const initialLabel = files.length === 1
            ? `Copying "${files[0].name}"…`
            : `Copying ${files.length} files…`;
        const overlay = _showMoveOverlay(initialLabel);

        const batches = _chunk(files, 50);
        for (const batch of batches) {
            overlay.update(done, total, 'Copying files…');
            const batchItems = [];

            for (const file of batch) {
                try {
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
                        const teamKey = await Teams.encryptFileKeyForTeam(fileKeyBytes, destTeamPK);
                        item.pre_c1 = teamKey.pre_c1;
                        item.encrypted_file_key = teamKey.encrypted_file_key;
                        item.key_iv = teamKey.key_iv;

                    } else if (srcTeamId && !destTeamId) {
                        // Path 5: Team → Personal — decrypt DEK from team, re-wrap under personal KEK
                        const fk = srcTeamFileKeyMap?.get(file.id);
                        if (!fk) throw new Error(`Team file key not found for ${file.id}`);
                        const dekKey = await Teams.decryptFileKeyFromTeam(
                            fk.pre_c1, fk.encrypted_file_key, fk.key_iv, skSrcBigInt
                        );
                        const { encryptedKeyB64, ivB64 } = await Crypto.encryptFileKey(dekKey, masterKey);
                        item.encrypted_file_key = encryptedKeyB64;
                        item.key_iv = ivB64;

                    } else {
                        // Path 3: Cross-Team — apply re-encryption key to C1
                        const fk = srcTeamFileKeyMap?.get(file.id);
                        if (!fk) throw new Error(`Team file key not found for ${file.id}`);
                        item.pre_c1 = await Teams.applyPRERotation(fk.pre_c1, rkBigInt);
                    }

                    batchItems.push(item);
                } catch {
                    errors++;
                }
            }

            if (batchItems.length > 0) {
                try {
                    const result = await Api.post(
                        `${Config.app.apiPrefix}/files/batch-copy`,
                        { files: batchItems, destination_folder_id: destId },
                    );
                    errors += (result.failed || []).length;
                } catch {
                    errors += batchItems.length;
                }
            }
            done += batch.length;
            overlay.update(done, total);
        }

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
            if (isCancelled && isCancelled()) return;
            if (onProgress) {
                onProgress(`Moving "${folder.name}" — ${doneSoFar} / ${totalFiles} files…`);
            }

            const batches = _chunk(pageFiles, 50);
            for (const batch of batches) {
                if (isCancelled && isCancelled()) break;
                const batchItems = [];
                for (const file of batch) {
                    try {
                        const fileKeyBytes = await _resolveFileKeyBytes(file, masterKey);
                        const teamKey = destTeamPK
                            ? await Teams.encryptFileKeyForTeam(fileKeyBytes, destTeamPK)
                            : null;
                        batchItems.push({ id: file.id, team_key: teamKey });
                    } catch { /* skip file, leave in source */ }
                }
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

    /**
     * Upload an array of File objects sequentially, showing a progress overlay.
     * Requires Auth.getMasterKeyObj() to return a valid CryptoKey.
     */
    async function _uploadFiles(files, targetFolderId) {
        const folderId = targetFolderId !== undefined ? targetFolderId : _currentFolderId;
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
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

                // Register file_team_keys so team members can decrypt this file
                if (_currentTeamId && _currentTeamPK && result.fileId && result.fileKeyBytes) {
                    try {
                        const teamKey = await Teams.encryptFileKeyForTeam(result.fileKeyBytes, _currentTeamPK);
                        await Api.post(
                            `${Config.app.apiPrefix}/teams/${_currentTeamId}/file-keys`,
                            { file_keys: [{ file_id: result.fileId, ...teamKey }] },
                        );
                    } catch (teamKeyErr) {
                        // Non-fatal: file is uploaded and owner can access it; log the failure
                        console.warn('Failed to register team file key for', result.fileId, teamKeyErr);
                    }
                }

                Utils.showToast(`"${file.name}" uploaded`, 'success');
            } catch (err) {
                overlay.remove();
                if (err instanceof Upload.AbortedError) {
                    transfer.cancelled();
                    if (ctrl.shouldDeleteOnAbort()) {
                        Api.del(err.location).catch(() => {});
                        Utils.showToast(`"${file.name}" upload cancelled`, 'info');
                    }
                    ctrl.cleanup();
                    break;
                }
                transfer.fail();
                Utils.showToast(`Upload failed: ${err.message}`, 'error');
                ctrl.cleanup();
                break;
            }
            ctrl.cleanup();
        }

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

    /**
     * Recursively upload a list of FileSystemEntry objects (files and/or folders).
     * Folders are created on the server first, then their contents are uploaded.
     */
    async function _uploadEntries(entries, parentFolderId) {
        for (const entry of entries) {
            if (entry.isFile) {
                const file = await new Promise((res, rej) => entry.file(res, rej));
                await _uploadFiles([file], parentFolderId);
            } else if (entry.isDirectory) {
                // Create the folder on the server, then recurse into it
                let newFolderId;
                try {
                    const created = await Api.post(`${Config.app.apiPrefix}/folders`, {
                        name: entry.name,
                        parent_id: parentFolderId || null,
                    });
                    newFolderId = created.id;
                } catch (err) {
                    Utils.showToast(`Failed to create folder "${entry.name}": ${err.message}`, 'error');
                    return;
                }

                const reader = entry.createReader();
                const children = await new Promise((res, rej) => {
                    const all = [];
                    function readBatch() {
                        reader.readEntries((batch) => { // NOSONAR — callback inside readBatch inside Promise; nesting is required by the FileSystem API
                            if (batch.length === 0) { res(all); return; }
                            all.push(...batch);
                            readBatch();
                        }, rej);
                    }
                    readBatch();
                });
                if (children.length > 0) {
                    await _uploadEntries(children, newFolderId);
                }
            }
        }
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

    return {
        renderFileBrowser,
        loadFolder,
        getSelectedItems,
        stopLive: _stopLive,
    };
})();
