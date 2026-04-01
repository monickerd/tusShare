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
    const _pageSize = Config.ui.paginationDefaultLimit;

    /**
     * @param {HTMLElement} container
     * @param {{ shared?: boolean }} opts
     */
    function renderFileBrowser(container, opts = {}) {
        _isSharedView = !!opts.shared;
        _clearContainer(container);

        const myFilesLink = Utils.el('a', {
            href: '#/files',
            className: 'sidebar-link' + (_isSharedView ? '' : ' active'),
            textContent: 'My Files',
        });
        const sharedLink = Utils.el('a', {
            href: '#/shared',
            className: 'sidebar-link' + (_isSharedView ? ' active' : ''),
            textContent: 'Shared Folder',
        });

        const layout = Utils.el('div', { className: 'files-layout' }, [
            Utils.el('aside', { className: 'sidebar', id: 'folder-sidebar' }, [
                Utils.el('nav', { className: 'sidebar-nav' }, [
                    myFilesLink,
                    sharedLink,
                    Utils.el('a', {
                        href: '#/shares', className: 'sidebar-link',
                        textContent: 'My Shares',
                    }),
                    Utils.el('a', {
                        href: '#/shares/received', className: 'sidebar-link',
                        textContent: 'Received Shares',
                    }),
                    Utils.el('a', {
                        href: '#/teams', className: 'sidebar-link',
                        textContent: 'Teams',
                    }),
                ]),
                Utils.el('div', { id: 'folder-tree', className: 'folder-tree' }),
            ]),
            Utils.el('main', { className: 'files-main' }, [
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
            ]),
        ]);

        // Admin link if admin
        const user = Auth.getCurrentUser();
        if (user && user.is_admin) {
            const nav = layout.querySelector('.sidebar-nav');
            nav.appendChild(Utils.el('a', {
                href: '#/admin', className: 'sidebar-link sidebar-admin',
                textContent: 'Admin',
            }));
        }

        container.appendChild(layout);
        if (!_isSharedView) {
            _loadRootFolders();
            _loadFolderTree();
        }

        // Wire up drag-and-drop on the file list area
        const dropZone = layout.querySelector('.drop-zone');
        if (dropZone) _initDropZone(dropZone);
    }

    async function _loadRootFolders() {
        _currentFolderId = null;
        _currentFolder = null;
        const listEl = document.getElementById('file-list');
        // Show root breadcrumb
        _renderBreadcrumbs([], null);
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/folders`);
            _renderFolderContents(listEl, data.folders, data.files || []);
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
            _renderBreadcrumbs(data.breadcrumbs || [], data.folder);
            _renderFolderContents(listEl, data.child_folders, data.files);
        } catch (err) {
            listEl.textContent = 'Failed to load folder: ' + err.message;
        }
    }

    function _renderBreadcrumbs(ancestors, currentFolder) {
        const el = document.getElementById('breadcrumbs');
        if (!el) return;
        _clearContainer(el);

        // Root link
        const rootLabel = _isSharedView ? 'Shared Folder' : 'My Files';
        const rootHash = _isSharedView ? '#/shared' : '#/files';
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

    function _renderFolderContents(container, folders, files) {
        _clearContainer(container);

        if (folders.length === 0 && files.length === 0) {
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
        return Utils.el('tr', { className: 'row-folder' }, [
            Utils.el('td', {}, [Utils.el('input', { type: 'checkbox', dataset: { type: 'folder', id: folder.id } })]),
            Utils.el('td', {}, [
                Utils.el('a', {
                    href: `#/files/${folder.id}`,
                    className: 'folder-link',
                    textContent: folder.name,
                }),
            ]),
            Utils.el('td', { textContent: '--' }),
            Utils.el('td', { textContent: Utils.timeAgo(folder.updated_at) }),
            Utils.el('td', { className: 'row-actions' }, [
                _createContextButton([
                    { label: 'Share', action: () => Shares.openFolderShareDialog(folder) },
                    { label: 'Rename', action: () => _renameFolder(folder) },
                    { label: 'Delete', action: () => _deleteFolder(folder), danger: true },
                ]),
            ]),
        ]);
    }

    function _createFileRow(file) {
        return Utils.el('tr', { className: 'row-file' }, [
            Utils.el('td', {}, [Utils.el('input', { type: 'checkbox', dataset: { type: 'file', id: file.id } })]),
            Utils.el('td', { textContent: file.original_name }),
            Utils.el('td', { textContent: Utils.formatBytes(file.size_bytes) }),
            Utils.el('td', { textContent: Utils.timeAgo(file.created_at) }),
            Utils.el('td', { className: 'row-actions' }, [
                _createContextButton([
                    { label: 'Download', action: () => _downloadFile(file) },
                    { label: 'Share (link)', action: () => Shares.openShareDialog([file]) },
                    { label: 'Share with user', action: () => Shares.openUserShareDialog([file]) },
                    { label: 'Add to Team', action: () => Teams.openAddToTeamDialog([file]) },
                    { label: 'Rename', action: () => _renameFile(file) },
                    { label: 'Delete', action: () => _deleteFile(file), danger: true },
                ]),
            ]),
        ]);
    }

    async function _downloadFile(file) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        const overlay = _showUploadOverlay(file.original_name);
        try {
            await Download.downloadFile(file.id, masterKey, (done, total) => {
                const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                overlay.update(pct, file.original_name);
            });
            overlay.remove();
        } catch (err) {
            overlay.remove();
            Utils.showToast(`Download failed: ${err.message}`, 'error');
        }
    }

    function _createContextButton(items) {
        const btn = Utils.el('button', {
            className: 'btn-context',
            textContent: '\u22EE',
            onClick: (e) => {
                e.stopPropagation();
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

        anchor.style.position = 'relative';
        anchor.appendChild(menu);
        _activeMenu = { menu, dismiss: _onDocClickDismiss };
        document.addEventListener('click', _onDocClickDismiss, { once: true });
    }

    function _onDocClickDismiss() {
        _dismissContextMenu();
    }

    function _dismissContextMenu() {
        if (_activeMenu) {
            if (_activeMenu.menu.parentNode) _activeMenu.menu.parentNode.removeChild(_activeMenu.menu);
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
            if (res.removed_chars && res.removed_chars.length) {
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
            textContent: 'Share selected',
            onClick: () => _bulkShare(selected),
        }));
        bar.appendChild(Utils.el('button', {
            className: 'btn btn-secondary btn-sm',
            textContent: 'Add to Team',
            onClick: () => _bulkAddToTeam(selected),
        }));
        bar.appendChild(Utils.el('button', {
            className: 'btn btn-danger btn-sm',
            textContent: 'Delete selected',
            onClick: () => _bulkDelete(selected),
        }));
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

    function _promptNewFolder() {
        const name = prompt('Folder name:');
        if (!name) return;
        Api.post(`${Config.app.apiPrefix}/folders`, { name, parent_id: _currentFolderId })
            .then(() => {
                Utils.showToast('Folder created', 'success');
                if (_currentFolderId) loadFolder(_currentFolderId);
                else _loadRootFolders();
            })
            .catch(err => Utils.showToast(err.message, 'error'));
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
    async function _uploadFiles(files) {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const label = files.length > 1 ? `${file.name} (${i + 1}/${files.length})` : file.name;
            const overlay = _showUploadOverlay(label);

            try {
                await Upload.uploadFile(file, _currentFolderId, masterKey, (done, total) => {
                    const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                    overlay.update(pct, label);
                });
                overlay.remove();
                Utils.showToast(`"${file.name}" uploaded`, 'success');
            } catch (err) {
                overlay.remove();
                Utils.showToast(`Upload failed: ${err.message}`, 'error');
                // Stop the queue on first error
                break;
            }
        }

        _reloadCurrentView();
    }

    /**
     * Render a small progress bar in the toolbar.
     * Returns { update(pct, label), remove() }.
     */
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
                if (bar.parentNode) bar.parentNode.removeChild(bar);
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
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                _uploadFiles(Array.from(files));
            }
        });
    }

    /** Remove all child nodes properly instead of innerHTML = '' */
    function _clearContainer(el) {
        while (el.firstChild) {
            el.removeChild(el.firstChild);
        }
    }

    function getSelectedItems() {
        const checkboxes = document.querySelectorAll('#file-list input[type="checkbox"]:checked:not(.select-all)');
        return Array.from(checkboxes).map(cb => ({
            type: cb.dataset.type,
            id: cb.dataset.id,
        }));
    }

    return {
        renderFileBrowser,
        loadFolder,
        getSelectedItems,
    };
})();
