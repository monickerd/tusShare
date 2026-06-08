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
    let _currentTeamId = null;      // non-null when browsing a team folder tree
    let _currentTeamName = null;    // display name of current team, cached for pin metadata
    let _currentTeamPK = null;      // base64 team public key, cached alongside _currentTeamId
    let _currentTeamSKBytes = null; // Uint8Array team sk_team bytes for HKDF share key derivation
    const _pageSize = Config.ui.paginationDefaultLimit;

    // Metadata encryption state.
    // _nameKeys: { nameKey, searchKey } derived once from master key on init.
    // _nameCache: uuid → decrypted name string, populated lazily per folder load.
    let _nameKeys = null;
    const _nameCache = new Map();

    // Folder-key model: the decrypted AES-GCM key for the currently viewed folder.
    // Set when entering a folder that has folder_key_ct; cleared on leaving the folder.
    // Used to wrap/unwrap per-file keys for v2-folder files.
    let _currentFolderKey = null;

    async function _initNameKeys() {
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey || _nameKeys) return;
        try {
            _nameKeys = await Crypto.deriveNameKeys(masterKey);
        } catch {
            // Non-fatal — plaintext names are used as fallback
        }
    }

    // Decrypt any name_ct values in a list of file/folder objects in parallel and
    // cache the results.  Falls back silently to the plaintext field on any error.
    async function _decryptAndCacheNames(items, _plaintextField) {
        if (!_nameKeys || !items || items.length === 0) return;
        await Promise.all(items.map(async (item) => {
            if (!item.name_ct || _nameCache.has(item.id)) return;
            try {
                _nameCache.set(item.id, await Crypto.decryptName(item.name_ct, _nameKeys.nameKey));
            } catch {
                // Leave un-cached; fallback to plaintext below
            }
        }));
    }

    // Return the display name for an item, preferring the decrypted cache entry.
    function _dn(item, plaintextField) {
        return (item && _nameCache.get(item.id)) || (item && item[plaintextField]) || '';
    }

    // Live update state — one EventSource per viewed folder/root
    let _liveSource = null;
    let _liveReloadTimer = null;

    // Active uploads being managed in this page session: uploadId → { pct: number }.
    // Used to inject a live "uploading" row during folder re-renders so the file
    // stays visible while a TransferManager row shows real-time progress.
    const _activeUploads = new Map();

    function _mkBreadcrumbStar() {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('width', '18');
        svg.setAttribute('height', '18');
        svg.setAttribute('aria-hidden', 'true');
        const poly = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
        poly.setAttribute('class', 'star-shape');
        poly.setAttribute('points', '12,2 15.09,8.26 22,9.27 17,14.14 18.18,21.02 12,17.77 5.82,21.02 7,14.14 2,9.27 8.91,8.26');
        svg.appendChild(poly);
        return svg;
    }

    // Concurrency gate for all upload paths.  When release() is called with a
    // waiter in the queue the slot is passed directly (no decrement+increment)
    // to avoid a window where a racing acquire() could exceed the cap.
    function _makeTransferSemaphore(max) {
        let active = 0;
        const queue = [];
        return {
            async acquire() {
                if (active < max) { active++; return; }
                await new Promise(resolve => queue.push(resolve));
                // active is NOT incremented here — release() passes the slot directly
            },
            release() {
                if (queue.length) {
                    queue.shift()(); // hand slot to next waiter; active stays the same
                } else {
                    active--;
                }
            },
        };
    }

    const _uploadSemaphore  = _makeTransferSemaphore(Config.upload.maxConcurrent);
    // Shared across ALL concurrent _uploadFiles calls so the total number of
    // simultaneous prepareUpload (escrow-key + AES keygen) operations is bounded
    // even when _uploadFromDirMap fires many _uploadFiles calls in parallel.
    const _prewarmSemaphore = _makeTransferSemaphore(Config.upload.maxConcurrent * 2);

    function _runTeamKeyBatch(batch, folderId) {
        const teamKeys = _batchRegisterTeamFileKeys(batch)
            .catch(err => console.warn('Batch team key registration failed', err));
        const shareKeys = _fulfillPendingShareKeys(batch, folderId)
            .catch(err => console.warn('Batch share key fulfillment failed', err));
        return Promise.allSettled([teamKeys, shareKeys]);
    }

    // Serialised time-based batcher for post-upload finishing work (team keys + share items).
    // When the first item lands after a quiet period, a timer fires after intervalMs and
    // flushes everything that has accumulated — uniform regardless of file size.  Flushes
    // are chained so concurrent API bursts cannot occur.
    function _makeFinishBatcher(intervalMs, folderId) {
        const pending = [];
        let chain     = Promise.resolve();
        let timer     = null;

        function _runBatch(batch) {
            chain = chain.then(() => _runTeamKeyBatch(batch, folderId));
        }

        return {
            push(item) {
                pending.push(item);
                // Schedule one flush per quiet window; next push after a flush arms a new timer.
                if (timer === null) {
                    timer = setTimeout(() => {
                        timer = null;
                        if (pending.length) _runBatch(pending.splice(0));
                    }, intervalMs);
                }
            },
            flush() {
                if (timer !== null) { clearTimeout(timer); timer = null; }
                if (pending.length) _runBatch(pending.splice(0));
                return chain; // resolves when all chained flushes are settled
            },
        };
    }

    function _startLive(folderId) {
        _stopLive();
        const url = folderId
            ? `${Config.app.apiPrefix}/events?folder_id=${encodeURIComponent(folderId)}`
            : `${Config.app.apiPrefix}/events`;
        const source = new EventSource(url, { withCredentials: true });
        source.onmessage = (e) => {
            // Debounce rapid bursts (e.g. multiple files uploaded at once)
            clearTimeout(_liveReloadTimer);
            _liveReloadTimer = setTimeout(() => {
                try {
                    const data = JSON.parse(e.data || '{}');
                    if (data.type?.startsWith('file.') && (data.file || data.file_id)) {
                        // File-level delta: update manifest in-place (async fire-and-forget).
                        App?.applyManifestDelta?.({
                            action: data.type,
                            file: data.file || { id: data.file_id, folder_id: data.folder_id },
                        });
                    } else {
                        App?.invalidateSearchManifest?.();
                    }
                } catch {
                    App?.invalidateSearchManifest?.();
                }
                _reloadCurrentView();
            }, 500);
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
        _closeUploadMenu();
    }

    /**
     * @param {HTMLElement} container
     * @param {{ shared?: boolean }} opts
     */
    function renderFileBrowser(container, opts = {}) {
        _stopLive();
        _isSharedView    = !!opts.shared;
        _isTeamView      = !!opts.teamView;
        _currentTeamId   = null;
        _currentTeamName = null;
        _currentTeamPK   = null;
        _currentTeamSKBytes = null;
        _clearContainer(container);

        const uploadNewBtn = Utils.el('button', {
            id: 'upload-new-btn',
            className: 'btn-upload-new',
            title: 'Upload or create',
            textContent: '+',
            'aria-haspopup': 'true',
            'aria-expanded': 'false',
            onClick: (e) => _toggleUploadMenu(e.currentTarget),
        });
        const main = Utils.el('main', { className: 'files-main' }, [
            Utils.el('div', { id: 'folder-share-banner' }),
            Utils.el('div', { className: 'files-toolbar', id: 'files-toolbar' }, [
                Utils.el('div', { className: 'toolbar-left' }, [
                    uploadNewBtn,
                    Utils.el('span', { className: 'toolbar-divider' }),
                    Utils.el('div', { id: 'breadcrumbs', className: 'breadcrumbs' }),
                ]),
                Utils.el('div', { className: 'toolbar-right' }, [
                    Utils.el('input', {
                        type: 'text',
                        id: 'file-list-filter',
                        className: 'input-sm toolbar-filter',
                        placeholder: 'Filter files by name...',
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
                        className: 'btn btn-sm btn-secondary trash-nav-btn',
                        textContent: 'Deleted',
                        onClick: () => {
                            globalThis.location.hash = _isTeamView && _currentTeamId
                                ? `#/trash/teams/${_currentTeamId}`
                                : '#/trash';
                        },
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

        // Refresh the share banner when a share is deleted or updated from the modal
        document.addEventListener('folder-shares-changed', () => {
            if (_currentFolderId) _loadFolderShareBanner(_currentFolderId);
        });
    }

    async function _loadRootFolders() {
        _currentFolderId = null;
        _currentFolder   = null;
        _currentTeamId   = null;
        _currentTeamName = null;
        _currentTeamPK   = null;
        _currentFolderKey = null;
        const listEl = document.getElementById('file-list');
        if (!listEl) return;
        // Show root breadcrumb
        _renderBreadcrumbs([], null);
        await _initNameKeys();
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/folders`);
            await Promise.all([
                _decryptAndCacheNames(data.folders, 'name'),
                _decryptAndCacheNames(data.files, 'original_name'),
            ]);
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
            textContent: _dn(folder, 'name'),
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
        await _initNameKeys();
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
                _currentTeamName = null;
                _currentTeamPK = null;
                _currentTeamSKBytes = null;
                try {
                    const teamData = await Api.get(`${Config.app.apiPrefix}/teams/${data.team_id}`);
                    _currentTeamPK   = teamData.team?.pre_public_key || null;
                    _currentTeamName = teamData.team?.name || null;
                } catch { /* best-effort; uploads will fall back to no team key */ }
                // Fetch and unwrap team SK for HKDF share key derivation (best-effort)
                _fetchTeamSKBytes(data.team_id).then(sk => { _currentTeamSKBytes = sk; }).catch(() => {});
            } else if (!data.team_id) {
                _currentTeamId = null;
                _currentTeamName = null;
                _currentTeamPK = null;
                _currentTeamSKBytes = null;
            }

            // Unwrap folder key for v2-folder uploads/downloads (best-effort; only for personal folders)
            _currentFolderKey = null;
            if (data.folder?.folder_key_ct && !_currentTeamId) {
                const masterKey = Auth.getMasterKeyObj();
                if (masterKey) {
                    try {
                        _currentFolderKey = await Crypto.unwrapFolderKey(
                            data.folder.folder_key_ct, data.folder.folder_key_iv, masterKey
                        );
                    } catch { /* Non-fatal — fall back to v1-master key path */ }
                }
            }

            // Pre-decrypt encrypted names before rendering so _dn() can return synchronously
            await Promise.all([
                _decryptAndCacheNames(data.child_folders, 'name'),
                _decryptAndCacheNames(data.files, 'original_name'),
                data.folder ? _decryptAndCacheNames([data.folder], 'name') : Promise.resolve(),
                _decryptAndCacheNames(data.breadcrumbs || [], 'name'),
            ]);
            _renderBreadcrumbs(data.breadcrumbs || [], data.folder);
            _renderFolderContents(listEl, data.child_folders, data.files, data.pending_uploads || []);
            const _mc = document.getElementById('main-content');
            const _savedScroll = sessionStorage.getItem('scroll:' + (globalThis.location.hash || ''));
            if (_mc && _savedScroll) {
                requestAnimationFrame(() => { _mc.scrollTop = parseInt(_savedScroll, 10); });
                sessionStorage.removeItem('scroll:' + (globalThis.location.hash || ''));
            }
            _startLive(folderId);
            _loadFolderShareBanner(folderId);
        } catch (err) {
            if (err.message === 'key_pending') {
                listEl.textContent = 'Waiting for a team member to log in to complete your setup.';
            } else {
                listEl.textContent = 'Failed to load folder: ' + err.message;
            }
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
                textContent: _dn(ancestors[0], 'name'),
            }));
            el.appendChild(Utils.el('span', { className: 'breadcrumb-sep breadcrumb-ellipsis', textContent: ' / … / ' }));
            const parent = ancestors[ancestors.length - 1];
            el.appendChild(Utils.el('a', {
                href: crumbHash(parent),
                className: 'breadcrumb-tile',
                textContent: _dn(parent, 'name'),
            }));
        } else {
            for (const crumb of ancestors) {
                el.appendChild(Utils.el('span', { className: 'breadcrumb-sep', textContent: ' / ' }));
                el.appendChild(Utils.el('a', {
                    href: crumbHash(crumb),
                    className: 'breadcrumb-tile',
                    textContent: _dn(crumb, 'name'),
                }));
            }
        }

        // Current folder (plain non-clickable text)
        if (currentFolder) {
            el.appendChild(Utils.el('span', { className: 'breadcrumb-sep', textContent: ' / ' }));
            el.appendChild(Utils.el('span', {
                className: 'breadcrumb-current',
                textContent: _dn(currentFolder, 'name'),
            }));

            // Star icon at end of breadcrumb trail (toggle Favourites)
            const _folderPinned = typeof App !== 'undefined' && App.isPinned?.(currentFolder.id);
            const pinBtn = Utils.el('button', {
                className: 'breadcrumb-pin-btn' + (_folderPinned ? ' breadcrumb-pin-btn--active' : ''),
                title: _folderPinned ? 'Remove from Favourites' : 'Add to Favourites',
            });
            pinBtn.appendChild(_mkBreadcrumbStar());
            pinBtn.addEventListener('click', () => {
                const hash = _isTeamView
                    ? `#/team-folders/${currentFolder.id}`
                    : `#/files/${currentFolder.id}`;
                if (typeof App !== 'undefined') {
                    if (_folderPinned) {
                        App.unpinCurrentFolder?.(currentFolder.id);
                        Utils.showToast(`Removed "${currentFolder.name}" from Favourites`, 'info');
                    } else {
                        const root = _isTeamView ? 'Team Folders' : 'My Files';
                        const pathParts = [root, ...ancestors.map(a => a.name), currentFolder.name];
                        App.pinCurrentFolder?.(currentFolder.id, currentFolder.name, hash,
                            _currentTeamId, _currentTeamName, pathParts.join(' / '));
                        Utils.showToast(`Added "${currentFolder.name}" to Favourites`, 'success');
                    }
                    _renderBreadcrumbs(ancestors, currentFolder);
                }
            });
            el.appendChild(pinBtn);
        }

        // Scroll to reveal the rightmost item (current folder name + star icon).
        requestAnimationFrame(() => { el.scrollLeft = el.scrollWidth; });
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

        // "Load more" / "Load all" buttons if there are more files than the first page
        if (files.length > _pageSize) {
            let shown = _pageSize;
            const btnRow = Utils.el('div', { className: 'load-more-row' });

            const loadMore = Utils.el('button', {
                className: 'btn btn-secondary',
                textContent: `Show more (${files.length - shown} remaining)`,
            });
            const loadAll = Utils.el('button', {
                className: 'btn btn-secondary',
                textContent: `Load all ${files.length} files`,
            });

            const updateButtons = () => {
                if (shown >= files.length) {
                    btnRow.remove();
                } else {
                    loadMore.textContent = `Show more (${files.length - shown} remaining)`;
                    loadAll.textContent = `Load all ${files.length} files`;
                }
            };

            loadMore.addEventListener('click', () => {
                const nextBatch = files.slice(shown, shown + _pageSize);
                for (const file of nextBatch) {
                    tbody.appendChild(_createFileRow(file));
                }
                shown += nextBatch.length;
                updateButtons();
            });

            loadAll.addEventListener('click', () => {
                const rest = files.slice(shown);
                for (const file of rest) {
                    tbody.appendChild(_createFileRow(file));
                }
                shown = files.length;
                updateButtons();
            });

            btnRow.appendChild(loadMore);
            btnRow.appendChild(loadAll);
            container.appendChild(btnRow);
        }
    }

    function _createFolderRow(folder) {
        const displayName = _dn(folder, 'name');
        const folderHash = _isTeamView ? `#/team-folders/${folder.id}` : `#/files/${folder.id}`;
        return Utils.el('tr', { className: 'row-folder', dataset: { name: displayName } }, [
            Utils.el('td', {}, [Utils.el('input', { type: 'checkbox', dataset: { type: 'folder', id: folder.id, name: displayName } })]),
            Utils.el('td', {}, [
                Utils.el('a', {
                    href: folderHash,
                    className: 'folder-link',
                    textContent: displayName,
                }),
            ]),
            Utils.el('td', { textContent: '--' }),
            Utils.el('td', { textContent: Utils.timeAgo(folder.updated_at) }),
            Utils.el('td', { className: 'row-actions' }, [
                _createContextButton([
                    { label: 'Share', action: () => Shares.openFolderShareDialog({ ...folder, teamId: _currentTeamId }) },
                    { label: 'Move/Copy', action: () => _openMoveCopyModal([{ type: 'folder', id: folder.id, name: displayName }]) },
                    { label: 'Rename', action: () => _renameFolder(folder) },
                    folder.user_can_manage ? {
                        label: 'Manage Folder',
                        action: () => _openManageFolderModal(folder),
                    } : null,
                    { label: 'Delete', action: () => _deleteFolder(folder), danger: true },
                ].filter(Boolean)),
            ]),
        ]);
    }

    function _createFileRow(file) {
        const displayName = _dn(file, 'original_name');
        const nameLink = Utils.el('a', {
            href: '#',
            className: 'file-name-link',
            textContent: displayName,
        });
        nameLink.addEventListener('click', (e) => {
            e.preventDefault();
            _downloadFile(file);
        });
        return Utils.el('tr', { className: 'row-file', dataset: { name: displayName } }, [
            Utils.el('td', {}, [Utils.el('input', { type: 'checkbox', dataset: { type: 'file', id: file.id, name: displayName } })]),
            Utils.el('td', {}, [nameLink]),
            Utils.el('td', { textContent: Utils.formatBytes(file.size_bytes) }),
            Utils.el('td', { textContent: Utils.timeAgo(file.created_at) }),
            Utils.el('td', { className: 'row-actions' }, [
                _createContextButton(() => _fileContextItems(file)),
            ]),
        ]);
    }

    async function _fileContextItems(file) {
        const fileForPicker = { type: 'file', id: file.id, name: _dn(file, 'original_name'), encrypted_file_key: file.encrypted_file_key, key_iv: file.key_iv };
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
            Utils.el('h3', { textContent: `Share: ${_dn(file, 'original_name')}`, style: 'margin-top:0' }),
            tabBar,
            contentWrap,
            actionsRow,
        ]));
        document.body.appendChild(overlay);
        _switchTab('link');
    }

    async function _openFileInfoModal(file) {
        const displayName = _dn(file, 'original_name');
        Utils.showModal(`Info: ${displayName}`, Utils.el('p', { textContent: 'Loading…' }));
        let info;
        try {
            info = await Api.get(`${Config.app.apiPrefix}/files/${file.id}/info`);
        } catch (e) {
            Utils.showModal(`Info: ${displayName}`, Utils.el('p', { className: 'text-error', textContent: 'Failed to load: ' + e.message }));
            return;
        }

        const _esc = (s) => {
            if (s == null) return '—';
            return String(s).replace(/[^a-zA-Z0-9 .\-_]/g, c => '%' + c.codePointAt(0).toString(16).padStart(2, '0'));
        };

        const wrap = Utils.el('div', { style: 'min-width:400px' });
        const grid = Utils.el('div', { style: 'display:grid;grid-template-columns:auto 1fr;gap:4px 16px;font-size:var(--font-size-sm);margin-bottom:14px' });
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
            const tbl = Utils.el('table', { className: 'admin-table', style: 'font-size:var(--font-size-sm);width:100%' });
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
        Utils.showToast(`Partial download for "${_dn(file, 'original_name')}" discarded.`, 'info');
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

        const displayName  = _dn(file, 'original_name');
        const abortCtrl    = new AbortController();
        const abortDownload = () => abortCtrl.abort();
        const overlay      = _showUploadOverlay(displayName);
        const transfer     = TransferManager.start(displayName, 'download', {
            onStop:   abortDownload,
            onLogout: abortDownload,
        });
        try {
            // v2-folder files: fileKey is wrapped with folderKey, not masterKey.
            // Use _currentFolderKey as the unwrapping key when available.
            const unwrapKey = (file.key_version === 'v2-folder' && _currentFolderKey)
                ? _currentFolderKey
                : masterKey;
            await Download.downloadFile(file.id, unwrapKey, (done, total) => {
                const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                overlay.update(pct, displayName);
                transfer.update(pct);
            }, abortCtrl.signal, _currentTeamId);
            overlay.remove();
            transfer.complete();
            Utils.showToast(`"${displayName}" downloaded`, 'success');
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
                const unwrapKey = (upload.key_version === 'v2-folder' && _currentFolderKey)
                    ? _currentFolderKey
                    : masterKey;
                fileKey = await Crypto.decryptFileKey(upload.encrypted_file_key, upload.key_iv, unwrapKey);
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
                await _fulfillPendingShareKeys(
                    [{ fileId: result.fileId, fileKeyBytes: result.fileKeyBytes }],
                    _currentFolderId,
                ).catch(err => console.warn('Share key fulfillment failed for', result.fileId, err));
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
    let _activeUploadMenu = null;
    let _uploadMenuOutsideListener = null;

    function _closeUploadMenu() {
        if (_activeUploadMenu?.parentNode) _activeUploadMenu.remove();
        _activeUploadMenu = null;
        if (_uploadMenuOutsideListener) {
            document.removeEventListener('mousedown', _uploadMenuOutsideListener, true);
            _uploadMenuOutsideListener = null;
        }
        const btn = document.getElementById('upload-new-btn');
        if (btn) { btn.classList.remove('active'); btn.setAttribute('aria-expanded', 'false'); }
    }

    function _toggleUploadMenu(btn) {
        if (_activeUploadMenu) { _closeUploadMenu(); return; }
        btn.classList.add('active');
        btn.setAttribute('aria-expanded', 'true');
        const menu = Utils.el('div', { className: 'upload-new-menu' }, [
            Utils.el('button', { className: 'upload-new-item', textContent: 'Upload File',   onClick: () => { _closeUploadMenu(); _triggerUpload(); } }),
            Utils.el('button', { className: 'upload-new-item', textContent: 'Upload Folder', onClick: () => { _closeUploadMenu(); _triggerFolderUpload(); } }),
            Utils.el('button', { className: 'upload-new-item', textContent: 'New Folder',    onClick: () => { _closeUploadMenu(); _promptNewFolder(); } }),
        ]);
        document.body.appendChild(menu);
        const rect = btn.getBoundingClientRect();
        menu.style.position = 'fixed';
        menu.style.left = `${rect.left}px`;
        menu.style.top = `${rect.bottom + 4}px`;
        _activeUploadMenu = menu;
        _uploadMenuOutsideListener = (e) => {
            if (!menu.contains(e.target) && e.target !== btn && !btn.contains(e.target)) {
                _closeUploadMenu();
            }
        };
        document.addEventListener('mousedown', _uploadMenuOutsideListener, true);
    }

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
        const currentName = _dn(folder, 'name');
        const name = prompt('New name:', currentName);
        if (!name || name === currentName) return;
        try {
            const payload = { name };
            if (_nameKeys && !_isTeamView) {
                try {
                    payload.name_ct  = await Crypto.encryptName(name, _nameKeys.nameKey);
                    payload.name_idx = await Crypto.computeNameHmac(name, _nameKeys.searchKey);
                } catch { /* Non-fatal — fall through to plaintext rename */ }
            }
            await Api.put(`${Config.app.apiPrefix}/folders/${folder.id}`, payload);
            if (payload.name_ct) _nameCache.delete(folder.id);
            Utils.showToast('Folder renamed', 'success');
            _reloadCurrentView();
        } catch (err) {
            Utils.showToast(err.message, 'error');
        }
    }

    async function _openManageFolderModal(folder) {
        const overlay = Utils.el('div', { className: 'modal-overlay' });
        const modal   = Utils.el('div', { className: 'modal manage-folder-modal' });
        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        const _close = () => { if (overlay.parentNode) overlay.remove(); };
        overlay.addEventListener('click', (e) => { if (e.target === overlay) _close(); });

        modal.appendChild(Utils.el('div', { className: 'modal-header' }, [
            Utils.el('h3', { textContent: `Manage: ${_dn(folder, 'name')}`, className: 'modal-title' }),
            Utils.el('button', { className: 'modal-close', textContent: '×', 'aria-label': 'Close', onClick: _close }),
        ]));

        const body = Utils.el('div', { className: 'modal-body' });
        modal.appendChild(body);
        body.textContent = 'Loading…';

        try {
            const [stats, grantsData, roleGrantsData] = await Promise.all([
                Api.get(`${Config.app.apiPrefix}/folders/${folder.id}/stats`),
                Api.get(`${Config.app.apiPrefix}/folders/${folder.id}/grants`),
                Api.get(`${Config.app.apiPrefix}/folders/${folder.id}/role-grants`),
            ]);
            body.innerHTML = '';
            _renderManageFolderBody(body, folder, stats, grantsData.grants || [], roleGrantsData.role_grants || [], _close);
        } catch (err) {
            body.innerHTML = '';
            body.appendChild(Utils.el('p', { className: 'text-error', textContent: 'Failed to load folder info: ' + err.message }));
        }
    }

    function _renderManageFolderBody(body, folder, stats, grants, roleGrants, _close) {
        // Per-folder permission groups for the checkbox tree
        const _FOLDER_PERM_GROUPS = [
            {
                label: 'Read / Write',
                items: [
                    { flag: 'view_contents',  label: 'View contents',  desc: 'See file and subfolder listings' },
                    { flag: 'download_files', label: 'Download',       desc: 'Download and decrypt files' },
                    { flag: 'upload_files',   label: 'Upload',         desc: 'Upload new files to this folder' },
                    { flag: 'delete_files',   label: 'Delete files',   desc: 'Delete files in this folder' },
                ],
            },
            {
                label: 'Move / Copy',
                items: [
                    { flag: 'move_own_within_folder', label: 'Own files within folder', desc: 'Move or copy own files between subfolders' },
                    { flag: 'move_all_within_folder', label: 'All files within folder', desc: 'Move or copy any file between subfolders' },
                    { flag: 'move_own_out_of_folder', label: 'Own files out of folder', desc: 'Move own files out to another folder' },
                    { flag: 'move_all_out_of_folder', label: 'All files out of folder', desc: 'Move any file out to another folder' },
                ],
            },
            {
                label: 'Folders',
                items: [
                    { flag: 'folder_create',         label: 'Create subfolders',    desc: 'Create new subfolders within this folder' },
                    { flag: 'manage_own_subfolders', label: 'Manage own subfolders', desc: 'Manage subfolders you created' },
                    { flag: 'manage_all_subfolders', label: 'Manage all subfolders', desc: 'Manage any subfolder regardless of creator' },
                ],
            },
            {
                label: 'Shares',
                items: [
                    { flag: 'share_create',     label: 'Create shares',      desc: 'Create share links from files in this folder' },
                    { flag: 'share_manage_own', label: 'Manage own shares',  desc: 'Manage share links you created' },
                    { flag: 'share_manage_all', label: 'Manage all shares',  desc: 'Manage any share link from this folder' },
                ],
            },
            {
                label: 'Manage this folder',
                items: [
                    { flag: 'manage_this_folder', label: 'Manage this folder', desc: 'Change permissions and access grants for this folder' },
                ],
            },
        ];
        // Human-readable labels for stored permission values (legacy levels + new flags)
        const _PERM_MAP = {
            read: 'View', download: 'View + Download', write: 'Read / Write', admin: 'Admin',
            manage_permissions: 'Manage folder',
            view_contents: 'View', download_files: 'Download', upload_files: 'Upload',
            delete_files: 'Delete', manage_this_folder: 'Manage folder',
        };
        const _permLabel = (perm) => {
            if (!perm || perm === 'none') return '—';
            if (_PERM_MAP[perm]) return _PERM_MAP[perm];
            return perm.split(',').map(f => _PERM_MAP[f.trim()] || f.trim()).join(' + ');
        };
        const callerCtx     = stats.caller_context || {};
        const _allowedFlags = callerCtx.allowed_flags || null;  // null = all allowed

        // ---- Section 1: Metadata ----
        const metaSection = Utils.el('section', { className: 'manage-folder-section' });
        metaSection.appendChild(Utils.el('h4', { textContent: 'Folder Information', className: 'manage-folder-section-title' }));
        const metaGrid = Utils.el('dl', { className: 'manage-folder-meta' });
        const _row = (label, value) => {
            metaGrid.appendChild(Utils.el('dt', { textContent: label }));
            metaGrid.appendChild(Utils.el('dd', { textContent: value }));
        };
        _row('Files',         `${stats.file_count} file${stats.file_count !== 1 ? 's' : ''}`);
        _row('Total size',    Utils.formatBytes(stats.total_size_bytes));
        _row('Created by',    stats.owner_username);
        _row('Created',       stats.created_at ? Utils.timeAgo(stats.created_at) : '—');
        _row('Last modified', stats.updated_at  ? Utils.timeAgo(stats.updated_at)  : '—');
        metaSection.appendChild(metaGrid);
        body.appendChild(metaSection);

        // ---- Section 2: Permission inheritance ----
        const inheritSection = Utils.el('section', { className: 'manage-folder-section' });
        inheritSection.appendChild(Utils.el('h4', { textContent: 'Permission Inheritance', className: 'manage-folder-section-title' }));

        const inheritLabel = Utils.el('label', { className: 'manage-folder-toggle-label' });
        const inheritChk   = Utils.el('input', { type: 'checkbox' });
        inheritChk.checked = stats.restrict_permissions;
        inheritLabel.appendChild(inheritChk);
        inheritLabel.appendChild(document.createTextNode(' Disable inherited permissions'));
        inheritSection.appendChild(inheritLabel);
        inheritSection.appendChild(Utils.el('p', {
            className: 'text-muted',
            style: 'font-size:0.85em;margin-top:4px',
            textContent: 'When enabled, this folder does not inherit access from its parent. Users must be explicitly granted access below.',
        }));

        // ---- Section 3: Access grants (shown when inheritance disabled) ----
        const grantsSection = Utils.el('section', { className: 'manage-folder-section', style: stats.restrict_permissions ? '' : 'display:none' });
        grantsSection.appendChild(Utils.el('h4', { textContent: 'Access Grants', className: 'manage-folder-section-title' }));

        // Tab strip
        const tabStrip = Utils.el('div', { className: 'manage-folder-tabs' });
        const _mkTab = (label, active) => Utils.el('button', {
            textContent: label,
            className: 'manage-folder-tab' + (active ? ' active' : ''),
        });
        const tabByUser = _mkTab('By User', true);
        const tabByRole = _mkTab('By Role', false);
        tabStrip.append(tabByUser, tabByRole);
        grantsSection.appendChild(tabStrip);

        // ---- Tab: By User ----
        const userGrantsPane = Utils.el('div');
        const grantsTable = Utils.el('table', { className: 'file-table manage-folder-grants-table' });
        grantsTable.innerHTML = '<thead><tr><th>User</th><th>Permissions</th><th>Subfolders</th><th></th></tr></thead>';
        const grantsTbody = Utils.el('tbody');

        // Folder creator always has full access — show as a static, non-removable row.
        const _creatorRow = Utils.el('tr', { className: 'manage-folder-implicit-row' });
        _creatorRow.appendChild(Utils.el('td', { textContent: stats.owner_username + ' (creator)' }));
        _creatorRow.appendChild(Utils.el('td', {}, [Utils.el('em', { textContent: 'Full access (folder creator)' })]));
        _creatorRow.appendChild(Utils.el('td', {}, [Utils.el('em', { textContent: 'Yes' })]));
        _creatorRow.appendChild(Utils.el('td'));
        grantsTbody.appendChild(_creatorRow);

        grantsTable.appendChild(grantsTbody);
        userGrantsPane.appendChild(grantsTable);

        const _ownerId = stats.owner_id || '';
        const _renderGrants = (grantsList) => {
            // Re-append the static creator row first; innerHTML wipe removes it.
            grantsTbody.innerHTML = '';
            grantsTbody.appendChild(_creatorRow);
            // Exclude the creator from the editable list — they have implicit full access.
            const filtered = grantsList.filter(g => g.user_id !== _ownerId);
            if (!filtered.length) {
                grantsTbody.appendChild(Utils.el('tr', {}, [
                    Utils.el('td', { colSpan: 4, className: 'text-muted', style: 'text-align:center', textContent: 'No explicit grants. Add one below.' }),
                ]));
                return;
            }
            for (const g of filtered) {
                const removeBtn = Utils.el('button', { className: 'btn btn-danger btn-sm', textContent: 'Remove' });
                removeBtn.addEventListener('click', async () => {
                    removeBtn.disabled = true;
                    try {
                        await Api.del(`${Config.app.apiPrefix}/folders/${folder.id}/grants/${g.id}`);
                        grants = grants.filter(x => x.id !== g.id);
                        _renderGrants(grants);
                    } catch (err) {
                        Utils.showToast(err.message, 'error');
                        removeBtn.disabled = false;
                    }
                });
                grantsTbody.appendChild(Utils.el('tr', {}, [
                    Utils.el('td', { textContent: g.username }),
                    Utils.el('td', { textContent: _permLabel(g.permission) }),
                    Utils.el('td', { textContent: g.recursive ? 'Yes' : 'No' }),
                    Utils.el('td', {}, [removeBtn]),
                ]));
            }
        };
        _renderGrants(grants);

        // Add-grant form: username → permission tree → apply-to-subfolders + Add
        const userAddForm = Utils.el('div', { className: 'manage-folder-add-form' });
        const usernameInput = Utils.el('input', { type: 'text', className: 'input-sm manage-folder-add-username', placeholder: 'Username' });
        userAddForm.appendChild(usernameInput);
        const userPermTree = Utils.mkPermTree(_FOLDER_PERM_GROUPS, [], { allowedFlags: _allowedFlags });
        userAddForm.appendChild(userPermTree.el);
        const userAddFooter = Utils.el('div', { className: 'manage-folder-add-footer' });
        const recursiveChk = Utils.el('input', { type: 'checkbox', id: 'mf-subfolder', checked: true });
        const recursiveLbl = Utils.el('label', { htmlFor: 'mf-subfolder', className: 'manage-folder-subfolder-label' });
        recursiveLbl.appendChild(recursiveChk);
        recursiveLbl.appendChild(document.createTextNode(' Apply to subfolders'));
        const addBtn = Utils.el('button', { className: 'btn btn-primary btn-sm', textContent: 'Add' });
        addBtn.addEventListener('click', async () => {
            const uname = usernameInput.value.trim();
            if (!uname) { Utils.showToast('Enter a username', 'error'); return; }
            const permStr = userPermTree.getPermString();
            if (permStr === 'none') { Utils.showToast('Select at least one permission', 'error'); return; }
            addBtn.disabled = true;
            try {
                const newGrant = await Api.post(`${Config.app.apiPrefix}/folders/${folder.id}/grants`, {
                    username: uname, permission: permStr, recursive: recursiveChk.checked,
                });
                grants = [...grants, newGrant];
                _renderGrants(grants);
                usernameInput.value = '';
            } catch (err) {
                Utils.showToast(err.message, 'error');
            } finally {
                addBtn.disabled = false;
            }
        });
        userAddFooter.append(recursiveLbl, addBtn);
        userAddForm.appendChild(userAddFooter);
        userGrantsPane.appendChild(userAddForm);
        grantsSection.appendChild(userGrantsPane);

        // ---- Tab: By Role ----
        const roleGrantsPane = Utils.el('div', { style: 'display:none' });

        // Org-level access notice (shown before the table so users know some accounts have implicit access)
        if (callerCtx.has_org_access) {
            roleGrantsPane.appendChild(Utils.el('div', {
                className: 'manage-folder-org-notice',
                textContent: 'One or more organizational accounts have access to all files and folders in this system.',
            }));
        }

        const roleGrantsTable = Utils.el('table', { className: 'file-table manage-folder-grants-table' });
        roleGrantsTable.innerHTML = '<thead><tr><th>Role</th><th>Permissions</th><th>Subfolders</th><th></th></tr></thead>';
        const roleGrantsTbody = Utils.el('tbody');

        // Team Owner always has full access — show as a static, non-removable row.
        if (_currentTeamId) {
            const ownerRow = Utils.el('tr', { className: 'manage-folder-implicit-row' });
            ownerRow.appendChild(Utils.el('td', { textContent: 'Team Owner' }));
            ownerRow.appendChild(Utils.el('td', {}, [Utils.el('em', { textContent: 'Full access (automatic)' })]));
            ownerRow.appendChild(Utils.el('td', {}, [Utils.el('em', { textContent: 'Yes' })]));
            ownerRow.appendChild(Utils.el('td'));
            roleGrantsTbody.appendChild(ownerRow);
        }

        roleGrantsTable.appendChild(roleGrantsTbody);
        roleGrantsPane.appendChild(roleGrantsTable);

        const _renderRoleGrants = (list) => {
            // Remove all rows except the static implicit ones (Team Owner etc.)
            const staticRows = roleGrantsTbody.querySelectorAll('.manage-folder-implicit-row');
            roleGrantsTbody.innerHTML = '';
            staticRows.forEach(r => roleGrantsTbody.appendChild(r));
            if (!list.length) {
                roleGrantsTbody.appendChild(Utils.el('tr', {}, [
                    Utils.el('td', { colSpan: 4, className: 'text-muted', style: 'text-align:center', textContent: 'No role grants. Add one below.' }),
                ]));
                return;
            }
            for (const g of list) {
                const removeBtn = Utils.el('button', { className: 'btn btn-danger btn-sm', textContent: 'Remove' });
                removeBtn.addEventListener('click', async () => {
                    removeBtn.disabled = true;
                    try {
                        await Api.del(`${Config.app.apiPrefix}/folders/${folder.id}/role-grants/${g.id}`);
                        roleGrants = roleGrants.filter(x => x.id !== g.id);
                        _renderRoleGrants(roleGrants);
                    } catch (err) {
                        Utils.showToast(err.message, 'error');
                        removeBtn.disabled = false;
                    }
                });
                roleGrantsTbody.appendChild(Utils.el('tr', {}, [
                    Utils.el('td', { textContent: g.role_name }),
                    Utils.el('td', { textContent: _permLabel(g.permission) }),
                    Utils.el('td', { textContent: g.recursive ? 'Yes' : 'No' }),
                    Utils.el('td', {}, [removeBtn]),
                ]));
            }
        };
        _renderRoleGrants(roleGrants);

        // Role add form
        const roleAddForm = Utils.el('div', { className: 'manage-folder-add-form' });
        const roleSelect  = Utils.el('select', { className: 'input-sm manage-folder-role-select' });
        roleAddForm.appendChild(roleSelect);
        const rolePermTree = Utils.mkPermTree(_FOLDER_PERM_GROUPS, [], { allowedFlags: _allowedFlags });
        roleAddForm.appendChild(rolePermTree.el);
        const roleAddFooter = Utils.el('div', { className: 'manage-folder-add-footer' });
        const roleRecChk = Utils.el('input', { type: 'checkbox', id: 'mf-role-subfolder', checked: true });
        const roleRecLbl = Utils.el('label', { htmlFor: 'mf-role-subfolder', className: 'manage-folder-subfolder-label' });
        roleRecLbl.appendChild(roleRecChk);
        roleRecLbl.appendChild(document.createTextNode(' Apply to subfolders'));
        const roleAddBtn = Utils.el('button', { className: 'btn btn-primary btn-sm', textContent: 'Add' });

        // Populate role picker lazily. When inside a team folder, shows only that
        // team's built-in roles + custom roles; otherwise falls back to admin roles.
        let _rolesLoaded = false;
        const _loadRoles = async () => {
            if (_rolesLoaded) return;
            _rolesLoaded = true;
            roleSelect.innerHTML = '';
            try {
                let roles = [];
                if (_currentTeamId) {
                    const builtIn = [
                        { id: 'team_admin',   name: 'Team Owner' },
                        { id: 'team_manager', name: 'Team Supervisor' },
                        { id: 'team_member',  name: 'Team Member' },
                    ];
                    const data = await Api.get(`${Config.app.apiPrefix}/teams/${_currentTeamId}/custom-roles`);
                    roles = [...builtIn, ...(data.roles || [])];
                } else {
                    const data = await Api.get(`${Config.app.apiPrefix}/admin/roles`);
                    roles = data.roles || [];
                }
                if (!roles.length) {
                    roleSelect.appendChild(Utils.el('option', { value: '', textContent: '— no roles —', disabled: true }));
                } else {
                    for (const r of roles) {
                        roleSelect.appendChild(Utils.el('option', { value: r.id, textContent: r.name }));
                    }
                }
            } catch {
                roleSelect.appendChild(Utils.el('option', { value: '', textContent: '— failed to load —', disabled: true }));
            }
        };

        roleAddBtn.addEventListener('click', async () => {
            if (!roleSelect.value) { Utils.showToast('Select a role', 'error'); return; }
            const permStr = rolePermTree.getPermString();
            if (permStr === 'none') { Utils.showToast('Select at least one permission', 'error'); return; }
            roleAddBtn.disabled = true;
            try {
                const newGrant = await Api.post(`${Config.app.apiPrefix}/folders/${folder.id}/role-grants`, {
                    role_id: roleSelect.value, permission: permStr, recursive: roleRecChk.checked,
                });
                roleGrants = [...roleGrants, newGrant];
                _renderRoleGrants(roleGrants);
            } catch (err) {
                Utils.showToast(err.message, 'error');
            } finally {
                roleAddBtn.disabled = false;
            }
        });
        roleAddFooter.append(roleRecLbl, roleAddBtn);
        roleAddForm.appendChild(roleAddFooter);
        roleGrantsPane.appendChild(roleAddForm);
        grantsSection.appendChild(roleGrantsPane);

        // Tab switching
        const _switchTab = (showUser) => {
            userGrantsPane.style.display = showUser ? '' : 'none';
            roleGrantsPane.style.display = showUser ? 'none' : '';
            tabByUser.classList.toggle('active', showUser);
            tabByRole.classList.toggle('active', !showUser);
            if (!showUser) _loadRoles();
        };
        tabByUser.addEventListener('click', () => _switchTab(true));
        tabByRole.addEventListener('click', () => _switchTab(false));

        inheritSection.appendChild(grantsSection);

        // Toggle grants section visibility + save
        let _saving = false;
        inheritChk.addEventListener('change', async () => {
            if (_saving) return;
            _saving = true;
            inheritChk.disabled = true;
            try {
                await Api.put(`${Config.app.apiPrefix}/folders/${folder.id}`, { restrict_permissions: inheritChk.checked });
                grantsSection.style.display = inheritChk.checked ? '' : 'none';
                Utils.showToast(
                    inheritChk.checked
                        ? 'Inheritance disabled — this folder manages its own access.'
                        : 'Inheritance restored — folder inherits access from parent.',
                    'success',
                );
                _reloadCurrentView();
            } catch (err) {
                inheritChk.checked = !inheritChk.checked;
                Utils.showToast(err.message, 'error');
            } finally {
                inheritChk.disabled = false;
                _saving = false;
            }
        });

        body.appendChild(inheritSection);

        const footer = Utils.el('div', { className: 'modal-footer' });
        footer.appendChild(Utils.el('button', { className: 'btn btn-secondary', textContent: 'Close', onClick: _close }));
        body.parentElement.appendChild(footer);
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
        const currentName = _dn(file, 'original_name');
        const name = prompt('New name:', currentName);
        if (!name || name === currentName) return;

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
            const payload = { original_name: name };
            if (_nameKeys) {
                try {
                    payload.name_ct  = await Crypto.encryptName(name, _nameKeys.nameKey);
                    payload.name_idx = await Crypto.computeNameHmac(name, _nameKeys.searchKey);
                } catch { /* Non-fatal */ }
            }
            const res = await Api.put(`${Config.app.apiPrefix}/files/${file.id}`, payload);
            if (payload.name_ct) _nameCache.delete(file.id);
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
        // Pre-check: block deletion if any restricted subfolder lacks manage_this_folder.
        try {
            const check = await Api.get(`${Config.app.apiPrefix}/folders/${folder.id}/subtree-restricted`);
            if (check.has_blocking_folders) {
                const blocked = check.restricted_folders.filter(f => !f.has_manage_access);
                Utils.showToast(
                    `You do not have access to complete this action on "${blocked[0].name}"`,
                    'error',
                );
                return;
            }
        } catch { /* non-fatal — let the DELETE itself surface the error */ }

        const ok = await Utils.showConfirm(`Delete folder "${_dn(folder, 'name')}" and all its contents?`);
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
        const ok = await Utils.showConfirm(`Delete "${_dn(file, 'original_name')}"?`);
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
                _currentTeamId,
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
            Shares.openFolderShareDialog({ id: folderItems[0].id, name: '(selected folder)', teamId: _currentTeamId });
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
     * Show a modal listing restricted subfolders before a move or delete.
     * Returns a Promise<boolean> — true if the user confirmed, false to abort.
     *
     * accessible: [{name, path}] — restricted folders the user CAN manage (will proceed)
     * blocked:    [{name, path}] — restricted folders the user CANNOT manage (hard block)
     * verb: 'move' | 'delete' (used in button label and heading copy)
     */
    function _showRestrictedFolderModal(accessible, blocked, verb) {
        return new Promise((resolve) => {
            const overlay = Utils.el('div', { className: 'modal-overlay' });
            const modal   = Utils.el('div', { className: 'modal restricted-folder-modal' });

            const title = Utils.el('h3', {
                textContent: blocked.length
                    ? `Cannot ${verb}: restricted folder access required`
                    : `Restricted folders will be ${verb}d`,
                style: 'margin-top:0',
            });

            const makeSection = (heading, items, isBlocked) => {
                const sec = Utils.el('details', { open: true });
                const sum = Utils.el('summary', {
                    textContent: heading,
                    className: 'restricted-folder-section-summary' + (isBlocked ? ' restricted-blocked' : ' restricted-ok'),
                });
                sec.appendChild(sum);
                const ul = Utils.el('ul', { className: 'restricted-folder-list' });
                for (const f of items) {
                    ul.appendChild(Utils.el('li', {
                        textContent: f.path || f.name,
                        className: 'restricted-folder-item',
                    }));
                }
                sec.appendChild(ul);
                return sec;
            };

            const body = Utils.el('div', {
                className: 'restricted-folder-body',
                style: 'max-height:320px;overflow-y:auto;margin:12px 0',
            });
            if (blocked.length) {
                body.appendChild(makeSection(
                    `Cannot ${verb} (no "Manage this folder" access):`,
                    blocked, true,
                ));
            }
            if (accessible.length) {
                body.appendChild(makeSection(
                    blocked.length
                        ? `Would be ${verb}d (you have access):`
                        : `Restricted folders that will be ${verb}d:`,
                    accessible, false,
                ));
            }

            const actions = Utils.el('div', { className: 'modal-actions', style: 'justify-content:flex-end;gap:8px' });
            const cancelBtn = Utils.el('button', {
                className: 'btn btn-secondary',
                textContent: 'Cancel',
                onClick: () => { overlay.remove(); resolve(false); },
            });
            actions.appendChild(cancelBtn);

            if (!blocked.length) {
                const proceedBtn = Utils.el('button', {
                    className: 'btn btn-primary',
                    textContent: verb === 'move' ? 'Move anyway' : 'Proceed',
                    onClick: () => { overlay.remove(); resolve(true); },
                });
                actions.appendChild(proceedBtn);
            }

            modal.append(title, body, actions);
            overlay.appendChild(modal);
            overlay.addEventListener('click', (e) => { if (e.target === overlay) { overlay.remove(); resolve(false); } });
            document.body.appendChild(overlay);
        });
    }

    /**
     * Run pre-move checks (active shares, cross-boundary warning) then execute.
     * destination: { id: string|null, label: string, isTeam: boolean }
     */
    async function _confirmAndExecuteMoves(items, destination, sourceIsTeam) {
        if (!await _warnIfActiveShares(items)) return;
        if (!await _warnIfBoundary(items, sourceIsTeam, destination)) return;

        // Restricted-subfolder pre-check for folder items.
        const folders = items.filter(i => i.type === 'folder');
        if (folders.length > 0) {
            const allRestricted = [];
            for (const folder of folders) {
                try {
                    const check = await Api.get(`${Config.app.apiPrefix}/folders/${folder.id}/subtree-restricted`);
                    allRestricted.push(...(check.restricted_folders || []));
                } catch { /* skip — backend will guard */ }
            }
            if (allRestricted.length > 0) {
                const blocked    = allRestricted.filter(f => !f.has_manage_access);
                const accessible = allRestricted.filter(f =>  f.has_manage_access);
                const ok = await _showRestrictedFolderModal(accessible, blocked, 'move');
                if (!ok) return;
            }
        }

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
        const unwrapKey = (file.key_version === 'v2-folder' && _currentFolderKey)
            ? _currentFolderKey
            : masterKey;
        const fileKey = await Crypto.decryptFileKey(file.encrypted_file_key, file.key_iv, unwrapKey);
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
        Utils.showPrompt('New Folder', 'Folder name').then(async (name) => {
            if (!name) return;
            try {
                const payload = { name, parent_id: _currentFolderId };
                if (_nameKeys && !_isTeamView) {
                    try {
                        payload.name_ct  = await Crypto.encryptName(name, _nameKeys.nameKey);
                        payload.name_idx = await Crypto.computeNameHmac(name, _nameKeys.searchKey);
                    } catch { /* Non-fatal */ }
                }
                // Personal folders get a folderKey so new uploads use the v2-folder model.
                if (!_isTeamView) {
                    const masterKey = Auth.getMasterKeyObj();
                    if (masterKey) {
                        try {
                            const folderKey = await Crypto.generateFolderKey();
                            const { ctB64, ivB64 } = await Crypto.wrapFolderKey(folderKey, masterKey);
                            payload.folder_key_ct = ctB64;
                            payload.folder_key_iv = ivB64;
                        } catch { /* Non-fatal — folder will fall back to v1-master key path */ }
                    }
                }
                await Api.post(`${Config.app.apiPrefix}/folders`, payload);
                Utils.showToast('Folder created', 'success');
                if (_currentFolderId) loadFolder(_currentFolderId);
                else _loadRootFolders();
            } catch (err) {
                Utils.showToast(err.message, 'error');
            }
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

    function _triggerFolderUpload() {
        const input = document.createElement('input');
        input.type = 'file';
        input.webkitdirectory = true;
        input.addEventListener('change', async () => {
            const files = Array.from(input.files);
            input.remove();
            if (files.length) await _uploadFolderFiles(files);
        });
        input.click();
    }

    async function _createOrResolveFolder(name, parentServerId, ctx) {
        try {
            const payload = { name, parent_id: parentServerId || null };
            if (_nameKeys && !_isTeamView) {
                try {
                    payload.name_ct  = await Crypto.encryptName(name, _nameKeys.nameKey);
                    payload.name_idx = await Crypto.computeNameHmac(name, _nameKeys.searchKey);
                } catch { /* Non-fatal */ }
            }
            const r = await Api.post(`${Config.app.apiPrefix}/folders`, payload);
            return r.folder.id;
        } catch (err) {
            if (err.status === 409 && err.existingFolderId) {
                let action = ctx.mergeState.decision;
                if (!action) {
                    const choice = await _showFolderMergeModal(name);
                    if (choice.applyToAll) ctx.mergeState.decision = choice.action;
                    action = choice.action;
                }
                return action === 'merge' ? err.existingFolderId : null;
            }
            ctx.results.failed.push(name);
            return null;
        }
    }

    function _isSystemFile(name) {
        const lower = name.toLowerCase();
        return name.startsWith('.')
            || name.startsWith('~$')          // Office temp files
            || lower === 'thumbs.db'
            || lower === 'ehthumbs.db'
            || lower === 'desktop.ini';
    }

    // Shared engine used by both upload paths.
    // Phase 1: BFS folder creation — siblings created serially to prevent concurrent
    //          merge-conflict modals; independent branches proceed in parallel via BFS.
    // Phase 2: All file uploads start concurrently once every folder ID is known.
    //          The module-level _uploadSemaphore caps actual network concurrency.
    async function _uploadFromDirMap(dirMap, rootServerId, ctx) {
        const serverIdMap = new Map([['', rootServerId]]);
        let bfsLevel = [''];
        while (bfsLevel.length > 0) {
            const nextLevel = [];
            for (const dirPath of bfsLevel) {
                const entry = dirMap.get(dirPath);
                if (!entry) continue;
                const parentServerId = serverIdMap.get(dirPath);
                for (const subPath of entry.subdirs) {
                    const newId = await _createOrResolveFolder(subPath.split('/').pop(), parentServerId, ctx);
                    if (newId !== null) {
                        serverIdMap.set(subPath, newId);
                        nextLevel.push(subPath);
                    }
                }
            }
            bfsLevel = nextLevel;
        }

        // One aggregate progress overlay for the whole operation replaces the
        // per-batch overlays that _executeBatchUpload would otherwise create.
        // ctx._bulkOnBatchDone is the signal _executeBatchUpload checks.
        const totalFiles = [...dirMap.values()].reduce((s, e) => s + e.files.length, 0);
        let doneFiles = 0;
        const bulkOverlay = _showUploadOverlay(`Uploading 0 / ${totalFiles} files`);
        ctx._bulkOnBatchDone = (n) => {
            doneFiles += n;
            bulkOverlay.update(
                Math.round(doneFiles / totalFiles * 100),
                `Uploading ${doneFiles} / ${totalFiles} files`,
            );
        };

        const uploadTasks = [];
        for (const [dirPath, entry] of dirMap) {
            if (!entry.files.length) continue;
            const serverId = serverIdMap.get(dirPath);
            if (serverId === undefined) continue;
            uploadTasks.push(_uploadFiles(entry.files, serverId, ctx));
        }
        await Promise.allSettled(uploadTasks);

        bulkOverlay.remove();
        delete ctx._bulkOnBatchDone;
    }

    async function _uploadFolderFiles(files) {
        files = files.filter(f => !_isSystemFile(f.name));
        if (files.length > Config.upload.bulkWarnThreshold) {
            if (!await _showBulkUploadWarning(files.length)) return;
        }
        const ctx = {
            results: { ok: 0, failed: [], firstName: null },
            mergeState: { decision: null },
            conflictState: { decisionDifferent: null, decisionIdentical: null },
            fileCache: new Map(),
            lastUploadMs: null,
        };
        // Build dirMap from webkitRelativePath strings — all File objects are already resolved.
        const dirMap = new Map([['', { files: [], subdirs: new Set() }]]);
        for (const file of files) {
            const parts = file.webkitRelativePath.split('/');
            for (let depth = 1; depth < parts.length; depth++) {
                const path   = parts.slice(0, depth).join('/');
                const parent = parts.slice(0, depth - 1).join('/');
                if (!dirMap.has(path)) dirMap.set(path, { files: [], subdirs: new Set() });
                dirMap.get(parent).subdirs.add(path);
            }
            dirMap.get(parts.slice(0, -1).join('/')).files.push(file);
        }
        await _uploadFromDirMap(dirMap, _currentFolderId, ctx);
        _reportUploadResults(ctx);
        _reloadCurrentView();
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

    // Batch variant: wraps all file keys concurrently then issues a single POST.
    async function _batchRegisterTeamFileKeys(pairs) {
        if (!_currentTeamId || !_currentTeamPK || !pairs.length) return;
        const file_keys = await Promise.all(
            pairs.map(async ({ fileId, fileKeyBytes }) => ({
                file_id: fileId,
                ...(await Teams.encryptFileKeyForTeam(fileKeyBytes, _currentTeamPK)), // NOSONAR
            })),
        );
        await Api.post(
            `${Config.app.apiPrefix}/teams/${_currentTeamId}/file-keys`,
            { file_keys },
        );
    }

    /** Fetch and unwrap the team SK bytes for HKDF share key derivation. */
    async function _fetchTeamSKBytes(teamId) {
        const asymKeys = Auth.getAsymmetricKeys();
        if (!asymKeys) return null;
        const entry = await Api.get(`${Config.app.apiPrefix}/teams/${teamId}/my-key`);
        if (!entry) return null;
        const { sk_bytes } = await Teams.unwrapTeamKey( // NOSONAR — async function accessed via Teams module export
            entry, asymKeys.x25519PrivateKey, asymKeys.mlkem768SecretKey
        );
        return sk_bytes instanceof Uint8Array ? sk_bytes : new Uint8Array(sk_bytes);
    }

    /**
     * After a successful upload, wrap the new file's key for every active HKDF-keyed
     * folder share so recipients see it immediately on next page load.
     */
    // Fulfill outstanding share-keying obligations for a set of just-uploaded files.
    // Fetches server-side pending records (files flagged as needing key wrapping for
    // active HKDF shares), matches them against the in-memory file keys from this
    // upload session, and posts wrapped keys per share.  Files the caller has no key
    // for (uploaded by someone else) are silently skipped — the server keeps the
    // pending record for the next eligible team member.
    async function _fulfillPendingShareKeys(pairs, folderId) {
        if (!folderId || !pairs.length) return;
        let pending;
        try {
            pending = await Api.get(`${Config.app.apiPrefix}/folders/${folderId}/pending-share-keys`);
        } catch { return; }
        if (!pending?.length) return;

        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) return;
        const keyMaterial = _currentTeamSKBytes || masterKey;

        // Build file_id → fileKeyBytes lookup from this upload batch.
        const keyMap = new Map(pairs.map(p => [p.fileId, p.fileKeyBytes]));

        // Group pending items by share so we issue one POST per share.
        const byShare = new Map();
        for (const item of pending) {
            if (!keyMap.has(item.file_id)) continue;
            if (!byShare.has(item.share_id)) byShare.set(item.share_id, { token: item.token, files: [] });
            byShare.get(item.share_id).files.push({ fileId: item.file_id, fileKeyBytes: keyMap.get(item.file_id) });
        }

        for (const [shareId, { token, files }] of byShare) {
            try {
                const shareKey = await Crypto.deriveShareKey(keyMaterial, token);
                const items = await Promise.all(
                    files.map(async ({ fileId, fileKeyBytes }) => {
                        const fileKey = await crypto.subtle.importKey(
                            'raw', fileKeyBytes,
                            { name: 'AES-GCM', length: 256 },
                            true, ['encrypt', 'decrypt'],
                        );
                        const { wrappedKeyB64, ivB64 } = await Crypto.wrapFileKeyForShare(fileKey, shareKey);
                        return {
                            resource_type:      'file',
                            resource_id:        fileId,
                            encrypted_file_key: wrappedKeyB64,
                            key_iv:             ivB64,
                        };
                    }),
                );
                await Api.post(`${Config.app.apiPrefix}/shares/${shareId}/items`, { items });
            } catch (err) {
                console.warn('Share key fulfillment failed for', shareId, err);
            }
        }
    }

    /** Load and display the folder share banner, if the folder has active shares. */
    async function _loadFolderShareBanner(folderId) {
        const bannerSlot = document.getElementById('folder-share-banner');
        if (!bannerSlot) return;
        bannerSlot.textContent = '';

        let shares;
        try {
            shares = await Api.get(`${Config.app.apiPrefix}/folders/${folderId}/shares`);
        } catch {
            return;
        }
        if (!shares || shares.length === 0) return;

        const masterKey = Auth.getMasterKeyObj();

        const banner = Utils.el('div', { className: 'folder-share-banner' });
        const label = shares.length === 1 ? 'This folder is being shared.' : `This folder has ${shares.length} active shares.`;
        banner.appendChild(Utils.el('span', { textContent: label }));

        for (const s of shares) {
            const detailsBtn = Utils.el('button', {
                className: 'btn-link',
                textContent: s.creator_username
                    ? `Details (${s.creator_username})…`
                    : 'More details…',
            });
            detailsBtn.addEventListener('click', async () => {
                try {
                    const resp = await Api.get(`${Config.app.apiPrefix}/shares/${s.share_id}`);
                    Shares.openSingleShareDetailModal(resp.share, masterKey, null, resp.share.can_manage);
                } catch (err) {
                    Utils.showToast(`Could not load share details: ${err.message}`, 'error');
                }
            });
            banner.appendChild(detailsBtn);
        }

        bannerSlot.appendChild(banner);
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
        for (const name of ctx.results.failed) Utils.showToast(`"${name}" failed to upload`, 'error');
    }

    async function _uploadFiles(files, targetFolderId, _ctx = null) {
        const folderId = targetFolderId === undefined ? _currentFolderId : targetFolderId;
        const masterKey = Auth.getMasterKeyObj();
        if (!masterKey) {
            Utils.showToast('Master key not available — please re-enter your password.', 'error');
            return;
        }

        const isStandalone = _ctx === null;
        if (isStandalone) {
            // Strip system/hidden files before showing the count — this path is
            // called from the file picker and drag-and-drop fallback, both of
            // which may include Thumbs.db, desktop.ini, ~$ Office temps, etc.
            files = files.filter(f => !_isSystemFile(f.name));
            _ctx = await _initStandaloneUploadCtx(files.length);
            if (!_ctx) return;
        }

        const existingFiles = await _getExistingFiles(folderId, _ctx.fileCache);
        const existingByName = new Map(existingFiles.map(f => [f.original_name.toLowerCase(), f]));

        // Phase 1: resolve all conflicts sequentially (modals cannot overlap)
        const resolved = [];
        for (let i = 0; i < files.length; i++) {
            const conflict = await _processFileConflict(files[i], existingByName, _ctx);
            if (!conflict.skip) {
                resolved.push({ file: conflict.file, index: i, deletedForReplace: conflict.deletedForReplace });
            }
        }

        // Phase 2: route single-chunk files through the batch POST path; multi-chunk
        // files use the existing semaphore-gated tus path.
        const chunkThreshold = Upload.getChunkSize();
        const smallResolved  = resolved.filter(({ file }) => file.size > 0 && file.size <= chunkThreshold);
        const largeResolved  = resolved.filter(({ file }) => file.size === 0 || file.size > chunkThreshold);

        const batcher = _makeFinishBatcher(Config.upload.finishIntervalMs, folderId);

        // Small files: group by approximate encrypted size before any crypto runs, so
        // each group can prepare independently.  The upload semaphore limits how many
        // batch POSTs are in-flight at once; it is held until the server responds so
        // the server is never handed more work than it can queue at one time.
        // _prewarmSemaphore ensures the NEXT group's crypto runs while the current
        // batch is uploading, hiding crypto latency inside network latency.
        if (smallResolved.length > 0) {
            const allRetryItems = [];
            await Promise.allSettled(
                _groupByFileSize(smallResolved, _BATCH_BUDGET_BYTES).map(async (group) => {
                    const batch = await Promise.all(
                        group.map(async ({ file }) => {
                            await _prewarmSemaphore.acquire();
                            const prepared = await Upload.prepareUpload(file, folderId, masterKey, _nameKeys, _currentFolderKey);
                            _prewarmSemaphore.release();
                            return { prepared, file };
                        })
                    );
                    await _uploadSemaphore.acquire();
                    try {
                        const retryItems = await _executeBatchUpload(batch, folderId, batcher, _ctx);
                        allRetryItems.push(...retryItems);
                    } finally {
                        _uploadSemaphore.release();
                    }
                })
            );

            // Sequential retry pass: each deferred file is re-prepared fresh from disk
            // and submitted as a single-file batch. noRetry=true prevents further deferral.
            for (const { file, folderId: retryFolderId } of allRetryItems) {
                let prepared;
                try {
                    await _prewarmSemaphore.acquire();
                    prepared = await Upload.prepareUpload(file, retryFolderId, masterKey, _nameKeys, _currentFolderKey);
                    _prewarmSemaphore.release();
                } catch (_err) {
                    _prewarmSemaphore.release();
                    _ctx.results.failed.push(file.name);
                    continue;
                }
                await _uploadSemaphore.acquire();
                try {
                    await _executeBatchUpload([{ prepared, file }], retryFolderId, batcher, _ctx, true);
                } finally {
                    _uploadSemaphore.release();
                }
            }
        }

        // Large files: existing bounded tus path (unchanged).
        const uploads = largeResolved.map(async ({ file, index, deletedForReplace }) => {
            await _prewarmSemaphore.acquire();
            const preparedPromise = Upload.prepareUpload(file, folderId, masterKey, _nameKeys, _currentFolderKey);

            await _uploadSemaphore.acquire();
            _prewarmSemaphore.release(); // crypto done + upload slot secured; next file can pre-warm
            await _paceUploadIfNeeded(_ctx);
            _ctx.lastUploadMs = Date.now();
            try {
                const outcome = await _executeFileUploadPrepared(
                    await preparedPromise, file, folderId, _ctx, files, index, deletedForReplace,
                );
                if (outcome?.fileId) batcher.push({ fileId: outcome.fileId, fileKeyBytes: outcome.fileKeyBytes });
            } finally {
                _uploadSemaphore.release();
            }
        });
        await Promise.allSettled(uploads);

        // Phase 3: flush any remaining finish pairs and wait for all chained batches.
        await batcher.flush();

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

    // Maximum encrypted bytes to pack into a single batch POST.
    // The client tracks ciphertext bytes (binary); multipart framing overhead is small.
    const _BATCH_BUDGET_BYTES = 5 * 1024 * 1024;
    // Must stay in sync with _MAX_FILES_PER_BATCH in backend/app/routes/batch_upload.py.
    const _MAX_BATCH_FILES = 50;

    // Group resolved small files by approximate encrypted size (file.size + 16 AES-GCM tag).
    // Called before crypto prep so each group can start uploading as soon as its own
    // crypto is done, without waiting for the full set of small files.
    function _groupByFileSize(entries, budgetBytes) {
        const groups = [];
        let current = [];
        let accumulated = 0;
        for (const entry of entries) {
            const approx = entry.file.size + 16;
            if (current.length > 0 && (accumulated + approx > budgetBytes || current.length >= _MAX_BATCH_FILES)) {
                groups.push(current);
                current = [];
                accumulated = 0;
            }
            current.push(entry);
            accumulated += approx;
        }
        if (current.length > 0) groups.push(current);
        return groups;
    }

    // Build a multipart/form-data body for a batch of single-chunk prepared files.
    // Metadata part comes first (JSON array), then one binary 'file_N' part per file.
    // Encryptions and hashes are awaited in parallel since they are independent.
    async function _buildBatchFormData(batch, folderId) {
        const processed = await Promise.all(
            batch.map(async ({ prepared, file }) => {
                const { ciphertext, ivB64: chunkIvB64 } = await prepared.firstEncrypted;
                const chunkHash = await Upload.sha256Hex(ciphertext);
                return { file, prepared, ciphertext, chunkIvB64, chunkHash };
            })
        );
        const metadataArr = processed.map(({ file, prepared, chunkIvB64, chunkHash }) => ({
            filename:           file.name,
            filetype:           file.type || 'application/octet-stream',
            folder_id:          folderId || '',
            original_size:      String(file.size),
            encrypted_size:     String(prepared.totalEncryptedSize),
            encrypted_file_key: prepared.encryptedKeyB64,
            key_iv:             prepared.keyIvB64,
            key_version:        prepared.keyVersion || 'v1-master',
            chunk_iv:           chunkIvB64,
            chunk_hash:         `sha256:${chunkHash}`,
            last_modified_ms:   String(file.lastModified),
            ...prepared.escrowMeta,
            ...prepared.nameMeta,
        }));
        const form = new FormData();
        form.append('metadata', new Blob([JSON.stringify(metadataArr)], { type: 'application/json' }));
        for (let i = 0; i < processed.length; i++) {
            form.append(`file_${i}`, new Blob([processed[i].ciphertext], { type: 'application/octet-stream' }));
        }
        return form;
    }

    // Send one batch POST and record per-file results into ctx.
    // Returns an array of {file, folderId} items that need a fresh individual retry
    // (status "rolled_back" = collateral from a sibling failure; "error" = causal file).
    // Pass noRetry=true on retry attempts to treat all failures as permanent.
    async function _executeBatchUpload(batch, folderId, batcher, ctx, noRetry = false) {
        const label = batch.length === 1 ? batch[0].file.name : `Uploading ${batch.length} files`;
        // When a bulk overlay owns the banner, suppress individual per-batch overlays
        // so the screen doesn't fill with dozens of progress bars.
        const _noop = { update: () => {}, remove: () => {} };
        const overlay  = ctx._bulkOnBatchDone ? _noop : _showUploadOverlay(label);
        const transfer = TransferManager.start(label, 'upload', {});

        let form;
        try {
            form = await _buildBatchFormData(batch, folderId);
        } catch (err) {
            overlay.remove();
            transfer.cancelled();
            for (const { file } of batch) ctx.results.failed.push(file.name);
            Utils.showToast(`Batch preparation failed: ${err.message}`, 'error');
            ctx._bulkOnBatchDone?.(batch.length);
            return [];
        }

        const csrf = Utils.parseCookie(Config.auth.cookieCsrfName) || '';
        const makeReq = () => fetch(`${Config.app.apiPrefix}/uploads/batch`, {
            method: 'POST',
            body: form,
            credentials: 'same-origin',
            headers: { 'X-CSRF-Token': csrf },
        });

        let resp;
        try {
            resp = await makeReq();
            if (resp.status === 401) {
                const refreshed = await Api.refreshTokens();
                if (!refreshed) throw new Error('Session expired — please log in again.');
                resp = await makeReq();
            }
        } catch (err) {
            overlay.remove();
            transfer.cancelled();
            for (const { file } of batch) ctx.results.failed.push(file.name);
            Utils.showToast(err.message || 'Batch upload network error', 'error');
            ctx._bulkOnBatchDone?.(batch.length);
            return [];
        }

        if (!resp.ok) {
            overlay.remove();
            transfer.cancelled();
            const body = await resp.json().catch(() => ({}));
            for (const { file } of batch) ctx.results.failed.push(file.name);
            Utils.showToast(body.detail || `Batch upload failed (${resp.status})`, 'error');
            ctx._bulkOnBatchDone?.(batch.length);
            return [];
        }

        const { results } = await resp.json();
        overlay.remove();
        transfer.complete();
        const retryItems = [];
        for (const result of results) {
            const { file, prepared } = batch[result.index];
            if (result.status === 'ok' && result.file_id) {
                ctx.results.ok++;
                if (!ctx.results.firstName) ctx.results.firstName = file.name;
                batcher.push({ fileId: result.file_id, fileKeyBytes: prepared.fileKeyBytes });
            } else if (!noRetry && (result.status === 'rolled_back' || result.status === 'error')) {
                // Don't count as failed yet — queue for individual retry at end.
                retryItems.push({ file, folderId });
            } else {
                ctx.results.failed.push(file.name);
            }
        }
        ctx._bulkOnBatchDone?.(batch.length);
        return retryItems;
    }

    // Executes the network phase of a queued upload using pre-warmed prepared data.
    // Team key registration and share auto-keying are deliberately excluded here and
    // batched by the caller (_uploadFiles Phase 3) after all transfers complete.
    // Returns {fileId, fileKeyBytes} on success, or null on abort/error.
    async function _executeFileUploadPrepared(prepared, file, folderId, ctx, files, i, deletedForReplace) {
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
            const result = await Upload.uploadFromPrepared(prepared, file, (done, total) => {
                const pct = total > 0 ? Math.round((done / total) * 100) : 0;
                overlay.update(pct, label);
                transfer.update(pct);
                const _ae = ctrl.uploadId ? _activeUploads.get(ctrl.uploadId) : null;
                if (_ae) _ae.pct = pct;
            }, ctrl);
            overlay.remove();
            transfer.complete();
            ctx.results.ok++;
            if (!ctx.results.firstName) ctx.results.firstName = file.name;
            ctrl.cleanup();
            return { fileId: result.fileId, fileKeyBytes: result.fileKeyBytes };
        } catch (err) {
            overlay.remove();
            ctrl.cleanup();
            if (err instanceof Upload.AbortedError) {
                transfer.cancelled();
                if (ctrl.shouldDeleteOnAbort()) {
                    Api.del(err.location).catch(() => {});
                    Utils.showToast(`"${file.name}" upload cancelled`, 'info');
                }
                return null;
            }
            transfer.fail();
            if (deletedForReplace) {
                Utils.showToast(`Original deleted but upload failed — "${file.name}" lost. Re-upload manually.`, 'error');
            } else {
                ctx.results.failed.push(file.name);
            }
            return null;
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

    // Traverse a FileSystemEntry tree into the same dirMap structure used by
    // _uploadFolderFiles, resolving File objects eagerly.  Returns the map and
    // a total file count so callers need only one tree walk.
    async function _buildDirMapFromEntries(entries) {
        const dirMap = new Map([['', { files: [], subdirs: new Set() }]]);
        let totalFiles = 0;
        async function traverse(entries, dirPath) {
            for (const entry of entries) {
                if (_isSystemFile(entry.name)) continue;
                if (entry.isFile) {
                    const file = await new Promise((res, rej) => entry.file(res, rej));
                    dirMap.get(dirPath).files.push(file);
                    totalFiles++;
                } else if (entry.isDirectory) {
                    const childPath = dirPath ? `${dirPath}/${entry.name}` : entry.name;
                    dirMap.set(childPath, { files: [], subdirs: new Set() });
                    dirMap.get(dirPath).subdirs.add(childPath);
                    await traverse(await _readAllDirEntries(entry.createReader()), childPath);
                }
            }
        }
        await traverse(entries, '');
        return { dirMap, totalFiles };
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

    async function _uploadEntries(entries, parentFolderId) {
        const { dirMap, totalFiles } = await _buildDirMapFromEntries(entries);
        if (totalFiles > Config.upload.bulkWarnThreshold) {
            if (!await _showBulkUploadWarning(totalFiles)) return;
        }
        const ctx = {
            results: { ok: 0, failed: [], firstName: null },
            mergeState: { decision: null },
            conflictState: { decisionDifferent: null, decisionIdentical: null },
            fileCache: new Map(),
            lastUploadMs: null,
        };
        await _uploadFromDirMap(dirMap, parentFolderId, ctx);
        _reportUploadResults(ctx);
        _reloadCurrentView();
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
        const _resumeResolvers = [];

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

    // Lazily migrate plaintext names to encrypted form in the background.
    // Called once after login; safe to call multiple times (server enforces name_ct IS NULL guard).
    async function migrateNames() {
        await _initNameKeys();
        if (!_nameKeys) return;
        try {
            const data = await Api.get(`${Config.app.apiPrefix}/files/unmigrated-names`);
            const items = data.items || [];
            if (items.length === 0) return;
            const updates = [];
            for (const item of items) {
                const rawName = item.name || item.original_name || '';
                if (!rawName) continue;
                try {
                    updates.push({
                        type: item.type,
                        id:   item.id,
                        name_ct:  await Crypto.encryptName(rawName, _nameKeys.nameKey),
                        name_idx: await Crypto.computeNameHmac(rawName, _nameKeys.searchKey),
                    });
                } catch { /* skip this item */ }
            }
            if (updates.length > 0) {
                await Api.post(`${Config.app.apiPrefix}/files/migrate-names`, { items: updates });
            }
        } catch { /* Non-fatal — migration will retry on next login */ }
    }

    return {
        renderFileBrowser,
        loadFolder,
        downloadFileById,
        getSelectedItems,
        stopLive: _stopLive,
        migrateNames,
    };
})();
