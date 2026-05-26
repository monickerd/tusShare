/**
 * tusShare — Global transfer progress tracker.
 *
 * A singleton that maintains a floating panel showing active uploads/downloads.
 * Persists across route changes since it renders directly to document.body.
 *
 * Usage:
 *   const handle = TransferManager.start('filename.zip', 'upload', {
 *       onPause: () => ctrl.pause(),
 *       onResume: () => ctrl.resume(),
 *       onStop:  () => ctrl.stop(),
 *   });
 *   handle.update(42);        // percent complete
 *   handle.setPaused(true);   // switch pause btn ⏸→▶ and dim the row
 *   handle.setPaused(false);  // switch back to ⏸
 *   handle.complete();        // marks done and auto-removes after a delay
 *   handle.cancelled();       // marks cancelled and auto-removes after a delay
 *   handle.fail();            // marks failed and auto-removes after a delay
 *
 * opts.onPause / opts.onResume are only meaningful for uploads.
 * opts.onStop works for both uploads and downloads.
 * Omit individual callbacks to hide the corresponding button.
 */
const TransferManager = (() => {
    const _transfers = new Map(); // id → { rowEl, status }
    let _nextId = 0;
    let _panel = null;
    let _listEl = null;
    let _countEl = null;
    let _minimized = false;
    let _mobileBtn = null;
    let _mobileBackdrop = null;

    function _closeMobileSheet() {
        if (_panel) _panel.classList.remove('transfer-panel--mobile-open');
        if (_mobileBackdrop) _mobileBackdrop.classList.remove('transfer-panel-backdrop--open');
        if (_mobileBtn) _mobileBtn.setAttribute('aria-expanded', 'false');
    }

    function _ensureMobileBackdrop() {
        if (_mobileBackdrop) return;
        _mobileBackdrop = Utils.el('div', { className: 'transfer-panel-backdrop' });
        _mobileBackdrop.addEventListener('click', _closeMobileSheet);
        document.body.appendChild(_mobileBackdrop);
    }

    function _toggleMobileSheet() {
        if (_transfers.size === 0) return;
        _ensurePanel();
        _ensureMobileBackdrop();
        const isOpen = _panel.classList.toggle('transfer-panel--mobile-open');
        _mobileBackdrop.classList.toggle('transfer-panel-backdrop--open', isOpen);
        if (_mobileBtn) _mobileBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    }

    function _updateMobileBtn() {
        if (!_mobileBtn) return;
        const activeCount = Array.from(_transfers.values())
            .filter(t => t.status === 'active' || t.status === 'paused').length;
        _mobileBtn.classList.toggle('transfer-btn--active', activeCount > 0);
        const label = _mobileBtn.querySelector('.bn-label');
        if (label) label.textContent = activeCount > 0 ? `${activeCount} active` : 'Transfers';
    }

    function _ensurePanel() {
        if (_panel) return;

        _countEl = Utils.el('span', { className: 'transfer-panel-count' });

        const minBtn = Utils.el('button', {
            className: 'transfer-panel-min',
            title: 'Minimize',
            textContent: '−',
            onClick: _toggleMinimize,
        });

        const mobileCloseBtn = Utils.el('button', {
            className: 'transfer-panel-close-mobile',
            title: 'Close',
            'aria-label': 'Close transfers',
            textContent: '×',
            onClick: _closeMobileSheet,
        });

        const header = Utils.el('div', { className: 'transfer-panel-header' }, [
            Utils.el('span', { className: 'transfer-panel-title', textContent: 'Transfers' }),
            _countEl,
            minBtn,
            mobileCloseBtn,
        ]);

        _listEl = Utils.el('div', { className: 'transfer-panel-list' });

        _panel = Utils.el('div', { className: 'transfer-panel' }, [header, _listEl]);
        document.body.appendChild(_panel);
    }

    function _toggleMinimize() {
        _minimized = !_minimized;
        _panel.classList.toggle('transfer-panel--minimized', _minimized);
        const btn = _panel.querySelector('.transfer-panel-min');
        if (btn) btn.textContent = _minimized ? '▴' : '−';
    }

    function _refreshVisibility() {
        if (!_panel) return;
        const active = Array.from(_transfers.values())
            .filter(t => t.status === 'active' || t.status === 'paused').length;
        _countEl.textContent = active > 0 ? `${active} active` : '';
        _panel.classList.toggle('transfer-panel--visible', _transfers.size > 0);
        if (_transfers.size === 0) _closeMobileSheet();
        _updateMobileBtn();
    }

    function _removeTransfer(id, rowEl, delay) {
        setTimeout(() => {
            _transfers.delete(id);
            if (rowEl.parentNode) rowEl.remove();
            _refreshVisibility();
        }, delay);
    }

    /**
     * Register a new transfer and return a handle to update it.
     *
     * @param {string} label   - Filename or display label
     * @param {'upload'|'download'} type
     * @param {object} [opts]
     * @param {function} [opts.onPause]  - Called when user clicks pause (uploads only).
     * @param {function} [opts.onResume] - Called when user clicks resume (uploads only).
     * @param {function} [opts.onStop]   - Called when user clicks stop.
     * @returns {{
     *   update(pct: number): void,
     *   setPaused(paused: boolean): void,
     *   complete(): void,
     *   cancelled(): void,
     *   fail(): void,
     * }}
     */
    function start(label, type, opts = {}) {
        _ensurePanel();
        const id = _nextId++;
        const { onPause, onResume, onStop } = opts;

        const iconEl  = Utils.el('span', { className: 'transfer-row-icon', textContent: type === 'upload' ? '↑' : '↓' });
        const nameEl  = Utils.el('span', { className: 'transfer-row-name', textContent: label });
        const fillEl  = Utils.el('div',  { className: 'transfer-row-fill', style: 'width:0%' });
        const trackEl = Utils.el('div',  { className: 'transfer-row-track' }, [fillEl]);
        const pctEl   = Utils.el('span', { className: 'transfer-row-pct', textContent: '0%' });

        const { onLogout } = opts;

        // Pause/resume button — uploads only.
        // The onclick handler is re-assigned by setPaused() to toggle between pause and resume.
        let pauseBtn = null;
        if (onPause && onResume) {
            pauseBtn = Utils.el('button', {
                className: 'transfer-row-ctrl',
                title: 'Pause',
                textContent: '⏸',
                onClick: () => {
                    const t = _transfers.get(id);
                    if (t?.status === 'active') onPause();
                },
            });
        }

        // Stop button — uploads and downloads.
        let stopBtn = null;
        if (onStop) {
            stopBtn = Utils.el('button', {
                className: 'transfer-row-ctrl',
                title: 'Stop',
                textContent: '■',
                onClick: () => {
                    const t = _transfers.get(id);
                    if (!t || (t.status !== 'active' && t.status !== 'paused')) return;
                    // Disable both buttons immediately to prevent double-clicks
                    if (pauseBtn) pauseBtn.disabled = true;
                    if (stopBtn)  stopBtn.disabled  = true;
                    onStop();
                },
            });
        }

        // Always emit both control slots so the grid columns align across all rows.
        const pauseSlot = pauseBtn ?? Utils.el('span', { className: 'transfer-row-ctrl-placeholder' });
        const stopSlot  = stopBtn  ?? Utils.el('span', { className: 'transfer-row-ctrl-placeholder' });

        const rowEl = Utils.el('div', { className: 'transfer-row' },
            [iconEl, nameEl, trackEl, pctEl, pauseSlot, stopSlot]);

        _listEl.appendChild(rowEl);
        // Store onLogout so pauseAll() can signal this transfer without the stop
        // button's delete-on-server semantics.  Falls back to onStop if not provided.
        _transfers.set(id, { rowEl, status: 'active', onLogout: onLogout ?? onStop });
        _refreshVisibility();

        /** Shared teardown for complete / cancelled / fail. Guards against double-calls. */
        function _endTransfer(cssClass, pctText, delay) {
            const t = _transfers.get(id);
            if (!t || (t.status !== 'active' && t.status !== 'paused')) return;
            t.status = cssClass.replace('transfer-row--', '');
            rowEl.classList.add(cssClass);
            pctEl.textContent = pctText;
            if (pauseBtn) pauseBtn.style.display = 'none';
            if (stopBtn)  stopBtn.style.display  = 'none';
            _refreshVisibility();
            _removeTransfer(id, rowEl, delay);
        }

        return {
            update(pct) {
                fillEl.style.width = `${pct}%`;
                pctEl.textContent  = `${pct}%`;
            },

            /** Reflect pause state: toggles the pause/resume button icon and dims the row. */
            setPaused(paused) {
                const t = _transfers.get(id);
                if (!t) return;
                t.status = paused ? 'paused' : 'active';
                rowEl.classList.toggle('transfer-row--paused', paused);
                if (pauseBtn) {
                    pauseBtn.textContent = paused ? '▶' : '⏸';
                    pauseBtn.title       = paused ? 'Resume' : 'Pause';
                    // Re-bind click so it calls the right callback
                    pauseBtn.onclick = () => {
                        const t2 = _transfers.get(id);
                        if (!t2) return;
                        if (t2.status === 'paused') onResume();
                        else if (t2.status === 'active') onPause();
                    };
                }
                _refreshVisibility();
            },

            complete() {
                _endTransfer('transfer-row--done', '✓', 1500);
            },

            cancelled() {
                _endTransfer('transfer-row--cancelled', '✕', 1500);
            },

            fail() {
                _endTransfer('transfer-row--failed', 'Failed', 3000);
            },
        };
    }

    /**
     * Signal every active/paused transfer to stop due to logout.
     * Each transfer's onLogout callback is called (falling back to onStop).
     * For uploads this means stop-without-delete; for downloads it aborts the fetch.
     * The panel rows are left in place briefly — dismissAll() removes them immediately.
     */
    function pauseAll() {
        for (const t of _transfers.values()) {
            if (t.status === 'active' || t.status === 'paused') {
                t.onLogout?.();
            }
        }
    }

    /**
     * Immediately remove every row and hide the panel.
     * Call before pauseAll() so the UI disappears at once rather than waiting
     * for each upload loop to reach its next chunk boundary.
     */
    function dismissAll() {
        for (const t of _transfers.values()) {
            if (t.rowEl.parentNode) t.rowEl.remove();
        }
        _transfers.clear();
        _refreshVisibility();
    }

    /**
     * Return a snapshot of all current transfers for display in the account menu.
     * Each entry: { label, type, status, pct }
     */
    function getAll() {
        return Array.from(_transfers.entries()).map(([id, t]) => {
            const nameEl = t.rowEl.querySelector('.transfer-row-name');
            const pctEl  = t.rowEl.querySelector('.transfer-row-pct');
            const icon   = t.rowEl.querySelector('.transfer-row-icon');
            return {
                id,
                label:  nameEl ? nameEl.textContent : '',
                type:   icon?.textContent === '↑' ? 'upload' : 'download',
                status: t.status,
                pct:    pctEl ? pctEl.textContent : '',
            };
        });
    }

    function setMobileBtn(el) {
        _mobileBtn = el;
        el.addEventListener('click', _toggleMobileSheet);
        el.setAttribute('aria-haspopup', 'true');
        el.setAttribute('aria-expanded', 'false');
    }

    return { start, pauseAll, dismissAll, getAll, setMobileBtn };
})();
