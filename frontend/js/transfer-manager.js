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

    function _ensurePanel() {
        if (_panel) return;

        _countEl = Utils.el('span', { className: 'transfer-panel-count' });

        const minBtn = Utils.el('button', {
            className: 'transfer-panel-min',
            title: 'Minimize',
            innerHTML: '&#x2212;',
            onClick: _toggleMinimize,
        });

        const header = Utils.el('div', { className: 'transfer-panel-header' }, [
            Utils.el('span', { className: 'transfer-panel-title', textContent: 'Transfers' }),
            _countEl,
            minBtn,
        ]);

        _listEl = Utils.el('div', { className: 'transfer-panel-list' });

        _panel = Utils.el('div', { className: 'transfer-panel' }, [header, _listEl]);
        document.body.appendChild(_panel);
    }

    function _toggleMinimize() {
        _minimized = !_minimized;
        _panel.classList.toggle('transfer-panel--minimized', _minimized);
        const btn = _panel.querySelector('.transfer-panel-min');
        if (btn) btn.innerHTML = _minimized ? '&#x25B4;' : '&#x2212;';
    }

    function _refreshVisibility() {
        if (!_panel) return;
        const active = Array.from(_transfers.values())
            .filter(t => t.status === 'active' || t.status === 'paused').length;
        _countEl.textContent = active > 0 ? `${active} active` : '';
        _panel.classList.toggle('transfer-panel--visible', _transfers.size > 0);
    }

    function _removeTransfer(id, rowEl, delay) {
        setTimeout(() => {
            _transfers.delete(id);
            if (rowEl.parentNode) rowEl.parentNode.removeChild(rowEl);
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
        _transfers.set(id, { rowEl, status: 'active' });
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

    return { start };
})();
