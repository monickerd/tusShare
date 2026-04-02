/**
 * tusShare — Global transfer progress tracker.
 *
 * A singleton that maintains a floating panel showing active uploads/downloads.
 * Persists across route changes since it renders directly to document.body.
 *
 * Usage:
 *   const handle = TransferManager.start('filename.zip', 'upload');
 *   handle.update(42);   // percent complete
 *   handle.complete();   // marks done and auto-removes after a delay
 *   handle.fail();       // marks failed and auto-removes after a delay
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
        const active = Array.from(_transfers.values()).filter(t => t.status === 'active').length;
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
     * @param {string} label   - Filename or display label
     * @param {'upload'|'download'} type
     * @returns {{ update(pct: number): void, complete(): void, fail(): void }}
     */
    function start(label, type) {
        _ensurePanel();
        const id = _nextId++;

        const iconEl  = Utils.el('span', { className: 'transfer-row-icon', textContent: type === 'upload' ? '↑' : '↓' });
        const nameEl  = Utils.el('span', { className: 'transfer-row-name', textContent: label });
        const fillEl  = Utils.el('div',  { className: 'transfer-row-fill', style: 'width:0%' });
        const trackEl = Utils.el('div',  { className: 'transfer-row-track' }, [fillEl]);
        const pctEl   = Utils.el('span', { className: 'transfer-row-pct', textContent: '0%' });
        const rowEl   = Utils.el('div',  { className: 'transfer-row' }, [iconEl, nameEl, trackEl, pctEl]);

        _listEl.appendChild(rowEl);
        _transfers.set(id, { rowEl, status: 'active' });
        _refreshVisibility();

        return {
            update(pct) {
                fillEl.style.width = `${pct}%`;
                pctEl.textContent  = `${pct}%`;
            },
            complete() {
                const t = _transfers.get(id);
                if (!t || t.status !== 'active') return;
                t.status = 'done';
                rowEl.classList.add('transfer-row--done');
                pctEl.textContent = '✓';
                _refreshVisibility();
                _removeTransfer(id, rowEl, 1500);
            },
            fail() {
                const t = _transfers.get(id);
                if (!t || t.status !== 'active') return;
                t.status = 'failed';
                rowEl.classList.add('transfer-row--failed');
                pctEl.textContent = 'Failed';
                _refreshVisibility();
                _removeTransfer(id, rowEl, 3000);
            },
        };
    }

    return { start };
})();
