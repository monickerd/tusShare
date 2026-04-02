/**
 * tusShare — Shared utility functions.
 */
const Utils = (() => {
    /**
     * Format bytes to human-readable string.
     */
    function formatBytes(bytes, decimals = 1) {
        if (bytes === 0 || bytes == null) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
    }

    /**
     * Format ISO date string to local readable format.
     */
    function formatDate(iso) {
        if (!iso) return '';
        const d = new Date(iso);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    /**
     * Relative time ago string.
     */
    function timeAgo(iso) {
        if (!iso) return '';
        const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
        if (seconds < Config.time.minute) return 'just now';
        if (seconds < Config.time.hour) return Math.floor(seconds / Config.time.minute) + 'm ago';
        if (seconds < Config.time.day) return Math.floor(seconds / Config.time.hour) + 'h ago';
        if (seconds < Config.time.week) return Math.floor(seconds / Config.time.day) + 'd ago';
        return formatDate(iso);
    }

    /**
     * Create a DOM element with attributes and children.
     */
    function el(tag, attrs = {}, children = []) {
        const elem = document.createElement(tag);
        for (const [key, val] of Object.entries(attrs)) {
            if (key === 'className') {
                elem.className = val;
            } else if (key === 'textContent') {
                elem.textContent = val;
            } else if (key === 'innerHTML') {
                elem.innerHTML = val;
            } else if (key.startsWith('on') && typeof val === 'function') {
                elem.addEventListener(key.slice(2).toLowerCase(), val);
            } else if (key === 'dataset') {
                for (const [dk, dv] of Object.entries(val)) {
                    elem.dataset[dk] = dv;
                }
            } else {
                elem.setAttribute(key, val);
            }
        }
        for (const child of (Array.isArray(children) ? children : [children])) {
            if (typeof child === 'string') {
                elem.appendChild(document.createTextNode(child));
            } else if (child instanceof Node) {
                elem.appendChild(child);
            }
        }
        return elem;
    }

    /**
     * Toast notification system.
     */
    let _toastContainer = null;

    function _ensureToastContainer() {
        if (!_toastContainer) {
            _toastContainer = el('div', { className: 'toast-container' });
            document.body.appendChild(_toastContainer);
        }
        return _toastContainer;
    }

    function showToast(message, type = 'info', duration = Config.ui.toastDurationMs) {
        const container = _ensureToastContainer();
        const toast = el('div', { className: `toast toast-${type}`, textContent: message });
        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('toast-visible'));
        setTimeout(() => {
            toast.classList.remove('toast-visible');
            setTimeout(() => {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, Config.ui.toastFadeOutMs);
        }, duration);
    }

    /**
     * Confirmation dialog — returns Promise<boolean>.
     */
    function showConfirm(message) {
        return new Promise((resolve) => {
            let overlay = el('div', { className: 'modal-overlay' });
            const dismiss = (result) => {
                if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
                overlay = null;  // Release DOM reference for GC
                resolve(result);
            };
            const dialog = el('div', { className: 'modal confirm-dialog' }, [
                el('p', { textContent: message }),
                el('div', { className: 'modal-actions' }, [
                    el('button', {
                        className: 'btn btn-secondary',
                        textContent: 'Cancel',
                        onClick: () => dismiss(false),
                    }),
                    el('button', {
                        className: 'btn btn-danger',
                        textContent: 'Confirm',
                        onClick: () => dismiss(true),
                    }),
                ]),
            ]);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);
        });
    }

    /**
     * Prompt dialog with a text input — returns Promise<string|null>.
     */
    function showPrompt(title, placeholder = '') {
        return new Promise((resolve) => {
            let overlay = el('div', { className: 'modal-overlay' });
            const dismiss = (result) => {
                if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
                overlay = null;
                resolve(result);
            };
            const input = el('input', {
                className: 'prompt-dialog-input',
                type: 'text',
                placeholder,
            });
            const submit = () => {
                const val = input.value.trim();
                dismiss(val || null);
            };
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') submit();
                if (e.key === 'Escape') dismiss(null);
            });
            const dialog = el('div', { className: 'modal prompt-dialog' }, [
                el('h3', { textContent: title }),
                input,
                el('div', { className: 'modal-actions' }, [
                    el('button', {
                        className: 'btn btn-secondary',
                        textContent: 'Cancel',
                        onClick: () => dismiss(null),
                    }),
                    el('button', {
                        className: 'btn btn-primary',
                        textContent: 'Create',
                        onClick: submit,
                    }),
                ]),
            ]);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);
            input.focus();
        });
    }

    /**
     * Read a cookie by name.
     */
    function parseCookie(name) {
        const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
        return match ? decodeURIComponent(match[2]) : null;
    }

    /**
     * Simple debounce.
     */
    function debounce(fn, ms) {
        let timer;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => fn(...args), ms);
        };
    }

    return {
        formatBytes,
        formatDate,
        timeAgo,
        el,
        showToast,
        showConfirm,
        showPrompt,
        parseCookie,
        debounce,
    };
})();
