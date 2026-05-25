// Restore appearance preferences from localStorage before CSS renders.
// Loaded synchronously from <head> to prevent flash of wrong theme or text size.
(function () {
    const t = localStorage.getItem('tus_theme') || 'system';
    const s = localStorage.getItem('tus_text_size');
    document.documentElement.dataset.theme = t;
    if (s && s !== 'medium') {
        document.documentElement.dataset.textSize = s;
    }
})();
