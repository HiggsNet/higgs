// format.js — escaping, time/number formatting, copy helpers.
// Every dynamic text rendered into an HTML string MUST pass through esc().

export function esc(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

export function formatTime(unix) {
    if (!unix || unix === 0) return '-';
    return new Date(unix * 1000).toLocaleString();
}

// relTime renders a relative timestamp ("3m ago") with the absolute
// time in the hover title.
export function relTime(unix) {
    if (!unix || unix === 0) return '<span class="muted">-</span>';
    const delta = Date.now() - unix * 1000;
    const s = Math.abs(Math.round(delta / 1000));
    let text;
    if (s < 60) text = `${s}s`;
    else if (s < 3600) text = `${Math.floor(s / 60)}m`;
    else if (s < 86400) text = `${Math.floor(s / 3600)}h`;
    else text = `${Math.floor(s / 86400)}d`;
    const label = delta < 0 ? `in ${text}` : `${text} ago`;
    return `<span class="rel-time" title="${esc(formatTime(unix))}">${esc(label)}</span>`;
}

export function ms(v) {
    if (v == null || v === '' || v === 0) return '-';
    const n = Number(v);
    if (!Number.isFinite(n)) return `${esc(v)}ms`;
    return `${n % 1 === 0 ? n : n.toFixed(1)}ms`;
}

export function pct(v) {
    if (v == null || v === '') return '-';
    return `${esc(v)}%`;
}

export function shortHash(s, n = 12) {
    if (!s) return '-';
    return s.length > n ? `${s.substring(0, n)}…` : s;
}

// copyable renders a truncated machine identifier (hash/address) that
// copies its full value on click. main.js binds the delegated handler.
export function copyable(text, display) {
    if (!text) return '<span class="muted">-</span>';
    return `<code class="copyable" data-copy="${esc(text)}" title="${esc(text)} — click to copy">${esc(display || shortHash(text))}</code>`;
}

export async function copyToClipboard(el) {
    const original = el.textContent;
    try {
        await navigator.clipboard.writeText(el.dataset.copy);
        el.textContent = 'Copied';
    } catch {
        el.textContent = 'Copy failed';
    }
    setTimeout(() => { el.textContent = original; }, 900);
}
