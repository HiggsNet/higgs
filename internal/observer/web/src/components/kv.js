// kv.js — key/value table. Keys are escaped; values are pre-rendered HTML.

import { esc } from '../format.js';

export function kvTable(rows) {
    return `<table class="kv-table">${rows
        .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`)
        .join('')}</table>`;
}
