// table.js — table wrapper and empty-row helpers.

export function tableWrap(html) {
    return `<div class="table-wrap">${html}</div>`;
}

export function emptyRow(cols) {
    return `<tr><td colspan="${cols}" class="muted" style="text-align:center;">No entries</td></tr>`;
}
