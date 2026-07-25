// jsonview.js — pretty-printed JSON block for Inspect/debug sections.

import { esc } from '../format.js';

export function jsonViewer(obj) {
    return `<div class="json-viewer">${esc(JSON.stringify(obj, null, 2))}</div>`;
}
