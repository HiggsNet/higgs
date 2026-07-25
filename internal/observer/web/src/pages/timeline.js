// timeline.js — Events page: recent event stream from the hub replay
// buffer (GET /api/v1/events/recent). Kept separate from src/events.js
// (the SSE connection module) to avoid the name clash.

import * as store from '../store.js';
import { navigate } from '../router.js';
import { esc, relTime } from '../format.js';
import { pageHeader, filterInput, emptyState, loading, errorMsg } from '../components/card.js';
import { tableWrap } from '../components/table.js';
import { badge } from '../components/badge.js';

export const deps = ['/events/recent'];

function payloadSummary(payload) {
    if (!payload || typeof payload !== 'object') return '<span class="muted">-</span>';
    const parts = Object.entries(payload).map(([key, value]) => {
        if (Array.isArray(value)) {
            const shown = value.slice(0, 3).map(v => `<code>${esc(v)}</code>`).join(' ');
            const more = value.length > 3 ? ` <span class="muted">+${value.length - 3} more</span>` : '';
            return `<span class="muted">${esc(key)}:</span> ${shown || '-'}${more}`;
        }
        const text = typeof value === 'object' && value !== null ? JSON.stringify(value) : value;
        return `<span class="muted">${esc(key)}:</span> <code>${esc(text)}</code>`;
    });
    return parts.length ? parts.join(' ') : '<span class="muted">-</span>';
}

export function render(container, route) {
    const header = pageHeader('Events', 'Recent observer event stream', filterInput(route, 'Filter by type / id…'));
    const entry = store.get('/events/recent');
    if (!entry) { container.innerHTML = header + loading(); return; }
    if (entry.error && !entry.data) {
        container.innerHTML = header + errorMsg(`Failed to load recent events: ${entry.error.message}`);
        return;
    }
    const filter = (route.filter || '').toLowerCase();
    // Recent() arrives in ascending time order; display newest first.
    const events = ((entry.data && entry.data.events) || []).slice().reverse();
    const rows = events.filter(ev => !filter
        || (ev.type || '').toLowerCase().includes(filter)
        || JSON.stringify(ev.payload || '').toLowerCase().includes(filter));
    container.innerHTML = `
        ${header}
        ${rows.length === 0 ? emptyState('No recent events — set observer.event_buffer_seconds > 0 to retain them') : tableWrap(`<table>
            <thead><tr><th>Time</th><th>Type</th><th>Payload</th></tr></thead>
            <tbody>${rows.map(ev => `
                <tr>
                    <td>${relTime(ev.time)}</td>
                    <td>${badge(ev.type || 'unknown', 'unknown')}</td>
                    <td>${payloadSummary(ev.payload)}</td>
                </tr>`).join('')}</tbody>
        </table>`)}`;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
}
