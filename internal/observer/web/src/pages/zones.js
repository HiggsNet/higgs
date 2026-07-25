// zones.js — two-column layout: filterable zone list + selected zone detail.
// Debug material (authority / proofs / revocations / Raw JSON) lives in
// collapsed Inspect sections.

import * as store from '../store.js';
import { fetchAPI } from '../api.js';
import { navigate, renderCurrent } from '../router.js';
import { esc, copyable, compareZones } from '../format.js';
import { pageHeader, filterInput, emptyState, loading, errorMsg } from '../components/card.js';
import { kvTable } from '../components/kv.js';
import { jsonViewer } from '../components/jsonview.js';
import { dot, stateBadge } from '../components/badge.js';
import { recordTable, groupRecordsByKey } from '../components/records.js';

export const deps = ['/zones'];

let detail = { id: '', stamp: 0, data: null, error: null };

function zoneItem(z, selected) {
    return `<div class="zone-item${selected ? ' selected' : ''}" data-zone="${esc(z.path)}">
        ${dot(z.revoked ? 'revoked' : 'healthy')}
        <span class="zone-path">${esc(z.path)}</span>
        <span class="zone-count">${z.records || 0} rec</span>
    </div>`;
}

function inspectSection(summary, body) {
    return `<details class="record-details"><summary>${esc(summary)}</summary>${body}</details>`;
}

function jsonList(items) {
    if (!items || items.length === 0) return emptyState('No entries');
    return items.map(d => jsonViewer(d)).join('');
}

function zoneDetailPanel(route) {
    if (!route.selected) return emptyState('Select a zone to inspect records and proofs');
    if (detail.error) return errorMsg(`Failed to load zone detail: ${detail.error.message}`);
    if (!detail.data) return loading('Loading zone detail…');
    const z = detail.data;
    const historyByKey = groupRecordsByKey(z.record_history || []);
    return `<section class="zone-detail">
        <h2>${esc(z.path)}</h2>
        ${kvTable([
            ['Parent', esc(z.parent || '-')],
            ['Status', z.revoked ? stateBadge('revoked') : stateBadge('healthy')],
            ['Authority Hash', copyable(z.authority_hash)],
            ['Merkle Root', copyable(z.merkle_root)],
            ['Counts', esc(`${z.record_count || 0} records · ${z.history_count || 0} historical · ${z.delegation_count || 0} delegations · ${z.revocation_count || 0} revocations`)],
        ])}
        <h3>Active Records</h3>
        ${recordTable(z.records || [], historyByKey)}
        ${inspectSection(`Inspect · Authority`, jsonViewer(z.authority || {}))}
        ${inspectSection(`Inspect · Parent Proof (${(z.parent_proof || []).length})`, jsonList(z.parent_proof))}
        ${inspectSection(`Inspect · Delegations (${(z.delegations || []).length})`, jsonList(z.delegations))}
        ${inspectSection(`Inspect · Revocations (${(z.revocations || []).length})`, jsonList(z.revocations))}
        ${inspectSection('Inspect · Raw JSON', jsonViewer(z))}
    </section>`;
}

function ensureDetail(route) {
    if (!route.selected) return;
    const stamp = (store.get('/zones') || {}).updatedAt || 0;
    if (detail.id === route.selected && detail.stamp === stamp) return;
    detail = { id: route.selected, stamp, data: null, error: null };
    // The root zone "." cannot be a URL path segment (ServeMux redirects it);
    // it is fetched via the ?zone= query form instead.
    const url = route.selected === '.' ? '/zones?zone=.' : `/zones/${encodeURIComponent(route.selected)}`;
    fetchAPI(url)
        .then(data => { detail.data = data; renderCurrent(); })
        .catch(error => { detail.error = error; renderCurrent(); });
}

export function render(container, route) {
    const header = pageHeader('Zones', 'Namespace zones and records', filterInput(route, 'Filter zones…'));
    const entry = store.get('/zones');
    if (!entry) { container.innerHTML = header + loading(); return; }
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load zones: ${entry.error.message}`); return; }
    const filter = (route.filter || '').toLowerCase();
    const zones = (entry.data.zones || []).filter(z => !filter || (z.path || '').toLowerCase().includes(filter))
        .sort((a, b) => compareZones(a.path, b.path));
    container.innerHTML = `
        ${header}
        <div class="global-root">
            <span class="muted">Global Root</span>
            ${copyable(entry.data.global_root, entry.data.global_root || '-')}
        </div>
        <div class="zone-layout">
            <div class="zone-list">${zones.map(z => zoneItem(z, route.selected === z.path)).join('') || emptyState('No zones match')}</div>
            <div id="zone-detail">${zoneDetailPanel(route)}</div>
        </div>`;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
    container.querySelectorAll('[data-zone]').forEach(item => {
        item.addEventListener('click', () => navigate('zones', item.dataset.zone, route.filter));
    });
    ensureDetail(route);
}
