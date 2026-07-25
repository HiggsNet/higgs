// routes.js — authorization errors first, export set, IPAM pools and
// assignments with zone filtering.

import * as store from '../store.js';
import { navigate } from '../router.js';
import { esc } from '../format.js';
import { pageHeader, filterInput, banner, emptyState, loading, errorMsg } from '../components/card.js';
import { tableWrap, emptyRow } from '../components/table.js';
import { stateBadge } from '../components/badge.js';

export const deps = ['/routes'];

function errorsSection(errors) {
    if (!errors.length) {
        return `<h2>Authorization Errors (0)</h2>${emptyState('No authorization errors')}`;
    }
    return `<section class="section-errors">
        <h2>Authorization Errors (${errors.length})</h2>
        ${tableWrap(`<table>
            <thead><tr><th>Zone</th><th>Prefix</th><th>Code</th><th>Detail</th></tr></thead>
            <tbody>${errors.map(e => `
                <tr><td>${esc(e.zone)}</td><td><code>${esc(e.prefix || '-')}</code></td><td>${esc(e.code)}</td><td>${esc(e.detail)}</td></tr>`).join('')}</tbody>
        </table>`)}
    </section>`;
}

export function render(container, route) {
    const header = pageHeader('Routes', 'Prefix authorization and IPAM', filterInput(route, 'Filter by zone / prefix…'));
    const entry = store.get('/routes');
    if (!entry) { container.innerHTML = header + loading(); return; }
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load routes: ${entry.error.message}`); return; }
    const data = entry.data || {};
    const filter = (route.filter || '').toLowerCase();
    const match = (...fields) => !filter || fields.some(f => (f || '').toLowerCase().includes(filter));

    const exportSet = (data.export_set || []).filter(p => match(p));
    const authorized = Object.entries(data.authorized || {}).filter(([zone, prefixes]) =>
        match(zone, ...(prefixes || [])));
    const pools = (data.ipam_pools || []).filter(p => match(p.prefix, p.source, p.delegated_to));
    const assignments = (data.ipam_assignments || Object.entries(data.assignments || {}).map(([prefix, info]) => ({
        prefix,
        source: info.source,
        assigned_to: info.assigned_to,
    }))).filter(a => match(a.prefix, a.source, a.assigned_to));
    const errors = data.errors || [];

    const errorBanner = errors.length
        ? banner(`${errors.length} authorization error${errors.length === 1 ? '' : 's'}`, 'err')
        : '';

    container.innerHTML = `
        ${header}
        ${errorBanner}
        ${errorsSection(errors)}
        <h2>Local Export Set</h2>
        <div>${exportSet.map(p => `<span class="chip">${esc(p)}</span>`).join('') || emptyState('No exports')}</div>
        <h2>Authorized Prefixes by Zone</h2>
        ${tableWrap(`<table>
            <thead><tr><th>Zone</th><th>Prefixes</th></tr></thead>
            <tbody>${authorized.map(([zone, prefixes]) => `
                <tr><td>${esc(zone)}</td><td>${prefixes.map(p => `<span class="chip">${esc(p)}</span>`).join('')}</td></tr>`).join('') || emptyRow(2)}</tbody>
        </table>`)}
        <h2>IPAM Pools</h2>
        ${tableWrap(`<table>
            <thead><tr><th>Prefix</th><th>Source</th><th>Delegated To</th></tr></thead>
            <tbody>${pools.map(pool => `
                <tr><td><code>${esc(pool.prefix || '-')}</code></td><td>${esc(pool.source || '-')}</td><td>${esc(pool.delegated_to || '-')}</td></tr>`).join('') || emptyRow(3)}</tbody>
        </table>`)}
        <h2>IPAM Assignments</h2>
        ${tableWrap(`<table>
            <thead><tr><th>Prefix</th><th>Source</th><th>Assigned To</th><th>Mode</th></tr></thead>
            <tbody>${assignments.map(info => `
                <tr>
                    <td><code>${esc(info.prefix || '-')}</code></td>
                    <td>${esc(info.source || '-')}</td>
                    <td>${esc(info.assigned_to || '-')}</td>
                    <td>${info.shared ? stateBadge('shared') : '-'}</td>
                </tr>`).join('') || emptyRow(4)}</tbody>
        </table>`)}`;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
}
