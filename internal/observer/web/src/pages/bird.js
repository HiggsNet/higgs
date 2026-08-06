// bird.js — BIRD instance table with prominent routing errors.
// Deep birdc protocol/neighbor parsing is out of scope (observer.md 10.2).

import * as store from '../store.js';
import { navigate } from '../router.js';
import { esc } from '../format.js';
import { pageHeader, filterInput, banner, emptyState, loading, errorMsg } from '../components/card.js';
import { tableWrap } from '../components/table.js';
import { stateBadge } from '../components/badge.js';

export const deps = ['/bird', '/status'];

export function render(container, route) {
    const header = pageHeader('BIRD', 'Routing daemon instances', filterInput(route, 'Filter instances…'));
    const entry = store.get('/bird');
    if (!entry) { container.innerHTML = header + loading(); return; }
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load BIRD: ${entry.error.message}`); return; }

    const status = (store.get('/status') && store.get('/status').data) || {};
    const routingError = status.last_routing_error || '';
    const errorBanner = routingError ? banner(`Last routing error: ${routingError}`, 'err') : '';

    const filter = (route.filter || '').toLowerCase();
    const instances = Object.entries((entry.data && entry.data.instances) || {})
        .filter(([name, inst]) => !filter
            || name.toLowerCase().includes(filter)
            || (inst.netns_name || '').toLowerCase().includes(filter));

    container.innerHTML = `
        ${header}
        ${errorBanner}
        ${instances.length === 0 ? emptyState('No BIRD instances configured') : tableWrap(`<table>
            <thead><tr><th>Name</th><th>NetNS</th><th>State</th><th>Router ID</th><th>Last Error</th></tr></thead>
            <tbody>${instances.map(([name, inst]) => `
                <tr>
                    <td>${esc(name)}</td>
                    <td>${esc(inst.netns_name || '-')}</td>
                    <td>${stateBadge(inst.state)}</td>
                    <td><code>${esc(inst.router_id || '-')}</code></td>
                    <td>${inst.last_error ? `<span class="badge badge-err">${esc(inst.last_error)}</span>` : '-'}</td>
                </tr>`).join('')}</tbody>
        </table>`)}
        <h3>CLI Reference</h3>
        <code>photon debug babel</code>`;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
}
