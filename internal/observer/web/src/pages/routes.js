// routes.js — authorization errors first, export set, IPAM pools and
// assignments with zone filtering.

import * as store from '../store.js';
import { navigate } from '../router.js';
import { esc, compareZones } from '../format.js';
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

function groupSharedAssignments(assignments) {
    const groups = new Map();
    for (const assignment of assignments.filter(item => item.shared)) {
        const prefix = assignment.prefix || '';
        if (!groups.has(prefix)) groups.set(prefix, []);
        groups.get(prefix).push(assignment);
    }
    return [...groups.entries()]
        .map(([prefix, members]) => ({
            prefix,
            members: members.slice().sort((a, b) => compareZones(a.assigned_to, b.assigned_to)),
        }))
        .sort((a, b) => String(a.prefix).localeCompare(String(b.prefix)));
}

function participantList(members) {
    return `<div class="route-participants">${members.map(member => `
        <div class="route-participant">
            <span>${esc(member.assigned_to || '-')}</span>
            ${member.source && member.source !== member.assigned_to ? `<span class="muted">via ${esc(member.source)}</span>` : ''}
        </div>`).join('')}</div>`;
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
        match(zone, ...(prefixes || [])))
        .sort(([a], [b]) => compareZones(a, b));
    const pools = (data.ipam_pools || []).filter(p => match(p.prefix, p.source, p.delegated_to));
    const allAssignments = data.ipam_assignments || Object.entries(data.assignments || {}).map(([prefix, info]) => ({
        prefix,
        source: info.source,
        assigned_to: info.assigned_to,
    }));
    const assignments = allAssignments.filter(a => match(a.prefix, a.source, a.assigned_to))
        .sort((a, b) => compareZones(a.assigned_to, b.assigned_to));
    const nonSharedAssignments = assignments.filter(a => !a.shared);
    const sharedAssignmentGroups = groupSharedAssignments(assignments);
    const sharedAuthorizedGroups = data.shared_authorized || {};
    const sharedPrefixes = new Set(Object.keys(sharedAuthorizedGroups));
    if (!sharedPrefixes.size) {
        for (const assignment of allAssignments.filter(a => a.shared)) sharedPrefixes.add(assignment.prefix);
    }
    const nonSharedAuthorized = authorized
        .map(([zone, prefixes]) => [zone, prefixes.filter(prefix => !sharedPrefixes.has(prefix))])
        .filter(([, prefixes]) => prefixes.length);
    const sharedAuthorizedByPrefix = new Map();
    for (const [zone, prefixes] of authorized) {
        for (const prefix of prefixes.filter(value => sharedPrefixes.has(value))) {
            if (!sharedAuthorizedByPrefix.has(prefix)) sharedAuthorizedByPrefix.set(prefix, []);
            sharedAuthorizedByPrefix.get(prefix).push({ assigned_to: zone });
        }
    }
    const sharedAuthorized = [...sharedAuthorizedByPrefix.entries()]
        .map(([prefix, members]) => ({ prefix, members: members.sort((a, b) => compareZones(a.assigned_to, b.assigned_to)) }))
        .sort((a, b) => String(a.prefix).localeCompare(String(b.prefix)));
    const errors = (data.errors || []).slice()
        .sort((a, b) => compareZones(a.zone, b.zone) || String(a.prefix || '').localeCompare(String(b.prefix || '')));

    const errorBanner = errors.length
        ? banner(`${errors.length} authorization error${errors.length === 1 ? '' : 's'}`, 'err')
        : '';

    container.innerHTML = `
        ${header}
        ${errorBanner}
        ${errorsSection(errors)}
        <h2>Local Export Set</h2>
        <div>${exportSet.map(p => `<span class="chip">${esc(p)}</span>`).join('') || emptyState('No exports')}</div>
        <h2>Non-shared Authorized Prefixes by Zone</h2>
        ${tableWrap(`<table>
            <thead><tr><th>Zone</th><th>Prefixes</th></tr></thead>
            <tbody>${nonSharedAuthorized.map(([zone, prefixes]) => `
                <tr><td>${esc(zone)}</td><td>${prefixes.map(p => `<span class="chip">${esc(p)}</span>`).join('')}</td></tr>`).join('') || emptyRow(2)}</tbody>
        </table>`)}
        <h2>Shared Authorized Prefixes</h2>
        ${tableWrap(`<table>
            <thead><tr><th>Prefix</th><th>Participating Nodes</th></tr></thead>
            <tbody>${sharedAuthorized.map(group => `
                <tr><td><code>${esc(group.prefix || '-')}</code></td><td>${participantList(group.members)}</td></tr>`).join('') || emptyRow(2)}</tbody>
        </table>`)}
        <h2>IPAM Pools</h2>
        ${tableWrap(`<table>
            <thead><tr><th>Prefix</th><th>Source</th><th>Delegated To</th></tr></thead>
            <tbody>${pools.map(pool => `
                <tr><td><code>${esc(pool.prefix || '-')}</code></td><td>${esc(pool.source || '-')}</td><td>${esc(pool.delegated_to || '-')}</td></tr>`).join('') || emptyRow(3)}</tbody>
        </table>`)}
        <h2>Non-shared IPAM Assignments</h2>
        ${tableWrap(`<table>
            <thead><tr><th>Prefix</th><th>Source</th><th>Assigned To</th></tr></thead>
            <tbody>${nonSharedAssignments.map(info => `
                <tr>
                    <td><code>${esc(info.prefix || '-')}</code></td>
                    <td>${esc(info.source || '-')}</td>
                    <td>${esc(info.assigned_to || '-')}</td>
                </tr>`).join('') || emptyRow(3)}</tbody>
        </table>`)}
        <h2>Shared IPAM Assignments ${stateBadge('shared')}</h2>
        ${tableWrap(`<table>
            <thead><tr><th>Prefix</th><th>Participating Nodes</th></tr></thead>
            <tbody>${sharedAssignmentGroups.map(group => `
                <tr><td><code>${esc(group.prefix || '-')}</code></td><td>${participantList(group.members)}</td></tr>`).join('') || emptyRow(2)}</tbody>
        </table>`)}`;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
}
