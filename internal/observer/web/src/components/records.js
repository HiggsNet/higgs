// records.js — zone record summaries and Inspect tables.
// Pure HTML-string builders; all dynamic text passes through esc().

import { esc, copyable, relTime } from '../format.js';
import { stateBadge } from './badge.js';
import { jsonViewer } from './jsonview.js';
import { emptyState } from './card.js';

function addrForEndpoint(ep) {
    if (!ep) return '-';
    if (ep.addr) return ep.addr;
    if (ep.address && ep.port) return `${ep.address}:${ep.port}`;
    return ep.address || '-';
}

function endpointValueSummary(record) {
    const value = record && record.value_json;
    if (!value || !Array.isArray(value.endpoints)) return null;
    const endpoints = value.endpoints;
    const selected = endpoints.slice().sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];
    const bits = [`${endpoints.length} endpoint${endpoints.length === 1 ? '' : 's'}`];
    if (selected) bits.push(addrForEndpoint(selected));
    if (value.source) bits.push(value.source);
    return bits.join(' · ');
}

function ipamValueSummary(record) {
    const value = record && record.value_json;
    if (!value || typeof value !== 'object') return null;
    if (record.type === 'ipam.pool') {
        return `${value.prefix || '-'} -> ${value.delegated_to || '-'}${value.active === false ? ' · revoked' : ''}`;
    }
    if (record.type === 'ipam.assignment') {
        const bits = [`${value.prefix || '-'} -> ${value.assigned_to || '-'}`];
        if (value.shared) bits.push('shared');
        if (value.active === false) bits.push('revoked');
        return bits.join(' · ');
    }
    return null;
}

export function recordValueSummary(record) {
    const endpointSummary = endpointValueSummary(record);
    if (endpointSummary) return endpointSummary;
    const ipamSummary = ipamValueSummary(record);
    if (ipamSummary) return ipamSummary;
    if (record.value_json && typeof record.value_json === 'object') {
        const keys = Object.keys(record.value_json);
        return keys.length ? `{${keys.slice(0, 4).join(', ')}${keys.length > 4 ? ', ...' : ''}}` : '{}';
    }
    const value = record.value || '';
    if (!value) return '-';
    return value.length > 96 ? `${value.substring(0, 96)}…` : value;
}

function endpointValueTable(record) {
    const value = record && record.value_json;
    if (!value || !Array.isArray(value.endpoints) || value.endpoints.length === 0) return '';
    return `<table class="mini-table">
        <tr><th>Addr</th><th>Protocol</th><th>Scope</th><th>Source</th><th>Priority</th><th>Last Observed</th></tr>
        ${value.endpoints.map(ep => `
            <tr>
                <td><code>${esc(addrForEndpoint(ep))}</code></td>
                <td>${esc(ep.protocol || 'udp')}</td>
                <td>${esc(ep.scope || '-')}</td>
                <td>${esc(ep.source || '-')}</td>
                <td>${ep.priority || 0}</td>
                <td>${relTime(ep.last_observed)}</td>
            </tr>`).join('')}
    </table>`;
}

function ipamValueTable(record) {
    const value = record && record.value_json;
    if (!value || typeof value !== 'object') return '';
    if (record.type === 'ipam.pool') {
        return `<table class="mini-table">
            <tr><th>Prefix</th><th>Delegated To</th><th>Active</th><th>Version</th></tr>
            <tr>
                <td><code>${esc(value.prefix || '-')}</code></td>
                <td>${esc(value.delegated_to || '-')}</td>
                <td>${value.active === false ? stateBadge('revoked') : stateBadge('healthy')}</td>
                <td>${esc(value.version || '-')}</td>
            </tr>
        </table>`;
    }
    if (record.type === 'ipam.assignment') {
        return `<table class="mini-table">
            <tr><th>Prefix</th><th>Assigned To</th><th>Shared</th><th>Active</th><th>Version</th></tr>
            <tr>
                <td><code>${esc(value.prefix || '-')}</code></td>
                <td>${esc(value.assigned_to || '-')}</td>
                <td>${value.shared ? 'Yes' : 'No'}</td>
                <td>${value.active === false ? stateBadge('revoked') : stateBadge('healthy')}</td>
                <td>${esc(value.version || '-')}</td>
            </tr>
        </table>`;
    }
    return '';
}

export function groupRecordsByKey(records) {
    const out = {};
    (records || []).forEach(r => {
        const key = r.key || '';
        if (!out[key]) out[key] = [];
        out[key].push(r);
    });
    Object.values(out).forEach(items => items.sort((a, b) => (b.version || 0) - (a.version || 0)));
    return out;
}

function recordDetails(record, history) {
    return `
        <details class="record-details">
            <summary>Inspect record${history && history.length ? ` · ${history.length} historical` : ''}</summary>
            ${endpointValueTable(record)}
            ${ipamValueTable(record)}
            <h3>Value</h3>
            ${record.value_json ? jsonViewer(record.value_json) : `<div class="json-viewer">${esc(record.value || '')}</div>`}
            ${history && history.length ? `
                <h3>History</h3>
                <table class="mini-table">
                    <tr><th>Version</th><th>Type</th><th>Value</th><th>Record Hash</th><th>Signed By</th></tr>
                    ${history.map(h => `
                        <tr>
                            <td>${h.version || 0}</td>
                            <td>${esc(h.type || '-')}</td>
                            <td class="value-cell">${esc(recordValueSummary(h))}</td>
                            <td>${copyable(h.record_hash)}</td>
                            <td>${copyable(h.signed_by)}</td>
                        </tr>`).join('')}
                </table>` : ''}
            <h3>Raw Record</h3>
            ${jsonViewer(record)}
        </details>`;
}

export function recordTable(records, historyByKey) {
    if (!records || records.length === 0) return emptyState('No records');
    return `<div class="table-wrap"><table class="record-table">
        <thead><tr><th>Key</th><th>Type</th><th>Version</th><th>Value</th><th>Record Hash</th><th>Signed By</th></tr></thead>
        <tbody>${records.map(r => {
            const history = (historyByKey && historyByKey[r.key]) || [];
            return `
            <tr>
                <td><code>${esc(r.key || '-')}</code></td>
                <td>${esc(r.type || '-')}</td>
                <td>${r.version || 0}</td>
                <td class="value-cell">${esc(recordValueSummary(r))}</td>
                <td>${copyable(r.record_hash)}</td>
                <td>${copyable(r.signed_by)}</td>
            </tr>
            <tr class="subrow"><td colspan="6">${recordDetails(r, history)}</td></tr>`;
        }).join('')}</tbody>
    </table></div>`;
}
