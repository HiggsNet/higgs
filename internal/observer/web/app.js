'use strict';

// Higgs Observer - Read-only Web Status Console
// Native JS SPA, no build step required.

const API_BASE = '/api/v1';
let pollTimer = null;
let eventSource = null;
let currentPage = 'overview';
let connectionMode = 'disconnected';
let selectedZone = null;
let selectedPeer = null;

// ===== API Helpers =====

async function fetchAPI(endpoint) {
    const resp = await fetch(API_BASE + endpoint);
    if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    }
    const body = await resp.json();
    if (!body.ok) {
        throw new Error(body.error || 'API error');
    }
    return body.data;
}

// ===== SSE Connection =====

function connectSSE() {
    if (eventSource) {
        eventSource.close();
    }
    try {
        eventSource = new EventSource(API_BASE + '/events');
        eventSource.addEventListener('connected', () => {
            setConnectionMode('connected');
        });
        eventSource.addEventListener('state_changed', () => refreshCurrentPage());
        eventSource.addEventListener('peer_updated', () => refreshCurrentPage());
        eventSource.addEventListener('link_updated', () => refreshCurrentPage());
        eventSource.addEventListener('health_updated', () => refreshCurrentPage());
        eventSource.addEventListener('route_changed', () => refreshCurrentPage());
        eventSource.addEventListener('bird_updated', () => refreshCurrentPage());
        eventSource.onerror = () => {
            setConnectionMode('polling');
            eventSource.close();
            eventSource = null;
            // Retry SSE after 10s
            setTimeout(() => {
                if (connectionMode === 'polling') connectSSE();
            }, 10000);
        };
    } catch (e) {
        setConnectionMode('polling');
    }
}

function setConnectionMode(mode) {
    connectionMode = mode;
    const el = document.getElementById('connection-status');
    if (mode === 'connected') {
        el.textContent = 'Live';
        el.className = 'status-connected';
        stopPolling();
    } else if (mode === 'polling') {
        el.textContent = 'Polling';
        el.className = 'status-polling';
        startPolling();
    } else {
        el.textContent = 'Disconnected';
        el.className = 'status-disconnected';
    }
}

function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(() => refreshCurrentPage(), 5000);
}

function stopPolling() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

// ===== Routing =====

function handleHashChange() {
    const hash = window.location.hash.slice(1) || '/';
    const parts = hash.split('/').filter(Boolean);
    const page = parts[0] || 'overview';
    currentPage = page;
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.toggle('active', link.dataset.page === page);
    });
    refreshCurrentPage();
}

function refreshCurrentPage() {
    switch (currentPage) {
        case 'overview': renderOverview(); break;
        case 'gossip': renderGossip(); break;
        case 'zones': renderZones(); break;
        case 'overlay': renderOverlay(); break;
        case 'health': renderHealth(); break;
        case 'routes': renderRoutes(); break;
        case 'bird': renderBird(); break;
        default: renderOverview();
    }
}

// ===== Render Helpers =====

function esc(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatTime(unix) {
    if (!unix || unix === 0) return '-';
    const d = new Date(unix * 1000);
    return d.toLocaleString();
}

function stateBadge(state) {
    const cls = {
        'up': 'badge-green', 'healthy': 'badge-green', 'running': 'badge-green', 'established': 'badge-green',
        'connecting': 'badge-yellow', 'degraded': 'badge-yellow', 'stale': 'badge-yellow', 'pending': 'badge-yellow', 'polling': 'badge-yellow',
        'down': 'badge-red', 'error': 'badge-red', 'revoked': 'badge-red', 'offline': 'badge-red', 'failed': 'badge-red',
    };
    return `<span class="badge ${cls[state] || 'badge-gray'}">${esc(state || 'unknown')}</span>`;
}

function card(label, value, valueClass) {
    return `<div class="card"><div class="card-label">${esc(label)}</div><div class="card-value ${valueClass||''}">${esc(value)}</div></div>`;
}

function emptyState(msg) {
    return `<div class="empty-state">${esc(msg || 'No data available')}</div>`;
}

function jsonViewer(obj) {
    return `<div class="json-viewer">${esc(JSON.stringify(obj, null, 2))}</div>`;
}

function shortHash(s) {
    if (!s) return '-';
    return s.length > 18 ? `${s.substring(0, 18)}...` : s;
}

function kvTable(rows) {
    return `<table class="kv-table">${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join('')}</table>`;
}

function compactList(items, renderer) {
    if (!items || items.length === 0) return emptyState('No entries');
    return items.map(renderer).join('');
}

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
    const selected = endpoints
        .slice()
        .sort((a, b) => (b.priority || 0) - (a.priority || 0))[0];
    const bits = [`${endpoints.length} endpoint${endpoints.length === 1 ? '' : 's'}`];
    if (selected) bits.push(addrForEndpoint(selected));
    if (value.source) bits.push(value.source);
    return bits.join(' · ');
}

function recordValueSummary(record) {
    const endpointSummary = endpointValueSummary(record);
    if (endpointSummary) return endpointSummary;
    if (record.value_json && typeof record.value_json === 'object') {
        const keys = Object.keys(record.value_json);
        return keys.length ? `{${keys.slice(0, 4).join(', ')}${keys.length > 4 ? ', ...' : ''}}` : '{}';
    }
    const value = record.value || '';
    if (!value) return '-';
    return value.length > 96 ? `${value.substring(0, 96)}...` : value;
}

function endpointValueTable(record) {
    const value = record && record.value_json;
    if (!value || !Array.isArray(value.endpoints) || value.endpoints.length === 0) return '';
    return `
        <table class="mini-table">
            <tr><th>Addr</th><th>Protocol</th><th>Scope</th><th>Source</th><th>Priority</th><th>Last Observed</th></tr>
            ${value.endpoints.map(ep => `
                <tr>
                    <td><code>${esc(addrForEndpoint(ep))}</code></td>
                    <td>${esc(ep.protocol || 'udp')}</td>
                    <td>${esc(ep.scope || '-')}</td>
                    <td>${esc(ep.source || '-')}</td>
                    <td>${ep.priority || 0}</td>
                    <td>${formatTime(ep.last_observed)}</td>
                </tr>`).join('')}
        </table>`;
}

function diagnosticsList(peer) {
    const items = [];
    if (peer.last_error) items.push(['Last Error', peer.last_error]);
    if (peer.last_update_source) items.push(['Update Source', peer.last_update_source]);
    if (peer.last_relay_suppression) items.push(['Relay Suppression', peer.last_relay_suppression]);
    if (peer.observed_failure_count) items.push(['Observed Failures', peer.observed_failure_count]);
    if (peer.datagram_stats) items.push(['Datagram Stats', JSON.stringify(peer.datagram_stats)]);
    if (peer.object_pull_stats) items.push(['Object Pull Stats', JSON.stringify(peer.object_pull_stats)]);
    if (peer.rejected_digests && Object.keys(peer.rejected_digests).length) items.push(['Rejected Digests', JSON.stringify(peer.rejected_digests)]);
    if (!items.length) return emptyState('No diagnostics recorded');
    return kvTable(items.map(([k, v]) => [k, `<code>${esc(v)}</code>`]));
}

function groupRecordsByKey(records) {
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
    const endpointTableHTML = endpointValueTable(record);
    return `
        <details class="record-details">
            <summary>Inspect record${history && history.length ? ` · ${history.length} historical` : ''}</summary>
            ${endpointTableHTML}
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
                            <td><code title="${esc(h.record_hash || '')}">${esc(shortHash(h.record_hash))}</code></td>
                            <td><code title="${esc(h.signed_by || '')}">${esc(shortHash(h.signed_by))}</code></td>
                        </tr>`).join('')}
                </table>` : ''}
            <h3>Raw Record</h3>
            ${jsonViewer(record)}
        </details>`;
}

function recordTable(records, historyByKey) {
    if (!records || records.length === 0) return emptyState('No records');
    return `
        <table class="record-table">
            <tr><th>Key</th><th>Version</th><th>Type</th><th>Value</th><th>Record Hash</th><th>Signed By</th></tr>
            ${records.map(r => {
                const history = (historyByKey && historyByKey[r.key]) || [];
                return `
                <tr>
                    <td><code>${esc(r.key || '-')}</code></td>
                    <td>${r.version || 0}</td>
                    <td>${esc(r.type || '-')}</td>
                    <td class="value-cell">${esc(recordValueSummary(r))}</td>
                    <td><code title="${esc(r.record_hash || '')}">${esc(shortHash(r.record_hash))}</code></td>
                    <td><code title="${esc(r.signed_by || '')}">${esc(shortHash(r.signed_by))}</code></td>
                </tr>
                <tr class="subrow"><td colspan="6">${recordDetails(r, history)}</td></tr>`;
            }).join('')}
        </table>`;
}

function endpointTable(endpoints) {
    if (!endpoints || endpoints.length === 0) return emptyState('No endpoints');
    return `
        <table>
            <tr><th>Addr</th><th>Source</th><th>Protocol</th><th>Scope</th><th>Priority</th><th>Last Observed</th><th>Selected</th></tr>
            ${endpoints.map(ep => `
                <tr>
                    <td><code>${esc(ep.addr || '-')}</code></td>
                    <td>${esc(ep.source || '-')}</td>
                    <td>${esc(ep.protocol || '-')}</td>
                    <td>${esc(ep.scope || '-')}</td>
                    <td>${ep.priority || 0}</td>
                    <td>${formatTime(ep.last_observed)}</td>
                    <td>${ep.selected ? stateBadge('healthy') : '-'}</td>
                </tr>`).join('')}
        </table>`;
}

function healthValue(item) {
    if (!item) return null;
    return item.health || item;
}

function desiredValue(link) {
    return (link && link.desired) || {};
}

function actualSAValue(link) {
    return (link && link.actual_sa) || {};
}

function healthStateForLink(link) {
    const h = healthValue(link && link.health);
    return h ? h.state : '';
}

function pct(v) {
    if (v == null || v === '') return '-';
    return `${v}%`;
}

function ms(v) {
    if (v == null || v === '' || v === 0) return '-';
    return `${v}ms`;
}

function linkDetail(link) {
    const desired = desiredValue(link);
    const sa = actualSAValue(link);
    const health = healthValue(link.health);
    const routing = link.routing || {};
    const rotation = link.rotation || {};
    const takeover = link.takeover || {};
    return `
        <details class="record-details">
            <summary>Inspect link diagnostics</summary>
            <div class="detail-grid">
                <section>
                    <h3>Planner</h3>
                    ${kvTable([
                        ['Desired Hash', `<code title="${esc(desired.desired_spec_hash || '')}">${esc(shortHash(desired.desired_spec_hash || link.desired_spec_hash))}</code>`],
                        ['Actual Hash', `<code title="${esc(link.desired_spec_hash || '')}">${esc(shortHash(link.desired_spec_hash))}</code>`],
                        ['Endpoint', `<code>${esc(desired.endpoint || link.endpoint || '-')}</code>`],
                        ['Local Tunnel', `<code>${esc(desired.local_tunnel_addr || '-')}</code>`],
                        ['Peer Tunnel', `<code>${esc(desired.peer_tunnel_addr || '-')}</code>`],
                    ])}
                </section>
                <section>
                    <h3>StrongSwan</h3>
                    ${kvTable([
                        ['IKE', `<code>${esc(link.raw && link.raw.ike_name || sa.name || '-')}</code>`],
                        ['Child SA', `<code>${esc(link.raw && link.raw.child_sa_name || sa.child_sa || '-')}</code>`],
                        ['SA State', stateBadge(sa.established ? 'established' : (sa.child_state || sa.ike_state || '-'))],
                        ['ReqID', esc(sa.reqid || '-')],
                        ['Observed if_id', esc(sa.xfrm_if_id || '-')],
                        ['Local Endpoint', `<code>${esc(sa.local_endpoint || '-')}</code>`],
                        ['Remote Endpoint', `<code>${esc(sa.remote_endpoint || sa.endpoint || '-')}</code>`],
                        ['Local Identity', `<code>${esc(sa.local_identity || '-')}</code>`],
                        ['Remote Identity', `<code>${esc(sa.remote_identity || '-')}</code>`],
                    ])}
                </section>
                <section>
                    <h3>Health</h3>
                    ${health ? kvTable([
                        ['State', stateBadge(health.state)],
                        ['Probe', esc(health.probe_type || '-')],
                        ['Samples', `${health.sent || 0} sent, ${health.received || 0} received, ${health.lost || 0} lost`],
                        ['Loss', pct(health.loss_ratio_pct)],
                        ['RTT', `last ${ms(health.last_rtt_ms)}, ewma ${ms(health.ewma_rtt_ms)}, p95 ${ms(health.p95_rtt_ms)}`],
                        ['Jitter', ms(health.jitter_ms)],
                        ['Next Probe', formatTime(health.next_probe_unix)],
                        ['Cutover Blocking', health.cutover_blocking ? 'Yes' : 'No'],
                        ['Last Error', `<code>${esc(health.last_error || '-')}</code>`],
                    ]) : emptyState('No live health sample')}
                </section>
                <section>
                    <h3>Routing</h3>
                    ${kvTable([
                        ['BIRD State', stateBadge(routing.bird_state || '-')],
                        ['Neighbors', esc(routing.bird_neighbors || '-')],
                        ['Best Routes', esc(routing.bird_best_routes || '-')],
                    ])}
                </section>
                <section>
                    <h3>Rotation</h3>
                    ${kvTable([
                        ['Phase', esc(rotation.phase || 'idle')],
                        ['Remote Generation', esc(rotation.remote_generation || 0)],
                        ['Staged Generation', esc(rotation.staged_generation || 0)],
                        ['Staged IKE', `<code>${esc(rotation.staged_ike_name || '-')}</code>`],
                        ['Staged Child', `<code>${esc(rotation.staged_child_sa_name || '-')}</code>`],
                        ['Staged Interface', `<code>${esc(rotation.staged_interface_name || '-')}</code>`],
                        ['Deadline', formatTime(rotation.rotate_deadline)],
                    ])}
                </section>
                <section>
                    <h3>Takeover</h3>
                    ${kvTable([
                        ['Initiator Role', esc(takeover.initiator_role || '-')],
                        ['Phase', esc(takeover.phase || '-')],
                        ['Until', formatTime(takeover.until)],
                        ['Observed Initiator', `<code>${esc(takeover.observed_initiator || '-')}</code>`],
                        ['Last Error', `<code>${esc(takeover.last_error || '-')}</code>`],
                    ])}
                </section>
            </div>
            <h3>Raw JSON</h3>
            ${jsonViewer(link)}
        </details>`;
}

// ===== Page Renderers =====

async function renderOverview() {
    const content = document.getElementById('content');
    try {
        const status = await fetchAPI('/status');
        const zones = status.known_zones || 0;
        const peers = status.known_peers || 0;
        const links = status.link_instances || 0;
        content.innerHTML = `
            <h1>Overview</h1>
            <div class="card-grid">
                ${card('Peer ID', status.peer_id || '-')}
                ${card('Managed Zone', status.managed_zone || '-')}
                ${card('Zones', zones)}
                ${card('Peers', peers)}
                ${card('Links', links)}
                ${card('Desired Links', status.desired_links || 0)}
            </div>
            <h2>Status</h2>
            <table>
                <tr><th>Listen Addr</th><td>${esc(status.listen_addr || '-')}</td></tr>
                <tr><th>Last Sync</th><td>${formatTime(status.last_sync_unix)}</td></tr>
                <tr><th>Last Reconcile</th><td>${formatTime(status.last_reconcile_unix)}</td></tr>
                <tr><th>Last Link Error</th><td>${esc(status.last_link_error || '-')}</td></tr>
                <tr><th>Last Routing Error</th><td>${esc(status.last_routing_error || '-')}</td></tr>
            </table>
        `;
    } catch (e) {
        content.innerHTML = `<div class="error-msg">Failed to load status: ${esc(e.message)}</div>`;
    }
}

async function renderGossip() {
    const content = document.getElementById('content');
    try {
        const data = await fetchAPI('/peers');
        const peers = data.peers || [];
        if (peers.length === 0) {
            content.innerHTML = `<h1>Gossip</h1>${emptyState('No peers known')}`;
            return;
        }
        let rows = peers.map(p => `
            <tr class="click-row ${selectedPeer === p.peer_id ? 'selected-row' : ''}" data-peer="${esc(p.peer_id)}">
                <td>${esc(p.peer_id)}</td>
                <td>${esc(p.source || '-')}</td>
                <td>${formatTime(p.last_sync_unix)}</td>
                <td>${p.failure_count || 0}</td>
                <td>${esc(p.last_error || '-')}</td>
                <td>${esc(p.configured_addr || '-')}</td>
                <td>${esc(p.discovered_addr || '-')}</td>
                <td>${esc(p.observed_addr || '-')}</td>
            </tr>`).join('');
        content.innerHTML = `
            <h1>Gossip Peers</h1>
            <table>
                <tr><th>Peer ID</th><th>Source</th><th>Last Sync</th><th>Failures</th><th>Last Error</th><th>Bootstrap</th><th>Discovered</th><th>Observed</th></tr>
                ${rows}
            </table>
            <div id="peer-detail">${selectedPeer ? '<div class="empty-state">Loading peer detail...</div>' : emptyState('Select a peer to inspect endpoints and diagnostics')}</div>`;
        document.querySelectorAll('[data-peer]').forEach(row => {
            row.addEventListener('click', () => {
                selectedPeer = row.dataset.peer;
                renderGossip();
            });
        });
        if (selectedPeer) renderPeerDetail(selectedPeer);
    } catch (e) {
        content.innerHTML = `<div class="error-msg">Failed to load peers: ${esc(e.message)}</div>`;
    }
}

async function renderPeerDetail(peerID) {
    const el = document.getElementById('peer-detail');
    if (!el) return;
    try {
        const peer = await fetchAPI(`/peers/${encodeURIComponent(peerID)}`);
        el.innerHTML = `
            <section class="detail-panel">
                <h2>${esc(peer.peer_id)}</h2>
                ${kvTable([
                    ['Source', esc(peer.source || '-')],
                    ['Bootstrap Addr', `<code>${esc(peer.configured_addr || '-')}</code>`],
                    ['Discovered Addr', `<code>${esc(peer.discovered_addr || '-')}</code>`],
                    ['Observed Addr', `<code>${esc(peer.observed_addr || '-')}</code>`],
                    ['Observed Window', `${formatTime(peer.observed_first_seen_unix)} to ${formatTime(peer.observed_until_unix)}`],
                    ['Last Attempt', formatTime(peer.last_attempt_unix)],
                    ['Backoff Until', formatTime(peer.backoff_until_unix)],
                    ['Last Relay', formatTime(peer.last_relay_unix)],
                ])}
                <h2>Endpoints</h2>
                ${endpointTable(peer.endpoints || [])}
                <h2>Diagnostics</h2>
                ${diagnosticsList(peer)}
            </section>`;
    } catch (e) {
        el.innerHTML = `<div class="error-msg">Failed to load peer detail: ${esc(e.message)}</div>`;
    }
}

async function renderZones() {
    const content = document.getElementById('content');
    try {
        const data = await fetchAPI('/zones');
        const zones = data.zones || [];
        if (zones.length === 0) {
            content.innerHTML = `<h1>Zones</h1>${emptyState('No zones known')}`;
            return;
        }
        let rows = zones.map(z => `
            <tr class="click-row ${selectedZone === z.path ? 'selected-row' : ''}" data-zone="${esc(z.path)}">
                <td>${esc(z.path)}</td>
                <td>${z.records}</td>
                <td>${z.delegations}</td>
                <td>${z.revocations}</td>
                <td>${z.revoked ? stateBadge('revoked') : stateBadge('healthy')}</td>
                <td><code title="${esc(z.root_hash || '')}">${esc(shortHash(z.root_hash))}</code></td>
            </tr>`).join('');
        content.innerHTML = `
            <h1>Zones</h1>
            <table>
                <tr><th>Path</th><th>Records</th><th>Delegations</th><th>Revocations</th><th>Status</th><th>Root Hash</th></tr>
                ${rows}
            </table>
            <h2>Global Root</h2>
            <div class="json-viewer">${esc(data.global_root || '-')}</div>
            <div id="zone-detail">${selectedZone ? '<div class="empty-state">Loading zone detail...</div>' : emptyState('Select a zone to inspect authority, records and proofs')}</div>`;
        document.querySelectorAll('[data-zone]').forEach(row => {
            row.addEventListener('click', () => {
                selectedZone = row.dataset.zone;
                renderZones();
            });
        });
        if (selectedZone) renderZoneDetail(selectedZone);
    } catch (e) {
        content.innerHTML = `<div class="error-msg">Failed to load zones: ${esc(e.message)}</div>`;
    }
}

async function renderZoneDetail(path) {
    const el = document.getElementById('zone-detail');
    if (!el) return;
    try {
        const z = await fetchAPI(`/zones/${encodeURIComponent(path)}`);
        const historyByKey = groupRecordsByKey(z.record_history || []);
        el.innerHTML = `
            <section class="detail-panel">
                <h2>${esc(z.path)}</h2>
                ${kvTable([
                    ['Parent', esc(z.parent || '-')],
                    ['Status', z.revoked ? stateBadge('revoked') : stateBadge('healthy')],
                    ['Authority Hash', `<code>${esc(z.authority_hash || '-')}</code>`],
                    ['Merkle Root', `<code>${esc(z.merkle_root || '-')}</code>`],
                    ['Counts', `${z.record_count || 0} records, ${z.history_count || 0} historical, ${z.delegation_count || 0} delegations, ${z.revocation_count || 0} revocations`],
                ])}
                <h2>Authority</h2>
                ${jsonViewer(z.authority || {})}
                <h2>Active Records</h2>
                ${recordTable(z.records || [], historyByKey)}
                <h2>Delegations</h2>
                ${compactList(z.delegations || [], d => jsonViewer(d))}
                <h2>Parent Proof</h2>
                ${compactList(z.parent_proof || [], d => jsonViewer(d))}
                <h2>Revocations</h2>
                ${compactList(z.revocations || [], r => jsonViewer(r))}
            </section>`;
    } catch (e) {
        el.innerHTML = `<div class="error-msg">Failed to load zone detail: ${esc(e.message)}</div>`;
    }
}

async function renderOverlay() {
    const content = document.getElementById('content');
    try {
        const data = await fetchAPI('/links');
        const instances = data.instances || [];
        if (instances.length === 0) {
            content.innerHTML = `<h1>Overlay</h1>${emptyState('No link instances')}</div>`;
            return;
        }
        let rows = instances.map(li => {
            const desired = desiredValue(li);
            const sa = actualSAValue(li);
            const healthState = healthStateForLink(li);
            const routing = li.routing || {};
            return `
            <tr>
                <td>${esc(li.id || '-')}</td>
                <td>${esc(li.peer_zone || '-')}</td>
                <td>${esc(li.group_id || '-')}</td>
                <td>${stateBadge(li.state || li.actual_state)}</td>
                <td>${stateBadge(healthState || 'unknown')}</td>
                <td><code>${esc(li.interface_name || desired.interface_name || '-')}</code><br><span class="muted">if_id ${esc(li.xfrm_if_id || desired.xfrm_if_id || '-')}</span></td>
                <td><code>${esc(li.endpoint || desired.endpoint || '-')}</code></td>
                <td><code>${esc(desired.peer_tunnel_addr || '-')}</code></td>
                <td>${stateBadge(sa.established ? 'established' : (sa.child_state || sa.ike_state || '-'))}</td>
                <td>${stateBadge(routing.bird_state || '-')}</td>
                <td>${esc((li.rotation && li.rotation.phase) || 'idle')}</td>
                <td>${li.failure_count || 0}</td>
            </tr>
            <tr class="subrow"><td colspan="12">${linkDetail(li)}</td></tr>`;
        }).join('');
        content.innerHTML = `
            <h1>Overlay Links</h1>
            <table>
                <tr><th>Link ID</th><th>Peer Zone</th><th>Group</th><th>State</th><th>Health</th><th>Interface</th><th>Endpoint</th><th>Peer Tunnel</th><th>SA</th><th>Routing</th><th>Rotate</th><th>Failures</th></tr>
                ${rows}
            </table>
            <h2>Reconcile</h2>
            ${kvTable([
                ['Last Run', formatTime(data.last_run_unix)],
                ['Desired Links', esc(data.desired_links || 0)],
                ['Actual SAs', esc(data.actual_sas || 0)],
                ['Last Error', `<code>${esc(data.last_error || '-')}</code>`],
            ])}
            <h2>Actions</h2>
            ${jsonViewer(data.actions || [])}
            <h2>Skipped</h2>
            ${jsonViewer(data.skipped || [])}`;
    } catch (e) {
        content.innerHTML = `<div class="error-msg">Failed to load links: ${esc(e.message)}</div>`;
    }
}

async function renderHealth() {
    const content = document.getElementById('content');
    try {
        const data = await fetchAPI('/health');
        const links = data.links || [];
        if (links.length === 0) {
            content.innerHTML = `<h1>Health</h1>${emptyState('No health data available')}`;
            return;
        }
        const seriesByID = await fetchHealthRTTSeries(data.datasource, links);
        let rows = links.map(item => {
            const h = healthValue(item);
            const desired = item.desired || {};
            const series = seriesByID[h.instance_id] || [];
            return `
            <tr>
                <td>${esc(h.instance_id || '-')}</td>
                <td>${esc(item.peer_zone || '-')}</td>
                <td>${esc(item.group_id || '-')}</td>
                <td><code>${esc(item.interface_name || desired.interface_name || '-')}</code></td>
                <td><code>${esc(item.peer_tunnel_addr || desired.peer_tunnel_addr || '-')}</code></td>
                <td>${stateBadge(h.state)}</td>
                <td>${esc(h.probe_type || '-')}</td>
                <td>${ms(h.last_rtt_ms)}</td>
                <td>${pct(h.loss_ratio_pct)}</td>
                <td>${ms(h.jitter_ms)}</td>
                <td>${sparkline(series)}</td>
                <td>${h.cutover_blocking ? 'Yes' : 'No'}</td>
                <td>${esc(h.last_error || '-')}</td>
            </tr>
            <tr class="subrow"><td colspan="13">${jsonViewer(item)}</td></tr>`;
        }).join('');
        content.innerHTML = `
            <h1>Link Health</h1>
            <table>
                <tr><th>Link ID</th><th>Peer</th><th>Group</th><th>Interface</th><th>Peer Tunnel</th><th>State</th><th>Probe</th><th>RTT</th><th>Loss</th><th>Jitter</th><th>Trend</th><th>Cutover Block</th><th>Error</th></tr>
                ${rows}
            </table>`;
    } catch (e) {
        content.innerHTML = `<div class="error-msg">Failed to load health: ${esc(e.message)}</div>`;
    }
}

async function fetchHealthRTTSeries(datasource, links) {
    if (!datasource || !datasource.configured) return {};
    const entries = await Promise.all((links || []).map(async item => {
        const h = healthValue(item);
        if (!h.instance_id) return null;
        try {
            const data = await fetchAPI(`/health/${encodeURIComponent(h.instance_id)}/series?metric=rtt&range=30m&step=1m`);
            const points = (data.series && data.series.points) || [];
            return [h.instance_id, points.map(p => Number(p.value)).filter(v => Number.isFinite(v))];
        } catch (e) {
            return [h.instance_id, []];
        }
    }));
    const out = {};
    entries.forEach(entry => {
        if (entry) out[entry[0]] = entry[1];
    });
    return out;
}

function sparkline(values) {
    if (!values || values.length === 0) return '-';
    const width = 96;
    const height = 24;
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = Math.max(1, max - min);
    const points = values.map((v, i) => {
        const x = values.length === 1 ? width : (i / (values.length - 1)) * width;
        const y = height - ((v - min) / span) * (height - 4) - 2;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    return `<svg class="sparkline" viewBox="0 0 ${width} ${height}" role="img"><polyline points="${points}"></polyline></svg>`;
}

async function renderRoutes() {
    const content = document.getElementById('content');
    try {
        const data = await fetchAPI('/routes');
        const exportSet = data.export_set || [];
        const authorized = data.authorized || {};
        const assignments = data.assignments || {};
        const errors = data.errors || [];
        let zoneRows = Object.entries(authorized).map(([zone, prefixes]) => `
            <tr><td>${esc(zone)}</td><td>${prefixes.map(p => esc(p)).join(', ')}</td></tr>`).join('');
        let assignRows = Object.entries(assignments).map(([prefix, info]) => `
            <tr><td>${esc(prefix)}</td><td>${esc(info.source || '-')}</td><td>${esc(info.assigned_to || '-')}</td></tr>`).join('');
        let errorRows = errors.map(e => `
            <tr><td>${esc(e.zone)}</td><td>${esc(e.prefix || '-')}</td><td>${esc(e.code)}</td><td>${esc(e.detail)}</td></tr>`).join('');
        content.innerHTML = `
            <h1>Route Authorization</h1>
            <h2>Local Export Set</h2>
            <div>${exportSet.map(p => `<span class="badge badge-green">${esc(p)}</span> `).join('') || emptyState('No exports')}</div>
            <h2>Authorized Prefixes by Zone</h2>
            <table><tr><th>Zone</th><th>Prefixes</th></tr>${zoneRows || emptyRow(2)}</table>
            <h2>IPAM Assignments</h2>
            <table><tr><th>Prefix</th><th>Source</th><th>Assigned To</th></tr>${assignRows || emptyRow(3)}</table>
            <h2>Authorization Errors (${errors.length})</h2>
            <table><tr><th>Zone</th><th>Prefix</th><th>Code</th><th>Detail</th></tr>${errorRows || emptyRow(4)}</table>`;
    } catch (e) {
        content.innerHTML = `<div class="error-msg">Failed to load routes: ${esc(e.message)}</div>`;
    }
}

function emptyRow(cols) {
    return `<tr><td colspan="${cols}" style="text-align:center;color:var(--text-dim);">No entries</td></tr>`;
}

async function renderBird() {
    const content = document.getElementById('content');
    try {
        const data = await fetchAPI('/bird');
        const instances = data.instances || {};
        const instanceList = Object.entries(instances);
        if (instanceList.length === 0) {
            content.innerHTML = `<h1>BIRD</h1>${emptyState('No BIRD instances configured')}`;
            return;
        }
        let rows = instanceList.map(([name, inst]) => `
            <tr>
                <td>${esc(name)}</td>
                <td>${esc(inst.netns_name || '-')}</td>
                <td>${stateBadge(inst.state)}</td>
                <td>${inst.router_id || '-'}</td>
                <td>${esc(inst.last_error || '-')}</td>
            </tr>`).join('');
        content.innerHTML = `
            <h1>BIRD Instances</h1>
            <table>
                <tr><th>Name</th><th>NetNS</th><th>State</th><th>Router ID</th><th>Last Error</th></tr>
                ${rows}
            </table>
            <div class="detail-section">
                <h3>CLI Reference</h3>
                <code>higgs debug babel</code>
            </div>`;
    } catch (e) {
        content.innerHTML = `<div class="error-msg">Failed to load BIRD: ${esc(e.message)}</div>`;
    }
}

// ===== Init =====

window.addEventListener('hashchange', handleHashChange);
window.addEventListener('load', () => {
    handleHashChange();
    connectSSE();
});
