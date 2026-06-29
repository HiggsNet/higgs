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
const foldState = new Map();

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
    rememberFoldState();
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

function foldKey(key) {
    return `${currentPage}:${key}`;
}

function foldAttr(key) {
    return key ? ` data-fold-key="${esc(foldKey(key))}"` : '';
}

function rememberFoldState(root) {
    const el = root || document.getElementById('content');
    if (!el) return;
    el.querySelectorAll('details[data-fold-key]').forEach(detail => {
        foldState.set(detail.dataset.foldKey, detail.open);
    });
}

function restoreFoldState(root) {
    const el = root || document.getElementById('content');
    if (!el) return;
    el.querySelectorAll('details[data-fold-key]').forEach(detail => {
        const key = detail.dataset.foldKey;
        if (foldState.has(key)) detail.open = foldState.get(key);
    });
}

function foldedSection(summary, body, className, key) {
    return `
        <details class="${esc(className || 'record-details')}"${foldAttr(key)}>
            <summary>${summary}</summary>
            ${body}
        </details>`;
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

function recordDetails(record, history, zonePath) {
    const endpointTableHTML = endpointValueTable(record);
    return `
        <details class="record-details"${foldAttr(`zone:${zonePath || ''}:record:${record.key || ''}`)}>
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

function recordTable(records, historyByKey, zonePath) {
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
                <tr class="subrow"><td colspan="6">${recordDetails(r, history, zonePath)}</td></tr>`;
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
    const n = Number(v);
    if (!Number.isFinite(n)) return `${esc(v)}ms`;
    return `${n % 1 === 0 ? n : n.toFixed(1)}ms`;
}

function linkDetail(link) {
    const desired = desiredValue(link);
    const sa = actualSAValue(link);
    const health = healthValue(link.health);
    const routing = link.routing || {};
    const rotation = link.rotation || {};
    const takeover = link.takeover || {};
    return `
        <details class="record-details"${foldAttr(`link:${link.id || link.instance_id || ''}`)}>
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

function actionTable(actions) {
    if (!actions || actions.length === 0) return emptyState('No actions');
    return `
        <table class="mini-table">
            <tr><th>Action</th><th>Link ID</th><th>Peer</th><th>Group</th><th>Reason</th></tr>
            ${actions.map(a => `
                <tr>
                    <td>${stateBadge(a.action || '-')}</td>
                    <td><code>${esc(a.instance_id || '-')}</code></td>
                    <td>${esc(a.peer_zone || '-')}</td>
                    <td>${esc(a.group_id || '-')}</td>
                    <td>${esc(a.reason || '-')}</td>
                </tr>`).join('')}
        </table>`;
}

function skippedTable(skipped) {
    if (!skipped || skipped.length === 0) return emptyState('No skipped items');
    return `
        <table class="mini-table">
            <tr><th>Group</th><th>Peer</th><th>Reason</th><th>Detail</th></tr>
            ${skipped.map(s => `
                <tr>
                    <td>${esc(s.group_id || '-')}</td>
                    <td>${esc(s.peer || '-')}</td>
                    <td>${stateBadge(s.reason || '-')}</td>
                    <td>${esc(s.detail || '-')}</td>
                </tr>`).join('')}
        </table>`;
}

function healthDetail(item, datasource) {
    const h = healthValue(item) || {};
    const desired = item.desired || {};
    const history = datasource && datasource.configured
        ? healthHistoryPanel(h.instance_id)
        : `<div class="muted">No local health history datasource configured.</div>`;
    return foldedSection(
        `Health diagnostics · ${esc(h.instance_id || '-')}${h.probe_role ? ` · ${esc(h.probe_role)}` : ''}`,
        `<div class="detail-grid">
            <section>
                <h3>Probe</h3>
                ${kvTable([
                    ['Probe ID', `<code>${esc(h.probe_id || h.instance_id || '-')}</code>`],
                    ['Role', esc(h.probe_role || 'active')],
                    ['State', stateBadge(h.state)],
                    ['Probe', esc(h.probe_type || '-')],
                    ['Samples', `${h.sent || 0} sent, ${h.received || 0} received, ${h.lost || 0} lost`],
                    ['Loss', pct(h.loss_ratio_pct)],
                    ['Consecutive Failures', esc(h.consecutive_fail || 0)],
                    ['Cutover Blocking', h.cutover_blocking ? 'Yes' : 'No'],
                    ['Next Probe', formatTime(h.next_probe_unix)],
                    ['Last Error', `<code>${esc(h.last_error || '-')}</code>`],
                ])}
            </section>
            <section>
                <h3>Latency</h3>
                ${kvTable([
                    ['Last RTT', ms(h.last_rtt_ms)],
                    ['EWMA RTT', ms(h.ewma_rtt_ms)],
                    ['P50 RTT', ms(h.p50_rtt_ms)],
                    ['P95 RTT', ms(h.p95_rtt_ms)],
                    ['P99 RTT', ms(h.p99_rtt_ms)],
                    ['Jitter', ms(h.jitter_ms)],
                ])}
            </section>
            <section>
                <h3>Link</h3>
                ${kvTable([
                    ['Peer', esc(item.peer_zone || '-')],
                    ['Group', esc(item.group_id || '-')],
                    ['Interface', `<code>${esc(h.interface_name || item.interface_name || desired.interface_name || '-')}</code>`],
                    ['Local Tunnel', `<code>${esc(item.local_tunnel_addr || desired.local_tunnel_addr || '-')}</code>`],
                    ['Peer Tunnel', `<code>${esc(item.peer_tunnel_addr || desired.peer_tunnel_addr || '-')}</code>`],
                    ['Endpoint', `<code>${esc(item.endpoint || desired.endpoint || '-')}</code>`],
                ])}
            </section>
        </div>
        <section class="health-history-section">
            <h3>RTT History</h3>
            ${history}
        </section>`,
        'record-details health-details',
        `health:${h.probe_id || h.instance_id || ''}`
    );
}

function healthHistoryPanel(instanceID) {
    if (!instanceID) return `<div class="muted">No link instance selected.</div>`;
    return `
        <div class="history-panel" data-link-id="${esc(instanceID)}">
            <div class="history-toolbar" role="group" aria-label="RTT history range">
                ${healthRangeButton('5m', '5m')}
                ${healthRangeButton('30m', '30m', true)}
                ${healthRangeButton('1h', '1h')}
                ${healthRangeButton('6h', '6h')}
                ${healthRangeButton('24h', '24h')}
            </div>
            <div class="health-chart-body muted">Open this section to load RTT history.</div>
        </div>`;
}

function healthRangeButton(label, range, active) {
    return `<button type="button" class="btn range-btn${active ? ' active' : ''}" data-health-range="${esc(range)}">${esc(label)}</button>`;
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
                ${recordTable(z.records || [], historyByKey, z.path || path)}
                <h2>Delegations</h2>
                ${compactList(z.delegations || [], d => jsonViewer(d))}
                <h2>Parent Proof</h2>
                ${compactList(z.parent_proof || [], d => jsonViewer(d))}
                <h2>Revocations</h2>
                ${compactList(z.revocations || [], r => jsonViewer(r))}
            </section>`;
        restoreFoldState(el);
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
            ${foldedSection(`Actions (${(data.actions || []).length})`, actionTable(data.actions || []), 'record-details reconcile-details', 'reconcile:actions')}
            ${foldedSection(`Skipped (${(data.skipped || []).length})`, skippedTable(data.skipped || []), 'record-details reconcile-details', 'reconcile:skipped')}`;
        restoreFoldState(content);
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
                <td><code>${esc(h.interface_name || item.interface_name || desired.interface_name || '-')}</code></td>
                <td><code>${esc(item.peer_tunnel_addr || desired.peer_tunnel_addr || '-')}</code></td>
                <td>${stateBadge(h.state)}</td>
                <td>${esc(h.probe_role || 'active')} / ${esc(h.probe_type || '-')}</td>
                <td>${ms(h.last_rtt_ms)}</td>
                <td>${pct(h.loss_ratio_pct)}</td>
                <td>${ms(h.jitter_ms)}</td>
                <td>${sparkline(series)}</td>
                <td>${h.cutover_blocking ? 'Yes' : 'No'}</td>
                <td>${esc(h.last_error || '-')}</td>
            </tr>
            <tr class="subrow"><td colspan="13">${healthDetail(item, data.datasource)}</td></tr>`;
        }).join('');
        content.innerHTML = `
            <h1>Link Health</h1>
            <table>
                <tr><th>Link ID</th><th>Peer</th><th>Group</th><th>Interface</th><th>Peer Tunnel</th><th>State</th><th>Probe</th><th>RTT</th><th>Loss</th><th>Jitter</th><th>Trend</th><th>Cutover Block</th><th>Error</th></tr>
                ${rows}
            </table>`;
        restoreFoldState(content);
        bindHealthHistory(content, data.datasource);
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

function bindHealthHistory(root, datasource) {
    if (!datasource || !datasource.configured) return;
    root.querySelectorAll('details.health-details').forEach(detail => {
        if (!detail.querySelector('.history-panel')) return;
        detail.addEventListener('toggle', () => {
            if (detail.open) loadHealthHistory(detail);
        });
        if (detail.open) loadHealthHistory(detail);
    });
    root.querySelectorAll('[data-health-range]').forEach(button => {
        button.addEventListener('click', () => {
            const detail = button.closest('details.health-details');
            if (!detail) return;
            detail.querySelectorAll('[data-health-range]').forEach(btn => btn.classList.toggle('active', btn === button));
            loadHealthHistory(detail, button.dataset.healthRange);
        });
    });
}

async function loadHealthHistory(detail, range) {
    const panel = detail.querySelector('.history-panel');
    const body = detail.querySelector('.health-chart-body');
    if (!panel || !body) return;
    const linkID = panel.dataset.linkId || '';
    const selectedRange = range || selectedHealthRange(detail);
    const step = healthRangeStep(selectedRange);
    const requestKey = `${linkID}:${selectedRange}:${step}`;
    if (body.dataset.loadedKey === requestKey || body.dataset.loadingKey === requestKey) return;
    body.dataset.loadingKey = requestKey;
    body.classList.add('muted');
    body.textContent = 'Loading RTT history...';
    try {
        const data = await fetchAPI(`/health/${encodeURIComponent(linkID)}/series?metric=rtt&range=${encodeURIComponent(selectedRange)}&step=${encodeURIComponent(step)}`);
        const series = data.series || {};
        body.classList.remove('muted');
        body.innerHTML = healthChart(series, series.range || selectedRange, series.step || step);
        body.dataset.loadedKey = requestKey;
    } catch (e) {
        delete body.dataset.loadedKey;
        body.classList.add('muted');
        body.textContent = `RTT history unavailable: ${e.message}`;
    } finally {
        delete body.dataset.loadingKey;
    }
}

function selectedHealthRange(detail) {
    const active = detail.querySelector('[data-health-range].active');
    return active ? active.dataset.healthRange : '30m';
}

function healthRangeStep(range) {
    switch (range) {
        case '5m': return '10s';
        case '30m': return '1m';
        case '1h': return '2m';
        case '6h': return '10m';
        case '24h': return '30m';
        default: return '1m';
    }
}

function healthChart(series, range, step) {
    const lines = healthChartLines(series);
    const all = lines.flatMap(line => line.points);
    if (all.length === 0) {
        return `<div class="empty-state compact">No RTT samples for ${esc(range)}.</div>`;
    }
    const width = 720;
    const height = 220;
    const pad = {top: 18, right: 20, bottom: 34, left: 54};
    const xs = all.map(p => p.ts);
    const ys = all.map(p => p.value);
    const minX = Math.min(...xs);
    const maxX = Math.max(...xs);
    const minY = Math.min(0, Math.min(...ys));
    const maxY = Math.max(...ys);
    const xSpan = Math.max(1, maxX - minX);
    const ySpan = Math.max(1, maxY - minY);
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;
    const x = ts => pad.left + ((ts - minX) / xSpan) * plotW;
    const y = value => pad.top + plotH - ((value - minY) / ySpan) * plotH;
    const pathFor = points => points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${x(p.ts).toFixed(1)} ${y(p.value).toFixed(1)}`).join(' ');
    const latest = all.reduce((max, point) => !max || point.ts > max.ts ? point : max, null);
    const avg = ys.reduce((sum, value) => sum + value, 0) / ys.length;
    const yTicks = [minY, minY + ySpan / 2, maxY];
    const start = new Date(minX).toLocaleTimeString();
    const end = new Date(maxX).toLocaleTimeString();
    return `
        <div class="chart-meta">
            <span>Latest ${ms(latest.value)}</span>
            <span>Avg ${ms(avg)}</span>
            <span>Max ${ms(maxY)}</span>
            <span>${esc(range)} · ${esc(step)}</span>
        </div>
        <div class="chart-legend">
            ${lines.map((line, i) => `<span><i class="legend-swatch line-${i % 4}"></i>${esc(line.label)}</span>`).join('')}
        </div>
        <svg class="history-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="RTT history chart">
            ${yTicks.map(tick => `
                <line class="chart-grid" x1="${pad.left}" y1="${y(tick).toFixed(1)}" x2="${width - pad.right}" y2="${y(tick).toFixed(1)}"></line>
                <text class="chart-label" x="${pad.left - 8}" y="${(y(tick) + 4).toFixed(1)}" text-anchor="end">${esc(ms(tick))}</text>`).join('')}
            <line class="chart-axis" x1="${pad.left}" y1="${height - pad.bottom}" x2="${width - pad.right}" y2="${height - pad.bottom}"></line>
            <line class="chart-axis" x1="${pad.left}" y1="${pad.top}" x2="${pad.left}" y2="${height - pad.bottom}"></line>
            ${lines.map((line, i) => `
                <path class="history-line line-${i % 4}" d="${pathFor(line.points)}"></path>
                ${line.points.map(p => `<circle class="history-point line-${i % 4}" cx="${x(p.ts).toFixed(1)}" cy="${y(p.value).toFixed(1)}" r="2.6"></circle>`).join('')}
            `).join('')}
            <text class="chart-label" x="${pad.left}" y="${height - 10}" text-anchor="start">${esc(start)}</text>
            <text class="chart-label" x="${width - pad.right}" y="${height - 10}" text-anchor="end">${esc(end)}</text>
        </svg>`;
}

function healthChartLines(series) {
    const rawLines = (series && Array.isArray(series.lines) && series.lines.length > 0)
        ? series.lines
        : [{probe_role: 'active', points: (series && series.points) || []}];
    return rawLines.map(line => {
        const points = (line.points || [])
            .map(p => ({ts: Number(p.unix_ms), value: Number(p.value)}))
            .filter(p => Number.isFinite(p.ts) && Number.isFinite(p.value));
        return {
            label: line.probe_role || line.probe_id || 'active',
            points,
        };
    }).filter(line => line.points.length > 0);
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
