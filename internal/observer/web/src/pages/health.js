// health.js — data plane: probes, RTT/loss/jitter, history charts.
// Sparklines lazy-load on visibility; detail charts load per range. No N× amplification.

import * as store from '../store.js';
import { fetchAPI } from '../api.js';
import { navigate } from '../router.js';
import { esc, ms, pct, relTime } from '../format.js';
import { pageHeader, filterInput, entityCard, entityField, emptyState, loading, errorMsg } from '../components/card.js';
import { kvTable } from '../components/kv.js';
import { stateBadge, dot } from '../components/badge.js';
import { sparkline, healthChart } from '../components/chart.js';

export const deps = ['/health'];

const RANGES = ['5m', '30m', '1h', '6h', '24h'];
const RANGE_STEPS = { '5m': '10s', '30m': '1m', '1h': '2m', '6h': '10m', '24h': '30m' };

// Sparkline series cache, invalidated when /health refetches.
const sparkCache = new Map(); // instanceID -> {stamp, values}

function healthValue(item) { return item ? (item.health || item) : null; }

function severityOf(h) {
    if (!h) return '';
    if (h.state === 'down') return 'err';
    if (h.state && h.state !== 'healthy') return 'warn';
    return h.cutover_blocking ? 'warn' : '';
}

function historyPanel(instanceID) {
    if (!instanceID) return '<div class="muted">No link instance selected.</div>';
    const buttons = RANGES.map(r =>
        `<button type="button" class="btn range-btn${r === '30m' ? ' active' : ''}" data-health-range="${r}">${r}</button>`).join('');
    return `<div class="history-panel" data-link-id="${esc(instanceID)}">
        <div class="history-toolbar" role="group" aria-label="RTT history range">${buttons}</div>
        <div class="health-chart-body muted">Open this section to load RTT history.</div>
    </div>`;
}

function healthDetail(item, datasource) {
    const h = healthValue(item) || {};
    const desired = item.desired || {};
    const history = datasource && datasource.configured
        ? historyPanel(h.instance_id)
        : '<div class="muted">No local health history datasource configured.</div>';
    const probe = kvTable([
        ['Probe ID', `<code>${esc(h.probe_id || h.instance_id || '-')}</code>`],
        ['Role', esc(h.probe_role || 'active')],
        ['State', stateBadge(h.state)],
        ['Probe', esc(h.probe_type || '-')],
        ['Samples', esc(`${h.sent || 0} sent · ${h.received || 0} received · ${h.lost || 0} lost`)],
        ['Loss', pct(h.loss_ratio_pct)],
        ['Consecutive Failures', esc(h.consecutive_fail || 0)],
        ['Cutover Blocking', h.cutover_blocking ? 'Yes' : 'No'],
        ['Next Probe', relTime(h.next_probe_unix)],
        ['Last Error', `<code>${esc(h.last_error || '-')}</code>`],
    ]);
    const latency = kvTable([
        ['Last RTT', ms(h.last_rtt_ms)], ['EWMA RTT', ms(h.ewma_rtt_ms)],
        ['P50 RTT', ms(h.p50_rtt_ms)], ['P95 RTT', ms(h.p95_rtt_ms)],
        ['P99 RTT', ms(h.p99_rtt_ms)], ['Jitter', ms(h.jitter_ms)],
    ]);
    const link = kvTable([
        ['Peer', esc(item.peer_zone || '-')],
        ['Group', esc(item.group_id || '-')],
        ['Interface', `<code>${esc(h.interface_name || item.interface_name || desired.interface_name || '-')}</code>`],
        ['Local Tunnel', `<code>${esc(item.local_tunnel_addr || desired.local_tunnel_addr || '-')}</code>`],
        ['Peer Tunnel', `<code>${esc(item.peer_tunnel_addr || desired.peer_tunnel_addr || '-')}</code>`],
        ['Endpoint', `<code>${esc(item.endpoint || desired.endpoint || '-')}</code>`],
    ]);
    return `<details class="record-details health-details">
        <summary>Health diagnostics · ${esc(h.instance_id || '-')}${h.probe_role ? ` · ${esc(h.probe_role)}` : ''}</summary>
        <div class="detail-grid">
            <section><h3>Probe</h3>${probe}</section>
            <section><h3>Latency</h3>${latency}</section>
            <section><h3>Link</h3>${link}</section>
        </div>
        <section class="health-history-section"><h3>RTT History</h3>${history}</section>
    </details>`;
}

function linkCard(item, datasource) {
    const h = healthValue(item) || {};
    return entityCard({
        title: h.instance_id || '-',
        dot: dot(h.state || 'unknown'),
        subtitle: `${esc(item.peer_zone || '-')} · ${esc(item.group_id || '-')}`,
        severity: severityOf(h),
        fields: [
            entityField('State', stateBadge(h.state)),
            entityField('RTT', ms(h.last_rtt_ms)),
            entityField('Loss', pct(h.loss_ratio_pct)),
            entityField('Jitter', ms(h.jitter_ms)),
            entityField('Trend', `<span class="sparkline-slot" data-instance="${esc(h.instance_id || '')}"><span class="muted">…</span></span>`),
            entityField('Cutover Block', h.cutover_blocking ? 'Yes' : 'No'),
        ],
        details: healthDetail(item, datasource),
        wide: true,
    });
}

// Lazy sparklines: fetch a 30m series only when the card scrolls into
// view, and only when /health data is newer than the cached series.
function setupSparklines(root, stamp) {
    const load = async slot => {
        const id = slot.dataset.instance;
        if (!id) { slot.innerHTML = '<span class="muted">-</span>'; return; }
        const cached = sparkCache.get(id);
        if (cached && cached.stamp === stamp) { slot.innerHTML = sparkline(cached.values); return; }
        try {
            const data = await fetchAPI(`/health/${encodeURIComponent(id)}/series?metric=rtt&range=30m&step=1m`);
            const points = (data.series && data.series.points) || [];
            const values = points.map(p => Number(p.value)).filter(v => Number.isFinite(v));
            sparkCache.set(id, { stamp, values });
            if (slot.isConnected) slot.innerHTML = sparkline(values);
        } catch {
            sparkCache.set(id, { stamp, values: [] });
            if (slot.isConnected) slot.innerHTML = '<span class="muted">-</span>';
        }
    };
    const slots = root.querySelectorAll('.sparkline-slot[data-instance]');
    if (!('IntersectionObserver' in window)) { slots.forEach(load); return; }
    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) { observer.unobserve(entry.target); load(entry.target); }
        });
    }, { root: document.getElementById('content') });
    slots.forEach(slot => observer.observe(slot));
}

async function loadHistory(detail, range) {
    const panel = detail.querySelector('.history-panel');
    const body = detail.querySelector('.health-chart-body');
    if (!panel || !body) return;
    const linkID = panel.dataset.linkId || '';
    const step = RANGE_STEPS[range] || '1m';
    const key = `${linkID}:${range}`;
    if (body.dataset.loadedKey === key || body.dataset.loadingKey === key) return;
    body.dataset.loadingKey = key;
    body.classList.add('muted');
    body.textContent = 'Loading RTT history…';
    try {
        const data = await fetchAPI(`/health/${encodeURIComponent(linkID)}/series?metric=rtt&range=${range}&step=${step}`);
        const series = data.series || {};
        body.classList.remove('muted');
        body.innerHTML = healthChart(series, series.range || range, series.step || step);
        body.dataset.loadedKey = key;
    } catch (e) {
        body.classList.add('muted');
        body.textContent = `RTT history unavailable: ${e.message}`;
    } finally {
        delete body.dataset.loadingKey;
    }
}

function bindHistory(root, datasource) {
    if (!datasource || !datasource.configured) return;
    const loadActive = detail => {
        const active = detail.querySelector('[data-health-range].active');
        loadHistory(detail, active ? active.dataset.healthRange : '30m');
    };
    root.querySelectorAll('details.health-details').forEach(detail => {
        if (!detail.querySelector('.history-panel')) return;
        detail.addEventListener('toggle', () => { if (detail.open) loadActive(detail); });
        if (detail.open) loadActive(detail);
    });
    root.querySelectorAll('[data-health-range]').forEach(button => {
        button.addEventListener('click', () => {
            const detail = button.closest('details.health-details');
            if (!detail) return;
            detail.querySelectorAll('[data-health-range]').forEach(b => b.classList.toggle('active', b === button));
            loadHistory(detail, button.dataset.healthRange);
        });
    });
}

export function render(container, route) {
    const header = pageHeader('Health · Data Plane', 'Probe state, latency and loss', filterInput(route, 'Filter links…'));
    const entry = store.get('/health');
    if (!entry) { container.innerHTML = header + loading(); return; }
    if (entry.error && !entry.data) { container.innerHTML = header + errorMsg(`Failed to load health: ${entry.error.message}`); return; }
    const data = entry.data || {};
    const filter = (route.filter || '').toLowerCase();
    const rank = item => {
        const sev = severityOf(healthValue(item) || {});
        return sev === 'err' ? 0 : sev === 'warn' ? 1 : 2;
    };
    const links = (data.links || [])
        .filter(item => {
            const h = healthValue(item) || {};
            return !filter
                || (h.instance_id || '').toLowerCase().includes(filter)
                || (item.peer_zone || '').toLowerCase().includes(filter)
                || (item.group_id || '').toLowerCase().includes(filter);
        })
        .slice()
        .sort((a, b) => rank(a) - rank(b));
    container.innerHTML = `
        ${header}
        <div class="entity-list">${links.map(item => linkCard(item, data.datasource)).join('') || emptyState('No health data available')}</div>`;
    container.querySelector('#page-filter').addEventListener('input', ev => {
        navigate(route.page, route.selected, ev.target.value);
    });
    setupSparklines(container, entry.updatedAt || 0);
    bindHistory(container, data.datasource);
}
