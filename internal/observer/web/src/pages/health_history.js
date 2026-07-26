// health_history.js — RTT history panel for the Health page: range
// selector (5m/30m/1h/6h/24h) with on-demand series loading.

import { fetchAPI } from '../api.js';
import { esc } from '../format.js';
import { healthChart } from '../components/chart.js';

const RANGES = ['5m', '30m', '1h', '6h', '24h'];
const RANGE_STEPS = { '5m': '10s', '30m': '1m', '1h': '2m', '6h': '10m', '24h': '30m' };

export function historyPanel(instanceID) {
    if (!instanceID) return '<div class="muted">No link instance selected.</div>';
    const buttons = RANGES.map(r =>
        `<button type="button" class="btn range-btn${r === '30m' ? ' active' : ''}" data-health-range="${r}">${r}</button>`).join('');
    return `<div class="history-panel" data-link-id="${esc(instanceID)}">
        <div class="history-toolbar" role="group" aria-label="RTT history range">${buttons}</div>
        <div class="health-chart-body muted">Loading RTT history…</div>
    </div>`;
}

async function loadHistory(panel, range) {
    const body = panel.querySelector('.health-chart-body');
    if (!body) return;
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

export function bindHistory(root, datasource) {
    if (!datasource || !datasource.configured) return;
    const loadActive = panel => {
        const active = panel.querySelector('[data-health-range].active');
        loadHistory(panel, active ? active.dataset.healthRange : '30m');
    };
    root.querySelectorAll('.history-panel').forEach(loadActive);
    root.querySelectorAll('[data-health-range]').forEach(button => {
        button.addEventListener('click', () => {
            const panel = button.closest('.history-panel');
            if (!panel) return;
            panel.querySelectorAll('[data-health-range]').forEach(b => b.classList.toggle('active', b === button));
            loadHistory(panel, button.dataset.healthRange);
        });
    });
}
