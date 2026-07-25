// events.js — SSE connection, event → endpoint invalidation mapping,
// and fallback polling of the current page's watched keys only.

import { API_BASE } from './api.js';
import * as store from './store.js';

// Event type → endpoints invalidated by that event.
const INVALIDATE = {
    state_changed: ['/status', '/zones', '/peers', '/links', '/health'],
    peer_updated: ['/peers', '/status'],
    link_updated: ['/links', '/status'],
    health_updated: ['/health'],
    route_changed: ['/routes'],
    bird_updated: ['/bird', '/status'],
};

const POLL_INTERVAL_MS = 5000;
const RECONNECT_MS = 10000;

let eventSource = null;
let pollTimer = null;
let mode = 'disconnected';

export function connect() {
    close();
    try {
        eventSource = new EventSource(`${API_BASE}/events`);
        eventSource.addEventListener('connected', () => setMode('live'));
        for (const [type, keys] of Object.entries(INVALIDATE)) {
            eventSource.addEventListener(type, () => store.invalidate(keys));
        }
        eventSource.onerror = () => {
            close();
            setMode('polling');
            setTimeout(() => {
                if (mode === 'polling') connect();
            }, RECONNECT_MS);
        };
    } catch {
        setMode('polling');
    }
}

export function connectionMode() {
    return mode;
}

function close() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
}

function setMode(next) {
    mode = next;
    renderStatus();
    if (next === 'live') {
        stopPolling();
    } else if (next === 'polling') {
        startPolling();
    }
}

function renderStatus() {
    const el = document.getElementById('connection-status');
    if (!el) return;
    const states = {
        live: { label: 'Live', tone: 'ok' },
        polling: { label: 'Polling', tone: 'warn' },
        disconnected: { label: 'Disconnected', tone: 'err' },
    };
    const state = states[mode] || states.disconnected;
    el.className = `conn conn-${mode}`;
    el.innerHTML = `<span class="dot dot-${state.tone}"></span><span class="conn-label">${state.label}</span>`;
}

function startPolling() {
    if (pollTimer) return;
    // Fallback polling only refetches the current page's watched keys.
    pollTimer = setInterval(() => store.refreshWatched(), POLL_INTERVAL_MS);
}

function stopPolling() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}
