// store.js — per-endpoint cache with invalidation and subscriptions.
//
// The store keeps Map<endpoint, {data, error, updatedAt}>. Pages declare
// the endpoints they depend on ("watched keys"); SSE invalidations and
// fallback polling only refetch watched keys.

import { fetchAPI } from './api.js';

const cache = new Map();
const inflight = new Map();
const listeners = new Set();
let watchedKeys = [];

export function setWatched(keys) {
    watchedKeys = Array.isArray(keys) ? keys.slice() : [];
}

export function watched() {
    return watchedKeys.slice();
}

export function subscribe(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
}

function notify(key) {
    for (const fn of listeners) fn(key);
}

export function get(key) {
    return cache.get(key);
}

// fetch deduplicates concurrent requests for the same endpoint.
export function fetch(key) {
    if (inflight.has(key)) return inflight.get(key);
    const p = (async () => {
        try {
            const data = await fetchAPI(key);
            cache.set(key, { data, error: null, updatedAt: Date.now() });
        } catch (error) {
            const prev = cache.get(key);
            cache.set(key, { data: prev ? prev.data : null, error, updatedAt: Date.now() });
        } finally {
            inflight.delete(key);
        }
        notify(key);
    })();
    inflight.set(key, p);
    return p;
}

// invalidate drops cached entries; watched keys are refetched immediately.
export function invalidate(keys) {
    for (const key of keys) {
        cache.delete(key);
        if (watchedKeys.includes(key)) {
            fetch(key);
        }
    }
}

export function refreshWatched() {
    return Promise.all(watchedKeys.map(fetch));
}
