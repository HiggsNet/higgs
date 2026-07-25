// api.js — fetch wrapper with unified error handling.

export const API_BASE = '/api/v1';

export async function fetchAPI(endpoint) {
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
