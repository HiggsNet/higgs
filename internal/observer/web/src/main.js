// main.js — entry point: wires router, store and events together.

import * as store from './store.js';
import * as router from './router.js';
import * as events from './events.js';
import { copyToClipboard } from './format.js';

// Any store update re-renders the current page (UI state is preserved).
store.subscribe(() => router.renderCurrent());

// Delegated click-to-copy for hashes/addresses (.copyable elements).
document.addEventListener('click', ev => {
    const el = ev.target.closest('.copyable[data-copy]');
    if (el) copyToClipboard(el);
});

window.addEventListener('hashchange', () => router.handleHashChange());
window.addEventListener('load', () => {
    router.handleHashChange();
    events.connect();
});
