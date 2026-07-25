// card.js — page header, stat cards, entity cards and state blocks.
// Options-object values like sub/subtitle/details are pre-rendered HTML;
// plain-text inputs are escaped here.

import { esc } from '../format.js';

export function pageHeader(title, blurb, actions = '') {
    return `<header class="page-header">
        <div><h1>${esc(title)}</h1>${blurb ? `<p class="page-blurb">${esc(blurb)}</p>` : ''}</div>
        ${actions ? `<div class="page-actions">${actions}</div>` : ''}
    </header>`;
}

export function filterInput(route, placeholder) {
    return `<input type="text" id="page-filter" class="filter-input"
        placeholder="${esc(placeholder || 'Filter…')}" value="${esc(route.filter || '')}">`;
}

export function statCard(label, value, sub = '') {
    return `<div class="stat-card">
        <div class="stat-value">${esc(value)}</div>
        <div class="stat-label">${esc(label)}</div>
        ${sub ? `<div class="stat-sub">${sub}</div>` : ''}
    </div>`;
}

export function entityField(label, value) {
    return `<div class="entity-field">
        <div class="entity-field-label">${esc(label)}</div>
        <div class="entity-field-value">${value}</div>
    </div>`;
}

export function entityCard(opts) {
    const cls = ['entity-card'];
    if (opts.clickable) cls.push('clickable');
    if (opts.selected) cls.push('selected');
    if (opts.severity) cls.push(`sev-${opts.severity}`);
    const dataAttr = opts.dataKey ? ` data-${opts.dataAttr || 'key'}="${esc(opts.dataKey)}"` : '';
    return `
        <div class="${cls.join(' ')}"${dataAttr}>
            <div class="entity-header">
                ${opts.dot || ''}
                <span class="entity-title">${esc(opts.title || '')}</span>
                ${opts.subtitle ? `<span class="entity-subtitle">${opts.subtitle}</span>` : ''}
            </div>
            <div class="entity-meta${opts.wide ? ' wide' : ''}">${(opts.fields || []).join('')}</div>
            ${opts.details || ''}
        </div>`;
}

export function emptyState(msg) {
    return `<div class="empty-state">${esc(msg || 'No data available')}</div>`;
}

export function loading(msg) {
    return `<div class="loading">${esc(msg || 'Loading…')}</div>`;
}

export function errorMsg(msg) {
    return `<div class="error-msg">${esc(msg)}</div>`;
}

export function banner(text, tone) {
    return `<div class="banner banner-${tone}"><span class="dot dot-${tone}"></span><span>${esc(text)}</span></div>`;
}
