'use strict';
// Target list with O(1) dedupe, debounced atomic persistence and import/export.
const store = require('./store');

const MAX = 500000;
let targets = store.load('targets.json', []);
let urlIndex = new Set(targets.map(t => t.url));

function normalize(url) {
    let s = String(url || '').trim();
    if (!s) return null;
    if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
    try {
        const u = new URL(s);
        if (!u.hostname) return null;
        return {
            host: u.hostname,
            port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80),
            ssl: u.protocol === 'https:',
            url: u.protocol + '//' + u.host,
        };
    } catch (e) { return null; }
}

let seq = 0;
function add(list) {
    const added = [];
    for (const raw of list || []) {
        if (targets.length >= MAX) break;
        const t = normalize(raw);
        if (!t || urlIndex.has(t.url)) continue;
        urlIndex.add(t.url);
        targets.push({ id: Date.now().toString(36) + '_' + (seq++).toString(36), ...t, added: new Date().toISOString() });
        added.push(t.url);
    }
    if (added.length) save();
    return added;
}

function remove(id) {
    const before = targets.length;
    targets = targets.filter(t => t.id !== id);
    if (targets.length !== before) { urlIndex = new Set(targets.map(t => t.url)); save(); }
}

function removeUrls(list) {
    const rm = new Set((list || []).map(u => normalize(u)).filter(Boolean).map(t => t.url));
    if (!rm.size) return 0;
    const before = targets.length;
    targets = targets.filter(t => !rm.has(t.url));
    urlIndex = new Set(targets.map(t => t.url));
    const n = before - targets.length;
    if (n) save();
    return n;
}

function clear() { targets = []; urlIndex = new Set(); save(); }

function all() { return targets; }
function urls() { return targets.map(t => t.url); }
function count() { return targets.length; }
function lines() { return targets.map(t => t.url.replace(/^https?:\/\//, '')); }

function save() { store.saveSoon('targets.json', targets, 500); }
function saveNow() { store.save('targets.json', targets); }

module.exports = { add, remove, removeUrls, clear, all, urls, lines, count, normalize, saveNow, MAX };
