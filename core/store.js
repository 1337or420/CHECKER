'use strict';
// Simple JSON storage (results, settings, targets, found creds, geo cache)
// Atomic writes (tmp + rename) and debounced persistence so heavy task loops
// never block on disk I/O.
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function file(name) { return path.join(DATA_DIR, name); }

function load(name, fallback) {
    try {
        return JSON.parse(fs.readFileSync(file(name), 'utf8'));
    } catch (e) {
        return fallback;
    }
}

function writeAtomic(name, text) {
    const target = file(name);
    const tmp = target + '.' + process.pid + '.tmp';
    try {
        fs.writeFileSync(tmp, text);
        fs.renameSync(tmp, target);
        return true;
    } catch (e) {
        try { fs.unlinkSync(tmp); } catch (_) { /* ignore */ }
        try { fs.writeFileSync(target, text); return true; } catch (_) { return false; }
    }
}

function save(name, data, pretty) {
    try {
        return writeAtomic(name, JSON.stringify(data, null, pretty === false ? 0 : 2));
    } catch (e) {
        return false;
    }
}

// ---- debounced saver: coalesces bursts (e.g. one save per found cred) ----
const pending = new Map();
let timer = null;

function saveSoon(name, data, delay = 800) {
    pending.set(name, { data, delay });
    if (timer) return;
    const tick = () => {
        timer = null;
        const now = Date.now();
        let next = Infinity;
        for (const [n, item] of pending) {
            if (item.at === undefined) item.at = now + item.delay;
            if (item.at <= now) {
                pending.delete(n);
                save(n, item.data);
            } else {
                next = Math.min(next, item.at);
            }
        }
        if (pending.size) timer = setTimeout(tick, Math.max(50, next - now));
    };
    timer = setTimeout(tick, Math.min(delay, 300));
}

function flush() {
    if (timer) { clearTimeout(timer); timer = null; }
    for (const [n, item] of pending) save(n, item.data);
    pending.clear();
}

// ---- append-only text sink (plain credential export) ----
function append(name, line) {
    try { fs.appendFileSync(file(name), line + '\r\n'); return true; } catch (e) { return false; }
}

function readText(name) {
    try { return fs.readFileSync(file(name), 'utf8'); } catch (e) { return ''; }
}

function remove(name) {
    try { if (fs.existsSync(file(name))) fs.unlinkSync(file(name)); return true; } catch (e) { return false; }
}

module.exports = { DATA_DIR, file, load, save, saveSoon, flush, append, readText, remove, writeAtomic };
