'use strict';
// Combo line parsing.
//   ip:port:login:pass   -> target + cred
//   ip:login:pass        -> target (443) + cred
//   login:pass           -> global cred
//   ip:port / host       -> plain target
//   https://host:port    -> plain target
//   host:port:login:pass:text:with:colons  -> pass keeps trailing colons
const { isIp } = require('./http');

function looksLikePort(s) { return /^\d{1,5}$/.test(s) && +s >= 1 && +s <= 65535; }

function looksLikeHost(s) {
    const v = String(s || '').trim();
    if (!v) return false;
    if (isIp(v)) return true;
    if (!/^[a-z0-9_.\-\[\]:]+$/i.test(v)) return false;
    return v.includes('.') || v.includes(':') || /^[a-z0-9-]+$/i.test(v);
}

function parseUrl(raw) {
    const s = String(raw || '').trim().replace(/\/+$/, '');
    if (!s) return null;
    try {
        const u = new URL(/^https?:\/\//i.test(s) ? s : 'https://' + s);
        if (!u.hostname) return null;
        return u;
    } catch (e) { return null; }
}

function normUrl(u) {
    return (u.protocol === 'http:' ? 'http://' : 'https://') + u.host;
}

// Returns { url?, user?, pass? }
function parseEntryLine(line) {
    const raw = String(line || '').trim();
    if (!raw) return null;

    const url = parseUrl(raw);
    if (url && /^https?:\/\//i.test(raw)) return { url: normUrl(url) };

    const p = raw.split(':');
    if (!p[0].trim()) return null;

    // host:port[:user:pass]
    if (p.length >= 2 && looksLikePort(p[1]) && looksLikeHost(p[0])) {
        const u = parseUrl(p[0] + ':' + p[1]);
        if (!u) return null;
        if (p.length >= 4) return { url: normUrl(u), user: p[2].trim(), pass: p.slice(3).join(':') };
        return { url: normUrl(u) };
    }
    if (p.length === 1) return looksLikeHost(p[0]) ? { url: normUrl(parseUrl(p[0])) } : null;
    // user:pass (pass may contain colons)
    if (p.length >= 2) return { user: p[0].trim(), pass: p.slice(1).join(':') };
    return null;
}

// Explicit target list parser for the brute engine
function parseTargetList(input) {
    const out = [];
    const seen = new Map();
    for (const line of lines(input)) {
        const e = parseEntryLine(line);
        if (!e || !e.url) continue;
        let item = seen.get(e.url);
        if (!item) { item = { url: e.url, own: [] }; seen.set(e.url, item); out.push(item); }
        if (e.user !== undefined) item.own.push({ user: e.user, pass: e.pass });
    }
    return out;
}

function lines(text) {
    return String(text || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
}

// Build check plan: [{ url, creds: [{user, pass}] }]
function buildPlan(targetsText, credsText, fallbackUrls) {
    const plan = new Map();
    const plain = [];
    const global = [];
    const put = (url, cred) => {
        if (!url) return;
        if (!plan.has(url)) plan.set(url, []);
        if (cred) plan.get(url).push(cred);
    };
    for (const line of lines(credsText)) {
        const e = parseEntryLine(line);
        if (!e) continue;
        if (e.url && e.user !== undefined) put(e.url, { user: e.user, pass: e.pass });
        else if (e.url) put(e.url, null);
        else if (e.user !== undefined) global.push({ user: e.user, pass: e.pass });
    }
    for (const line of lines(targetsText)) {
        const e = parseEntryLine(line);
        if (!e) continue;
        if (e.url && e.user !== undefined) put(e.url, { user: e.user, pass: e.pass });
        else if (e.url) plain.push(e.url);
        else if (e.user !== undefined) global.push({ user: e.user, pass: e.pass });
    }
    const urls = new Set(plain);
    for (const k of plan.keys()) urls.add(k);
    if (!urls.size) (fallbackUrls || []).forEach(u => urls.add(String(u)));

    const out = [];
    for (const url of urls) {
        let creds = plan.has(url) ? plan.get(url).slice() : [];
        if (!creds.length && global.length) creds = global.map(g => ({ user: g.user, pass: g.pass }));
        if (!creds.length) creds = [{ user: '', pass: '' }];
        out.push({ url, creds });
    }
    return out;
}

module.exports = { parseEntryLine, parseTargetList, buildPlan, lines, looksLikePort, looksLikeHost, parseUrl, normUrl };
