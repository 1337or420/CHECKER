'use strict';
// GeoIP lookups with caches, multiple free providers and bounded concurrency.
// Used for country exclusion during scanning and for the Geo panel.
const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const store = require('./store');
const { isIp, limiter } = require('./http');

const cache = store.load('geo.json', {});
let dirty = false;
let saveTimer = null;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const pool = limiter(6);

const PRIVATE = [
    [/^10\./, 'private'], [/^192\.168\./, 'private'],
    [/^172\.(1[6-9]|2\d|3[01])\./, 'private'],
    [/^127\./, 'loopback'], [/^169\.254\./, 'link-local'],
    [/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, 'cgnat'],
    [/^0\./, 'reserved'], [/^2[2-5]\d\./, 'multicast'],
];

function flag(cc) {
    if (!cc || cc.length !== 2) return '';
    return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 127397 + c.charCodeAt(0)));
}

function privateKind(ip) {
    for (const [re, kind] of PRIVATE) if (re.test(ip)) return kind;
    return null;
}

function scheduleSave() {
    dirty = true;
    if (saveTimer) return;
    saveTimer = setTimeout(() => { saveTimer = null; if (dirty) { dirty = false; store.save('geo.json', cache); } }, 3000);
    saveTimer.unref && saveTimer.unref();
}

function norm(cc, country) {
    const c = String(cc || '').toUpperCase().slice(0, 2);
    return { cc: c, country: String(country || '').slice(0, 64) };
}

function remember(key, info) {
    cache[key] = { ...info, at: Date.now() };
    scheduleSave();
    return { ...info, flag: flag(info.cc) };
}

function known(key) {
    const hit = cache[key];
    if (hit) return { cc: hit.cc || '', country: hit.country || '', flag: flag(hit.cc) };
    return null;
}

// resolve host -> ip with dns cache in geo.json ('dns:<host>')
async function resolveIp(host) {
    if (isIp(host)) return host;
    const c = cache['dns:' + host];
    if (c && c.ip && Date.now() - (c.at || 0) < 6 * 3600e3) return c.ip;
    try {
        const r = await dns.lookup(host, { family: 4 });
        cache['dns:' + host] = { ip: r.address, at: Date.now() };
        scheduleSave();
        return r.address;
    } catch (e) {
        return null;
    }
}

function fetchJson(url, timeout = 6000) {
    return new Promise(resolve => {
        const mod = url.startsWith('https') ? https : http;
        const req = mod.get(url, {
            timeout,
            headers: { 'User-Agent': 'checker/2.0', Accept: 'application/json' },
            rejectUnauthorized: false,
        }, res => {
            if (res.statusCode === 429) { res.resume(); return resolve({ rate: true }); }
            if (res.statusCode !== 200) { res.resume(); return resolve(null); }
            let b = '';
            res.setEncoding('utf8');
            res.on('data', c => { b += c; if (b.length > 64 * 1024) req.destroy(); });
            res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { resolve(null); } });
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
    });
}

async function lookupIp(ip) {
    const pk = privateKind(ip);
    if (pk) return remember(ip, { cc: '', country: pk });

    const hit = known(ip);
    if (hit) return hit;

    const providers = [
        async () => {
            const r = await fetchJson(`https://ipwho.is/${ip}?fields=success,country,country_code`);
            if (r && r.success && r.country_code) return norm(r.country_code, r.country);
            return null;
        },
        async () => {
            const r = await fetchJson(`http://ip-api.com/json/${ip}?fields=status,country,countryCode`);
            if (r && r.status === 'success') return norm(r.countryCode, r.country);
            return null;
        },
        async () => {
            const r = await fetchJson(`https://ipapi.co/${ip}/json/`);
            if (r && r.country_code) return norm(r.country_code, r.country_name);
            return null;
        },
    ];
    for (const p of providers) {
        const info = await p();
        if (info) return remember(ip, info);
    }
    return remember(ip, { cc: '', country: 'unknown' });
}

// hot path used by the scanner: cached, queued, never throws
function queued(host) {
    if (!host) return Promise.resolve({ cc: '', country: 'unknown', flag: '' });
    const direct = known(host);
    if (direct) return Promise.resolve(direct);
    return pool(async () => {
        const cached = known(host);
        if (cached) return cached;
        const ip = await resolveIp(host);
        if (!ip || !isIp(ip)) return remember(host, { cc: '', country: 'unresolved' });
        return lookupIp(ip);
    }).catch(() => ({ cc: '', country: 'unknown', flag: '' }));
}

// bulk API for the Geo panel
async function lookup(hosts) {
    const uniq = [...new Set(hosts.map(h => String(h || '').trim()).filter(Boolean))];
    const out = {};
    for (let i = 0; i < uniq.length; i += 8) {
        const chunk = uniq.slice(i, i + 8);
        const res = await Promise.all(chunk.map(h => queued(h).then(info => [h, info])));
        for (const [h, info] of res) out[h] = info;
        if (i + 8 < uniq.length) await sleep(120);
    }
    if (dirty) { dirty = false; store.save('geo.json', cache); }
    return out;
}

function stats() {
    const keys = Object.keys(cache).filter(k => !k.startsWith('dns:'));
    return { hosts: keys.length, countries: new Set(keys.map(k => cache[k].cc).filter(Boolean)).size };
}

module.exports = { lookup, queued, lookupIp, flag, stats, privateKind, cache };
