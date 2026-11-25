'use strict';
// Country CIDR sources. Primary: ipdeny.com zones. Mirrors: herrbischoff and
// the Cloudflare-hosted country-ip-blocks repo. IPv4 only, validated + deduped.
const https = require('https');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const store = require('./store');

const DIR = path.join(store.DATA_DIR, 'sources');
if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });

const MIRRORS = [
    cc => `https://www.ipdeny.com/ipblocks/data/countries/${cc}.zone`,
    cc => `https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/${cc}.cidr`,
    cc => `https://cdn.jsdelivr.net/gh/herrbischoff/country-ip-blocks@master/ipv4/${cc}.cidr`,
    cc => `https://raw.githubusercontent.com/ipverse/rir-ip/master/country/${cc}/ipv4-aggregated.txt`,
];

function fetchText(url, redirects = 0) {
    return new Promise(resolve => {
        if (redirects > 4) return resolve(null);
        const req = https.get(url, {
            timeout: 25000,
            rejectUnauthorized: false,
            headers: { 'User-Agent': 'Mozilla/5.0 checker/2.0', 'Accept-Encoding': 'gzip, deflate' },
        }, res => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                res.resume();
                return resolve(fetchText(new URL(res.headers.location, url).href, redirects + 1));
            }
            if (res.statusCode !== 200) { res.resume(); return resolve(null); }
            const enc = String(res.headers['content-encoding'] || '').toLowerCase();
            let stream = res;
            if (enc === 'gzip') stream = res.pipe(zlib.createGunzip());
            else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
            const chunks = [];
            stream.on('data', c => { chunks.push(c); if (chunks.length > 200000) req.destroy(); });
            stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
            stream.on('error', () => resolve(null));
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
    });
}

function validCidr(s) {
    return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.test(s);
}

function parseList(text) {
    const out = new Set();
    for (const raw of String(text || '').split(/\r?\n/)) {
        const line = raw.split(/[#;]/)[0].trim();
        if (!line || line.includes(':')) continue;
        if (validCidr(line)) out.add(line);
        else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(line)) out.add(line);
    }
    return [...out];
}

async function download(cc) {
    cc = String(cc || '').toLowerCase().replace(/[^a-z]/g, '');
    if (cc.length !== 2) return 0;
    for (const mk of MIRRORS) {
        const text = await fetchText(mk(cc));
        if (!text) continue;
        const cidrs = parseList(text);
        if (cidrs.length < 1) continue;
        fs.writeFileSync(path.join(DIR, cc + '.txt'), cidrs.join('\n'));
        return cidrs.length;
    }
    return 0;
}

function list() {
    try {
        return fs.readdirSync(DIR)
            .filter(f => /^[a-z]{2}\.txt$/.test(f))
            .map(f => ({
                cc: f.replace('.txt', ''),
                count: fs.readFileSync(path.join(DIR, f), 'utf8').split('\n').filter(Boolean).length,
                size: fs.statSync(path.join(DIR, f)).size,
            }))
            .sort((a, b) => a.cc.localeCompare(b.cc));
    } catch (e) { return []; }
}

function load(cc, cap = 200000) {
    const f = path.join(DIR, String(cc || '').toLowerCase().replace(/[^a-z]/g, '') + '.txt');
    try {
        return fs.readFileSync(f, 'utf8').split(/\r?\n/).filter(Boolean).slice(0, cap);
    } catch (e) { return []; }
}

function remove(cc) {
    try {
        const f = path.join(DIR, String(cc || '').toLowerCase().replace(/[^a-z]/g, '') + '.txt');
        if (fs.existsSync(f)) fs.unlinkSync(f);
        return true;
    } catch (e) { return false; }
}

// Merge every downloaded country into one list (fresh pool)
function mergeAll() {
    const out = new Set();
    for (const s of list()) for (const c of load(s.cc)) out.add(c);
    return [...out];
}

module.exports = { download, list, load, remove, mergeAll, parseList };
