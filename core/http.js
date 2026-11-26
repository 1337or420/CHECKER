'use strict';
// HTTP/TLS client tuned for mass SSL-VPN probing.
//  - keep-alive connection pools (no TLS handshake per credential)
//  - DNS cache with in-flight de-duplication (no repeated lookups)
//  - optional HTTP proxy with CONNECT tunnelling + round-robin rotation
//  - hard body cap, connect+idle timeout, retry on transport errors
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const zlib = require('zlib');
const dns = require('dns');
const { URL } = require('url');

// ---------------------------------------------------------------- user agents
const UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
];
let uaIdx = 0;
function randomUA() { return UAS[uaIdx++ % UAS.length]; }

// ------------------------------------------------------------------ DNS cache
const dnsCache = new Map(); // host -> { ip, exp }
const dnsInflight = new Map();
const DNS_TTL = 10 * 60 * 1000;

function isIp(s) { return net.isIP(String(s || '')) !== 0; }

function cachedLookup(hostname, options, cb) {
    if (typeof options === 'function') { cb = options; options = {}; }
    const all = !!(options && options.all);
    const family = (options && options.family) || 0;
    const emit = ip => {
        const fam = net.isIP(ip);
        if (all) cb(null, [{ address: ip, family: fam }]);
        else cb(null, ip, fam);
    };
    if (isIp(hostname)) return emit(hostname);

    const hit = dnsCache.get(hostname);
    if (hit && hit.exp > Date.now() && (!family || net.isIP(hit.ip) === family)) return emit(hit.ip);

    const inflight = dnsInflight.get(hostname);
    if (inflight) { inflight.push(cb); return; }

    dnsInflight.set(hostname, [cb]);
    const finish = (err, ip) => {
        const waiters = dnsInflight.get(hostname) || [];
        dnsInflight.delete(hostname);
        for (const w of waiters) {
            if (err) { try { w(err); } catch (_) { /* ignore */ } continue; }
            try {
                if (w === cb) emit(ip);
                else if (all) w(null, [{ address: ip, family: net.isIP(ip) }]);
                else w(null, ip, net.isIP(ip));
            } catch (_) { /* ignore */ }
        }
    };
    dns.lookup(hostname, { family, all: false }, (err, address) => {
        if (err && family !== 4) {
            return dns.lookup(hostname, { family: 4 }, (e2, a2) => finish(e2, a2));
        }
        if (!err && address) dnsCache.set(hostname, { ip: address, exp: Date.now() + DNS_TTL });
        finish(err, address);
    });
}

function clearDns(host) { if (host) dnsCache.delete(host); else dnsCache.clear(); }

// --------------------------------------------------------------------- agents
const pools = { http: null, https: null };
const proxyPools = new Map();
let netOpts = { maxSockets: 400, maxFreeSockets: 64, timeout: 30000 };

function makeAgents(maxSockets) {
    netOpts = { maxSockets: Math.max(4, maxSockets | 0), maxFreeSockets: 64, timeout: 30000 };
    pools.http = new http.Agent({ keepAlive: true, maxSockets: netOpts.maxSockets, maxFreeSockets: 64, timeout: 30000 });
    pools.https = new https.Agent({ keepAlive: true, maxSockets: netOpts.maxSockets, maxFreeSockets: 64, timeout: 30000 });
}
makeAgents(400);

function configure({ maxSockets } = {}) {
    if (!maxSockets || maxSockets === netOpts.maxSockets) return;
    try { pools.http && pools.http.destroy(); pools.https && pools.https.destroy(); } catch (e) { /* ignore */ }
    makeAgents(maxSockets);
}

// CONNECT tunnelling agent (works for https; http hosts are tunnelled too)
class ProxyAgent extends https.Agent {
    constructor(proxy, opts) {
        super({ keepAlive: true, maxSockets: opts.maxSockets, maxFreeSockets: 32, timeout: 30000 });
        this.proxy = proxy;
    }
    createConnection(options, cb) {
        const proxy = this.proxy;
        const target = `${options.host}:${options.port || 443}`;
        let done = false;
        const fail = err => { if (done) return; done = true; try { sock.destroy(); } catch (_) { /* ignore */ } cb(err); };
        const sock = net.connect({ host: proxy.host, port: proxy.port });
        sock.setTimeout(15000, () => fail(new Error('proxy connect timeout')));
        sock.once('error', fail);
        sock.once('connect', () => {
            let head = `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Connection: keep-alive\r\n`;
            if (proxy.auth) head += `Proxy-Authorization: Basic ${Buffer.from(proxy.auth).toString('base64')}\r\n`;
            sock.write(head + '\r\n');
        });
        let buf = '';
        const onData = chunk => {
            buf += chunk.toString('latin1');
            const end = buf.indexOf('\r\n\r\n');
            if (end === -1) {
                if (buf.length > 16384) fail(new Error('proxy header too large'));
                return;
            }
            sock.removeListener('data', onData);
            sock.setTimeout(30000, () => {});
            const status = parseInt(buf.slice(9, 12), 10);
            if (status !== 200) return fail(new Error('proxy CONNECT ' + (status || '???')));
            if (done) return;
            done = true;
            if (options.secureEndpoint === false) return cb(null, sock);
            const t = tls.connect({
                socket: sock,
                servername: options.servername || options.host,
                rejectUnauthorized: false,
            });
            t.once('error', e => { try { t.destroy(); } catch (_) { /* ignore */ } cb(e); });
            t.once('secureConnect', () => cb(null, t));
        };
        sock.on('data', onData);
    }
}

let proxyList = [];   // ['http://user:pass@host:port']
let proxyIdx = 0;

function setProxies(list) {
    proxyList = [];
    for (const raw of list || []) {
        const s = String(raw || '').trim();
        if (!s) continue;
        try {
            const u = new URL(/^[a-z]+:\/\//i.test(s) ? s : 'http://' + s);
            if (!u.hostname) continue;
            proxyList.push({
                host: u.hostname,
                port: Number(u.port) || 8080,
                auth: u.username ? decodeURIComponent(u.username) + ':' + decodeURIComponent(u.password) : null,
            });
        } catch (e) { /* ignore bad proxy */ }
    }
    proxyIdx = 0;
    for (const a of proxyPools.values()) a.destroy();
    proxyPools.clear();
}

function getAgent(isHttps) {
    if (!proxyList.length) return isHttps ? pools.https : pools.http;
    const proxy = proxyList[proxyIdx++ % proxyList.length];
    const key = proxy.host + ':' + proxy.port;
    let agent = proxyPools.get(key);
    if (!agent) {
        agent = new ProxyAgent(proxy, { maxSockets: Math.max(4, Math.min(netOpts.maxSockets, 100)) });
        proxyPools.set(key, agent);
    }
    return agent;
}

function proxyStats() { return { count: proxyList.length, list: proxyList.map(p => p.host + ':' + p.port) }; }

// ------------------------------------------------------------------- requests
/**
 * request(url, opts) -> { ok, status, headers, body, buf, ms, error }
 * opts: { method, body, headers, timeout, binary, maxBody, retries, retryDelay,
 *         userAgent, contentType, lookup }
 */
function request(urlStr, opts = {}) {
    const started = Date.now();
    return new Promise(resolve => {
        let u;
        try { u = new URL(urlStr); } catch (e) { return resolve({ ok: false, error: 'bad url', ms: 0 }); }
        if (!/^https?:$/.test(u.protocol)) return resolve({ ok: false, error: 'bad protocol', ms: 0 });

        const isHttps = u.protocol === 'https:';
        const mod = isHttps ? https : http;
        const data = opts.body ? Buffer.from(opts.body) : null;
        const maxBody = opts.maxBody || 256 * 1024;
        const retries = opts.retries === undefined ? 0 : opts.retries;
        const timeout = opts.timeout || 10000;

        let req;
        let settled = false;
        const finish = res => {
            if (settled) return;
            settled = true;
            res.ms = Date.now() - started;
            if (!res.ok && isTransport(res.error) && retries > 0) {
                setTimeout(() => {
                    request(urlStr, Object.assign({}, opts, { retries: retries - 1 }))
                        .then(r => resolve(r), () => resolve(res));
                }, (opts.retryDelay || 350) + Math.floor(Math.random() * 250));
                return;
            }
            resolve(res);
        };

        try {
            req = mod.request({
                protocol: u.protocol,
                hostname: u.hostname,
                port: u.port || (isHttps ? 443 : 80),
                path: u.pathname + u.search,
                method: opts.method || (data ? 'POST' : 'GET'),
                agent: opts.agent === undefined ? getAgent(isHttps) : opts.agent,
                servername: isIp(u.hostname) ? undefined : u.hostname,
                lookup: opts.lookup || cachedLookup,
                family: opts.family || 0,
                autoSelectFamily: true,
                rejectUnauthorized: false,
                headers: Object.assign({
                    'User-Agent': opts.userAgent || randomUA(),
                    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'identity',
                    Connection: opts.agent === false ? 'close' : 'keep-alive',
                    ...(data ? { 'Content-Type': opts.contentType || 'application/x-www-form-urlencoded', 'Content-Length': data.length } : {}),
                    ...opts.headers,
                }),
                timeout,
            }, res => {
                const chunks = [];
                let size = 0;
                let truncated = false;
                res.on('data', c => {
                    size += c.length;
                    if (size > maxBody) {
                        truncated = true;
                        const keep = Math.max(0, c.length - (size - maxBody));
                        if (keep) chunks.push(c.subarray(0, keep));
                        finish({
                            ok: true, status: res.statusCode, headers: res.headers,
                            body: Buffer.concat(chunks).toString('utf8'), truncated, url: urlStr,
                        });
                        try { req.destroy(); } catch (_) { /* ignore */ }
                        return;
                    }
                    chunks.push(c);
                });
                res.on('end', () => {
                    let buf = Buffer.concat(chunks);
                    // Some FortiOS builds/fronting proxies gzip regardless of
                    // Accept-Encoding. Decode by header AND by magic bytes.
                    const enc = String((res.headers && res.headers['content-encoding']) || '').toLowerCase();
                    try {
                        if (/gzip/.test(enc) || (buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b)) buf = zlib.gunzipSync(buf);
                        else if (/deflate/.test(enc)) buf = zlib.inflateSync(buf);
                        else if (/br/.test(enc)) buf = zlib.brotliDecompressSync(buf);
                    } catch (e) { /* keep raw */ }
                    finish({
                        ok: true, status: res.statusCode, headers: res.headers,
                        body: opts.binary ? null : buf.toString('utf8'), buf, truncated, url: urlStr,
                    });
                });
                res.on('error', e => finish({ ok: false, error: e.message, url: urlStr }));
            });
        } catch (e) {
            return resolve({ ok: false, error: e.message, ms: Date.now() - started });
        }

        req.on('timeout', () => { req.destroy(new Error('timeout')); });
        req.on('error', e => finish({ ok: false, error: e.code || e.message, url: urlStr }));
        if (data) req.write(data);
        req.end();
    });
}

function isTransport(err) {
    return /ECONNRESET|ECONNREFUSED|EPIPE|EAI_AGAIN|ETIMEDOUT|socket hang up|timeout|ECONNABORTED|EHOSTUNREACH|ENETUNREACH/i.test(String(err || ''));
}

// -------------------------------------------------------- range / CIDR parsing
function ipToInt(ip) {
    const p = String(ip).split('.').map(Number);
    if (p.length !== 4 || p.some(x => isNaN(x) || x < 0 || x > 255)) return null;
    return (((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0;
}

function intToIp(n) {
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

// Materialize a range list into individual hosts (cap per entry)
function expandRanges(input, cap = 65536) {
    const out = new Set();
    for (const part of parseRanges(input)) {
        if (part.kind === 'host') { out.add(part.host); continue; }
        const n = Math.min(part.size, cap);
        for (let i = 0; i < n; i++) out.add(intToIp(part.start + i));
    }
    return [...out];
}

// Parse range list WITHOUT materializing every IP.
// Returns [{kind:'host',host} | {kind:'cidr',start,size}]
function parseRanges(input, cap = 65536) {
    const out = [];
    const seen = new Set();
    for (let line of String(input || '').split(/[\s,;]+/)) {
        line = line.trim();
        if (!line) continue;
        const cidr = line.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
        if (cidr) {
            const base = ipToInt(cidr[1]);
            const bits = parseInt(cidr[2], 10);
            if (base === null || bits < 0 || bits > 32) continue;
            const size = Math.pow(2, 32 - bits);
            const start = size >= 4294967296 ? 0 : (base & (0xffffffff - size + 1)) >>> 0;
            const key = 'c' + start + '/' + bits;
            if (seen.has(key)) continue;
            seen.add(key);
            out.push({ kind: 'cidr', start, size: Math.min(size, cap) });
            continue;
        }
        const dash = line.match(/^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/);
        if (dash) {
            const s1 = ipToInt(dash[1]), s2 = ipToInt(dash[2]);
            if (s1 !== null && s2 !== null && s2 >= s1) {
                const key = 'r' + s1 + '-' + s2;
                if (seen.has(key)) continue;
                seen.add(key);
                out.push({ kind: 'cidr', start: s1, size: Math.min(s2 - s1 + 1, cap) });
            }
            continue;
        }
        if (isIp(line) || /^[a-z0-9_.-]+\.[a-z]{2,}$/i.test(line)) {
            if (seen.has(line)) continue;
            seen.add(line);
            out.push({ kind: 'host', host: line });
        }
    }
    return out;
}

function rangesTotal(parts) {
    return parts.reduce((n, p) => n + (p.kind === 'host' ? 1 : p.size), 0);
}

// Fast TCP pre-check with DNS cache — skips dead hosts before slow HTTP work
function tcpOpen(host, port, timeout = 2500) {
    return new Promise(resolve => {
        if (isIp(host)) {
            const s = net.connect({ host, port });
            const done = r => { s.destroy(); resolve(r); };
            s.setTimeout(timeout, () => done(false));
            s.once('connect', () => done(true));
            s.once('error', () => done(false));
            return;
        }
        cachedLookup(host, {}, (err, ip) => {
            if (err || !ip) return resolve(false);
            const s = net.connect({ host: ip, port, family: net.isIP(ip) });
            const done = r => { s.destroy(); resolve(r); };
            s.setTimeout(timeout, () => done(false));
            s.once('connect', () => done(true));
            s.once('error', () => done(false));
        });
    });
}

// Simple concurrency limiter
function limiter(max) {
    let active = 0;
    const queue = [];
    const next = () => {
        if (!queue.length || active >= max) return;
        active++;
        const { fn, resolve, reject } = queue.shift();
        Promise.resolve().then(fn).then(resolve, reject).finally(() => { active--; next(); });
    };
    return fn => new Promise((resolve, reject) => { queue.push({ fn, resolve, reject }); next(); });
}

module.exports = {
    request, expandRanges, parseRanges, rangesTotal, tcpOpen, ipToInt, intToIp,
    configure, setProxies, proxyStats, clearDns, cachedLookup, limiter, isIp, randomUA, UAS,
};
