'use strict';
// FastScan — собственный массовый TCP-сканер в духе masscan / rustscan.
// Без raw-сокетов и внешних зависимостей: пул параллельных connect(),
// DNS-кэш, edge-выборка адресов /24, heartbeat и лимиты. Цель — быстро
// отделить живые SSL-VPN порты от мёртвых хостов перед дорогими HTTP-пробами.
const net = require('net');
const { parseRanges, rangesTotal, intToIp, isIp, cachedLookup } = require('./http');
const { edgeHosts } = require('./scanner');
const stackfp = require('./fingerprint');

const sleep = ms => new Promise(r => setTimeout(r, ms));
function clamp(n, min, max) { n = parseInt(n, 10); if (isNaN(n)) n = min; return Math.max(min, Math.min(max, n)); }

// One non-blocking TCP connect with hard timeout
function connect(ip, port, timeout) {
    return new Promise(resolve => {
        let sock;
        try { sock = net.connect({ host: ip, port, family: net.isIP(ip) }); }
        catch (e) { return resolve(false); }
        let settled = false;
        const finish = open => {
            if (settled) return;
            settled = true;
            try { sock.destroy(); } catch (e) { /* ignore */ }
            resolve(open);
        };
        sock.setNoDelay(true);
        sock.setTimeout(timeout, () => finish(false));
        sock.once('connect', () => finish(true));
        sock.once('error', () => finish(false));
    });
}

async function resolveHost(host) {
    if (isIp(host)) return host;
    return new Promise(resolve => {
        let done = false;
        cachedLookup(host, {}, (err, ip) => {
            if (done) return;
            done = true;
            resolve(err ? null : ip);
        });
        setTimeout(() => { if (!done) { done = true; resolve(null); } }, 3000).unref?.();
    });
}

function buildHosts(task, portsCount, limit) {
    const parts = parseRanges(task.ranges || (task.hosts || []).join('\n'));
    if (!parts.length) return [];
    const strategy = task.strategy || 'edge';
    if (strategy === 'edge') {
        return edgeHosts(parts, Math.max(10000, Math.ceil(limit / portsCount)));
    }
    const total = rangesTotal(parts);
    const cap = Math.min(total, limit || total);
    const offs = []; let acc = 0;
    for (const p of parts) { offs.push(acc); acc += p.size; }
    const hostAt = v => {
        let lo = 0, hi = parts.length - 1;
        while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (offs[mid] <= v) lo = mid; else hi = mid - 1; }
        const p = parts[lo];
        return p.kind === 'host' ? p.host : intToIp(p.start + (v - offs[lo]));
    };
    const used = new Set();
    const out = [];
    let guard = 0;
    while (out.length < cap && guard < cap * 3) {
        guard++;
        const v = Math.floor(Math.random() * total);
        if (used.has(v)) continue;
        used.add(v);
        out.push(hostAt(v));
    }
    return out;
}

async function run(task, emit) {
    const timeout = clamp(task.timeout || 800, 100, 10000);
    const threads = clamp(task.threads || 2000, 1, 20000);
    const limit = clamp(task.limit || 200000, 1, 5000000);
    const ports = (Array.isArray(task.ports) && task.ports.length ? task.ports : [443])
        .map(p => clamp(p, 1, 65535)).slice(0, 32);
    const hosts = buildHosts(task, ports.length, limit);
    const total = Math.min(hosts.length * ports.length, limit);
    if (!total) { emit('fastscan_done', { total: 0, open: 0 }); return { total: 0, open: 0 }; }

    emit('fastscan_start', { total, hosts: hosts.length, ports, threads, timeout, strategy: task.strategy || 'edge' });

    let idx = 0, done = 0, open = 0, live = 0, failed = 0;
    const started = Date.now();
    const t0 = Date.now();
    let lastEmit = 0;

    function progress(force) {
        const now = Date.now();
        if (!force && now - lastEmit < 300) return;
        lastEmit = now;
        const sec = (now - t0) / 1000;
        emit('fastscan_progress', {
            done, total, open, live, failed,
            rate: sec > 0 ? Math.round(done / sec) : 0,
            elapsed: Math.round(sec),
        });
    }
    const hb = setInterval(() => progress(true), 2000);

    async function worker() {
        while (!task.stopped) {
            if (task.paused) { await sleep(150); continue; }
            if (idx >= total) return;
            const i = idx++;
            const host = hosts[Math.floor(i / ports.length)];
            const port = ports[i % ports.length];
            const ip = await resolveHost(host);
            if (!ip) { done++; failed++; progress(false); continue; }
            const ok = await connect(ip, port, timeout);
            done++;
            if (ok) {
                live++;
                const url = `${/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host) ? 'https://' + host : 'https://' + ip}:${port}`;
                const fp = task.fingerprint === false ? {} : await stackfp.probe(url, { timeout: Math.min(timeout, 2500) }).catch(() => ({}));
                const rec = {
                    host, ip, port, url,
                    status: fp.status || null,
                    title: fp.title || null,
                    server: fp.server || '',
                    product: fp.product || null,
                    tech: fp.tech || [],
                    lang: fp.lang || null,
                    panels: fp.panels || [],
                    generator: fp.generator || null,
                    ms: Date.now() - started,
                    time: new Date().toISOString(),
                };
                rec.line = `${host}:${port} ${rec.title || ''} | ${rec.product || 'unknown'} | ${rec.lang || rec.tech.join(',') || ''}`;
                open++;
                emit('fastscan_open', rec);
            } else failed++;
            progress(false);
        }
    }

    const pool = [];
    for (let i = 0; i < Math.min(threads, total); i++) pool.push(worker());
    await Promise.all(pool);
    clearInterval(hb);
    progress(true);
    const out = { total, hosts: hosts.length, open, live, failed, elapsed: Date.now() - t0 };
    emit('fastscan_done', out);
    return out;
}

module.exports = { run, connect, buildHosts };
