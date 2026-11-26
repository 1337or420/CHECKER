'use strict';
// Scanner: discover SSL-VPN endpoints across IP ranges / country blocks.
// Streams hosts without materializing country-scale sets, does a cheap TCP
// pre-check, then banner-fingerprints (multi-port, multi-path). Country
// exclusion is applied per hit with a hard time cap.
const { request, parseRanges, rangesTotal, tcpOpen, intToIp } = require('./http');
const { PRESETS } = require('./signatures');
const forti = require('./forti');
const stackfp = require('./fingerprint');
const geo = require('./geo');
const targets = require('./targets');
const settings = require('./settings');

const sleep = ms => new Promise(r => setTimeout(r, ms));
function clamp(n, min, max) { n = parseInt(n, 10); if (isNaN(n)) n = min; return Math.max(min, Math.min(max, n)); }

function fingerprint(res, preset) {
    if (!res || !res.ok) return null;
    const body = (res.body || '').toLowerCase();
    if (body.includes(preset.patternLogin.toLowerCase()) || (preset.patternAdmin && body.includes(preset.patternAdmin.toLowerCase()))) return preset.name;
    if (/fortinet|fortigate|fortios|sslvpn_login|fgt_lang|hostcheck_install|auth_type/i.test(body)) return 'Fortinet FortiGate SSL-VPN';
    if (/remote\/logincheck|svpncookie|top\.location=["']\/remote\/login/i.test(body)) return 'Fortinet SSL-VPN (login portal)';
    if (/\+cscoe\+|anyconnect/.test(body)) return 'Cisco ASA AnyConnect';
    if (/watchguard/.test(body)) return 'WatchGuard SSL-VPN';
    if (/dana-na/.test(body)) return 'Pulse / Ivanti Secure Access';
    if (/globalprotect/.test(body)) return 'Palo Alto GlobalProtect';
    if (/(^|\W)citrix(\W|$)/.test(body) && /vpn/.test(body)) return 'Citrix NetScaler Gateway';
    const server = String((res.headers && (res.headers.server || res.headers.Server)) || '').toLowerCase();
    if (/fortiweb|fortigate/.test(server)) return 'Fortinet (server header)';
    return null;
}

// Gateway/edge addresses of every /24 — appliances and admin panels live here.
function edgeHosts(parts, cap = 200000) {
    const out = [];
    const offsets = [1, 2, 3, 4, 253, 254];
    for (const p of parts) {
        if (p.kind === 'host') { out.push(p.host); continue; }
        const start = p.start >>> 0;
        const end = start + p.size;
        const firstNet = start - (start % 256);
        const lastNet = (end - 1) - ((end - 1) % 256);
        for (let net = firstNet; net <= lastNet; net += 256) {
            for (const d of offsets) {
                const ip = net + d;
                if (ip >= start && ip < end) {
                    out.push(intToIp(ip >>> 0));
                    if (out.length >= cap) return out;
                }
            }
        }
    }
    return out;
}

async function scanTask(task, emit) {
    const timeout = clamp(task.timeout || 6000, 500, 60000);
    const threads = clamp(task.threads || 200, 1, 2000);
    const tcpTimeout = clamp(task.tcpTimeout || 1200, 200, 10000);
    const limit = clamp(task.limit || 0, 0, 5000000);
    const preset = PRESETS[task.presetKey] || PRESETS.fortinet;
    const ports = (Array.isArray(task.ports) && task.ports.length ? task.ports : [task.port || 443])
        .map(p => clamp(p, 1, 65535)).slice(0, 8);

    const parts = parseRanges(task.ranges || (task.hosts || []).join('\n'));
    const edge = task.strategy === 'edge' || task.edge === true;
    const edgeList = edge ? edgeHosts(parts, Math.max(60000, Math.ceil((limit || 200000) / ports.length))) : null;
    const fullTotal = (edge ? edgeList.length : rangesTotal(parts)) * ports.length;
    if (!fullTotal) { emit('scan_done', { total: 0, found: 0 }); return { total: 0, found: 0 }; }
    const total = limit ? Math.min(fullTotal, limit) : fullTotal;

    const offs = [];
    let acc = 0;
    for (const p of parts) { offs.push(acc); acc += p.size; }

    function hostAt(v) {
        if (edge) return edgeList[v];
        let lo = 0, hi = parts.length - 1;
        while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (offs[mid] <= v) lo = mid; else hi = mid - 1; }
        const p = parts[lo];
        return p.kind === 'host' ? p.host : intToIp(p.start + (v - offs[lo]));
    }

    let found = 0, done = 0, dead = 0;
    const scanStarted = Date.now();
    const heartbeat = setInterval(() => {
        const sec = (Date.now() - scanStarted) / 1000;
        emit('scan_progress', {
            done, total, found, dead, heartbeat: true,
            elapsed: Math.round(sec), rate: sec > 0 ? Math.round(done / sec) : 0,
        });
    }, 2000);
    const exclude = (task.exclude || []).map(c => String(c).toLowerCase());
    const excl = new Set(exclude);

    // randomized order over the FULL index space. Country lists are clustered
    // by block, so sequential walking sticks inside one /16 — shuffling gives a
    // uniform cross-section of the whole country immediately.
    const shuffle = task.shuffle !== false;
    let v = 0, pos = 0;
    // For a full-list scan we can afford an in-place Fisher-Yates shuffle;
    // with a capped sample we use a Set over the FULL index space (never over
    // the truncated total, otherwise the sample only covers the first block).
    let order = null, used = null;
    if (shuffle && !limit && fullTotal <= 30e6) {
        order = new Int32Array(fullTotal);
        for (let i = 0; i < fullTotal; i++) order[i] = i;
    } else if (shuffle) {
        used = new Set();
    }
    function nextIndex() {
        if (!shuffle) return v < total ? v++ : -1;
        if (pos >= total) return -1;
        let idx;
        if (order) {
            const k = pos + Math.floor(Math.random() * (total - pos));
            const tmp = order[pos]; order[pos] = order[k]; order[k] = tmp; idx = order[pos];
        } else {
            let guard = 0;
            do { idx = Math.floor(Math.random() * fullTotal); } while (used.has(idx) && ++guard < 64);
            while (used.has(idx)) idx = (idx + 1) % fullTotal;
            used.add(idx);
        }
        pos++;
        return idx;
    }

    emit('scan_start', { total, ports, exclude: exclude.length, preset: preset.name, strategy: edge ? 'edge' : 'random' });

    let lastProgress = 0;
    function progress(force) {
        const now = Date.now();
        if (!force && now - lastProgress < 400) return;
        lastProgress = now;
        emit('scan_progress', { done, total, found, dead });
    }

    function finishHost() {
        done++;
        if (done >= total) return;
    }

    async function worker() {
        while (!task.stopped) {
            if (task.paused) { await sleep(250); continue; }
            if (limit && done >= limit) return;
            const i = nextIndex();
            if (i < 0) return;
            const host = hostAt(Math.floor(i / ports.length));
            const port = ports[i % ports.length];
            const proto = task.ssl === false ? 'http' : 'https';
            const base = `${proto}://${host}:${port}`;

            if (!(await tcpOpen(host, port, tcpTimeout))) {
                dead++;
                finishHost();
                progress(false);
                continue;
            }

            let hit = null, page = null, probe = null;
            for (const p of preset.paths) {
                const res = await request(`${base}/${String(p).replace(/^\//, '')}`, { timeout, maxBody: 24 * 1024, retries: 0 });
                probe = probe || res;
                const fp = fingerprint(res, preset);
                if (fp) { hit = fp; page = p; break; }
            }
            // always verify Fortinet hits: static/decoy portals must not enter
            // the credential queue. Also rescues custom-branded real devices.
            let info = null;
            if (preset === PRESETS.fortinet && (!hit || /fortinet/i.test(hit))) {
                info = await forti.detect(base, { timeout });
                if (!hit && info.forti) {
                    hit = 'Fortinet FortiGate SSL-VPN';
                    page = info.kind || 'logincheck';
                } else if (hit && info.kind === 'decoy') {
                    // only a proven static decoy cancels a fingerprint hit
                    hit = null;
                    page = null;
                } else if (hit && !info.forti && info.evidence && info.evidence.length) {
                    // custom branding / partial signals: keep the hit with evidence
                    hit = 'Fortinet SSL-VPN (по сигнатуре)';
                }
            }
            const fp = await stackfp.probe(base, { timeout: Math.min(timeout, 2500) }).catch(() => ({}));
            const openRec = {
                host, port, url: base,
                status: fp.status !== undefined ? fp.status : (probe && probe.status ? probe.status : null),
                title: fp.title || ((probe && probe.body || '').match(/<title>([^<]{1,80})/i) || [])[1] || '',
                server: fp.server || (probe && probe.headers ? (probe.headers.server || '') : ''),
                product: fp.product || null,
                tech: fp.tech || [],
                lang: fp.lang || null,
                panels: fp.panels || [],
                generator: fp.generator || null,
                evidence: info ? (info.evidence || []) : [],
                time: new Date().toISOString(),
            };
            openRec.line = `${host}:${port} ${openRec.title || ''} | ${openRec.product || 'unknown'} | ${openRec.lang || openRec.tech.join(',') || ''}`;
            if (task.keepOpen !== false) emit('scan_open', openRec);
            finishHost();
            if (!hit) {
                progress(false);
                continue;
            }

            // always report immediately; enrich with country in parallel
            const rec = { host, port, product: hit, path: page, url: base, time: new Date().toISOString() };
            const g = await Promise.race([geo.queued(host), sleep(4000).then(() => null)]);
            const cc = String((g && g.cc) || '').toLowerCase();
            Object.assign(rec, { country: (g && g.country) || '', cc: (g && g.cc) || '', flag: (g && g.flag) || '' });
            if (cc && excl.has(cc)) {
                emit('scan_skip', rec);
            } else {
                if (task.autoAdd !== false) targets.add([`${host}:${port}`]);
                found++;
                emit('scan_hit', rec);
            }
            progress(false);
        }
    }

    const pool = [];
    for (let i = 0; i < Math.min(threads, Math.max(1, total)); i++) pool.push(worker());
    await Promise.all(pool);
    clearInterval(heartbeat);

    progress(true);
    const out = { total, found, dead, scanned: done, stopped: !!task.stopped };
    emit('scan_done', out);
    return out;
}

module.exports = { scanTask, fingerprint, edgeHosts };
