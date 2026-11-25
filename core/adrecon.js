'use strict';
// ADRecon integration — Go/Docker recon orchestrator running next to the
// Node checker. It builds/starts the external module, streams its progress
// into the SSE feed and imports its VPN configs into the checker's targets.
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const store = require('./store');
const targets = require('./targets');
const { lines } = require('./lines');

const DIR = path.join(__dirname, '..', 'adrecon');
const EXE = path.join(DIR, 'adrecon.exe');
const INPUT = path.join(DIR, 'input_vpn.txt');
const INPUT_EXAMPLE = path.join(DIR, 'input_vpn.example.txt');
const REPORTS = path.join(DIR, 'reports');
const OUT_CREDS = path.join(store.DATA_DIR, 'adrecon_creds.txt');

function run(cmd, args, opts = {}) {
    return new Promise(resolve => {
        let proc;
        try { proc = spawn(cmd, args, { cwd: opts.cwd || DIR, windowsHide: true, env: { ...process.env, ...(opts.env || {}) } }); }
        catch (e) { return resolve({ ok: false, error: e.message }); }
        let out = '';
        const feed = d => {
            const text = d.toString('utf8').replace(/\x1b\[[0-9;]*m/g, '');
            out += text;
            if (opts.onLine) for (const line of text.split(/\r?\n/)) if (line.trim()) opts.onLine(line.trim());
        };
        proc.stdout.on('data', feed);
        proc.stderr.on('data', feed);
        proc.on('error', e => resolve({ ok: false, error: e.message, out }));
        proc.on('close', code => resolve({ ok: code === 0, code, out }));
    });
}

function hasGo() {
    return new Promise(resolve => {
        const p = spawn('go', ['version'], { windowsHide: true });
        let done = false;
        p.on('error', () => { if (!done) { done = true; resolve(false); } });
        p.on('close', c => { if (!done) { done = true; resolve(c === 0); } });
    });
}

function inputFile() { return fs.existsSync(INPUT) ? INPUT : INPUT_EXAMPLE; }

async function info() {
    let configs = [];
    try { configs = parseConfigs(fs.readFileSync(inputFile(), 'utf8')); } catch (e) { /* ignore */ }
    let reports = [];
    try {
        reports = fs.readdirSync(REPORTS).filter(f => f.endsWith('.json')).map(f => {
            const st = fs.statSync(path.join(REPORTS, f));
            let summary = null;
            try { const j = JSON.parse(fs.readFileSync(path.join(REPORTS, f), 'utf8')); summary = j.summary || null; } catch (e) { /* ignore */ }
            return { file: f, size: st.size, mtime: st.mtime.toISOString(), summary };
        }).sort((a, b) => b.mtime.localeCompare(a.mtime));
    } catch (e) { /* ignore */ }
    return {
        path: DIR, built: fs.existsSync(EXE), go: await hasGo(),
        configs: configs.length, reports: reports.slice(0, 50), reportCount: reports.length,
        output: REPORTS,
    };
}

function validIp(s) {
    const p = String(s).split('.');
    return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && Number(x) <= 255);
}

// input_vpn.txt: ip:port:login:password (password may contain ':')
function parseConfigs(text) {
    const out = [];
    for (const raw of lines(text)) {
        const p = raw.split(':');
        if (p.length < 4) continue;
        if (!validIp(p[0])) continue;
        const port = Number(p[1]);
        if (!port || port < 1 || port > 65535) continue;
        out.push({ url: `https://${p[0]}:${port}`, host: p[0], port, user: p[2], pass: p.slice(3).join(':'), raw });
    }
    return out;
}

function readConfigs() {
    try { return parseConfigs(fs.readFileSync(inputFile(), 'utf8')); } catch (e) { return []; }
}

// Feed configs into the checker: hosts -> targets, full lines -> candidate list
function importConfigs(addTargets = true) {
    const cfgs = readConfigs();
    const added = addTargets ? targets.add(cfgs.map(c => `${c.host}:${c.port}`)) : [];
    try { fs.writeFileSync(OUT_CREDS, cfgs.map(c => c.raw).join('\n')); } catch (e) { /* ignore */ }
    return { configs: cfgs.length, added: added.length, file: OUT_CREDS };
}

async function build(emit) {
    const ok = await hasGo();
    if (!ok) return { ok: false, error: 'go toolchain not found' };
    if (emit) emit('adrecon_log', { text: '[adrecon] go build -o adrecon.exe .' });
    const r = await run('go', ['build', '-o', 'adrecon.exe', '.'], {
        onLine: emit ? line => emit('adrecon_log', { text: '[adrecon] ' + line }) : null,
    });
    if (emit) emit('adrecon_log', { text: `[adrecon] build ${r.ok ? 'OK' : 'FAILED'}` });
    return { ok: r.ok, error: r.ok ? null : (r.error || r.out.slice(-500)) };
}

function parseProgress(line) {
    const m = line.match(/Queue:(\d+).*Running:(\d+).*OK:(\d+).*Fail:(\d+).*Retry:(\d+)\s+(\d+)\/(\d+)\s+\(([\d.]+)%\)/);
    if (!m) return null;
    return {
        queue: +m[1], running: +m[2], ok: +m[3], failed: +m[4], retried: +m[5],
        done: +m[6], total: +m[7], pct: parseFloat(m[8]),
    };
}

function readReports(since) {
    const out = [];
    let files = [];
    try { files = fs.readdirSync(REPORTS).filter(f => f.endsWith('.json')); } catch (e) { return out; }
    for (const f of files) {
        const full = path.join(REPORTS, f);
        try {
            const st = fs.statSync(full);
            if (since && st.mtimeMs < since) continue;
            const j = JSON.parse(fs.readFileSync(full, 'utf8'));
            out.push({
                file: f,
                url: (j.vpn && j.vpn.ip) ? `https://${j.vpn.ip}:${j.vpn.port || 443}` : null,
                login: (j.vpn && j.vpn.login) || null,
                domains: j.domains || null,
                creds: j.credentials || null,
                findings: j.critical_findings || [],
                summary: j.summary || null,
                time: st.mtime.toISOString(),
            });
        } catch (e) { /* ignore malformed report */ }
    }
    return out;
}

function cleanupContainers() {
    return new Promise(resolve => {
        let out = '';
        let p;
        try { p = spawn('docker', ['ps', '-a', '--filter', 'ancestor=adrecon-runner:latest', '-q'], { windowsHide: true }); }
        catch (e) { return resolve(0); }
        p.stdout.on('data', d => out += d.toString());
        p.on('error', () => resolve(0));
        p.on('close', () => {
            const ids = out.split(/\s+/).map(s => s.trim()).filter(Boolean);
            if (!ids.length) return resolve(0);
            let q;
            try { q = spawn('docker', ['rm', '-f', ...ids], { windowsHide: true }); }
            catch (e) { return resolve(0); }
            q.on('error', () => resolve(0));
            q.on('close', () => resolve(ids.length));
        });
    });
}

async function runTask(task, emit) {
    const started = Date.now();
    if (!fs.existsSync(EXE)) {
        const b = await build(emit);
        if (!b.ok) { emit('adrecon_done', { ok: false, error: b.error }); return { ok: false, error: b.error }; }
    }
    const workers = Math.max(1, Math.min(parseInt(task.workers, 10) || 5, 200));
    const queue = Math.max(1, Math.min(parseInt(task.queue, 10) || 5, 500));
    const hours = Math.max(1, Math.min(parseInt(task.hours, 10) || 3, 168));
    emit('adrecon_start', { workers, queue, hours, configs: readConfigs().length });

    let proc;
    try {
        proc = spawn(EXE, [], {
            cwd: DIR, windowsHide: true,
            env: { ...process.env, WORKER_POOL_SIZE: String(workers), QUEUE_SIZE: String(queue), GLOBAL_TIMEOUT_HOURS: String(hours) },
        });
    } catch (e) {
        emit('adrecon_done', { ok: false, error: e.message });
        return { ok: false, error: e.message };
    }

    let lastOut = '';
    const onData = d => {
        const text = d.toString('utf8').replace(/\x1b\[[0-9;]*m/g, '');
        lastOut += text;
        // orchestrator prints progress with a bare \r, not \n
        for (const line of text.split(/\r\n|\n|\r/)) {
            const s = line.trim();
            if (!s) continue;
            const pr = parseProgress(s);
            if (pr) emit('adrecon_progress', pr);
            else emit('adrecon_log', { text: s });
        }
    };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', onData);

    const code = await new Promise(resolve => {
        let settled = false;
        const finish = c => { if (settled) return; settled = true; resolve(c); };
        proc.on('error', () => finish(-1));
        proc.on('close', c => { clearInterval(stopWatch); finish(c); });
        const stopWatch = setInterval(() => {
            if (!task.stopped) return;
            clearInterval(stopWatch);
            try {
                if (process.platform === 'win32') spawn('taskkill', ['/PID', String(proc.pid), '/T', '/F'], { windowsHide: true });
                else proc.kill('SIGTERM');
                cleanupContainers().then(n => { if (n) emit('adrecon_log', { text: `[adrecon] остановлено контейнеров: ${n}` }); });
            } catch (e) { /* ignore */ }
            setTimeout(() => finish(-1), 1500);
        }, 250);
    });

    const fresh = readReports(started - 2000);
    for (const r of fresh) emit('adrecon_hit', r);
    const out = { ok: code === 0, code, reports: fresh.length, elapsed: Date.now() - started, tail: lastOut.slice(-2000) };
    emit('adrecon_done', out);
    return out;
}

module.exports = { info, parseConfigs, readConfigs, importConfigs, build, runTask };
