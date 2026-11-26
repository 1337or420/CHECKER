'use strict';
// CHECKER panel frontend

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[<>&"]/g, ch => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[ch]));
const ts = iso => new Date(iso || Date.now()).toLocaleTimeString();

async function api(path, opts = {}) {
    const res = await fetch('/api/' + path, {
        method: opts.method || 'GET',
        headers: { 'Content-Type': 'application/json' },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    try { return await res.json(); } catch (e) { return {}; }
}

// ---------------- SSE ----------------
const es = new EventSource('/api/events');
let sseWasDown = false;
es.onopen = () => {
    const b = $('sseBadge');
    if (b) { b.className = 'badge bg-success'; b.textContent = 'LIVE'; }
    if (sseWasDown) {
        sseWasDown = false;
        appendLog('[sse] соединение восстановлено');
        refreshStats(); loadResults();
    }
};
es.onerror = () => {
    sseWasDown = true;
    const b = $('sseBadge');
    if (b) { b.className = 'badge bg-danger'; b.textContent = 'SSE OFF'; }
};
es.addEventListener('hello', e => { $('versionBadge').textContent = 'v' + JSON.parse(e.data).version; });
es.addEventListener('log', e => appendLog(JSON.parse(e.data).text));
es.addEventListener('scan_hit', e => { addLive('scanResults', fmtScan(JSON.parse(e.data))); bump('scanFound'); });
es.addEventListener('scan_skip', e => {
    const d = JSON.parse(e.data);
    addLive('scanResults', `<span class="text-muted">[SKIP ${esc((d.cc || '').toUpperCase())}]</span><span>${esc(d.host)}:${esc(d.port)}</span><span class="t">${esc(d.country || '')}</span>`);
});
es.addEventListener('scan_progress', e => setProgress(JSON.parse(e.data)));
es.addEventListener('brute_progress', e => setProgress(JSON.parse(e.data)));
es.addEventListener('check_progress', e => setProgress(JSON.parse(e.data)));
es.addEventListener('exploit_progress', e => setProgress(JSON.parse(e.data)));
es.addEventListener('brute_target', e => { const d = JSON.parse(e.data); if (!d.alive) appendLog(`[brute] мёртв: ${d.url} (${d.reason || ''})`); });
es.addEventListener('brute_hit', e => { addLive('bruteResults', fmtCred(JSON.parse(e.data))); bump('bruteFound'); });
es.addEventListener('check_hit', e => addLive('checkResults', fmtCred(JSON.parse(e.data))));
es.addEventListener('check_target', e => addLive('checkResults', fmtTarget(JSON.parse(e.data))));
es.addEventListener('exploit_result', e => addLive('exploitResults', fmtExploit(JSON.parse(e.data))));
es.addEventListener('exploit_cred', e => { addLive('exploitResults', fmtCred(JSON.parse(e.data))); });
es.addEventListener('fastscan_start', e => appendLog('[fastscan] старт: ' + JSON.stringify(JSON.parse(e.data))));
es.addEventListener('fastscan_progress', e => setProgress(JSON.parse(e.data)));
es.addEventListener('fastscan_open', e => { const d = JSON.parse(e.data); addLive('fastscanResults', `<span class="tag">[OPEN]</span><span class="mono">${esc(d.ip || d.host)}:${esc(d.port)}</span><span class="t">${d.ms}мс · ${esc(d.host)}</span>`); bump('fastscanFound'); });
es.addEventListener('fastscan_done', e => appendLog('[fastscan] завершён: ' + JSON.stringify(JSON.parse(e.data))));
es.addEventListener('adrecon_log', e => { const d = JSON.parse(e.data); addLive('adreconLog', `<span class="mono">${esc(d.text)}</span>`); appendLog('[adrecon] ' + d.text); });
es.addEventListener('adrecon_progress', e => setProgress(JSON.parse(e.data)));
es.addEventListener('adrecon_hit', e => { const d = JSON.parse(e.data); addLive('adreconResults', `<span class="tag">[REPORT]</span><span class="mono">${esc(d.file)}</span><span class="t">${esc(JSON.stringify(d.summary || {}).slice(0, 120))}</span>`); bump('adReports'); });
es.addEventListener('adrecon_start', e => appendLog('[adrecon] запуск: ' + JSON.stringify(JSON.parse(e.data))));
es.addEventListener('adrecon_done', e => appendLog('[adrecon] завершено: ' + JSON.stringify(JSON.parse(e.data))));
es.addEventListener('task_state', e => updateState(JSON.parse(e.data)));
es.addEventListener('task_done', e => {
    const d = JSON.parse(e.data);
    updateState({ running: false });
    const r = d.result || {};
    const total = r.total || r.tried || 1;
    const done = r.scanned || r.tried || total;
    setProgress({ done, total, found: r.found ?? r.valid ?? r.leaked, rate: r.elapsed ? done / (r.elapsed / 1000) : undefined });
    const gl = $('gpLabel');
    if (gl) gl.textContent = `DONE: ${d.type}`;
    loadFound(); loadResults(); refreshStats();
});

function bump(id) { const el = $(id); if (el) el.textContent = String((parseInt(el.textContent, 10) || 0) + 1); }

function setProgress(d) {
    if (!d || !d.total) return;
    const done = d.done ?? d.tried ?? d.checked ?? 0;
    const pct = Math.min(100, Math.round((done / d.total) * 100));
    const bar = $('progressBar');
    bar.style.width = pct + '%';
    const speed = d.rate ? ` · ${Number(d.rate).toFixed(1)}/с` : '';
    const eta = d.rate && d.total - done > 0 ? ` · ETA ${Math.ceil((d.total - done) / d.rate)}с` : '';
    bar.textContent = `${pct}% (${done}/${d.total}${d.found ? ', found: ' + d.found : ''})${speed}${eta}`;
    const gb = $('gpBar');
    if (gb) { gb.style.width = pct + '%'; gb.textContent = `${pct}% (${done}/${d.total})`; }
    const gl = $('gpLabel');
    if (gl) gl.textContent = `${(currentTaskType || 'task').toUpperCase()}${d.found !== undefined ? ` · found ${d.found}` : ''}`;
    const gr = $('gpRate');
    if (gr) gr.textContent = d.rate ? `${Number(d.rate).toFixed(1)}/с` : '';
    $('rateInfo').textContent = d.rate ? `${Number(d.rate).toFixed(1)} проверок/с` : '';
}

function appendLog(text) {
    const box = $('logBox');
    box.value += text + '\n';
    if (box.value.length > 200000) box.value = box.value.slice(-150000);
    box.scrollTop = box.scrollHeight;
}

function addLive(id, html) {
    const c = $(id);
    if (!c) return;
    const div = document.createElement('div');
    div.className = 'live-item';
    div.innerHTML = html;
    c.prepend(div);
    while (c.childElementCount > 800) c.lastElementChild.remove();
}

function fmtScan(d) {
    const geo = d.country ? ` <span class="tag">${esc(d.flag || '')} ${esc(d.country)}</span>` : '';
    return `<span class="tag">[FOUND]</span><span class="mono">${esc(d.url)}</span>${geo}<span class="t">${esc(d.product)}</span>`;
}

function fmtCred(d) {
    const cookie = d.cookie ? `<span class="cookie" title="${esc(d.cookie)}">cookie</span>` : '';
    const badge = d.verify === 'session_ok' ? '<span class="tag">[SESSION OK]</span>' : '<span class="tag">[VALID]</span>';
    const host = String(d.url || '').replace(/^https?:\/\//, '');
    const line = `${host}:${d.username}:${d.password}`;
    return `${badge}<span class="mono cred" data-copy="${esc(line)}" title="копировать">${esc(line)}</span>${cookie}<span class="t">${ts(d.time)}</span>`;
}

function fmtTarget(d) {
    const cls = d.alive ? 'tag' : 'text-danger';
    const extra = [d.product, d.version ? 'v' + d.version : null, d.hostname].filter(Boolean).join(' ');
    return `<span class="${cls}">[${d.alive ? 'ALIVE' : 'DEAD'}]</span><span class="mono">${esc(d.url)}</span><span class="t">${esc(extra)}</span>`;
}

function fmtExploit(d) {
    const cls = d.vulnerable ? 'tag' : 'text-muted';
    const label = d.kind === 'cred' ? 'CRED' : (d.vulnerable ? 'VULN' : 'NO');
    return `<span class="${cls}">[${label}]</span><span class="mono">${esc(d.url)}</span><span>${esc(d.exploit || '')}</span><span class="t">${esc(d.detail || d.status || '')}</span>`;
}

// click-to-copy
document.addEventListener('click', e => {
    const el = e.target.closest('.cred');
    if (!el || !el.dataset.copy) return;
    navigator.clipboard?.writeText(el.dataset.copy);
    el.classList.add('copied');
    setTimeout(() => el.classList.remove('copied'), 600);
});

// ---------------- status ----------------
async function refreshStats() {
    const s = await api('status');
    $('statTargets').textContent = s.targets ?? 0;
    $('statFound').textContent = s.found ?? 0;
    $('statQueue').textContent = s.autoQueue ?? 0;
    $('statBrute').textContent = s.counts ? s.counts.brute : 0;
    $('statCheck').textContent = s.counts ? s.counts.check : 0;
    $('statExploit').textContent = s.counts ? s.counts.exploit : 0;
    loadFound();
}

// ---------------- found creds ----------------
async function loadFound() {
    const r = await api('found');
    const list = r.found || [];
    const cnt = $('foundCount');
    if (cnt) cnt.textContent = String(list.length);
    const box = $('foundList');
    if (!box) return;
    box.innerHTML = '';
    if (!list.length) { box.innerHTML = '<div class="live-item text-muted">— пока нет —</div>'; return; }
    for (const x of list.slice().reverse().slice(0, 100)) {
        const div = document.createElement('div');
        div.className = 'live-item';
        const line = x.line || `${String(x.url || '').replace(/^https?:\/\//, '')}:${x.username || ''}:${x.password || ''}`;
        div.innerHTML = `<span class="tag">[FOUND]</span><span class="mono cred" data-copy="${esc(line)}">${esc(line)}</span><span class="t">${x.product ? esc(x.product) : ''}</span>`;
        box.appendChild(div);
    }
}

function updateState(st) {
    const badge = $('statusBadge');
    if (st.running) {
        badge.className = 'badge bg-success';
        badge.textContent = 'RUN: ' + st.type + (st.paused ? ' (пауза)' : '');
        $('taskInfo').textContent = 'Выполняется: ' + st.type;
        const gl = $('gpLabel');
        if (gl) gl.textContent = String(st.type).toUpperCase();
    } else {
        badge.className = 'badge bg-secondary';
        badge.textContent = 'Idle';
        $('taskInfo').textContent = '— нет активных задач —';
        $('rateInfo').textContent = '';
        const bar = $('progressBar');
        if (bar) { bar.style.width = '0%'; bar.textContent = st.stopped ? 'остановлено' : '0%'; }
        const gb = $('gpBar');
        if (gb) { gb.style.width = '0%'; gb.textContent = st.stopped ? 'остановлено' : '0%'; }
        const gl = $('gpLabel');
        if (gl) gl.textContent = st.stopped ? 'ОСТАНОВЛЕНО' : 'Idle';
        const gr = $('gpRate');
        if (gr) gr.textContent = '';
    }
}

// ---------------- targets ----------------
async function refreshTargets() {
    const r = await api('targets');
    const list = $('targetList');
    list.innerHTML = '';
    for (const t of r.targets || []) {
        const row = document.createElement('div');
        row.className = 'target-row';
        row.innerHTML = `<span class="mono">${esc(t.url.replace(/^https?:\/\//, ''))}</span><span class="del" data-id="${esc(t.id)}"><i class="bi bi-x"></i></span>`;
        list.appendChild(row);
    }
    $('statTargets').textContent = (r.targets || []).length;
}

async function addTargets() {
    const urls = $('targetInput').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    if (!urls.length) return;
    const r = await api('targets', { method: 'POST', body: { urls } });
    $('targetInput').value = '';
    appendLog(`[targets] добавлено ${r.added ?? 0}`);
    refreshTargets();
}

document.addEventListener('click', e => {
    const del = e.target.closest('.del');
    if (del && del.dataset.id) { api('targets?id=' + encodeURIComponent(del.dataset.id), { method: 'DELETE' }).then(refreshTargets); }
});

async function clearTargets() { await api('targets', { method: 'POST', body: { action: 'clear' } }); refreshTargets(); }

function exportTargets() {
    api('targets').then(r => {
        const text = (r.targets || []).map(t => t.url.replace(/^https?:\/\//, '')).join('\r\n');
        download('targets.txt', text);
    });
}

function download(name, text, type = 'text/plain') {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type }));
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

// ---------------- task starters ----------------
// ---------------- FastScan ----------------
async function startFastscan() {
    const r = await api('start', {
        method: 'POST',
        body: {
            type: 'fastscan',
            ranges: $('fsRanges').value,
            ports: $('fsPorts').value.split(/[\s,;]+/).map(Number).filter(Boolean),
            threads: +$('fsThreads').value,
            timeout: +$('fsTimeout').value,
            limit: +$('fsLimit').value,
            strategy: $('fsStrategy').value,
        },
    });
    if (r.error) return alert(r.error);
    switchTab('tab-fastscan');
}

async function startCurrent() {
    if ($('bruteUsers').value.trim() || $('brutePasses').value.trim()) startBrute();
    else if ($('scanRanges').value.trim()) startScan();
    else if ($('fsRanges').value.trim()) startFastscan();
    else startExploit();
}

async function startScan() {
    const r = await api('start', {
        method: 'POST',
        body: {
            type: 'scan',
            ranges: $('scanRanges').value,
            ports: $('scanPorts').value.split(/[\s,;]+/).map(Number).filter(Boolean),
            ssl: $('scanSsl').checked,
            threads: +$('scanThreads').value,
            tcpTimeout: +$('scanTcp').value,
            timeout: +$('scanTimeout').value,
            limit: +$('scanLimit').value,
            autoAdd: $('scanAutoAdd').checked,
            keepOpen: $('scanKeepOpen').checked,
            strategy: $('scanStrategy').value,
            preset: $('scanPreset').value,
        },
    });
    if (r.error) return alert(r.error);
    switchTab('tab-scanner');
}

const fallback = id => { const v = $(id).value.split(/\r?\n/).map(s => s.trim()).filter(Boolean); return v.length ? v : null; };
const creds = (threads, perHost, timeout, resume) => ({
    threads: +threads.value, perHost: +perHost.value, timeout: +timeout.value, resume: resume.checked,
});

async function startBrute() {
    const shared = creds($('bruteThreads'), $('brutePerHost'), $('bruteTimeout'), $('bruteResume'));
    const r = await api('start', {
        method: 'POST',
        body: {
            type: 'brute', targets: fallback('targetInput'),
            usernames: $('bruteUsers').value, passwords: $('brutePasses').value,
            mode: $('bruteMode').value, rps: +$('bruteRps').value,
            maxHits: +$('bruteMaxHits').value, stopOnHit: $('bruteStopOnHit').checked, ...shared,
        },
    });
    if (r.error) return alert(r.error);
    switchTab('tab-brute');
}

async function startCheck() {
    const shared = creds($('checkThreads'), $('checkPerHost'), $('checkTimeout'), $('checkResume'));
    const r = await api('start', {
        method: 'POST',
        body: {
            type: 'check', targets: fallback('checkTargets'),
            credentials: $('checkCreds').value, ...shared,
        },
    });
    if (r.error) return alert(r.error);
    switchTab('tab-checker');
}

async function startExploit() {
    const selected = [...document.querySelectorAll('.ex-chk:checked')].map(x => x.value);
    const r = await api('start', {
        method: 'POST',
        body: { type: 'exploit', threads: +$('exploitThreads').value, timeout: +$('exploitTimeout').value, exploits: selected },
    });
    if (r.error) return alert(r.error);
    switchTab('tab-exploit');
}

async function startHarvest() {
    const r = await api('start', { method: 'POST', body: { type: 'harvest', threads: +$('exploitThreads').value, timeout: +$('exploitTimeout').value } });
    if (r.error) return alert(r.error);
    switchTab('tab-exploit');
}

// ---------------- ADRecon ----------------
async function loadAdrecon() {
    const r = await api('adrecon');
    const i = r.info || r;
    $('adreconInfo').innerHTML = `Модуль: <b>${esc(i.path || '')}</b><br>
        Собрано: <b>${i.built ? 'да' : 'нет'}</b> · Go: <b>${i.go ? 'да' : 'нет'}</b><br>
        VPN-конфигов: <b>${i.configs || 0}</b> · отчётов: <b>${i.reportCount || 0}</b>`;
    const box = $('adreconResults');
    box.innerHTML = '';
    for (const rep of (i.reports || []).slice(0, 20)) {
        const div = document.createElement('div');
        div.className = 'live-item';
        div.innerHTML = `<span class="mono">${esc(rep.file)}</span><span class="t">${esc(JSON.stringify(rep.summary || {}).slice(0, 100))}</span>`;
        box.appendChild(div);
    }
    $('adReports').textContent = String(i.reportCount || 0);
}

async function buildAdrecon() {
    appendLog('[adrecon] сборка модуля...');
    const r = await api('adrecon', { method: 'POST', body: { action: 'build' } });
    appendLog(r.ok ? '[adrecon] сборка OK' : '[adrecon] сборка ошибка: ' + (r.error || ''));
    loadAdrecon();
}

async function importAdrecon() {
    const r = await api('adrecon', { method: 'POST', body: { action: 'import' } });
    appendLog(`[adrecon] импортировано ${r.configs || 0} конфигов, целей добавлено ${r.added || 0}`);
    refreshTargets();
}

async function startAdrecon() {
    const r = await api('start', {
        method: 'POST',
        body: { type: 'adrecon', workers: +$('adWorkers').value, queue: +$('adQueue').value, hours: +$('adHours').value },
    });
    if (r.error) return alert(r.error);
    switchTab('tab-adrecon');
}

async function togglePause() { await api('pause', { method: 'POST' }); }
async function stopTask() { await api('stop', { method: 'POST' }); }

// ---------------- results ----------------
let resultTab = 'scan';

async function loadResults() {
    const [r, text] = await Promise.all([
        api('results'),
        fetch('/api/results/text?type=' + encodeURIComponent(resultTab)).then(x => x.text()).catch(() => ''),
    ]);
    const rows = (text || '').split(/\r?\n/).filter(Boolean);
    $('resultsBox').value = rows.length
        ? rows.join('\n')
        : '— нет результатов в категории "' + resultTab + '" —\nПроверьте папку data/results/' + resultTab + '/';
    const cat = ((r.files || []).find(f => f.type === resultTab) || {});
    const totalLines = (cat.files || []).reduce((n, f) => n + f.lines, 0);
    const p = $('resultsPath');
    if (p) p.textContent = `${r.dir || 'data/results'}${String(r.dir || '').endsWith('results') ? '/' + resultTab + '/' : ' → ' + resultTab}  ·  строк: ${totalLines}`;
    if (r.logs) { $('logBox').value = r.logs.join('\n') + '\n'; $('logBox').scrollTop = $('logBox').scrollHeight; }
}

async function openResultsFolder() {
    const r = await api('results/open-folder', { method: 'POST', body: {} });
    appendLog(r.ok ? '[results] папка открыта: ' + r.path : '[results] не удалось открыть папку');
}

async function clearResults() {
    await api('results/clear', { method: 'POST' });
    loadResults(); refreshStats();
    document.querySelectorAll('.live-list').forEach(e => e.innerHTML = '');
}

function exportResults(format) { window.location = `/api/export?type=${resultTab}&format=${format}`; }
function exportFound(format) { window.location = `/api/found?format=${format}`; }

document.querySelectorAll('.res-tab').forEach(a => a.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.res-tab').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    resultTab = a.dataset.tab;
    loadResults();
}));

// ---------------- exploits / wordlists ----------------
async function loadExploits() {
    const r = await api('exploits');
    const box = $('exploitList');
    box.innerHTML = '';
    for (const ex of r.exploits || []) {
        const div = document.createElement('div');
        div.className = 'form-check';
        div.innerHTML = `<input class="form-check-input ex-chk" type="checkbox" value="${esc(ex.id)}" checked>
            <label class="form-check-label"><strong>${esc(ex.id)}</strong> — ${esc(ex.name)}</label>`;
        box.appendChild(div);
    }
}

async function loadWords(kind) {
    const r = await api('wordlists?kind=' + kind);
    const target = kind === 'users' ? $('bruteUsers') : $('brutePasses');
    target.value = (r[kind] || []).join('\n');
    appendLog(`[wordlist] ${kind}: ${(r[kind] || []).length}`);
}

// ---------------- tabs ----------------
function switchTab(id) {
    document.querySelectorAll('#mainTabs .nav-link').forEach(a => a.classList.toggle('active', a.dataset.tab === id));
    document.querySelectorAll('.tab-pane').forEach(p => {
        p.classList.toggle('active', p.id === id);
        p.classList.toggle('show', p.id === id);
    });
    if (id === 'tab-results') loadResults();
    if (id === 'tab-geo') { refreshSources(); loadExclude(); }
    if (id === 'tab-adrecon') loadAdrecon();
}
document.querySelectorAll('#mainTabs .nav-link').forEach(a => a.addEventListener('click', e => { e.preventDefault(); switchTab(a.dataset.tab); }));
window.addEventListener('error', e => appendLog('[JS ERROR] ' + e.message));

// ---------------- settings / geo / sources ----------------
async function loadSettings() {
    const r = await api('settings');
    const s = r.settings || {};
    $('excludeInput').value = (s.excludeCountries || []).join(', ');
    $('proxyInput').value = (s.proxy || []).join('\n');
    $('maxSockets').value = s.maxSockets ?? 600;
    $('retries').value = s.retries ?? 1;
    $('perHost').value = s.perHost ?? 4;
    $('rps').value = s.rps ?? 0;
    $('userAgent').value = s.userAgent || '';
    $('autoBrute').checked = !!s.autoBrute;
    $('autoHarvest').checked = s.autoHarvest !== false;
    $('autoAddTargets').checked = s.autoAddTargets !== false;
}

async function saveSettings() {
    await api('settings', {
        method: 'POST',
        body: {
            maxSockets: +$('maxSockets').value, retries: +$('retries').value, perHost: +$('perHost').value,
            rps: +$('rps').value, userAgent: $('userAgent').value,
            autoBrute: $('autoBrute').checked, autoHarvest: $('autoHarvest').checked, autoAddTargets: $('autoAddTargets').checked,
        },
    });
    appendLog('[settings] сохранено');
}

async function saveExclude() {
    const list = $('excludeInput').value.split(/[,\s;]+/).map(s => s.trim()).filter(Boolean);
    await api('settings', { method: 'POST', body: { excludeCountries: list } });
    appendLog('[settings] исключены: ' + list.join(', '));
}
function resetExclude() { loadSettings(); }

async function saveProxy() {
    const text = $('proxyInput').value;
    const r = await api('settings', { method: 'POST', body: { proxyText: text } });
    $('proxyResult').textContent = 'прокси в списке: ' + (r.settings ? r.settings.proxy.length : 0);
    appendLog('[proxy] сохранено');
}

async function testProxy() {
    $('proxyResult').textContent = 'проверка...';
    const r = await api('proxy/test', { method: 'POST' });
    $('proxyResult').textContent = r.ok ? ('IP: ' + (r.body || '') + ' (прокси: ' + (r.proxies ? r.proxies.count : 0) + ')') : ('ошибка: ' + (r.error || r.status));
}

async function lookupGeo() {
    const t = await api('targets');
    const urls = (t.targets || []).map(x => x.url);
    const r = await api('geo', { method: 'POST', body: { urls } });
    const box = $('geoList');
    box.innerHTML = '';
    const entries = Object.entries(r.geo || {}).sort((a, b) => (a[1].country || '').localeCompare(b[1].country || ''));
    for (const [host, g] of entries) {
        const div = document.createElement('div');
        div.className = 'live-item';
        div.innerHTML = `<span>${esc(g.flag)} ${esc(g.country || '?')}</span><span class="mono">${esc(host)}</span>`;
        box.appendChild(div);
    }
    appendLog(`[geo] определено: ${entries.length}`);
}

async function refreshSources() {
    const r = await api('sources');
    const box = $('sourcesList');
    box.innerHTML = '';
    if (!(r.list || []).length) box.innerHTML = '<div class="live-item text-muted">— пока ничего не скачано —</div>';
    for (const s of r.list || []) {
        const div = document.createElement('div');
        div.className = 'live-item';
        div.innerHTML = `<span><span class="tag">${esc(s.cc.toUpperCase())}</span> ${s.count} CIDR</span>
            <span>
              <i class="bi bi-box-arrow-in-right text-success" style="cursor:pointer" title="В сканер" data-load="${esc(s.cc)}"></i>
              &nbsp;<i class="bi bi-trash text-danger" style="cursor:pointer" title="Удалить" data-del="${esc(s.cc)}"></i>
            </span>`;
        box.appendChild(div);
    }
}

document.addEventListener('click', e => {
    const load = e.target.closest('[data-load]');
    if (load) loadToScanner(load.dataset.load);
    const del = e.target.closest('[data-del]');
    if (del) deleteSource(del.dataset.del);
});

async function downloadCountry() {
    const cc = $('ccInput').value.trim().toLowerCase();
    if (cc.length !== 2) return alert('Код страны: ua, de, us ...');
    appendLog(`[sources] скачивание ${cc}...`);
    const r = await api('sources', { method: 'POST', body: { action: 'download', cc } });
    const res = (r.results || [])[0] || {};
    appendLog(`[sources] ${cc}: ${res.count || 0} CIDR`);
    $('ccInput').value = '';
    refreshSources();
    if (!res.count) alert('Не удалось скачать ' + cc.toUpperCase());
}

async function loadToScanner(cc) {
    const r = await api('sources/load?cc=' + encodeURIComponent(cc));
    if (!r.ok) return alert('Не скачано');
    const existing = $('scanRanges').value.trim();
    $('scanRanges').value = (existing ? existing + '\n' : '') + r.cidrs.join('\n');
    appendLog(`[sources] ${cc.toUpperCase()}: ${r.count} CIDR → сканер`);
    switchTab('tab-scanner');
}

async function deleteSource(cc) {
    await fetch('/api/sources/' + encodeURIComponent(cc) + '/file', { method: 'DELETE' });
    refreshSources();
}

// ---------------- init ----------------
refreshStats(); refreshTargets(); loadExploits(); loadResults(); loadSettings(); loadAdrecon(); updateState({ running: false });
setInterval(refreshStats, 4000);
