'use strict';
// API smoke test against a locally running server (PORT env)
const base = `http://127.0.0.1:${process.env.PORT || 7099}/api/`;
let fail = 0;

async function call(p, method = 'GET', body) {
    const r = await fetch(base + p, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
    });
    const text = await r.text();
    let obj;
    try { obj = JSON.parse(text); } catch (e) { obj = { raw: text.slice(0, 80) }; }
    return { code: r.status, obj, headers: r.headers };
}

function ok(name, cond, extra) {
    console.log((cond ? 'OK   ' : 'FAIL ') + name + (extra ? ' :: ' + extra : ''));
    if (!cond) fail++;
}

(async () => {
    let r = await call('status');
    ok('status', r.code === 200 && r.obj.version === '2.0.0');

    r = await call('targets', 'POST', { action: 'clear' });
    ok('targets clear', r.obj.ok === true);
    r = await call('targets', 'POST', { urls: ['1.2.3.4:10443', '5.6.7.8:admin:pass', '1.2.3.4'] });
    ok('targets add', r.obj.added === 2, JSON.stringify(r.obj.added));
    r = await call('targets');
    ok('targets dedupe', r.obj.targets.length === 2, String(r.obj.targets.length));

    r = await call('sources');
    ok('sources list', Array.isArray(r.obj.list) && r.obj.list.some(s => s.cc === 'ua'));
    r = await call('sources/load?cc=ua');
    ok('sources load ua', r.obj.ok && r.obj.count > 100, String(r.obj.count));

    r = await call('exploits');
    ok('exploits metadata', r.obj.exploits.length >= 5 && r.obj.presets.includes('fortinet'));
    r = await call('settings');
    ok('settings get', !!r.obj.settings && Array.isArray(r.obj.settings.proxy));
    r = await call('settings', 'POST', { rps: 12, perHost: 3 });
    ok('settings set', r.obj.settings.rps === 12 && r.obj.settings.perHost === 3);
    await call('settings', 'POST', { rps: 0, perHost: 4 });

    r = await call('wordlists?kind=users');
    ok('wordlists', Array.isArray(r.obj.users) && r.obj.users.length > 10, String((r.obj.users || []).length));

    r = await call('found');
    ok('found list', r.obj.ok && Array.isArray(r.obj.found));
    r = await call('export?type=brute&format=txt');
    ok('export txt', r.code === 200 && r.headers.get('content-disposition').includes('.txt'));

    // real task against a local mock target (started separately in tmp-mock is not an HTTP API here)
    r = await call('start', 'POST', { type: 'scan', ranges: '127.0.0.1/32', ports: [18080], threads: 2, timeout: 1000, tcpTimeout: 500, limit: 1, autoAdd: false });
    ok('start scan', r.obj.ok === true, JSON.stringify(r.obj));
    r = await call('pause', 'POST');
    ok('pause', r.obj.ok === true);
    r = await call('pause', 'POST');
    r = await call('stop', 'POST');
    ok('stop', r.obj.ok === true);
    r = await call('results');
    ok('results', r.obj.ok && !!r.obj.results.scan);
    r = await call('results/clear', 'POST');
    ok('results clear', r.obj.ok === true);

    r = await call('geo', 'POST', { urls: ['1.1.1.1'] });
    ok('geo', r.obj.ok && !!r.obj.geo['1.1.1.1'], JSON.stringify(r.obj.geo['1.1.1.1']));

    r = await call('proxy/test', 'POST');
    ok('proxy test', r.obj.ok === true, JSON.stringify(r.obj).slice(0, 100));

    r = await call('nope');
    ok('404 unknown api', r.code === 404);

    console.log(fail === 0 ? '\nALL API OK' : `\n${fail} FAILURES`);
    process.exit(fail ? 1 : 0);
})();
