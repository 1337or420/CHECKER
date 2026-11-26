'use strict';
const assert = require('assert');
const http = require('http');
const fingerprint = require('../core/fingerprint');

(async () => {
    const srv = http.createServer((req, res) => {
        res.writeHead(200, {
            'Content-Type': 'text/html',
            'Server': 'nginx',
            'X-Powered-By': 'PHP/7.4',
            'Set-Cookie': 'PHPSESSID=abc',
        });
        res.end('<html><head><title>Test Site</title><meta name="generator" content="WordPress 6.0"></head><body>/wp-content/</body></html>');
    });
    await new Promise(r => srv.listen(0, '127.0.0.1', r));
    const url = `http://127.0.0.1:${srv.address().port}`;
    const fp = await fingerprint.probe(url, { timeout: 3000 });
    await new Promise(r => srv.close(r));

    assert.equal(fp.ok, true);
    assert.equal(fp.title, 'Test Site');
    assert.ok(fp.tech.some(t => /PHP|WordPress|nginx/i.test(t)), 'tech not detected: ' + fp.tech);
    assert.equal(fp.lang, 'PHP');
    console.log(`Fingerprint OK — title="${fp.title}" lang=${fp.lang} tech=${fp.tech.join(',')}`);
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
