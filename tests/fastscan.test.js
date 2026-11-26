'use strict';
const assert = require('assert');
const net = require('net');
const fastscan = require('../core/fastscan');

(async () => {
    const srv = net.createServer(s => s.end());
    await new Promise(r => srv.listen(0, '127.0.0.1', r));
    const port = srv.address().port;

    const events = [];
    const emit = (ev, data) => events.push([ev, data]);
    const out = await fastscan.run({
        ranges: '127.0.0.1/32', ports: [port, 9], threads: 4,
        timeout: 500, limit: 2, strategy: 'random',
    }, emit);

    await new Promise(r => srv.close(r));
    const open = events.filter(e => e[0] === 'fastscan_open');
    assert.ok(open.length >= 1, 'open port not detected');
    assert.ok(open.some(e => e[1].port === port), 'listening port missing');
    assert.equal(out.total, 2);
    const done = events.find(e => e[0] === 'fastscan_done');
    assert.ok(done && done[1].open >= 1);
    console.log(`FastScan OK — open=${out.open} total=${out.total} events=${events.length}`);
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
