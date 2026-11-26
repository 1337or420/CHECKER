'use strict';
const assert = require('assert');
const forti = require('../core/forti');

// 61-byte records from a real sslvpn_websession dump:
// rec0 -> session id, rec1 -> client IP + username, later -> password/group/vdom
const rec = s => String(s).padEnd(61, '.');
const blob = 'var fgt_lang = '
    + rec('..bMj......P............u.........Mj.Mj.Mj.49')
    + rec('.149.99.106.......................piolo......................')
    + rec('.'.repeat(55) + 'pong97')
    + rec('VPN USERS')
    + rec('full-access')
    + rec('root')
    + rec('s&');

const creds = forti.parseSessionFile(blob);
assert.ok(creds.length, 'no creds parsed');
assert.equal(creds[0].user, 'piolo');
assert.equal(creds[0].pass, 'pong97');
console.log(`Websession OK — first pair ${creds[0].user}:${creds[0].pass}, candidates ${creds.length}`);
