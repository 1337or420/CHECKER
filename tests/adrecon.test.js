'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const ad = require('../core/adrecon');

const sample = [
    '1.2.3.4:10443:admin:Pass:Word',
    '5.6.7.8:443:vpn:123456',
    'bad line',
    '999.1.1.1:443:u:p',
].join('\n');

(async () => {
    const parsed = ad.parseConfigs(sample);
    assert.equal(parsed.length, 2);
    assert.equal(parsed[0].url, 'https://1.2.3.4:10443');
    assert.equal(parsed[0].pass, 'Pass:Word');
    assert.equal(parsed[1].user, 'vpn');

    const info = await ad.info();
    assert.ok(typeof info.built === 'boolean');
    assert.ok(typeof configsCount(info) === 'number');
    assert.ok(fs.existsSync(path.join(__dirname, '..', 'adrecon', 'main.go')));

    const real = ad.readConfigs();
    assert.ok(real.length > 0, 'input_vpn.txt should have configs');
    console.log(`ADRecon OK — built=${info.built} configs=${real.length} parsed=${parsed.length}`);
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });

function configsCount(i) { return i.configs || 0; }
