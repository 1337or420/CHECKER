'use strict';
const assert = require('assert');
const os = require('os');
const path = require('path');
const fs = require('fs');

const dir = path.join(os.tmpdir(), 'checker-results-test');
fs.mkdirSync(dir, { recursive: true });
process.env.CHECKER_DATA_DIR = dir;
const store = require('../core/store');

store.clearResults();
store.appendResult('brute', '1.2.3.4:443:admin:pass1');
store.appendResult('brute', '5.6.7.8:10443:vpn:pass2');
store.appendResult('scan', '9.9.9.9:443');

const cats = store.resultCategories();
assert.deepStrictEqual(cats.map(c => c.type).sort(), ['brute', 'scan']);
const brute = cats.find(c => c.type === 'brute');
assert.equal(brute.files[0].lines, 2);
assert.ok(fs.existsSync(store.resultPath('brute')));
assert.ok(store.readResults('brute').includes('admin:pass1'));
assert.ok(!store.readResults('scan').includes('admin'));

store.clearResults();
assert.equal(store.resultCategories().length, 0);
console.log('Results OK — category folders, txt files, read and clear');
