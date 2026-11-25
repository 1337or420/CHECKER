'use strict';
// UI smoke test: run app.js against a minimal DOM stub to catch top-level
// runtime errors (e.g. the $(document).onclick bug that killed all buttons).
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.join(__dirname, '..');
const app = fs.readFileSync(path.join(root, 'public', 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');

function el() {
    return {
        textContent: '', value: '', innerHTML: '', style: {}, dataset: {},
        classList: { toggle() {}, add() {}, remove() {}, contains() { return false; } },
        children: [], childElementCount: 0,
        appendChild() {}, prepend() {}, remove() {}, addEventListener() {}, closest() { return null; },
        scrollTop: 0, scrollHeight: 0, focus() {}, click() {},
    };
}

const errors = [];
const sandbox = {
    console,
    setTimeout,
    setInterval: () => 0,
    clearTimeout,
    URL,
    Blob: class {},
    EventSource: class { addEventListener() {} },
    navigator: { clipboard: { writeText() {} } },
    fetch: () => Promise.resolve({ json: () => Promise.resolve({}) }),
    document: {
        getElementById: () => el(),
        querySelectorAll: () => [],
        addEventListener() {},
        createElement: () => el(),
    },
};
sandbox.addEventListener = () => {};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;

vm.createContext(sandbox);
try {
    new vm.Script(app, { filename: 'app.js' }).runInContext(sandbox);
} catch (e) {
    errors.push(e.message);
}

// every inline onclick must have a top-level function
const handlers = [...html.matchAll(/onclick="([A-Za-z0-9_]+)\(/g)].map(m => m[1]);
const missing = handlers.filter(h => !new RegExp(`function\\s+${h}\\s*\\(`).test(app));

if (errors.length || missing.length) {
    console.error('FAIL runtime:', errors, 'missing handlers:', missing);
    process.exit(1);
}
console.log(`UI OK — app.js runs clean, ${handlers.length} inline handlers present`);
