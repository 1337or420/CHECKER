'use strict';
// Wordlists: built-in Fortinet / generic defaults with optional user overrides
// stored in data/wordlists/{users,passes}.txt
const fs = require('fs');
const path = require('path');
const store = require('./store');

const DIR = path.join(store.DATA_DIR, 'wordlists');
if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });

const FILE = { users: 'users.txt', passes: 'passes.txt' };

// FortiGate SSL-VPN flavoured defaults (contractor / MSP / appliance naming)
const BUILTIN_USERS = [
    'admin', 'vpn', 'vpnuser', 'vpn1', 'sslvpn', 'sslvpnuser', 'user', 'test', 'guest',
    'fortinet', 'administrator', 'support', 'backup', 'operator', 'monitor', 'it',
    'remote', 'tech', 'vpnadmin', 'fwadmin', 'sysadmin', 'service', 'noc', 'helpdesk',
    'root', 'administrador', 'usuario', 'soporte', 'admin1', 'administrator1',
    'vpn-guest', 'guest1', 'demo', 'cisco', 'ubnt', 'fortigate', 'ssl', 'ssladmin',
];

// FortiOS factory defaults first, then classic appliance/enterprise passwords
const BUILTIN_PASSES = [
    'Fortinet', 'fortinet', 'FortiGate', 'fortigate', 'admin', 'admin123', 'Admin123',
    'Admin1234', 'Admin123!', 'Password1', 'Password1!', 'Password123', 'password',
    'Password', 'P@ssw0rd', 'Passw0rd', 'Passw0rd!', 'Welcome1', 'Welcome123',
    'Welcome@123', 'changeme', 'ChangeMe', 'ChangeMe123', '123456', '12345678',
    '123456789', '1234567890', 'qwerty', 'qwerty123', 'letmein', '1qaz2wsx',
    'Password@123', 'Admin@123', 'admin@123', 'admin@2024', 'admin@2025', 'admin12345',
    'Admin12345', 'fortinet123', 'Fortinet123', 'Fortinet123!', 'Forti1234',
    'vpn', 'vpn123', 'vpn1234', 'vpn@123', 'Vpn1234!', 'sslvpn', 'sslvpn123',
    'secret', 'secret123', 'root', 'root123', 'toor', 'administrator', 'Administrator1',
    'administrator123', 'P@ssword', 'P@ssword1', 'P@ssw0rd123', 'P@ssw0rd!23',
    'Cisco123', 'cisco', 'default', 'Default123', 'test', 'test123', 'guest', 'guest123',
    'it', 'It123456', 'Support1', 'Support123', 'service', 'Service123', 'backup',
    'Backup123', 'noc123', 'helpdesk', 'welcome', 'Welcome', 'Welcome1!', 'summer2024',
    'Summer2024!', 'Autumn2024!', 'Winter2024!', 'Spring2025!', 'january2025',
    'qwerty12345', 'zaq12wsx', '1q2w3e4r', '1q2w3e4r5t', 'abc123', 'abcd1234',
    'Pass1234', 'Pass1234!', 'Fortinet1', 'Fortinet1!', 'Fortinet2023', 'Fortinet2024',
    'Fortinet2025', 'fortigate123', 'fgadmin', 'fg123456', 'ssl123456',
    'Temporal1', 'Temporal123', 'Bienvenido1', 'Bienvenido123', 'Admin12345!',
    'A1234567', 'Aa123456', 'Aa123456!', 'Aa12345678', 'Qwerty123!', 'Qwerty1234',
    'Welcome2024', 'Welcome2025', 'Server1', 'Server123', 'Manager1', 'Manager123',
    'Office123', 'Company123', 'vpn2024', 'vpn2025', 'Vpn2024!', 'Vpn2025!',
];

const cache = new Map();

function read(name) {
    if (cache.has(name)) return cache.get(name);
    let list = null;
    try {
        const raw = fs.readFileSync(path.join(DIR, name), 'utf8');
        list = raw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    } catch (e) { /* no override */ }
    cache.set(name, list);
    return list;
}

function users() { return read(FILE.users) || BUILTIN_USERS.slice(); }
function passes() { return read(FILE.passes) || BUILTIN_PASSES.slice(); }

function save(kind, text) {
    const name = FILE[kind];
    if (!name) return 0;
    const list = String(text || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    fs.writeFileSync(path.join(DIR, name), list.join('\n'));
    cache.set(name, list);
    return list.length;
}

function reset(kind) {
    const name = FILE[kind];
    if (!name) return;
    cache.set(name, null);
    try { fs.unlinkSync(path.join(DIR, name)); } catch (e) { /* ignore */ }
}

function info() {
    return {
        users: { builtin: BUILTIN_USERS.length, custom: (read(FILE.users) || []).length },
        passes: { builtin: BUILTIN_PASSES.length, custom: (read(FILE.passes) || []).length },
    };
}

module.exports = { users, passes, save, reset, info, BUILTIN_USERS, BUILTIN_PASSES };
