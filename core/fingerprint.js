'use strict';
// Passive stack fingerprint for every open port: what panel/site is running
// and which language/framework serves it. One small HTTP request per open port,
// no active exploitation.
const { request } = require('./http');

const PANELS = [
    [/fortigate|fortinet|fortios/i, 'FortiGate / FortiOS'],
    [/sonicwall/i, 'SonicWall'],
    [/routeros|mikrotik/i, 'MikroTik RouterOS'],
    [/pfsense|opnsense/i, 'pfSense / OPNsense'],
    [/unifi|ubiquiti/i, 'UniFi Controller'],
    [/grafana/i, 'Grafana'], [/kibana/i, 'Kibana'], [/jenkins/i, 'Jenkins'],
    [/gitlab/i, 'GitLab'], [/portainer/i, 'Portainer'],
    [/phpmyadmin|phpMyAdmin/i, 'phpMyAdmin'], [/cpanel|whm/i, 'cPanel'],
    [/webmin|virtualmin/i, 'Webmin'], [/openvpn|access server/i, 'OpenVPN Admin'],
    [/nextcloud|owncloud/i, 'NextCloud'], [/roundcube|webmail/i, 'Webmail'],
    [/teamviewer|anydesk/i, 'Remote access panel'],
    [/hikvision|dahua|axis communications/i, 'IP camera / NVR'],
    [/big-ip|f5 networks/i, 'F5 BIG-IP'],
    [/citrix|netscaler/i, 'Citrix NetScaler'],
    [/wireguard|wg-easy/i, 'WireGuard panel'],
];

const TECH = [
    [/x-powered-by:\s*express|express/i, 'Node.js / Express'],
    [/next\.js|__NEXT_DATA__|_next\/static/i, 'Next.js / React'],
    [/angular|ng-version/i, 'Angular'],
    [/vue|__NUXT__|_nuxt\//i, 'Vue / Nuxt'],
    [/laravel_session|laravel/i, 'PHP / Laravel'],
    [/ci_session|codeigniter/i, 'PHP / CodeIgniter'],
    [/PHPSESSID|x-powered-by:\s*php|<\?php|\.php["'?]/i, 'PHP'],
    [/JSESSIONID|jsp|servlet|tomcat/i, 'Java / JSP'],
    [/ASP\.NET_SessionId|__VIEWSTATE|\.aspx/i, 'ASP.NET'],
    [/django|csrftoken/i, 'Python / Django'],
    [/flask|werkzeug/i, 'Python / Flask'],
    [/X-Powered-By:\s*Go|go-build/i, 'Go'],
    [/rails|authenticity_token/i, 'Ruby / Rails'],
    [/wordpress|\/wp-content\/|wp-json/i, 'WordPress / PHP'],
    [/joomla/i, 'Joomla / PHP'],
    [/drupal/i, 'Drupal / PHP'],
    [/nginx/i, 'nginx'], [/apache/i, 'Apache'],
    [/IIS/i, 'Microsoft IIS'], [/openresty/i, 'OpenResty'],
    [/cloudflare/i, 'Cloudflare'], [/envoy/i, 'Envoy'],
];

function titleOf(body) {
    return ((body || '').match(/<title[^>]*>([^<]{1,120})<\/title>/i) || [])[1]?.trim() || '';
}

function detect(body, headers) {
    const raw = String(body || '');
    const meta = raw.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i)
        || raw.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator/i);
    const headerStr = Object.entries(headers || {}).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(',') : v}`).join('\n');
    const text = `${headerStr}\n${meta ? meta[1] + '\n' : ''}${raw.slice(0, 4096)}`;
    const panels = PANELS.filter(([re]) => re.test(text)).map(([, name]) => name);
    const tech = TECH.filter(([re]) => re.test(text)).map(([, name]) => name);
    const uniq = a => [...new Set(a)].slice(0, 6);
    return {
        panels: uniq(panels),
        tech: uniq(tech),
        product: uniq(panels)[0] || uniq(tech)[0] || null,
        lang: inferLang(uniq(tech)),
        generator: meta ? meta[1] : null,
    };
}

function inferLang(tech) {
    if (tech.some(t => /PHP|Laravel|WordPress|Joomla|Drupal/i.test(t))) return 'PHP';
    if (tech.some(t => /Java|JSP/i.test(t))) return 'Java';
    if (tech.some(t => /ASP\.NET/i.test(t))) return 'C# / .NET';
    if (tech.some(t => /Python/i.test(t))) return 'Python';
    if (tech.some(t => /Ruby/i.test(t))) return 'Ruby';
    if (tech.some(t => /Node|Next|Vue|Angular|React/i.test(t))) return 'JavaScript / Node.js';
    if (tech.some(t => /Go\b/i.test(t))) return 'Go';
    return null;
}

async function probe(base, opts = {}) {
    const res = await request(base, {
        timeout: opts.timeout || 2500,
        maxBody: 32 * 1024,
        retries: 0,
        agent: false,
        userAgent: opts.userAgent,
    });
    if (!res.ok) return { ok: false, error: res.error };
    const info = detect(res.body, res.headers);
    const cookies = ((res.headers && res.headers['set-cookie']) || []).map(c => String(c).split('=')[0]).join(',');
    return {
        ok: true,
        status: res.status,
        title: titleOf(res.body),
        server: (res.headers && (res.headers.server || res.headers.Server)) || '',
        powered: (res.headers && (res.headers['x-powered-by'] || res.headers['X-Powered-By'])) || '',
        cookies,
        ...info,
    };
}

module.exports = { probe, detect, titleOf, inferLang };
