'use strict';
// Reproduce a CIDR scan and watch all scan_* SSE events + task state.
const base = 'http://127.0.0.1:7000';
const ac = new AbortController();
const timer = setTimeout(() => ac.abort(), 30000);

(async () => {
    const r = await fetch(base + '/api/events', { signal: ac.signal });
    const reader = r.body.getReader(), dec = new TextDecoder();
    let buf = '', counts = {}, last = null;
    const read = (async () => {
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += dec.decode(value, { stream: true });
                const parts = buf.split('\n\n'); buf = parts.pop();
                for (const p of parts) {
                    const ev = (p.match(/^event: (.+)$/m) || [])[1] || '';
                    if (!ev.startsWith('scan') && ev !== 'task_state' && ev !== 'task_done') continue;
                    counts[ev] = (counts[ev] || 0) + 1;
                    const d = (p.match(/^data: (.+)$/m) || [])[1] || '';
                    if (ev === 'scan_progress') last = d;
                    if (ev !== 'scan_progress') console.log(ev, d.slice(0, 200));
                }
            }
        } catch (e) { /* abort */ }
    })();

    const start = await fetch(base + '/api/start', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            type: 'scan', ranges: '192.0.2.0/24\n198.51.100.0/24', ports: [443],
            threads: 100, tcpTimeout: 1000, timeout: 2500, limit: 0,
            preset: 'fortinet', strategy: 'edge', autoAdd: false,
        }),
    });
    console.log('start', await start.text());
    for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 1000));
        const s = await (await fetch(base + '/api/status')).json();
        if (!s.running && i > 1) break;
    }
    clearTimeout(timer); ac.abort(); await read.catch(() => {});
    const results = await (await fetch(base + '/api/results')).json();
    const summary = (results.results.events || []).filter(x => x.type === 'scan').pop();
    if (!summary) throw new Error('scan summary not persisted');
    console.log('events', JSON.stringify(counts), 'last_progress', last);
    console.log('SUMMARY STORED OK —', JSON.stringify(summary));
})();
