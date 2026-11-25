'use strict';
// Stop-button check: /api/stop must immediately broadcast task_state.
const base = `http://127.0.0.1:${process.env.PORT || 7000}`;

async function main() {
    const ac = new AbortController();
    const res = await fetch(base + '/api/events', { signal: ac.signal });
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let sawStopped = false;
    const collect = (async () => {
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += decoder.decode(value, { stream: true });
                const chunks = buf.split('\n\n');
                buf = chunks.pop();
                for (const chunk of chunks) {
                    const ev = (chunk.match(/^event: (.+)$/m) || [])[1];
                    const data = (chunk.match(/^data: (.+)$/m) || [])[1];
                    if (ev === 'task_state' && data && JSON.parse(data).stopped) sawStopped = true;
                }
            }
        } catch (e) { /* AbortError on shutdown is expected */ }
    })();

    await fetch(base + '/api/start', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'scan', ranges: '127.0.0.1/32', ports: [9], threads: 2, timeout: 1000, tcpTimeout: 300, limit: 1, autoAdd: false }),
    });
    await new Promise(r => setTimeout(r, 400));
    await fetch(base + '/api/stop', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    await new Promise(r => setTimeout(r, 600));
    ac.abort();
    if (!sawStopped) throw new Error('task_state(stopped) not received');
    console.log('STOP STATE OK — SSE task_state broadcast on stop');
}

main().catch(e => { console.error('FAIL', e.message); process.exit(1); });
