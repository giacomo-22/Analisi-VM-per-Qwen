'use strict';
// Driver CDP esterno: pausa sul throw che matcha MATCH, valuta una lista di espressioni
// sul frame 0 per identificare quale operando e' undefined al throw '.constructor'.
const PORT = process.argv[2] || '9229';
const MATCH = process.argv[3] || 'constructor';
const EXPRS = (process.argv[4] || '').split('|').filter(Boolean);
let ws, nextId = 1; const pending = new Map();
const send = (m, p) => new Promise((res) => { const id = nextId++; pending.set(id, res); ws.send(JSON.stringify({ id, method: m, params: p || {} })); });

(async () => {
  let info;
  for (let i = 0; i < 40; i++) { try { info = await fetch(`http://127.0.0.1:${PORT}/json/list`).then(r => r.json()); if (info && info[0] && info[0].webSocketDebuggerUrl) break; } catch (e) {} await new Promise(r => setTimeout(r, 250)); }
  if (!info || !info[0]) { console.log('[cdp] no target'); process.exit(1); }
  ws = new WebSocket(info[0].webSocketDebuggerUrl);
  let done = false;
  ws.addEventListener('message', async (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg.result); pending.delete(msg.id); return; }
    if (msg.method === 'Debugger.paused') {
      const p = msg.params; const desc = p.data ? (p.data.description || '') : '';
      if (!(p.reason === 'exception' && String(desc).includes(MATCH))) { ws.send(JSON.stringify({ id: nextId++, method: 'Debugger.resume' })); return; }
      done = true;
      const cf0 = p.callFrames[0].callFrameId;
      const ev1 = async (expr) => { const r = await send('Debugger.evaluateOnCallFrame', { callFrameId: cf0, expression: expr, returnByValue: true, silent: true });
        if (!r || !r.result) return '?'; if (r.exceptionDetails) return 'EXC'; return (r.result.value !== undefined) ? JSON.stringify(r.result.value) : (r.result.description || r.result.type); };
      console.log('=== THROW', String(desc).slice(0, 70), '@', p.callFrames[0].location.columnNumber);
      for (const e of EXPRS) { console.log('  ' + e + ' => ' + await ev1(e)); }
      await send('Debugger.resume'); setTimeout(() => { try { ws.close(); } catch (e) {} process.exit(0); }, 200);
    }
  });
  ws.addEventListener('open', async () => { await send('Debugger.enable'); await send('Runtime.enable'); await send('Debugger.setPauseOnExceptions', { state: 'all' }); await send('Runtime.runIfWaitingForDebugger'); console.log('[cdp] pronto, attendo throw', JSON.stringify(MATCH)); });
  setTimeout(() => { if (!done) { console.log('[cdp] TIMEOUT'); try { ws.close(); } catch (e) {} process.exit(2); } }, 90000);
})();
