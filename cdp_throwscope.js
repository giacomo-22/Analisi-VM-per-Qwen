'use strict';
// Driver CDP ESTERNO (processo separato): si connette a `node --inspect-brk` dell'harness,
// pausa sull'eccezione del throw (filtrata per 'ValrCFPtdqDq'), e dumpa lo scope del frame 0
// (mX, CXI, key1, ...). Node 24 ha WebSocket + fetch globali → nessuna dipendenza.
// Uso: node cdp_throwscope.js <port> <matchString>
const PORT = process.argv[2] || '9229';
const MATCH = process.argv[3] || 'ValrCFPtdqDq';

let ws, nextId = 1;
const pending = new Map();
function send(method, params) {
  return new Promise((res) => { const id = nextId++; pending.set(id, res); ws.send(JSON.stringify({ id, method, params: params || {} })); });
}

function fmt(ro) {
  if (!ro) return 'undefined';
  if (ro.type === 'undefined') return 'undefined';
  if (ro.type === 'string') return 'str ' + JSON.stringify((ro.value != null ? ro.value : ro.description || '').slice(0, 80));
  if (ro.type === 'number' || ro.type === 'boolean') return String(ro.value);
  if (ro.type === 'function') return 'fn';
  if (ro.type === 'object') return (ro.subtype === 'null') ? 'null' : ((ro.className || 'obj') + ' ' + (ro.description || ''));
  return ro.type;
}

(async () => {
  // trova il ws url
  let info;
  for (let i = 0; i < 40; i++) {
    try { info = await fetch(`http://127.0.0.1:${PORT}/json/list`).then(r => r.json()); if (info && info[0] && info[0].webSocketDebuggerUrl) break; } catch (e) {}
    await new Promise(r => setTimeout(r, 250));
  }
  if (!info || !info[0]) { console.log('[cdp] target non trovato su', PORT); process.exit(1); }
  const url = info[0].webSocketDebuggerUrl;
  console.log('[cdp] connetto', url);
  ws = new WebSocket(url);

  let done = false;
  ws.addEventListener('message', async (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg.result); pending.delete(msg.id); return; }
    if (msg.method === 'Debugger.paused') {
      const p = msg.params;
      const exc = p.data; // RemoteObject dell'eccezione (per reason=exception)
      const desc = exc ? (exc.description || exc.value || fmt(exc)) : '';
      const isTarget = p.reason === 'exception' && String(desc).includes(MATCH);
      if (!isTarget) { ws.send(JSON.stringify({ id: nextId++, method: 'Debugger.resume' })); return; }
      done = true;
      console.log('\n=== THROW INTERCETTATO ===');
      console.log('reason:', p.reason, '| desc:', String(desc).slice(0, 160));
      const frames = p.callFrames || [];
      for (let fi = 0; fi < Math.min(3, frames.length); fi++) {
        const f = frames[fi];
        console.log(`\n--- frame ${fi} fn=${f.functionName || '(anon)'} @${f.location.lineNumber}:${f.location.columnNumber}`);
        for (const sc of (f.scopeChain || [])) {
          if (!['local', 'closure', 'block'].includes(sc.type) || !sc.object || !sc.object.objectId) continue;
          const props = await send('Runtime.getProperties', { objectId: sc.object.objectId, ownProperties: true, generatePreview: false });
          const vars = (props.result || []).filter(x => x.value);
          const line = vars.map(x => x.name + '=' + fmt(x.value)).join(' | ');
          if (line) console.log(`  [${sc.type}] ${line.slice(0, 600)}`);
          // espandi gli oggetti interessanti del frame 0 (candidati mX / CXI)
          if (fi === 0) {
            for (const x of vars) {
              if (x.value && x.value.type === 'object' && x.value.subtype !== 'null' && x.value.objectId) {
                const inner = await send('Runtime.getProperties', { objectId: x.value.objectId, ownProperties: true, generatePreview: false });
                const keys = (inner.result || []).map(y => y.name).slice(0, 60);
                console.log(`      >> ${x.name} keys[${keys.length}]: ${JSON.stringify(keys).slice(0, 500)}`);
              }
            }
          }
        }
      }
      // EVALUATE sul frame 0: estrai key1, verifica mX, bot-detection
      try {
        const cf0 = frames[0].callFrameId;
        const ev = async (expr) => {
          const r = await send('Debugger.evaluateOnCallFrame', { callFrameId: cf0, expression: expr, returnByValue: true, silent: true });
          if (!r || !r.result) return '?';
          if (r.exceptionDetails) return 'EXC:' + (r.result.description || '').slice(0, 60);
          return (r.result.value !== undefined) ? JSON.stringify(r.result.value) : (r.result.description || r.result.type);
        };
        const KEY1 = "s3s()[PVs(RE)].apply(null,[bw,Zv(Zv(s5)),B6,lF,Zv(Zv(dF)),c6])";
        console.log('\n=== EVAL frame 0 ===');
        console.log('key1 =', await ev(KEY1));
        console.log('typeof mX =', await ev('typeof mX'), '| mX===globalThis?', await ev('mX===globalThis'), '| mX===window?', await ev('typeof window!=="undefined"&&mX===window'));
        console.log('key1 in mX =', await ev('(' + KEY1 + ') in mX'));
        console.log('typeof mX[key1] =', await ev('typeof mX[' + KEY1 + ']'));
        console.log('mX ownKeys n =', await ev('Object.getOwnPropertyNames(mX).length'));
        console.log('ValrCFPtdqDq literal =', await ev('d1()[IUs(qC)](Ew,Tq,Og,Bx,Zv(Zv(s5)))'));
        // bot-detection: zms signal presente? dump nome del modulo
        console.log('zms type =', await ev('typeof zms'));
      } catch (e) { console.log('[eval] err', String(e && e.message).slice(0, 80)); }
      try { await send('Debugger.resume'); } catch (e) {}
      setTimeout(() => { try { ws.close(); } catch (e) {} process.exit(0); }, 300);
    }
  });

  ws.addEventListener('open', async () => {
    await send('Debugger.enable');
    await send('Runtime.enable');
    await send('Debugger.setPauseOnExceptions', { state: 'all' });
    await send('Runtime.runIfWaitingForDebugger');
    console.log('[cdp] abilitato, pauseOnExceptions=all, resume. Attendo il throw con', JSON.stringify(MATCH));
  });
  ws.addEventListener('close', () => { if (!done) console.log('[cdp] ws chiuso senza intercettare il throw'); });

  setTimeout(() => { if (!done) { console.log('[cdp] TIMEOUT 60s senza throw target'); try { ws.close(); } catch (e) {} process.exit(2); } }, 60000);
})();
