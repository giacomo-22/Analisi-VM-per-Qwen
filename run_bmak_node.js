'use strict';
// TOOLING DI ANALISI (offline, non produzione): esegue lo script-challenge sec-cpt in Node con
// stub Proxy-guidati, catturando il bytecode (atob) e le stringhe decodificate (fromCharCode)
// prima che l'anti-sandbox fermi l'esecuzione. NON e' il generatore finale (quello sara' Python).
//
// Uso: node run_seccpt_node.js seccpt_script_<t>.js
const fs = require('fs');
const SRC = process.argv[2] || 'seccpt_script_980637903.js';
let code = fs.readFileSync(SRC, 'utf8');
// URL challenge REALE (t dal filename, v passabile come 3o arg) per il path 't'-context self-run
const CHLG_T = (SRC.match(/_(\d+)\.js/) || [])[1] || '980637903';
const CHLG_V = process.env.CHLG_V || process.argv[3] || 'b8d99e74-2e86-7a4f-f52f-6d6fbc175f64';
const CHLG_URL = process.env.CHLG_URL || `https://www.fansale.it/c6bMlM/Kby/0Or/7eqXIkgy/hk9tpJua/cggyWQ/TSUmL/3pBO1EW?v=${CHLG_V}&t=${CHLG_T}`;
console.log('[cfg] challenge t=' + CHLG_T + ' v=' + CHLG_V);
// evita dump da 500KB dello stack one-line: tronca errori non gestiti
process.on('unhandledRejection', (e) => console.log('[rej]', String(e && e.message || e).slice(0, 140)));
process.on('uncaughtException', (e) => console.log('[exc]', String(e && e.message || e).slice(0, 140)));
// NB: IL SORGENTE NON VA MODIFICATO (decoder self-referenziali/offset + integrity qx8).
// Osservazione SOLO via ambiente. Logghiamo gli accessi a String/Object per capire name2/name3.
const injLogs = [];

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";

const log = [];
function note(t) { log.push(String(t).slice(0, 70)); }

// cattura atob (bytecode base64) e fromCharCode (stringhe decodificate)
const capturedAtob = [];
const decodedStrings = new Set();
global.atob = function (s) {
  try { if (s && s.length > 100) { capturedAtob.push(s); } } catch (e) {}
  return Buffer.from(s, 'base64').toString('binary');
};
global.btoa = function (s) { return Buffer.from(s, 'binary').toString('base64'); };

// NB: NON hookare String.fromCharCode (una funzione non-native rompe i check anti-sandbox
// toString()==='[native code]'). Usiamo la nativa.

// Proxy ricorsivo: qualunque accesso ritorna uno stub chiamabile+indicizzabile; logga i path.
const NATIVE = 'function () { [native code] }';
const WRAPPED = new WeakSet();
// ---- OROLOGIO VIRTUALE UNICO (una sola sorgente di tempo: perf.now, Date, timer, rAF ne derivano) ----
// Il clock avanza SOLO nel pump (non a ogni now()), cosi' Hm()=ctG()-rAG() -- memoizzato, chiamate
// sincrone -- resta 0 (coerente col decode di init) MENTRE il tempo puo' scorrere per il gate press-hold.
const T0 = process.env.T0 !== undefined ? +process.env.T0 : 800;   // perf.now() iniziale (sweepabile)
const D0 = process.env.D0 !== undefined ? +process.env.D0 : 1792170586210;  // epoch assoluto (sweepabile; default = ground-truth 320873278)
const clock = { vt: T0, deadline: Infinity };
const perfNow = () => clock.vt;
const epochNow = () => D0 + (clock.vt - T0);       // drift perf<->Date = 0 per costruzione
const PERF = { calls: 0 };                         // compat col resto del file
// coda timer con cancellazione reale
let __seq = 0;
const __q = [];
function schedule(fn, at, interval) { const id = ++__seq; __q.push({ id, fn, at, interval, cancelled: false }); return id; }
function cancelTimer(id) { const t = __q.find((x) => x.id === id); if (t) t.cancelled = true; }
function sweepTimers() { for (let i = __q.length - 1; i >= 0; i--) if (__q[i].cancelled) __q.splice(i, 1); }
// Date deterministica derivata dal clock virtuale (coerente con performance.now()).
const RealDate = Date;
class FakeDate extends RealDate {
  constructor(...a) { if (a.length) super(...a); else super(epochNow()); }
  static now() { return epochNow(); }
}
const DOMWALK = new Set(['parentNode', 'parentElement', 'nextSibling', 'previousSibling',
  'nextElementSibling', 'previousElementSibling', 'firstChild', 'lastChild', 'firstElementChild',
  'lastElementChild', 'offsetParent', 'ownerElement', 'host', 'frameElement', 'opener']);
// built-in JS che i DECODER usano: NON vanno wrappati (servono reali).
const BUILTINS = new Set(['String', 'Object', 'Array', 'Math', 'Date', 'JSON', 'Number', 'Boolean',
  'RegExp', 'Function', 'Error', 'parseInt', 'parseFloat', 'isNaN', 'Symbol', 'Proxy', 'Reflect',
  'Map', 'Set', 'WeakMap', 'WeakSet', 'Promise', 'ArrayBuffer', 'Uint8Array', 'Int32Array',
  'Uint32Array', 'encodeURIComponent', 'decodeURIComponent', 'escape', 'unescape', '__LOG']);
function makeStub(path) {
  const fn = function () { return makeStub(path + '()'); };
  return new Proxy(fn, {
    get(t, prop) {
      if (prop === Symbol.toPrimitive) return () => 0;
      if (prop === 'toString' || prop === 'toLocaleString') return () => NATIVE;
      if (prop === Symbol.toStringTag) return undefined;
      if (prop === 'length') return 0;
      if (prop === 'name') return '';
      // proprieta' di navigazione DOM -> null (termina i walk `while(node){node=node.parentNode}`)
      if (DOMWALK.has(prop)) return null;
      if (prop === 'call') return function () { return makeStub(path + '.call()'); };
      if (prop === 'apply') return function () { return makeStub(path + '.apply()'); };
      if (typeof prop === 'symbol') return undefined;
      const p = path + '.' + String(prop);
      note(p);
      return makeStub(p);
    },
    apply() { return makeStub(path + '()'); },
    construct() { return makeStub('new ' + path); },
  });
}

// wrapFn: avvolge una funzione reale -> callable reale, toString "[native code]",
// metodo-ignoto -> stub cascante (cosi' fn[nomeDecodato] e' sempre una funzione).
function wrapFn(fn, path) {
  return new Proxy(fn, {
    get(t, p) {
      if (p === 'toString' || p === 'toLocaleString') return () => 'function ' + (t.name || '') + '() { [native code] }';
      if (p === 'name') return t.name || '';
      if (p === 'length') return t.length || 0;
      if (p === 'prototype') return t.prototype;
      if (typeof p === 'symbol') return t[p];
      if (p in t) return t[p];
      note(path + '.' + String(p));
      return makeStub(path + '.' + String(p));
    },
    apply(t, thiz, args) { try { return Reflect.apply(t, thiz, args); } catch (e) { return makeStub(path + '()'); } },
    construct(t, args) { try { return Reflect.construct(t, args); } catch (e) { return makeStub('new ' + path); } },
  });
}
// stub-elemento DOM realistico (per i container della challenge)
function makeElement(tag) {
  tag = (tag || 'div');
  const el = {
    tagName: tag.toUpperCase(), nodeType: 1, nodeName: tag.toUpperCase(), namespaceURI: 'http://www.w3.org/1999/xhtml',
    style: {}, className: '', id: '', innerHTML: '', outerHTML: '', textContent: '', value: '', name: '', type: '',
    children: [], childNodes: [], attributes: [], dataset: {},
    classList: { add() {}, remove() {}, contains() { return false; }, toggle() {}, replace() {} },
    appendChild: (c) => c, removeChild: (c) => c, insertBefore: (c) => c, replaceChild: (c) => c, remove() {},
    setAttribute() {}, getAttribute: () => null, removeAttribute() {}, hasAttribute: () => false, getAttributeNode: () => null,
    addEventListener: (ev, cb) => regListener(el, ev, cb), removeEventListener() {}, dispatchEvent: () => true,
    getBoundingClientRect: () => ({ x: 60, y: 200, width: 200, height: 60, top: 200, left: 60, right: 260, bottom: 260 }),
    getClientRects: () => [{ x: 8, y: 8, width: 300, height: 150, top: 8, left: 8, right: 308, bottom: 158 }],
    querySelector: () => null, querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [],
    contains: () => false, cloneNode: () => makeElement(tag), focus() {}, blur() {}, click() {}, closest: () => null,
    offsetWidth: 300, offsetHeight: 150, offsetTop: 8, offsetLeft: 8, clientWidth: 300, clientHeight: 150,
    scrollWidth: 300, scrollHeight: 150, scrollTop: 0, scrollLeft: 0, getContext: () => makeStub('ctx'),
    setAttributeNS() {}, appendData() {}, insertAdjacentHTML() {}, matches: () => false,
  };
  return wrapObj(el, 'el.' + tag);
}
// wrapObj: oggetto con props reali + catch-all. Le FUNZIONI reali vengono avvolte con wrapFn.
function wrapObj(real, path) {
  return new Proxy(real, {
    get(t, p) {
      if (typeof p === 'symbol') return t[p];
      if (p === 'toString') return () => NATIVE;
      if (p in t) {
        const v = t[p];
        return (typeof v === 'function') ? wrapFn(v, path + '.' + String(p)) : v;
      }
      note(path + '.' + String(p));
      return makeStub(path + '.' + String(p));
    },
    has() { return true; },
    set(t, p, v) { t[p] = v; return true; },
  });
}

const navReads = [];
const navigatorStub = new Proxy(wrapObj({
  userAgent: UA, platform: 'Win32', language: 'it-IT', languages: ['it-IT'],
  hardwareConcurrency: 12, deviceMemory: 16, vendor: 'Google Inc.', appVersion: UA.slice(8),
  webdriver: false, cookieEnabled: true, onLine: true, maxTouchPoints: 0, doNotTrack: null,
  pdfViewerEnabled: true,
  sendBeacon: function (u, b) { try { xhrCalls.push({ method: 'POST(beacon)', url: String(u), body: b != null ? String(b) : '' }); } catch (e) {} return true; },
  plugins: { length: 5, item: () => null, refresh: () => {} }, mimeTypes: { length: 2 },
}, 'navigator'), {
  get(t, p) {
    const v = Reflect.get(t, p);
    if (typeof p === 'string' && navReads.length < 300) {
      let sv; try { sv = (typeof v === 'object' || typeof v === 'function') ? Object.prototype.toString.call(v) : String(v); } catch (e) { sv = '?'; }
      navReads.push(p + ' = ' + String(sv).slice(0, 60));
    }
    return v;
  },
});

const docReads = [];
const docStub = new Proxy(wrapObj({
  cookie: (process.env.DOC_COOKIE || ''), readyState: 'complete', referrer: 'https://www.fansale.it/',
  title: 'fanSALE - Il mercato TicketOne per lo scambio di biglietti da fan a fan',
  characterSet: 'UTF-8', charset: 'UTF-8', compatMode: 'CSS1Compat', contentType: 'text/html', inputEncoding: 'UTF-8',
  currentScript: new Proxy(wrapObj({
    src: CHLG_URL,
    getAttribute: (n) => { docReads.push('currentScript.getAttribute(' + n + ')'); return (n === 'src' ? CHLG_URL : null); },
    nonce: '', type: 'text/javascript', async: false, defer: false,
  }, 'document.currentScript'), { get(t, p) { const v = Reflect.get(t, p); if (typeof p === 'string') { let sv; try { sv = (typeof v === 'object' || typeof v === 'function') ? Object.prototype.toString.call(v) : String(v); } catch (e) { sv = '?'; } docReads.push('currentScript.' + p + ' = ' + String(sv).slice(0, 50)); } return v; } }),
  activeElement: new Proxy(wrapObj({ getAttribute: () => null, tagName: 'DIV', nodeType: 1, nodeName: 'DIV', id: '', className: '' }, 'document.activeElement'), { get(t, p) { const v = Reflect.get(t, p); if (typeof p === 'string') docReads.push('activeElement.' + p); return v; } }),
  nodeType: 9, hidden: false, visibilityState: 'visible', hasFocus: () => true,
  body: wrapObj({ nodeType: 1, tagName: 'BODY', scrollTop: 0, scrollLeft: 0, clientWidth: 1280, clientHeight: 720, scrollWidth: 1280, scrollHeight: 720, offsetWidth: 1280, offsetHeight: 720 }, 'document.body'),
  createElement: (tag) => makeElement(tag), createElementNS: (ns, tag) => makeElement(tag),
  getElementsByTagName: () => [],
  getElementById: (id) => (elemCache['#' + id] || (elemCache['#' + id] = Object.assign(makeElement('div'), { id: String(id) }))),
  addEventListener: function (ev, cb) { regListener(docStub, ev, cb); },
  querySelector: (s) => (elemCache[s] || (elemCache[s] = makeElement('div'))),
  querySelectorAll: (s) => [elemCache[s] || (elemCache[s] = makeElement('div'))],
  documentElement: wrapObj({ nodeType: 1, tagName: 'HTML', nodeName: 'HTML', clientWidth: 1280, clientHeight: 720, scrollWidth: 1280, scrollHeight: 720, offsetWidth: 1280, offsetHeight: 720, scrollTop: 0, scrollLeft: 0, clientTop: 0, clientLeft: 0, style: {}, classList: { add() {}, remove() {}, contains: () => false }, getAttribute: () => null, setAttribute() {}, appendChild: (c) => c, lang: 'it' }, 'document.documentElement'), head: makeElement('head'),
  location: wrapObj({ href: 'https://www.fansale.it/', host: 'www.fansale.it', hostname: 'www.fansale.it',
    protocol: 'https:', pathname: '/', search: '', hash: '', origin: 'https://www.fansale.it' }, 'document.location'),
}, 'document'), {
  get(t, p) {
    const v = Reflect.get(t, p);
    if (typeof p === 'string' && docReads.length < 400) {
      let sv; try { sv = (typeof v === 'object' || typeof v === 'function') ? Object.prototype.toString.call(v) : String(v); } catch (e) { sv = '?'; }
      docReads.push(p + ' = ' + String(sv).slice(0, 50));
    }
    return v;
  },
});

const vm = require('vm');
const xhrCalls = [];
const winListeners = [];
// registry unico degli handler su QUALSIASI target (document/elementi) per l'event-replay del gate
const listeners = [];           // { target, ev, cb }
const elemCache = {};           // getElementById/querySelector -> stessa istanza (per dispatchare dopo)
function regListener(target, ev, cb) { if (typeof cb === 'function') listeners.push({ target, ev: String(ev), cb }); }
const intervalFns = [];
function XHRc() {
  this._m = ''; this._u = '';
  this.open = function (m, u) { this._m = m; this._u = u; };
  this.send = function (b) { xhrCalls.push({ method: this._m, url: this._u, body: b ? String(b) : '' }); };
  this.setRequestHeader = function () {};
  this.addEventListener = function () {};
  this.getAllResponseHeaders = function () { return ''; };
  this.readyState = 4; this.status = 200; this.responseText = '';
}
XHRc.prototype = {};

const perfReads = [];
const atobLog = [];
// MOVE 3c: logger di fromCharCode + DECODE-ORACLE (forza gli output ai char corretti del browser)
const fccBuf = [];
const RealFCC = String.fromCharCode;
let ORACLE = null;            // codici corretti del browser (stesso script)
let oracleOffset = -1;        // dove il flusso harness inizia nel browser
let oracleIdx = 0;            // posizione corrente nel flusso browser
const harnessPrefix = [];     // primi char harness per trovare l'offset
const ORACLE_ON = !!process.env.ORACLE;
if (ORACLE_ON) {
  try {
    const bo = JSON.parse(fs.readFileSync('fromcharcode_browser.json', 'utf8'));
    if (bo && bo.script === SRC) { ORACLE = bo.codes; console.log('[oracle] caricato: ' + ORACLE.length + ' codici browser (stesso script)'); }
    else console.log('[oracle] fromcharcode_browser.json e\' di un altro script (' + (bo && bo.script) + ') - oracle OFF');
  } catch (e) { console.log('[oracle] load fallito:', String(e).slice(0, 60)); }
}
function findSub(arr, sub, from) {
  for (let i = from || 0; i < arr.length - sub.length; i++) {
    let ok = true;
    for (let k = 0; k < sub.length; k++) if (arr[i + k] !== sub[k]) { ok = false; break; }
    if (ok) return i;
  }
  return -1;
}
// INSPECTOR in-process: al decode "touchend" (char ~5761) legge lo scope del caller (decoder VM)
// via Debugger.paused → vede enc/base/key anche se bracket-indexed (sono variabili nello scope).
const INSPECT = !!process.env.INSPECT;
const INSPECT_AT = INSPECT ? (+process.env.INSPECT_AT || 5761) : -1;
let inspectDone = false;
const inspectDump = [];
let insp = null;
if (INSPECT) {
  const inspector = require('inspector');
  insp = new inspector.Session();
  insp.connect();
  insp.post('Debugger.enable', () => {});
  insp.post('Runtime.enable', () => {});
  // STEP 3 (chirurgico): pausa all'eccezione non catturata -> dump dello scope al throw
  // (legge la chiave X in Gr[X], mX, CXI) per discriminare hook-mancante vs decode-corrotto.
  if (process.env.PAUSETHROW) insp.post('Debugger.setPauseOnExceptions', { state: 'uncaught' }, () => {});
  // Enumera TUTTE le variabili locali/closure di ogni frame via scopeChain + Runtime.getProperties.
  // I nomi delle var ruotano per challenge → niente guessing: dump completo dello scope reale.
  const fmtVal = (v) => {
    if (!v) return 'undefined';
    if (v.type === 'string') { const s = v.value != null ? v.value : v.description; return 'str(len=' + (s ? s.length : '?') + ') ' + JSON.stringify((s || '').slice(0, 48)); }
    if (v.type === 'number' || v.type === 'boolean') return String(v.value);
    if (v.type === 'object') {
      if (v.subtype === 'array') return 'array ' + (v.description || '');
      return (v.className || 'obj') + ' ' + (v.description || '');
    }
    if (v.type === 'function') return 'fn';
    return v.type + ' ' + (v.description || '');
  };
  // espande un array (objectId) e logga i suoi elementi; per elementi array annidati, risolve 1 livello
  const expand = (label, objectId, cb) => {
    insp.post('Runtime.getProperties', { objectId: objectId, ownProperties: true, generatePreview: false }, (err, res) => {
      const props = (res && res.result) || [];
      const els = [];
      const nested = []; // {idx, objectId}
      try {
        for (const p of props) {
          if (/^\d+$/.test(p.name) && p.value) {
            const idx = els.length;
            if (p.value.type === 'number' || p.value.type === 'string') els.push(p.value.value);
            else if (p.value.subtype === 'array' && p.value.objectId) { els.push('ARR?'); nested.push({ i: idx, oid: p.value.objectId }); }
            else els.push('<' + (p.value.className || p.value.subtype || p.value.type) + '>');
          }
        }
      } catch (e) {}
      // risolvi gli array annidati in sequenza
      let k = 0;
      const next = () => {
        if (k >= nested.length) {
          inspectDump.push('      >> ' + label + ' [' + els.length + ']: ' + JSON.stringify(els).slice(0, 4000));
          return cb();
        }
        const { i, oid } = nested[k++];
        insp.post('Runtime.getProperties', { objectId: oid, ownProperties: true, generatePreview: false }, (e2, r2) => {
          try {
            const inner = ((r2 && r2.result) || []).filter(x => /^\d+$/.test(x.name) && x.value).map(x => (x.value.type === 'number' || x.value.type === 'string') ? x.value.value : '<' + (x.value.className || x.value.type) + '>');
            els[i] = 'ARR' + JSON.stringify(inner);
          } catch (e) {}
          next();
        });
      };
      next();
    });
  };
  insp.on('Debugger.paused', (msg) => {
    const frames = msg.params.callFrames || [];
    let pending = 1;
    const done = () => { if (--pending <= 0) insp.post('Debugger.resume', () => {}); };
    for (let fi = 0; fi < Math.min(5, frames.length); fi++) {
      const f = frames[fi];
      inspectDump.push('=== frame ' + fi + ' fn=' + (f.functionName || '(anon)'));
      const scopes = f.scopeChain || [];
      for (let si = 0; si < scopes.length; si++) {
        const sc = scopes[si];
        if (sc.type !== 'local' && sc.type !== 'closure' && sc.type !== 'block') continue;
        if (!sc.object || !sc.object.objectId) continue;
        pending++;
        const scType = sc.type;
        const frameIdx = fi;
        insp.post('Runtime.getProperties', { objectId: sc.object.objectId, ownProperties: true, generatePreview: false }, (err, res) => {
          try {
            const props = (res && res.result) || [];
            const parts = [];
            for (const p of props) {
              if (!p.value) continue;
              if (p.value.type === 'number' || p.value.type === 'string' || p.value.type === 'boolean') {
                parts.push(p.name + '=' + fmtVal(p.value));
              } else if (p.value.type === 'object' && p.value.subtype === 'array') {
                parts.push(p.name + '=' + fmtVal(p.value));
              }
            }
            if (parts.length) inspectDump.push('    [' + scType + '] ' + parts.join(' | '));
            // espandi array piccoli (<=400) e stringhe lunghe nei frame del decoder (1,2,3)
            if ((scType === 'local' || scType === 'block') && frameIdx <= 3) {
              for (const p of props) {
                if (!p.value) continue;
                const isArr = p.value.type === 'object' && p.value.subtype === 'array' && p.value.objectId;
                const isLongStr = p.value.type === 'string' && p.value.value && p.value.value.length > 40;
                if (isArr) {
                  const m = /\((\d+)\)/.exec(p.value.description || '');
                  const len = m ? +m[1] : 999;
                  if (len <= 400) { pending++; expand('f' + frameIdx + '.' + p.name, p.value.objectId, done); }
                } else if (isLongStr) {
                  inspectDump.push('      >> f' + frameIdx + '.' + p.name + ' FULLSTR(len=' + p.value.value.length + '): ' + JSON.stringify(p.value.value).slice(0, 600));
                }
              }
            }
          } catch (e) {}
          done();
        });
      }
    }
    done();
  });
}
// DELTA-BASE: traccia unificata charCodeAt/fromCharCode per ricostruire enc/base/SQ.c8 al decode "touchend"
const DBASE_ON = !!process.env.DBASE;
const decTrace = [];            // [1,len,idx,ret] per charCodeAt ; [2,code] per fromCharCode
let keyString = null;           // SQ.c8 (stringa lunga)
if (DBASE_ON) {
  const RealCCA = String.prototype.charCodeAt;
  String.prototype.charCodeAt = function (i) {
    const r = RealCCA.call(this, i);
    try {
      if (decTrace.length < 3000000) {
        const len = this.length;
        decTrace.push([1, len, i | 0, r]);
        if (len > 2000 && keyString === null) keyString = String(this);
      }
    } catch (e) {}
    return r;
  };
  try { String.prototype.charCodeAt.toString = () => 'function charCodeAt() { [native code] }'; } catch (e) {}
}
function fccLogger() {
  const out = [];
  for (let i = 0; i < arguments.length; i++) {
    let code = arguments[i] | 0;
    if (DBASE_ON && decTrace.length < 3000000) decTrace.push([2, code]);
    if (INSPECT && !inspectDone && fccBuf.length >= INSPECT_AT) { inspectDone = true; inspectDump.push('[inspect] pausa a fccBuf.length=' + fccBuf.length + ' code=' + code); debugger; }  // eslint-disable-line no-debugger
    if (ORACLE) {
      if (oracleOffset < 0) {
        harnessPrefix.push(code);
        if (harnessPrefix.length === 80) {
          oracleOffset = findSub(ORACLE, harnessPrefix, 0);
          if (oracleOffset >= 0) { oracleIdx = 80; console.log('[oracle] allineato: harness[0]==browser[' + oracleOffset + ']'); }
          else console.log('[oracle] NON allineato (prefix non trovato) - oracle inattivo');
        }
      } else {
        const bc = ORACLE[oracleOffset + oracleIdx];
        if (bc !== undefined) code = bc;   // FORZA il char corretto del browser
        oracleIdx++;
      }
    }
    if (fccBuf.length < 150000) fccBuf.push(code);
    out.push(code);
  }
  return RealFCC.apply(String, out);
}
const StringProxy = new Proxy(String, { get(t, p) { if (p === 'fromCharCode') return fccLogger; return Reflect.get(t, p); } });
// R-test: conta le chiamate a Math.random (se 0 prima del garble -> RNG escluso)
const rng = { count: 0, atGarble: null };
const RealRandom = Math.random;
const MathProxy = new Proxy(Math, { get(t, p) { if (p === 'random') return () => { rng.count++; return (process.env.RNGFIX ? 0.5 : RealRandom()); }; return Reflect.get(t, p); } });
const sandbox = {
  atob: (s) => { try { atobLog.push(String(s).length + ':' + String(s).slice(0, 30)); } catch (e) {} return global.atob(s); }, btoa: global.btoa,
  navigator: navigatorStub, document: docStub,
  screen: wrapObj({ width: 1280, height: 720, availWidth: 1280, availHeight: 720, colorDepth: 24, pixelDepth: 24, availLeft: 0, availTop: 0 }, 'screen'),
  history: wrapObj({ length: 1, scrollRestoration: 'auto', state: null,
    pushState() {}, replaceState() {}, go() {}, back() {}, forward() {} }, 'history'),
  location: wrapObj({ href: 'https://www.fansale.it/', origin: 'https://www.fansale.it', protocol: 'https:', host: 'www.fansale.it', pathname: '/' }, 'location'),
  performance: new Proxy(wrapObj({
    now: () => { PERF.calls++; return perfNow() + (process.env.PNADV ? PERF.calls * (+process.env.PNADV) : 0); }, timeOrigin: D0 - T0,
    getEntriesByType: (t) => { perfReads.push('getEntriesByType(' + t + ')'); return (process.env.PERF_EMPTY ? [] : (t === 'navigation'
      ? [{ name: 'https://www.fansale.it/', type: 'navigate', startTime: 0, duration: 800, entryType: 'navigation' }]
      : t === 'resource'
        ? [{ name: CHLG_URL, entryType: 'resource', startTime: 10, duration: 50, initiatorType: 'script' }]
        : [])); },
    getEntries: () => [], getEntriesByName: () => [], clearResourceTimings: () => {},
    mark: () => {}, measure: () => {},
  }, 'performance'), { get(t, p) { if (typeof p === 'string' && perfReads.length < 200) perfReads.push(p); return Reflect.get(t, p); } }),
  pageXOffset: 0, pageYOffset: 0, scrollX: 0, scrollY: 0, innerWidth: 1280, innerHeight: 720,
  outerWidth: 1296, outerHeight: 808, devicePixelRatio: 1, screenX: 10, screenY: 10, screenLeft: 10, screenTop: 10,
  XMLHttpRequest: XHRc,
  fetch: function (u, o) { try { xhrCalls.push({ method: (o && o.method) || 'GET', url: String(u), body: (o && o.body) ? String(o.body) : '' }); } catch (e) {} return { then: () => ({ then: () => ({ catch: () => {} }), catch: () => {} }), catch: () => {} }; },
  addEventListener: function (ev, cb) { try { if (typeof cb === 'function') { winListeners.push({ ev: String(ev), cb }); regListener(sandboxProxy, ev, cb); } } catch (e) {} },
  removeEventListener: () => {},
  dispatchEvent: () => true,
  requestAnimationFrame: (f) => schedule(() => { try { f(clock.vt); } catch (e) {} }, clock.vt + 16.667),
  cancelAnimationFrame: (id) => cancelTimer(id),
  queueMicrotask: (f) => { Promise.resolve().then(() => { try { f(); } catch (e) {} }); },
  MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] }; },
  setTimeout: (f, d, ...a) => schedule(() => { try { if (typeof f === 'function') f(...a); } catch (e) {} }, clock.vt + Math.max(0, +d || 0)),
  setInterval: (f, d, ...a) => schedule(() => { try { if (typeof f === 'function') f(...a); } catch (e) {} }, clock.vt + Math.max(1, +d || 1), Math.max(1, +d || 1)),
  clearInterval: (id) => cancelTimer(id), clearTimeout: (id) => cancelTimer(id),
  MessageChannel: function () {
    const mk = () => ({
      onmessage: null, start() {}, close() {},
      postMessage(d) { const pr = this; schedule(() => { try { pr._pair && pr._pair.onmessage && pr._pair.onmessage({ data: d }); } catch (e) {} }, clock.vt); },
    });
    this.port1 = mk(); this.port2 = mk();
    this.port1._pair = this.port2; this.port2._pair = this.port1;
  },
  Image: function () { return makeStub('Image'); },
  String: StringProxy, Object, Array, Math: MathProxy, Date: FakeDate, JSON, Number, RegExp, Error, Function, Boolean,
  parseInt, parseFloat, isNaN, encodeURIComponent, decodeURIComponent, Symbol, Proxy, Reflect,
  Uint8Array, Int32Array, Uint32Array, ArrayBuffer, Map, Set, WeakMap, WeakSet, Promise,
  console: { log: () => {}, error: () => {}, warn: () => {} },
};
// interfacce DOM standard (ESISTONO in un browser reale): funzione con toString nativo + prototype.
function nativeIface(name, proto, statics) {
  const f = function () { return makeStub(name); };
  try { Object.defineProperty(f, 'name', { value: name }); } catch (e) {}
  f.prototype = proto || {};
  f.toString = () => 'function ' + name + '() { [native code] }';
  if (statics) Object.assign(f, statics);
  return f;
}
const DOM = {};
['Document', 'HTMLDocument', 'Window', 'Element', 'HTMLElement', 'HTMLDivElement', 'HTMLSpanElement',
 'HTMLIFrameElement', 'HTMLCanvasElement', 'HTMLScriptElement', 'HTMLBodyElement', 'HTMLInputElement',
 'HTMLAnchorElement', 'HTMLImageElement', 'Event', 'UIEvent', 'MouseEvent', 'KeyboardEvent', 'PointerEvent',
 'TouchEvent', 'FocusEvent', 'CustomEvent', 'EventTarget', 'CharacterData', 'Text', 'Attr', 'NamedNodeMap',
 'NodeList', 'HTMLCollection', 'DOMTokenList', 'CSSStyleDeclaration', 'File', 'Blob', 'FileReader', 'FormData',
 'PushManager', 'ServiceWorker', 'ServiceWorkerRegistration', 'Notification', 'MediaQueryList', 'Screen',
 'History', 'Location', 'Navigator', 'Storage', 'Performance', 'PerformanceEntry', 'PerformanceObserver',
 'IntersectionObserver', 'ResizeObserver', 'MutationObserver', 'WebSocket', 'Worker', 'SharedWorker',
 'Crypto', 'SubtleCrypto', 'TextEncoder', 'TextDecoder', 'URL', 'URLSearchParams', 'Headers', 'Request',
 'Response', 'AbortController', 'DOMParser', 'XPathResult', 'Range', 'Selection', 'DOMRect', 'DOMRectReadOnly',
 'WebGLRenderingContext', 'WebGL2RenderingContext', 'CanvasRenderingContext2D', 'AudioContext', 'OfflineAudioContext',
 'RTCPeerConnection', 'MediaStream', 'Plugin', 'PluginArray', 'MimeType', 'MimeTypeArray', 'BarProp',
 'HTMLFormElement', 'HTMLButtonElement', 'SVGElement', 'ShadowRoot', 'CSS', 'FontFace'].forEach((n) => {
  DOM[n] = nativeIface(n, {});
});
DOM.Node = nativeIface('Node', {}, { ELEMENT_NODE: 1, ATTRIBUTE_NODE: 2, TEXT_NODE: 3, CDATA_SECTION_NODE: 4,
  PROCESSING_INSTRUCTION_NODE: 7, COMMENT_NODE: 8, DOCUMENT_NODE: 9, DOCUMENT_TYPE_NODE: 10, DOCUMENT_FRAGMENT_NODE: 11 });
Object.assign(sandbox, DOM);
sandbox.__LOG = (x) => { injLogs.push(String(x)); };
// catch-all: qualunque global indefinito -> stub (niente ReferenceError), 'in' -> true
const sandboxProxy = new Proxy(sandbox, {
  has() { return true; },
  get(t, p) {
    if (typeof p !== 'symbol') note('G.' + String(p));
    if (p in t) return t[p];   // valori reali (niente wrapping invasivo: destabilizza i decoder)
    // STUB-AND-SEE (PERMISSIVE=1): global ignoto -> stub cascante invece di undefined,
    // per testare se i "muri" per-sessione (es. ValrCFPtdqDq) sono di PRESENZA o di CONTENUTO.
    if (process.env.PERMISSIVE) { note('G?.' + String(p)); return makeStub('G.' + String(p)); }
    return undefined;          // global ignoto -> undefined (fedele: API mancante in un browser)
  },
  set(t, p, v) { t[p] = v; return true; },
});
// window/self/globalThis/top -> il PROXY (cosi' hn=window usa il catch-all/wrapping, non il raw)
sandbox.window = sandboxProxy; sandbox.self = sandboxProxy; sandbox.globalThis = sandboxProxy; sandbox.top = sandboxProxy;
// STUB2 (targeted): fornisci SOLO i 2 global noti mancanti (lStr-1r, kwRStnGOCD) come
// oggetti self-returning, per misurare quanto avanza l'init (ordine-moduli vs detection vs cascata).
if (process.env.STUB2) {
  const mkObj = (nm) => { const f = function () { return o; }; const o = new Proxy(f, {
    get(t, p) { if (p === Symbol.toPrimitive) return () => 0; if (p === 'toString' || p === 'valueOf') return () => ''; if (typeof p === 'symbol') return undefined; return o; },
    apply() { return o; }, construct() { return o; }, has() { return true; } }); return o; };
  for (const nm of (process.env.STUB2NAMES || 'lStr-1r,kwRStnGOCD').split(',')) sandbox[nm] = mkObj(nm);
  console.log('[stub2] forniti global:', process.env.STUB2NAMES || 'lStr-1r,kwRStnGOCD');
}
vm.createContext(sandboxProxy);

// FIXGLOBALS (targeted anti-sandbox): il check rW itera una lista di global e ne legge .constructor
// via accesso DINAMICO globalThis[name]. Siccome globalThis e' il Proxy e `name` non e' own-prop di
// sandbox, il get ritorna undefined -> undefined.constructor THROW. Esponiamo gli intrinseci del
// CONTESTO stesso (via eval = risoluzione lessicale, stesso realm) su globalThis cosi' l'accesso
// dinamico li trova. NON usiamo i built-in dell'host (eviterebbe il realm hole).
if (process.env.FIXGLOBALS) {
  const INTR = ['Object','Function','Array','Number','Boolean','String','Symbol','Date','Promise','RegExp',
    'Error','AggregateError','EvalError','RangeError','ReferenceError','SyntaxError','TypeError','URIError',
    'JSON','Math','Intl','ArrayBuffer','Atomics','Uint8Array','Int8Array','Uint16Array','Int16Array',
    'Uint32Array','Int32Array','BigUint64Array','BigInt64Array','Uint8ClampedArray','Float32Array','Float64Array',
    'DataView','Map','BigInt','Set','WeakMap','WeakSet','Proxy','Reflect','WeakRef','FinalizationRegistry',
    'SharedArrayBuffer','WebAssembly','escape','unescape','encodeURI','encodeURIComponent','decodeURI',
    'decodeURIComponent','isNaN','isFinite','parseFloat','parseInt'];
  try {
    vm.runInContext('(function(){var n=' + JSON.stringify(INTR) + ';for(var i=0;i<n.length;i++){try{if(globalThis[n[i]]===undefined)globalThis[n[i]]=eval(n[i]);}catch(e){}}})()', sandboxProxy);
    console.log('[fixglobals] intrinseci esposti su globalThis:', INTR.length);
  } catch (e) { console.log('[fixglobals] errore:', String(e && e.message).slice(0, 80)); }
}

// DELTA-BASE in-realm: patcha i metodi stringa del REALM VM (Object.getPrototypeOf('')),
// NON String.prototype dell'host (che via StringProxy rimonta all'host = realm hole).
if (DBASE_ON) {
  sandbox.__vmTrace = (ev) => { if (decTrace.length < 3000000) decTrace.push(ev); };
  sandbox.__vmKey = (s) => { if (keyString === null && s && s.length > 2000) keyString = String(s); };
  try {
    vm.runInContext(`(function(){
      var SP = Object.getPrototypeOf('');
      var send = globalThis.__vmTrace, key = globalThis.__vmKey;
      function spoof(f,n){ try{ Object.defineProperty(f,'name',{value:n}); f.toString=function(){return 'function '+n+'() { [native code] }';}; }catch(e){} return f; }
      function wrap(orig,name,tag){ return spoof(function(){ var r=orig.apply(this,arguments);
        try{ if(this.length>2000) key(this); send([tag, this.length, arguments[0]|0, typeof r==='string'?(r.length===1?r.charCodeAt(0):-2):r]); }catch(e){}
        return r; }, name); }
      SP.charCodeAt  = wrap(SP.charCodeAt,'charCodeAt',1);
      SP.charAt      = wrap(SP.charAt,'charAt',3);
      SP.codePointAt = wrap(SP.codePointAt,'codePointAt',4);
    })();`, sandboxProxy);
    console.log('[dbase] patch in-realm installato (charCodeAt/charAt/codePointAt del realm VM)');
  } catch (e) { console.log('[dbase] patch in-realm FALLITO:', String(e && e.message || e).slice(0, 80)); }
}

let err = null;
try {
  vm.runInContext(code, sandboxProxy, { timeout: 15000 });
} catch (e) {
  err = (e && e.name ? e.name + ': ' + e.message : String(e)).slice(0, 300);
  // estrai la colonna nel sorgente one-line e mostra il contesto
  try {
    const m = /evalmachine[^:]*:1:(\d+)/.exec(e.stack || '');
    if (m) {
      const col = parseInt(m[1], 10);
      err += `\n   @col ${col}: ...${code.slice(Math.max(0, col - 90), col + 40)}...`;
    }
  } catch (e2) {}
}
console.log('[init-fine] fromCharCode prodotti durante init (pre-pump):', fccBuf.length, '| Math.random:', rng.count, '| err:', err ? err.slice(0, 50) : 'no');

// DIAG bmak: cosa espone? cerca l'oggetto bmak e metodi che generano/inviano il sensor.
try {
  const probe = (obj, path, depth) => {
    if (!obj || depth > 1) return;
    let keys = [];
    try { keys = Object.keys(obj); } catch (e) {}
    for (const k of keys) {
      let v; try { v = obj[k]; } catch (e) { continue; }
      const tn = typeof v;
      if (tn === 'function') {
        let src = ''; try { src = Function.prototype.toString.call(v); } catch (e) {}
        const hit = /sensor_data|sendBeacon|XMLHttp|get_cf|sensor/i.test(src) ? ' <<<SEND?' : '';
        console.log(`[bmak-api] ${path}.${k}() argc=${v.length}${hit}`);
      } else if (tn === 'object' && v && depth < 1) {
        console.log(`[bmak-api] ${path}.${k} = {obj}`);
        probe(v, path + '.' + k, depth + 1);
      } else {
        console.log(`[bmak-api] ${path}.${k} = ${String(v).slice(0, 40)} (${tn})`);
      }
    }
  };
  for (const g of ['bmak', 'ak', 'abck', '_cf', 'bmak_']) {
    if (sandbox[g] !== undefined) { console.log('[bmak-api] GLOBAL', g, 'presente'); probe(sandbox[g], g, 0); }
  }
  // scansiona TUTTE le globali del sandbox per funzioni con "sensor_data" nel sorgente
  for (const k of Object.keys(sandbox)) {
    let v; try { v = sandbox[k]; } catch (e) { continue; }
    if (typeof v === 'function') { let s = ''; try { s = Function.prototype.toString.call(v); } catch (e) {} if (/sensor_data/.test(s)) console.log('[bmak-api] GLOBAL fn', k, 'contiene "sensor_data"'); }
  }
} catch (e) { console.log('[bmak-api] diag err', String(e && e.message).slice(0, 80)); }

// DUMP sorgenti di listFunctions (_fetchParams/_set*) = superficie di init
try {
  const lf = sandbox.bmak && sandbox.bmak.listFunctions;
  if (lf) {
    const out = [];
    for (const k of Object.keys(lf)) {
      let v; try { v = lf[k]; } catch (e) { continue; }
      if (typeof v === 'function') { let s = ''; try { s = Function.prototype.toString.call(v); } catch (e) {} out.push('// ===== listFunctions.' + k + ' (argc=' + v.length + ') =====\n' + s + '\n'); }
    }
    fs.writeFileSync('bmak_listfunctions_src.js', out.join('\n'));
    console.log('[initfn] dump listFunctions ->', out.length, 'funzioni -> bmak_listfunctions_src.js');
  }
} catch (e) { console.log('[initfn] err', String(e && e.message).slice(0, 80)); }

// PROVA a chiamare _fetchParams e cattura la richiesta di rete (URL params dal server)
try {
  const lf = sandbox.bmak && sandbox.bmak.listFunctions;
  if (lf && typeof lf._fetchParams === 'function') {
    const n0 = xhrCalls.length;
    try { lf._fetchParams(function () { console.log('[initfn] _fetchParams callback invocato'); }); }
    catch (e) { console.log('[initfn] _fetchParams throw:', String(e && e.message).slice(0, 120)); }
    const req = xhrCalls.slice(n0);
    console.log('[initfn] _fetchParams -> richieste:', req.length);
    req.forEach((r) => console.log('   ' + r.method + ' ' + String(r.url).slice(0, 110) + ' body=' + (r.body || '').length + 'B'));
  }
} catch (e) { console.log('[initfn] call err', String(e && e.message).slice(0, 80)); }

// CHIAMA get_telemetry() -> il sensor_data (oracle browserless)
try {
  const bm = sandbox.bmak;
  if (bm && typeof bm.get_telemetry === 'function') {
    try { fs.writeFileSync('bmak_get_telemetry_src.js', Function.prototype.toString.call(bm.get_telemetry)); console.log('[telemetry] sorgente get_telemetry -> bmak_get_telemetry_src.js'); } catch (e) {}
    const fccBefore = fccBuf.length;
    const logBefore = log.length;
    let r;
    try { r = bm.get_telemetry(); } catch (e) { console.log('[telemetry] throw:', String(e && e.message).slice(0, 120)); }
    try {
      const d = log.slice(logBefore);
      const uniq = [...new Set(d)];
      fs.writeFileSync('bmak_telemetry_access.txt', uniq.join('\n'));
      // accessi "sospetti" = path profondi (walk su stub) o API fingerprint note
      const fp = uniq.filter((p) => /canvas|webgl|getContext|getParameter|toDataURL|audio|Audio|getImageData|measureText|font|timing|memory|getChannelData|createOscillator|getExtension|screen|plugin|mimeType/i.test(p));
      console.log('[telemetry] accessi durante call:', uniq.length, '| fingerprint-related:', fp.length);
      fp.slice(0, 40).forEach((p) => console.log('   FP ' + p));
    } catch (e) {}
    try {
      const delta = fccBuf.slice(fccBefore);
      const dstr = delta.map((c) => (c >= 32 && c < 127) ? String.fromCharCode(c) : '.').join('');
      fs.writeFileSync('bmak_telemetry_fcc.txt', dstr);
      console.log('[telemetry] fromCharCode durante la call:', delta.length, '-> bmak_telemetry_fcc.txt | head:', dstr.slice(0, 160));
    } catch (e) {}
    if (r != null) {
      const s = String(r);
      console.log('[telemetry] get_telemetry() len=' + s.length);
      console.log('[telemetry] head:', s.slice(0, 120));
      fs.writeFileSync('bmak_telemetry.txt', s);
      console.log('[telemetry] salvato -> bmak_telemetry.txt');
    } else {
      console.log('[telemetry] get_telemetry() ha restituito null/undefined');
    }
  }
} catch (e) { console.log('[telemetry] err', String(e && e.message).slice(0, 80)); }

// ---- PUMP: avanza l'orologio virtuale drenando la coda timer + microtask, finche' il POST parte
//      o scade il deadline. Prima emette gli eventi di lifecycle del documento ai listener registrati.
console.log('[fase2] winListeners registrati:', winListeners.map((l) => l.ev));
try { if (sandbox.document) { sandbox.document.readyState = 'complete'; } } catch (e) {}

function fireToWin(ev) {
  for (const l of winListeners.slice()) {
    if (l.ev === ev || l.ev === '*') {
      try { l.cb({ type: ev, timeStamp: clock.vt, target: sandbox.document, isTrusted: true }); } catch (e) {}
    }
  }
}

async function pump(maxVt) {
  clock.deadline = clock.vt + (maxVt || 60000);
  let steps = 0;
  while (xhrCalls.length === 0 && steps++ < 2_000_000) {
    sweepTimers();
    if (!__q.length) break;
    let mi = 0; for (let i = 1; i < __q.length; i++) if (__q[i].at < __q[mi].at || (__q[i].at === __q[mi].at && __q[i].id < __q[mi].id)) mi = i;
    const x = __q.splice(mi, 1)[0];
    if (x.at > clock.deadline) break;
    clock.vt = x.at;
    if (x.interval && clock.vt + x.interval <= clock.deadline) schedule(x.fn, clock.vt + x.interval, x.interval);
    try { x.fn(); } catch (e) {}
    await new Promise((r) => setImmediate(r));          // drena microtask della VM
  }
  return { vt: clock.vt, steps, qlen: __q.length };
}

function mkPointerEvt(type, x, y, buttons, pressure) {
  const el = elemCache['#sec-bc-tile-container'] || elemCache['#progress-button'] || sandbox.document;
  const ev = {
    type, timeStamp: clock.vt, isTrusted: true,
    clientX: x, clientY: y, screenX: x, screenY: y + 100, pageX: x, pageY: y, offsetX: x - 60, offsetY: y - 200,
    movementX: 0, movementY: 0, pressure, buttons, button: buttons ? 0 : -1, which: buttons ? 1 : 0, detail: 1,
    pointerId: 1, pointerType: 'mouse', isPrimary: true, altKey: false, ctrlKey: false, shiftKey: false, metaKey: false,
    getPredictedEvents: () => [], target: el, currentTarget: el, srcElement: el, composedPath: () => [el],
    preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, cancelBubble: false,
  };
  ev.getCoalescedEvents = () => [ev];
  return ev;
}
// fire tutti i listener (window + document + elementi) di un tipo
const isGarbled = (e) => !/^[\x20-\x7e]*$/.test(e);
function dispatchType(type, evt) {
  for (const l of winListeners.slice()) if (l.ev === type) { try { l.cb(evt); } catch (e) {} }
  for (const l of listeners.slice()) if (l.ev === type) { try { l.cb(Object.assign({}, evt, { currentTarget: l.target })); } catch (e) {} }
}
async function drainTimersTo(vt) {
  let n = 0;
  while (n++ < 500000 && xhrCalls.length === 0) {
    sweepTimers();
    let mi = -1;
    for (let i = 0; i < __q.length; i++) if (__q[i].at <= vt && (mi < 0 || __q[i].at < __q[mi].at || (__q[i].at === __q[mi].at && __q[i].id < __q[mi].id))) mi = i;
    if (mi < 0) break;
    const x = __q.splice(mi, 1)[0];
    clock.vt = Math.max(clock.vt, x.at);
    if (x.interval && clock.vt + x.interval <= vt + 100000) schedule(x.fn, clock.vt + x.interval, x.interval);
    try { x.fn(); } catch (e) {}
    await new Promise((r) => setImmediate(r));
  }
}
async function pressHold(holdMs, x, y) {
  // desktop, maxTouchPoints=0: SOLO pointer/mouse (niente touch*, che il reference non produce)
  for (const t of ['pointerover', 'pointerenter', 'pointerdown', 'mousedown']) dispatchType(t, mkPointerEvt(t, x, y, 1, 0.5));
  await drainTimersTo(clock.vt); if (xhrCalls.length) return;
  const end = clock.vt + holdMs;
  while (clock.vt < end && xhrCalls.length === 0) {
    clock.vt += 16;
    const jx = x + (Math.random() * 2 - 1), jy = y + (Math.random() * 2 - 1);
    dispatchType('pointermove', mkPointerEvt('pointermove', jx, jy, 1, 0.5));
    dispatchType('mousemove', mkPointerEvt('mousemove', jx, jy, 1, 0.5));
    await drainTimersTo(clock.vt);
  }
  if (xhrCalls.length) return;
  for (const t of ['pointerup', 'mouseup', 'click', 'pointerout', 'pointerleave']) dispatchType(t, mkPointerEvt(t, x, y, 0, 0));
  await drainTimersTo(clock.vt);
}

// challenge-data concreto: le FOGLIE sono stringhe (string-op sicure, niente crash atob),
// e QUALUNQUE proprieta' intermedia ritorna l'oggetto-challenge (per gli accessi annidati v98.detail[X][Y]).
function chlgeLeaf() {
  const known = { cpr_chlge: 'true', t: CHLG_T, v: CHLG_V, ct: '1', tc: '1', ts: '1000', context: 't', duration: '1000', chlge: 'true' };
  return new Proxy(known, {
    get(tt, p) { if (typeof p === 'symbol') { if (p === Symbol.toPrimitive) return () => 'true'; return undefined; } return (p in tt) ? tt[p] : ''; },
    has: () => true,
  });
}
function chlgeDetail() {
  const L = chlgeLeaf();
  return new Proxy({}, { get(tt, p) { if (typeof p === 'symbol') return undefined; if (p === 'cpr_chlge') return 'true'; if (p === 't') return CHLG_T; return L; }, has: () => true });
}
function fireChlgInit() {
  const evt = { type: 'ak_cpr_chlg_init', timeStamp: clock.vt, isTrusted: true, detail: chlgeDetail(), data: chlgeDetail(), target: sandbox.document };
  for (const l of winListeners.slice()) if (/ak_cpr|chlg|init/i.test(l.ev)) { try { l.cb(evt); } catch (e) { console.log('[init] err:', String(e && e.message || e).slice(0, 90)); console.log('[init] ultimi accessi:', log.slice(-14)); } }
  for (const l of listeners.slice()) if (/ak_cpr|chlg|init/i.test(l.ev)) { try { l.cb(evt); } catch (e) {} }
}

(async () => {
  const beforeXhr = xhrCalls.length;
  for (const ev of ['readystatechange', 'DOMContentLoaded', 'pageshow', 'load']) fireToWin(ev);
  await new Promise((r) => setImmediate(r));
  // REGOLA #1: niente invocazione diretta di handler interni. Tutto via pump/dispatch/timer.
  // DIAGNOSTICA: dump dei nomi-listener GARBLED (char codes) per l'analisi XOR-delta offline.
  const garbledNames = winListeners.map((l) => l.ev).filter((e) => !/^[\x20-\x7e]*$/.test(e))
    .map((e) => ({ str: e, codes: [...e].map((c) => c.charCodeAt(0)) }));
  fs.writeFileSync('garbled_listeners.json', JSON.stringify(garbledNames, null, 1));
  console.log('[diag] nomi-listener garbled:', garbledNames.length, '-> garbled_listeners.json');
  garbledNames.forEach((g) => console.log('   codes:', JSON.stringify(g.codes)));
  console.log('[replay] listeners: win=' + winListeners.length + ' tot=' + listeners.length + ' | timer=' + __q.length);
  const asciiTypes = [...new Set(listeners.map((l) => l.ev).filter((e) => /^[\x20-\x7e]+$/.test(e)))];
  const garbled = listeners.filter((l) => !/^[\x20-\x7e]+$/.test(l.ev));
  console.log('[replay] tipi ascii:', asciiTypes, '| listener garbled:', garbled.length);
  // DUMP nomi-evento di TUTTI i listener (win+doc+elem) con char-code per mapping
  try {
    const allL = winListeners.map((l) => ({ tgt: 'win', ev: l.ev })).concat(listeners.map((l) => ({ tgt: (l.target === docStub ? 'doc' : (l.target === sandboxProxy ? 'win2' : 'elem')), ev: l.ev })));
    const dump = allL.map((l) => ({ tgt: l.tgt, ev: l.ev, ascii: /^[\x20-\x7e]+$/.test(l.ev), codes: [...String(l.ev)].map((c) => c.charCodeAt(0)) }));
    fs.writeFileSync('bmak_listeners.json', JSON.stringify(dump, null, 1));
    console.log('[evmap] listener totali:', dump.length);
    dump.forEach((d) => console.log('   [' + d.tgt + '] ascii=' + d.ascii + ' ev=' + JSON.stringify(d.ev).slice(0, 30) + ' codes=' + JSON.stringify(d.codes).slice(0, 80)));
  } catch (e) { console.log('[evmap] err', String(e && e.message).slice(0, 80)); }
  fireToWin('focus'); dispatchType('focus', mkPointerEvt('focus', 0, 0, 0, 0));
  dispatchType('visibilitychange', mkPointerEvt('visibilitychange', 0, 0, 0, 0));
  await drainTimersTo(clock.vt + 500);
  console.log('[pre-hold] timer=' + __q.length + ' xhr=' + xhrCalls.length);
  await pressHold(2000, 160, 230);        // press-hold 2s sul tile
  console.log('[post-hold] vt=' + Math.round(clock.vt) + ' timer=' + __q.length + ' xhr=' + xhrCalls.length);
  const pr = await pump(60000);
  console.log('[pump] fine: vt=' + Math.round(pr.vt) + ' steps=' + pr.steps + ' qlen=' + pr.qlen
    + ' | xhr=' + xhrCalls.length + ' (prima ' + beforeXhr + ')');

  // ---- INIETTA EVENTI COMPORTAMENTALI (mouse+tastiera) e accumula in LEw, poi get_telemetry ----
  function mkKeyEvt(type, code, key) {
    const el = sandbox.document;
    return { type, timeStamp: clock.vt, isTrusted: true, key, code, keyCode: key ? key.charCodeAt(0) : 0, which: key ? key.charCodeAt(0) : 0,
      altKey: false, ctrlKey: false, shiftKey: false, metaKey: false, repeat: false, target: el, currentTarget: el, srcElement: el,
      preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, composedPath: () => [el] };
  }
  for (let i = 0; i < 25; i++) {
    clock.vt += 40 + Math.floor(Math.random() * 30);
    const x = 300 + i * 11 + Math.floor(Math.random() * 7), y = 240 + Math.floor(Math.sin(i / 3) * 40);
    dispatchType('mousemove', mkPointerEvt('mousemove', x, y, 0, 0));
    dispatchType('pointermove', mkPointerEvt('pointermove', x, y, 0, 0));
    if (i % 5 === 0) { dispatchType('mousedown', mkPointerEvt('mousedown', x, y, 1, 0.5)); dispatchType('mouseup', mkPointerEvt('mouseup', x, y, 0, 0)); dispatchType('click', mkPointerEvt('click', x, y, 0, 0)); }
    if (i % 4 === 0) { const k = 'abcdefg'[i % 7]; dispatchType('keydown', mkKeyEvt('keydown', 'Key' + k.toUpperCase(), k)); dispatchType('keyup', mkKeyEvt('keyup', 'Key' + k.toUpperCase(), k)); }
    await drainTimersTo(clock.vt);
  }
  console.log('[events] iniettati 25 tick mouse+key, vt=' + Math.round(clock.vt));
  try {
    const bm2 = sandbox.bmak;
    if (bm2 && typeof bm2.get_telemetry === 'function') {
      let r2; try { r2 = bm2.get_telemetry(); } catch (e) { console.log('[telemetry2] throw:', String(e && e.message).slice(0, 120)); }
      if (r2 != null) {
        const s2 = String(r2);
        const cps = [...s2].map((c) => c.charCodeAt(0));
        const asciiN = cps.filter((c) => c >= 32 && c < 127).length;
        console.log('[telemetry2] POST-eventi len=' + s2.length + ' ascii=' + asciiN + '/' + s2.length);
        console.log('[telemetry2] head:', s2.slice(0, 80));
        fs.writeFileSync('bmak_telemetry2.txt', s2);
        // confronto formato reale: deve iniziare con "3;0;1;0;" o essere JSON {"ver":...}
        console.log('[telemetry2] inizia con 3;0;1;0; ?', s2.startsWith('3;0;1;0;'), '| contiene {"ver" ?', s2.indexOf('{"ver') >= 0 || s2.indexOf('ver":') >= 0);
      }
    }
  } catch (e) { console.log('[telemetry2] err', String(e && e.message).slice(0, 80)); }

  console.log('=== RUN sec-cpt in Node ===');
  console.log('CONTATORI: perf.calls=' + PERF.calls + ' vt=' + Math.round(clock.vt) + ' atob=' + capturedAtob.length + ' xhr=' + xhrCalls.length + ' Math.random=' + rng.count);
  console.log('errore (atteso, anti-sandbox):', err || 'nessuno');
  console.log('ultimi 18 accessi globali:', log.slice(-18));
  const uniq = [...new Set(capturedAtob)];
  uniq.sort((a, b) => b.length - a.length);
  uniq.forEach((s, i) => { fs.writeFileSync(`seccpt_bc_${i}.txt`, s); });
  console.log('\n== XHR inviati:', xhrCalls.length);
  xhrCalls.forEach((c, i) => {
    console.log(`  [${i}] ${c.method} ${c.url.slice(0, 90)}  body=${c.body.length}B`);
    if (c.body.length > 50) fs.writeFileSync(`seccpt_xhr_${i}.txt`, c.body);
  });
  console.log('bytecode distinti (seccpt_bc_N.txt):', uniq.length);
  const allAccess = [...new Set(log)].map((p) => p.replace(/^G\./, '').replace(/^.*\./, ''));
  const vocab = [...new Set(allAccess)].filter((x) => x && !/^(Symbol|undefined|null)/.test(x)).sort();
  fs.writeFileSync('seccpt_vocab.txt', vocab.join('\n'));
  console.log('VOCABOLARIO decodificato (accessi unici):', vocab.length, '-> seccpt_vocab.txt');
  console.log('  parole reali (>=4 lettere):', vocab.filter((s) => /^[a-zA-Z]{4,}$/.test(s)).slice(0, 50));
  console.log('\n[nav] letture navigator (distinte):', [...new Set(navReads)].slice(0, 20));
  console.log('[perf] letture performance (distinte):', [...new Set(perfReads)]);
  fs.writeFileSync('fromcharcode_harness.json', JSON.stringify({ script: SRC, codes: fccBuf }));
  console.log('[fromCharCode] harness:', fccBuf.length, 'char-code -> fromcharcode_harness.json');
  if (INSPECT) {
    fs.writeFileSync('inspect_dump.txt', inspectDump.join('\n'));
    console.log('[inspect] dump scope caller (' + inspectDump.length + ' righe) -> inspect_dump.txt');
    inspectDump.slice(0, 60).forEach((l) => console.log('  ' + l));
  }
  if (DBASE_ON) {
    fs.writeFileSync('dec_trace.json', JSON.stringify({ trace: decTrace.slice(0, 2500000), keyLen: keyString ? keyString.length : 0 }));
    if (keyString) fs.writeFileSync('sqc8_key.txt', keyString);
    console.log('[dbase] decTrace:', decTrace.length, 'eventi | SQ.c8 len:', keyString ? keyString.length : 0, '-> dec_trace.json/sqc8_key.txt');
  }
  console.log('[atob] primi 6 input:', atobLog.slice(0, 6));
  console.log('[doc] letture document (prime 45 distinte):');
  [...new Set(docReads)].slice(0, 45).forEach((r) => console.log('   ' + r));
  // BISEZIONE: sequenza ORDINATA degli accessi (= decode in ordine). Trova la prima divergenza (garbled).
  fs.writeFileSync('access_log.txt', log.join('\n'));
  const firstBad = log.findIndex((p) => /[^\x20-\x7e]/.test(p));
  console.log('\n[bisez] primo accesso GARBLED all\'indice', firstBad, 'su', log.length, 'totali');
  if (firstBad >= 0) {
    console.log('[bisez] CONTESTO (10 accessi prima, poi il garbled):');
    log.slice(Math.max(0, firstBad - 10), firstBad + 1).forEach((p, i) => console.log('   ' + (firstBad - 10 + i) + ': ' + JSON.stringify(p)));
  }
})();
