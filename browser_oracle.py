"""
Oracolo sensore in BROWSER HEADLESS (Playwright) — genera sensor_data VALIDI
eseguendo lo script Akamai vero in un vero Chromium, senza stub ne' crypto.

Modello ibrido (deciso 2026-10-13):
  - Il browser headless fa SOLO da generatore: carica fansale, lo script Akamai gira
    nativamente (tutte le Web API esistono) e produce sensori validi. Noi intercettiamo
    i POST del sensore (riconosciuti dal body che contiene "sensor_data").
  - Il traffico di PRODUZIONE verso il sito resta request-based (curl_cffi, akamai_session.py).
  - Self-built: nessuna API di terzi.

Coerenza (linee guida sez. 3): stesso proxy sticky (exit Italia), UA Chrome, timezone/locale
allineati alla geo dell'IP. Il browser usa lo stesso proxy del client request-based.

Prerequisiti:
  pip install -r requirements.txt
  python -m playwright install chromium

Uso rapido:
  python browser_oracle.py                      # usa un proxy da proxies.txt
  python browser_oracle.py --no-proxy           # senza proxy (solo test locale)
"""

from __future__ import annotations
import argparse
import json
import re
import sys
from typing import List, Optional

# patchright = Playwright patchata che elimina il leak CDP `Runtime.enable` (il tell
# principale che Akamai usa per rilevare l'automazione). Drop-in, stessa API.
# Preferito; fallback a playwright normale se non installata.
DRIVER = None
try:
    from patchright.sync_api import sync_playwright  # type: ignore
    DRIVER = "patchright"
except Exception:
    try:
        from playwright.sync_api import sync_playwright
        DRIVER = "playwright"
    except Exception:  # pragma: no cover
        sync_playwright = None

from proxies import pick_proxy_dict

# UA / locale / timezone coerenti con exit Italia (vedi cattura reale Chrome 155).
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
HOME = "https://www.fansale.it/"


class CapturedSensor:
    def __init__(self, url: str, method: str, body: str):
        self.url = url
        self.method = method
        self.body = body
    def path(self) -> str:
        i = self.url.find("//")
        rest = self.url[i + 2:] if i >= 0 else self.url
        s = rest.find("/")
        return rest[s:] if s >= 0 else self.url
    def __repr__(self):
        return f"<Sensor {self.method} len={len(self.body)} {self.path()[:40]}>"


class BrowserOracle:
    def __init__(self, proxy: Optional[dict] = None, user_agent: str = DEFAULT_UA,
                 locale: str = "it-IT", timezone: str = "Europe/Rome", headless: bool = True,
                 channel: Optional[str] = None, user_data_dir: Optional[str] = None,
                 analyze: bool = False, dump_strings: bool = False, dump_keystream: bool = False,
                 dump_plaintext: bool = False, inject_probe: bool = False, locate_cipher: bool = False,
                 dump_cipher: bool = False):
        if sync_playwright is None:
            raise RuntimeError("Nessun driver browser. Installa patchright (consigliato): "
                               "`python -m pip install patchright` e `python -m patchright install chromium`; "
                               "oppure playwright: `python -m pip install playwright` e `python -m playwright install chromium`.")
        self.proxy = proxy
        self.user_agent = user_agent
        self.locale = locale
        self.timezone = timezone
        self.headless = headless
        self.channel = channel  # None=Chromium bundled; "chrome"/"msedge"=browser installato
        self.user_data_dir = user_data_dir  # profilo PERSISTENTE (non-incognito): scaldalo a mano una volta
        self.analyze = analyze  # modalita' reversing: cattura il PLAINTEXT pre-cifratura
        self.dump_keystream = dump_keystream
        self.dump_plaintext = dump_plaintext
        self.inject_probe = inject_probe  # oracolo chosen-plaintext: cifra NOSTRO input via hook charCodeAt
        self.locate_cipher = locate_cipher  # cattura la sorgente della funzione-cifrario (.caller chain)
        self.dump_cipher = dump_cipher  # dump runtime costanti LCG + alfabeto + seed + in/out
        self.dump_strings = (dump_strings or dump_keystream or dump_plaintext
                             or inject_probe or locate_cipher or dump_cipher)  # attiva intercetto+patch
        self.patcher = ("patch_cipher_dump.js" if dump_cipher else
                        "patch_locate.js" if locate_cipher else
                        "patch_oracle.js" if inject_probe else
                        "patch_scc.js" if dump_plaintext else
                        "patch_hg.js" if dump_keystream else "patch_dump.js")
        self.sensors: List[CapturedSensor] = []
        self.decoded = set()
        self.probe_results: List[dict] = []
        self.probe_off = 0

    # Riconosce la richiesta GET dello script Akamai (path a segmenti random, niente estensione).
    @staticmethod
    def _is_akamai_script(request) -> bool:
        try:
            if request.method != "GET" or "fansale.it" not in request.url:
                return False
            path = re.sub(r"https?://[^/]+", "", request.url).split("?")[0]
            segs = [s for s in path.split("/") if s]
            if len(segs) < 4:
                return False
            last = segs[-1]
            return "." not in last and bool(re.match(r"^[A-Za-z0-9_]{6,}$", segs[0]))
        except Exception:
            return False

    # Instrumentazione a document_start per il REVERSING del sensore v3:
    #  - hook XMLHttpRequest.send/fetch: al momento dell'invio del sensore cattura lo STACK
    #    TRACE -> gli offset akamai.js:1:<col> sono le funzioni reali di assembly/cifratura.
    #  - hook Array.prototype.join + String.prototype.concat: candidati plaintext pre-cifratura.
    # Tutti preservano un toString "nativo" per non essere evidenti.
    ANALYZE_JS = r"""
(function(){
  window.__akpt=[];        // candidati plaintext (stringhe lunghe assemblate)
  window.__aktrace=[];     // stack trace al send del sensore
  function nativeToString(fn,name){ try{ fn.toString=function(){return 'function '+name+'() { [native code] }';}; }catch(e){} }

  // 1) stack trace quando parte il sensore (contiene "sensor_data")
  function wrapSend(proto, key, name){
    if(!proto || typeof proto[key]!=='function') return;
    var orig=proto[key];
    proto[key]=function(){
      try{
        var body = (key==='send') ? arguments[0] : (arguments[1] && arguments[1].body);
        if(body && String(body).indexOf('sensor_data')>-1 && window.__aktrace.length<10){
          window.__aktrace.push({len:String(body).length, stack:String((new Error()).stack||'').split('\n').slice(0,30)});
        }
      }catch(e){}
      return orig.apply(this, arguments);
    };
    nativeToString(proto[key], name);
  }
  try{ wrapSend(XMLHttpRequest.prototype,'send','send'); }catch(e){}
  try{ var of=window.fetch; window.fetch=function(){ try{var o=arguments[1]; if(o&&o.body&&String(o.body).indexOf('sensor_data')>-1&&window.__aktrace.length<10){window.__aktrace.push({len:String(o.body).length,stack:String((new Error()).stack||'').split('\n').slice(0,30)});}}catch(e){} return of.apply(this,arguments);}; nativeToString(window.fetch,'fetch'); }catch(e){}

  // 2) candidati plaintext: join + concat di stringhe lunghe
  try{ var j=Array.prototype.join; Array.prototype.join=function(){var r=j.apply(this,arguments); try{if(typeof r==='string'&&r.length>60&&window.__akpt.length<400)window.__akpt.push({how:'join',s:r});}catch(e){} return r;}; nativeToString(Array.prototype.join,'join'); }catch(e){}
  try{ var c=String.prototype.concat; String.prototype.concat=function(){var r=c.apply(this,arguments); try{if(typeof r==='string'&&r.length>120&&window.__akpt.length<400)window.__akpt.push({how:'concat',s:r});}catch(e){} return r;}; nativeToString(String.prototype.concat,'concat'); }catch(e){}
})();
"""

    # Stealth minimale a document_start: nasconde i tell dell'automazione prima che
    # gli script di pagina (Akamai) girino. (channel="chrome" + headful e' comunque meglio.)
    STEALTH_JS = (
        "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
        "window.chrome=window.chrome||{runtime:{}};"
        "Object.defineProperty(navigator,'languages',{get:()=>['it-IT','it','en-US','en']});"
        "try{const o=Notification;}catch(e){}"
    )

    def _human_activity(self, page):
        """
        Attivita' umana realistica: accetta il consenso, muove il mouse a piccoli passi
        con pause (non teletrasporti), scrolla con dwell. Serve a dare al sensore
        comportamentale entropia simile a quella di un utente vero.
        """
        import random
        # 1. accetta il banner consenso (consentmanager/CMP) se presente
        for sel in ["text=Accetta tutto", "text=Accetta e chiudi", "text=Accetto",
                    "text=Accept all", "button:has-text('Accetta')", "[id*='accept']",
                    "[class*='accept']", "[aria-label*='Accetta']"]:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.click(timeout=2000)
                    page.wait_for_timeout(random.randint(400, 900))
                    break
            except Exception:
                pass
        # 2. mouse a piccoli passi lungo un percorso curvo, con pause
        try:
            x, y = random.randint(200, 500), random.randint(200, 400)
            page.mouse.move(x, y)
            for _ in range(random.randint(12, 20)):
                x += random.randint(-40, 90); y += random.randint(-30, 70)
                x = max(5, min(1900, x)); y = max(5, min(1000, y))
                page.mouse.move(x, y, steps=random.randint(3, 8))
                page.wait_for_timeout(random.randint(60, 220))
        except Exception:
            pass
        # 3. scroll naturale con dwell
        try:
            for dy in (250, 400, 300, -200):
                page.mouse.wheel(0, dy)
                page.wait_for_timeout(random.randint(500, 1200))
        except Exception:
            pass

    def _set_injection(self, page, kind, val):
        """Scrive la config in localStorage (PERSISTE tra i reload; letta dal hook same-origin)."""
        js = ("(a)=>{try{localStorage.removeItem('__ak_c');localStorage.removeItem('__ak_s');"
              "if(a[1]!==null){localStorage.setItem(a[0]==='c'?'__ak_c':'__ak_s',a[1]);}return 1;}"
              "catch(e){return 0;}}")
        try:
            return page.evaluate(js, [kind, val])
        except Exception as ex:
            print(f"[inject-probe] set_injection fallita: {ex}", file=sys.stderr)
            return 0

    def _accept_consent(self, page):
        for sel in ["text=Accetta tutto", "text=Accetta e chiudi", "text=Accetto",
                    "text=Accept all", "button:has-text('Accetta')", "[id*='accept']"]:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.click(timeout=1500)
                    page.wait_for_timeout(300)
                    return True
            except Exception:
                pass
        return False

    def _trigger_and_wait(self, page, before, timeout_ms=16000):
        """Due fasi: (1) attivita' forte SENZA reload (stessa key_b64); (2) fallback reload."""
        import random
        try:
            self._accept_consent(page)
        except Exception:
            pass
        step = 400
        # Fase 1: forza un post con mouse/scroll/tasti, senza ricaricare (preserva key_b64)
        waited = 0
        while waited < timeout_ms // 2:
            try:
                page.mouse.move(random.randint(150, 1600), random.randint(150, 900),
                                steps=random.randint(4, 10))
                page.mouse.wheel(0, random.randint(-200, 360))
                if random.random() < 0.3:
                    try:
                        page.keyboard.press("PageDown")
                    except Exception:
                        pass
            except Exception:
                pass
            page.wait_for_timeout(step)
            waited += step
            if len(self.sensors) > before:
                return True
        # Fase 2: fallback -> reload (probabile nuova key_b64)
        try:
            page.reload(wait_until="domcontentloaded", timeout=30000)
        except Exception as ex:
            print(f"[inject-probe] reload fallito: {ex}", file=sys.stderr)
        page.wait_for_timeout(800)
        try:
            self._accept_consent(page)
        except Exception:
            pass
        waited = 0
        while waited < timeout_ms:
            try:
                page.mouse.move(random.randint(200, 1500), random.randint(200, 850),
                                steps=random.randint(2, 6))
                if random.random() < 0.5:
                    page.mouse.wheel(0, random.randint(-120, 280))
            except Exception:
                pass
            page.wait_for_timeout(step)
            waited += step
            if len(self.sensors) > before:
                return True
        return len(self.sensors) > before

    def _run_probes(self, page):
        """Oracolo chosen-plaintext con OFFSET: lascia reali i primi OFF char (campo-seed del
        keystream), sovrascrive il resto. Cosi' i probe condividono il keystream."""
        import json as _json
        import os as _os
        # offset default 900: lascia REALI i campi iniziali incl. la key 'nte' (~pos 743),
        # che e' il probabile SEED del keystream (il resync naturale esclude il timestamp).
        OFF = int(_os.environ.get("AK_PROBE_OFF", "900"))
        self.probe_off = OFF
        probes = [
            ("c", "A", "A"), ("c", "B", "B"), ("c", "C", "C"), ("c", "M", "M"),
        ]
        print(f"[inject-probe] avvio {len(probes)} probe (offset={OFF}: primi {OFF} char reali)...")
        ok_ls = self._set_injection(page, "c", "A")
        try:
            page.evaluate("(v)=>{try{localStorage.setItem('__ak_off',''+v);return 1;}catch(e){return 0;}}", OFF)
        except Exception as ex:
            print(f"[inject-probe] set offset fallito: {ex}", file=sys.stderr)
        print(f"[inject-probe] localStorage scrivibile: {bool(ok_ls)}  offset={OFF}")
        for idx, (kind, val, label) in enumerate(probes):
            self._set_injection(page, kind, val)     # persiste al reload successivo
            # ri-scrive l'offset (set_injection non lo tocca, ma per sicurezza dopo reload)
            try:
                page.evaluate("(v)=>{try{localStorage.setItem('__ak_off',''+v);}catch(e){}}", OFF)
            except Exception:
                pass
            before = len(self.sensors)
            ok = self._trigger_and_wait(page, before, timeout_ms=18000)
            if ok:
                s = self.sensors[-1]
                try:
                    sd = _json.loads(s.body)["sensor_data"] if s.body.lstrip().startswith("{") else s.body
                    key = sd.split(";")[5] if sd.count(";") >= 5 else "?"
                except Exception:
                    key = "?"
                self.probe_results.append({"kind": kind, "label": label, "off": self.probe_off,
                                           "len_body": len(s.body), "key_b64": key, "body": s.body})
                print(f"[inject-probe] probe {idx} ({kind}:{label}): POST len={len(s.body)} key={key[:14]}..")
            else:
                print(f"[inject-probe] probe {idx} ({kind}:{label}): NESSUN nuovo POST (timeout)")
        self._set_injection(page, "c", None)   # ripristina passthrough
        try:
            with open("probe_table.json", "w", encoding="utf-8") as fh:
                _json.dump(self.probe_results, fh, indent=1)
            print(f"[inject-probe] salvati {len(self.probe_results)} probe -> probe_table.json")
        except Exception as ex:
            print(f"[inject-probe] salvataggio fallito: {ex}", file=sys.stderr)
        try:
            for fr in page.frames:
                txt = fr.evaluate("(function(){var e=document.getElementById('__akoracle');"
                                  "return e?e.textContent:'';})()")
                if txt:
                    lines = [l for l in txt.split("\n") if l.strip()]
                    print(f"[inject-probe] #__akoracle: {len(lines)} letture plaintext; "
                          f"ultime: {lines[-3:]}")
                    break
        except Exception:
            pass

    def _on_request(self, request):
        try:
            if request.method == "POST":
                body = request.post_data or ""
                # Il POST del sensore Akamai ha il body che contiene "sensor_data".
                if body and "sensor_data" in body:
                    self.sensors.append(CapturedSensor(request.url, request.method, body))
        except Exception:
            pass

    def capture(self, flow: Optional[List[str]] = None, settle_ms: int = 4000) -> dict:
        """
        Naviga il flusso (default: solo homepage), lascia girare lo script Akamai,
        intercetta i sensor POST. Ritorna sensori catturati + cookie finali.
        """
        flow = flow or [HOME]
        blocked = False
        statuses = []
        titles = []
        with sync_playwright() as p:
            # Con patchright lasciamo che sia la patch a gestire la stealth: niente args/init
            # custom (sarebbero essi stessi un tell). Con playwright normale, rimuoviamo almeno
            # il flag --enable-automation.
            use_patchright = (DRIVER == "patchright")
            common_args = [] if use_patchright else ["--disable-blink-features=AutomationControlled"]
            ignore = ["--enable-automation"]
            ctx_opts = dict(user_agent=self.user_agent, locale=self.locale,
                            timezone_id=self.timezone, viewport={"width": 1920, "height": 1040})
            browser = None
            if self.user_data_dir:
                # Profilo PERSISTENTE (non-incognito): porta cookie/consenso/storia -> visitatore fidato.
                launch_kw = dict(headless=self.headless, proxy=self.proxy, args=common_args,
                                 ignore_default_args=ignore, **ctx_opts)
                if self.channel:
                    launch_kw["channel"] = self.channel
                context = p.chromium.launch_persistent_context(self.user_data_dir, **launch_kw)
            else:
                launch_kw = {"headless": self.headless, "proxy": self.proxy,
                             "args": common_args, "ignore_default_args": ignore}
                if self.channel:
                    launch_kw["channel"] = self.channel
                browser = p.chromium.launch(**launch_kw)
                context = browser.new_context(**ctx_opts)
            if not use_patchright:
                context.add_init_script(self.STEALTH_JS)  # document_start, prima di Akamai
            if self.analyze:
                context.add_init_script(self.ANALYZE_JS)  # cattura plaintext pre-cifratura
            page = context.new_page()
            page.on("request", self._on_request)

            # Dump stringhe: intercetta OGNI script Akamai, lo patcha AL VOLO (gestisce i
            # 2+ script e le rotazioni) e lo serve; raccoglie i SLSTR dai console.
            if self.dump_strings:
                import subprocess, hashlib
                patch_cache = {}

                def _patch_on_fly(body):
                    h = hashlib.sha1(body.encode("utf-8", "ignore")).hexdigest()[:10]
                    if h in patch_cache:
                        return patch_cache[h]
                    inf, outf = f"_live_{h}.js", f"_patched_{h}.js"
                    with open(inf, "w", encoding="utf-8") as fh:
                        fh.write(body)
                    patched = body
                    try:
                        subprocess.run(["node", self.patcher, inf, outf], timeout=90, check=False,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        patched = open(outf, encoding="utf-8").read()
                        print(f"[dump-strings] patchato on-the-fly: {h} ({len(body)}B) -> {outf}")
                    except Exception as ex:
                        print(f"[dump-strings] patch on-the-fly fallita {h}: {ex}", file=sys.stderr)
                    patch_cache[h] = patched
                    return patched

                def _route(route):
                    req = route.request
                    if self._is_akamai_script(req):
                        try:
                            resp = route.fetch()
                            body = resp.text()
                        except Exception as ex:
                            print(f"[dump-strings] fetch fallita: {ex}", file=sys.stderr)
                            route.continue_(); return
                        served = _patch_on_fly(body) if (body and len(body) > 10000) else body
                        route.fulfill(status=200, content_type="application/javascript", body=served)
                    else:
                        route.continue_()
                page.route("**/*", _route)
                # disabilita la cache HTTP: senza, lo script cachato nel profilo
                # non genera richiesta di rete e la route non scatta.
                try:
                    _cdp = context.new_cdp_session(page)
                    _cdp.send("Network.enable")
                    _cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
                except Exception as ex:
                    print(f"[dump-strings] cache-disable fallita: {ex}", file=sys.stderr)

                def _console(msg):
                    try:
                        txt = msg.text
                        if txt.startswith("SLSTR:"):
                            self.decoded.add(txt[6:])
                    except Exception:
                        pass
                page.on("console", _console)

                # Cattura il SORGENTE del Web Worker (il sensore Akamai gira in un worker
                # creato da un Blob): hook su Blob a document_start -> lo salviamo per patcharlo.
                def _save_worker(src):
                    try:
                        import hashlib as _h
                        h = _h.sha1(src.encode("utf-8", "ignore")).hexdigest()[:10]
                        fn = f"worker_src_{h}.js"
                        with open(fn, "w", encoding="utf-8") as fh:
                            fh.write(src)
                        print(f"[dump-strings] worker source: {len(src)}B -> {fn}")
                    except Exception:
                        pass
                    return True
                try:
                    page.expose_function("__saveWorkerSrc", _save_worker)
                except Exception as ex:
                    print(f"[dump-strings] expose_function fallita: {ex}", file=sys.stderr)
                page.add_init_script(
                    "(function(){try{var W=(typeof window!=='undefined')?window:self;var RB=W.Blob;"
                    "W.Blob=function(parts,opts){try{if(parts&&parts.length){var s='';for(var i=0;i<parts.length;i++){if(typeof parts[i]==='string')s+=parts[i];}"
                    "if(s.length>50000&&s.indexOf('function')!==-1&&W.__saveWorkerSrc){try{W.__saveWorkerSrc(s);}catch(e){}}}}catch(e){}"
                    "return new RB(parts,opts);};try{W.Blob.prototype=RB.prototype;}catch(e){}}catch(e){}})();"
                )

            for url in flow:
                try:
                    resp = page.goto(url, wait_until="domcontentloaded", timeout=45000)
                    st = resp.status if resp else None
                    statuses.append(st)
                    page.wait_for_timeout(1500)
                    self._human_activity(page)      # consenso + mouse/scroll umani + dwell
                    page.wait_for_timeout(settle_ms)
                    # Ground truth: titolo + marker FORTI (evita falsi positivi da substring).
                    try:
                        title = page.title() or ""
                    except Exception:
                        title = ""
                    titles.append(title)
                    try:
                        txt = (page.content() or "")
                        strong = (st in (403, 429)) \
                            or (title.strip().lower() == "access denied") \
                            or ("You don't have permission to access" in txt) \
                            or ('Reference&#32;#' in txt)
                        if strong:
                            blocked = True
                    except Exception:
                        pass
                except Exception as e:
                    print(f"[warn] navigazione {url}: {e}", file=sys.stderr)

            # Oracolo chosen-plaintext: inietta plaintext scelti e cattura i body cifrati.
            if self.inject_probe:
                try:
                    self._run_probes(page)
                except Exception as e:
                    print(f"[inject-probe] errore: {e}", file=sys.stderr)

            # Dump costanti cifrario: stimola un sensore COMPLETO e fai polling di #__ckdump
            # finche' 'out' (ciphertext) non e' popolato (la navigazione puo' andare in timeout).
            if self.dump_cipher:
                try:
                    import random, json as _json
                    try:
                        self._accept_consent(page)
                    except Exception:
                        pass
                    best = ""
                    for _ in range(18):   # ~36s di polling con attivita'
                        try:
                            page.mouse.move(random.randint(150, 1500), random.randint(150, 850),
                                            steps=random.randint(3, 8))
                            page.mouse.wheel(0, random.randint(-150, 300))
                        except Exception:
                            pass
                        page.wait_for_timeout(2000)
                        cur = ""
                        for fr in page.frames:
                            try:
                                txt = fr.evaluate("(function(){var e=document.getElementById('__ckdump');"
                                                  "return e?e.textContent:'';})()")
                                if txt and len(txt) > len(cur):
                                    cur = txt
                            except Exception:
                                pass
                        if cur:
                            best = cur
                            try:
                                o = _json.loads(cur)
                                if o.get("out") and o.get("alpha"):
                                    print(f"[dump-cipher] catturato pair in/out dopo polling "
                                          f"(ncalls={o.get('ncalls')})")
                                    break
                            except Exception:
                                pass
                    if best:
                        with open("cipher_consts.json", "w", encoding="utf-8") as fh:
                            fh.write(best)
                        print(f"[dump-cipher] catturato {len(best)} char -> cipher_consts.json")
                        try:
                            obj = json.loads(best)
                            print(f"[dump-cipher] A={obj.get('A')} m1={obj.get('m1')} C={obj.get('C')} "
                                  f"m2={obj.get('m2')} shift={obj.get('shift')} ext={obj.get('ext')} "
                                  f"alpha_len={len(obj.get('alpha') or '')} seed={obj.get('seed')} "
                                  f"inlen={obj.get('inlen')} out_len={len(obj.get('out') or '')}")
                        except Exception:
                            pass
                    else:
                        print("[dump-cipher] NESSUNA cattura (#__ckdump vuoto)")
                except Exception as e:
                    print(f"[dump-cipher] errore: {e}", file=sys.stderr)

            # Localizzazione cifrario: leggi il sink #__aklocate (sorgente funzione-cifrario).
            if self.locate_cipher:
                try:
                    page.wait_for_timeout(1500)
                    got = ""
                    for fr in page.frames:
                        try:
                            txt = fr.evaluate("(function(){var e=document.getElementById('__aklocate');"
                                              "return e?e.textContent:'';})()")
                            if txt and len(txt) > len(got):
                                got = txt
                        except Exception:
                            pass
                    if got:
                        with open("cipher_locate.txt", "w", encoding="utf-8") as fh:
                            fh.write(got)
                        print(f"[locate-cipher] catturato {len(got)} char -> cipher_locate.txt")
                    else:
                        print("[locate-cipher] NESSUNA cattura (il cifrario potrebbe non esporre .caller)")
                except Exception as e:
                    print(f"[locate-cipher] errore: {e}", file=sys.stderr)

            # Salva artefatti dell'ULTIMA pagina per ispezione umana.
            try:
                page.screenshot(path="oracle_last.png", full_page=False)
                with open("oracle_last.html", "w", encoding="utf-8") as fh:
                    fh.write(page.content() or "")
            except Exception:
                pass
            # Salva i sensori COMPLETI (anche se la sessione e' bloccata, sono validi):
            # servono all'analisi del formato v3 / reversing crypto.
            try:
                with open("sensor_samples.json", "w", encoding="utf-8") as fh:
                    json.dump([{"url": s.url, "method": s.method, "len": len(s.body), "body": s.body}
                               for s in self.sensors], fh, indent=1)
            except Exception:
                pass

            # Modalita' analyze: estrai il plaintext pre-cifratura catturato dal hook join.
            if self.analyze:
                try:
                    pt = page.evaluate("window.__akpt || []")
                    tr = page.evaluate("window.__aktrace || []")
                    with open("plaintext_samples.json", "w", encoding="utf-8") as fh:
                        json.dump(pt, fh, indent=1, ensure_ascii=False)
                    with open("send_traces.json", "w", encoding="utf-8") as fh:
                        json.dump(tr, fh, indent=1, ensure_ascii=False)
                    print(f"[analyze] plaintext candidati: {len(pt)} -> plaintext_samples.json")
                    print(f"[analyze] stack trace al send: {len(tr)} -> send_traces.json")
                except Exception as e:
                    print(f"[analyze] estrazione fallita: {e}", file=sys.stderr)

            if self.dump_strings:
                # DOM sink #__akhg: condiviso tra i world (bypassa l'isolamento di patchright su evaluate)
                for fr in page.frames:
                    try:
                        txt = fr.evaluate("(function(){var e=document.getElementById('__akhg');return e?e.textContent:'';})()")
                        if txt:
                            for ln in txt.split("\n"):
                                ln = ln.strip()
                                if ln:
                                    self.decoded.add(ln)
                    except Exception:
                        pass
                # CANARY + lettura globali (main world; puo' essere invisibile se evaluate e' isolato)
                for fr in page.frames:
                    try:
                        ready = fr.evaluate("window.__Dready||0")
                        arr = fr.evaluate("window.__slstr || []")
                        arr2 = fr.evaluate("window.__hgarr || []")
                        if ready:
                            print(f"[dump] frame {fr.url[:36]}: __Dready={ready}")
                        if arr:
                            self.decoded.update(arr)
                        if arr2:
                            self.decoded.update(f"{len(s)}|{s}" for s in arr2)
                    except Exception:
                        pass
                # lettura dai WEB WORKER (il decoder Akamai gira qui): self.__slstr via worker.evaluate
                try:
                    workers = list(page.workers)
                    print(f"[dump-strings] web worker attivi: {len(workers)}")
                    for w in workers:
                        try:
                            ready = w.evaluate("self.__Dready||0")
                            arr = w.evaluate("self.__slstr || []")
                            print(f"[dump-strings] worker {w.url[:40]}: __Dready={ready} strings={len(arr) if arr else 0}")
                            if arr:
                                self.decoded.update(arr)
                        except Exception as ex:
                            print(f"[dump-strings] worker evaluate fallita: {ex}", file=sys.stderr)
                except Exception as ex:
                    print(f"[dump-strings] lettura worker fallita: {ex}", file=sys.stderr)
                outname = ("plaintext_live.txt" if self.dump_plaintext
                           else "keystream_live.txt" if self.dump_keystream else "decoded_strings.txt")
                try:
                    with open(outname, "w", encoding="utf-8") as fh:
                        fh.write("\n".join(sorted(self.decoded)))
                    print(f"[dump] catturate: {len(self.decoded)} -> {outname}")
                except Exception as e:
                    print(f"[dump] salvataggio fallito: {e}", file=sys.stderr)

            cookies = {c["name"]: c["value"] for c in context.cookies()}
            context.close()
            if browser:
                browser.close()

        return {
            "sensors": self.sensors,
            "abck": cookies.get("_abck", ""),
            "bm_sz": cookies.get("bm_sz", ""),
            "cookies": cookies,
            "blocked": blocked,
            "statuses": statuses,
            "titles": titles,
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-proxy", action="store_true", help="usa il TUO IP diretto (niente proxy)")
    ap.add_argument("--proxy-index", type=int, default=0, help="indice proxy in proxies.txt")
    ap.add_argument("--headful", action="store_true", help="mostra il browser")
    ap.add_argument("--channel", default=None, help="'chrome' o 'msedge' per usare il browser installato (consigliato vs detection headless)")
    ap.add_argument("--user-data-dir", default=None, help="cartella profilo PERSISTENTE (non-incognito): scaldala navigando fansale a mano una volta, poi riusala")
    ap.add_argument("--analyze", action="store_true", help="modalita' reversing crypto: cattura il plaintext pre-cifratura (plaintext_samples.json) + ciphertext (sensor_samples.json)")
    ap.add_argument("--dump-strings", action="store_true", help="patcha on-the-fly (patch_dump) e raccoglie le stringhe decodificate -> decoded_strings.txt")
    ap.add_argument("--dump-keystream", action="store_true", help="patch_hg: keystream del layer stringhe -> keystream_live.txt")
    ap.add_argument("--dump-plaintext", action="store_true", help="patch_scc: hook globale charCodeAt, cattura il PLAINTEXT del payload (stringhe >=100) -> plaintext_live.txt")
    ap.add_argument("--inject-probe", action="store_true", help="patch_oracle: ORACOLO chosen-plaintext. Inietta plaintext scelti (char costanti + ciclici) e cattura i body cifrati -> probe_table.json. Serve il profilo scaldato + --headful --channel chrome.")
    ap.add_argument("--locate-cipher", action="store_true", help="patch_locate: cattura la SORGENTE della funzione-cifrario (catena .caller alla lettura del plaintext) -> cipher_locate.txt. Un solo caricamento, nessun probe.")
    ap.add_argument("--dump-cipher", action="store_true", help="patch_cipher_dump: inietta logging dentro XBS, estrae a RUNTIME costanti LCG + alfabeto + seed + input/output -> cipher_consts.json. Un solo caricamento.")
    args = ap.parse_args()

    print(f"[info] driver: {DRIVER}")
    proxy = None if args.no_proxy else pick_proxy_dict(index=args.proxy_index)
    if proxy:
        print(f"[info] proxy: {proxy['server']} (credenziali nascoste)")
    else:
        print("[info] nessun proxy: uso l'IP diretto di questa macchina")
    if args.channel:
        print(f"[info] browser: channel={args.channel}")
    if args.user_data_dir:
        print(f"[info] profilo persistente (non-incognito): {args.user_data_dir}")
    oracle = BrowserOracle(proxy=proxy, headless=not args.headful, channel=args.channel,
                           user_data_dir=args.user_data_dir, analyze=args.analyze,
                           dump_strings=args.dump_strings, dump_keystream=args.dump_keystream,
                           dump_plaintext=args.dump_plaintext, inject_probe=args.inject_probe,
                           locate_cipher=args.locate_cipher, dump_cipher=args.dump_cipher)
    res = oracle.capture()

    print(f"\nSensori catturati: {len(res['sensors'])}")
    for s in res["sensors"]:
        print(f"  {s}  body[:80]={s.body[:80]!r}")
    print(f"\n_abck presente: {bool(res['abck'])} (len {len(res['abck'])})")
    print(f"bm_sz presente: {bool(res['bm_sz'])}")
    print(f"status navigazione: {res['statuses']}")
    print(f"titolo pagina: {res.get('titles')}")
    print(f"SESSIONE BLOCCATA (marker forti): {res['blocked']}")
    print("artefatti salvati: oracle_last.png (screenshot), oracle_last.html")
    if res["sensors"]:
        big = max(res["sensors"], key=lambda x: len(x.body))
        print(f"\nSensore piu' grande: len={len(big.body)} path={big.path()}")
        print("  -> da passare al client request-based (curl_cffi) o per harvest cookie")


if __name__ == "__main__":
    main()
