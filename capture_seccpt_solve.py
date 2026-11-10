#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cattura DINAMICA della risoluzione sec-cpt: carica fansale in un contesto COLD (incognito),
lascia che il browser risolva l'interstitial, e registra le richieste/risposte della challenge
(endpoint con t=<chlgeId>, /.well-known/sec-cpt, POST verso i path Akamai) -> seccpt_solve.json.

Da qui ricaviamo: endpoint esatto, metodo, header, PAYLOAD della soluzione (il PoW) e la
risposta -> poi reimplementiamo il proof-of-work in Python.

Uso: python capture_seccpt_solve.py --headful --channel chrome
"""
import argparse
import json
import re
import sys

try:
    from patchright.sync_api import sync_playwright
    DRIVER = "patchright"
except Exception:
    try:
        from playwright.sync_api import sync_playwright
        DRIVER = "playwright"
    except Exception:
        sync_playwright = None

HOME = "https://www.fansale.it/"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")


def is_challenge(url: str) -> bool:
    if "fansale.it" not in url:
        return False
    return (bool(re.search(r"[?&]t=\d{6,}", url))
            or "sec-cpt" in url or "well-known" in url or "/akam/" in url)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--headful", action="store_true")
    ap.add_argument("--channel", default="chrome")
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--proxy-index", type=int, default=0)
    ap.add_argument("--wait", type=int, default=12000)
    ap.add_argument("--record-reads", action="store_true",
                    help="MOVE 3: logga la sequenza ordinata delle letture-ambiente (document/navigator/performance/window) col valore -> env_reads.json (run diagnostica/sacrificale)")
    ap.add_argument("--clean", action="store_true",
                    help="NON iniettare l'hook charCodeAt (test pulito: isola se il blocco e' causato dalla manomissione)")
    ap.add_argument("--native", action="store_true",
                    help="NON forzare user_agent/viewport: usa i default reali del Chrome lanciato (evita il mismatch UA)")
    ap.add_argument("--exe", default=None,
                    help="path a un eseguibile Chromium specifico (es. Chrome for Testing 146/150) per EXACT-MATCH col target curl_cffi")
    ap.add_argument("--validate", action="store_true",
                    help="dopo HOME, interagisci (mouse/scroll) e POLLA _abck finche' il campo validazione != -1, "
                         "poi (se --gated-url) naviga alla pagina gated. Serve a harvestare un _abck VALIDATO (non ~-1~).")
    ap.add_argument("--gated-url", default="https://www.fansale.it/tickets/all/anna/777360/21866634",
                    help="URL gated da visitare durante --validate per forzare la validazione del cookie")
    ap.add_argument("--validate-timeout", type=int, default=60,
                    help="secondi massimi di poll/interazione per validare _abck")
    ap.add_argument("--capresp", action="store_true",
                    help="cattura il detail REALE degli eventi ak_cpr_chlg_* avvolgendo dispatchEvent/CustomEvent "
                         "su QUALSIASI target (il listener window passivo non basta) -> ak_cpr_events.txt")
    ap.add_argument("--capsend", action="store_true",
                    help="avvolge XHR.send/fetch/sendBeacon e logga body+stack delle POST verso /akam/, con "
                         "sensor_data, o grandi (>=500B, prende il cifrario sec-cpt) -> ak_cpr_send.txt")
    ap.add_argument("--cdptrace", action="store_true",
                    help="CDP PASSIVO (niente prototype-wrap, niente flag bot): traccia initiator.stack "
                         "ASYNC delle POST sec-cpt/akam -> chi scatena il sensor -> ak_cpr_cdp.txt")
    ap.add_argument("--cdpbreak", action="store_true",
                    help="breakpoint XHR su '?t=' (robusto, indip. dagli offset): al pause dumpa callFrames + "
                         "asyncStackTrace fino alla RADICE (kickoff) + scope best-effort -> ak_cpr_break.txt")
    ap.add_argument("--fccbind", action="store_true",
                    help="cattura fromCharCode del browser LIVE via binding (expose_function): sopravvive a "
                         "reload/Queue-it. Usa con --validate per far scattare la PoW. -> fromcharcode_browser.json")
    ap.add_argument("--capmc8", action="store_true",
                    help="salva INTERE le risposte di /_sec/cpr/* (params challenge) e lo script-stage mC8 "
                         "(URL con '&x=', caricato dinamicamente da BTn) -> seccpt_cpr_*.json / seccpt_mc8*.js. "
                         "Servono per proseguire il browserless (devirtualizzare lo stage col cifrario).")
    ap.add_argument("--capzc", action="store_true",
                    help="[DA VALIDARE sul tuo lato] cattura PASSIVA del self-hash d'integrita' ZC()=A()-B() "
                         "della VM sec-cpt: scopre via regex la funzione-hash memoizzata nello script VM, mette un "
                         "breakpoint PASSIVO (non avvolge nulla -> non altera Function.toString ne' il self-hash) e "
                         "al reload legge il valore. -> ak_cpr_zc.txt  (serve per ZCVAL in harness_clean.js)")
    args = ap.parse_args()

    if sync_playwright is None:
        print("[FATAL] nessun driver (patchright/playwright)"); sys.exit(1)
    print(f"[info] driver={DRIVER}")

    proxy = None
    if not args.no_proxy:
        try:
            from proxies import pick_proxy_dict
            proxy = pick_proxy_dict(index=args.proxy_index)
        except Exception:
            pass

    events = []
    netdump = []   # dump COMPLETO di rete fansale (per trovare U3/challenge-data)

    def on_response_dump(resp):
        try:
            u = resp.url
            if "fansale.it" not in u and "akamai" not in u:
                return
            rt = ""
            try:
                rt = resp.request.resource_type
            except Exception:
                pass
            entry = {"url": u[:200], "status": resp.status, "rt": rt, "method": resp.request.method}
            # salva corpo per akam/sec-cpt/documenti/script/xhr piccoli
            if ("/akam/" in u or "sec-cpt" in u or re.search(r"[?&]t=\d+", u)
                    or rt in ("document", "xhr", "fetch")):
                try:
                    body = resp.text() or ""
                    entry["body"] = body[:4000]
                    entry["blen"] = len(body)
                except Exception:
                    pass
            netdump.append(entry)
        except Exception:
            pass

    mc8_seen = set()

    def on_capmc8(resp):
        # salva INTERI: risposte /_sec/cpr/* (params) e lo script-stage mC8 (URL con &x=) caricato da BTn
        try:
            u = resp.url
            if "fansale.it" not in u:
                return
            if "/_sec/cpr/" in u or "/_sec/sbsd/" in u:
                try:
                    body = resp.text() or ""
                    tag = re.sub(r"[^a-zA-Z0-9]", "_", u.split("?")[0].rstrip("/").split("/")[-1])[:24] or "resp"
                    fn = "seccpt_cpr_%s.json" % tag
                    with open(fn, "w", encoding="utf-8") as fh:
                        fh.write("// " + u + "\n" + body)
                    print(f"[capmc8] /_sec/ risposta salvata -> {fn} ({len(body)}B)  {u[:70]}")
                except Exception as e:
                    print(f"[capmc8] body /_sec/ fallito ({u[:50]}): {e}")
            elif "&x=" in u and u not in mc8_seen:
                # stage dinamico mC8: BTn fa w58.src = mC8 + "&x=" + JLn()
                try:
                    rtp = ""
                    try:
                        rtp = resp.request.resource_type
                    except Exception:
                        pass
                    body = resp.text() or ""
                    if rtp == "script" or len(body) > 1000:
                        mc8_seen.add(u)
                        fn = "seccpt_mc8_%d.js" % (len(mc8_seen))
                        with open(fn, "w", encoding="utf-8") as fh:
                            fh.write(body)
                        print(f"[capmc8] STAGE mC8 salvato -> {fn} ({len(body)}B)  {u[:70]}")
                except Exception:
                    pass
        except Exception:
            pass

    def on_request(req):
        try:
            pd = req.post_data or ""
            # il POST sec-cpt va a un URL con t=<id>: cattura il body INTERO (per decifrarlo)
            if re.search(r"[?&]t=\d+", req.url) and req.method == "POST":
                events.append({"kind": "seccpt_post", "url": req.url,
                               "headers": dict(req.headers),
                               "post_data": pd})      # INTERO
            elif req.method == "POST" and '"sensor_data"' in pd:
                # SENSOR _abck (bmak): salva il body INTERO + headers (per RE del formato e del generatore)
                events.append({"kind": "abck_sensor", "url": req.url,
                               "headers": dict(req.headers), "post_data": pd})   # INTERO
            elif is_challenge(req.url) or (req.method == "POST" and "fansale.it" in req.url):
                events.append({"kind": "request", "method": req.method, "url": req.url,
                               "post_data": pd[:200]})
        except Exception:
            pass

    def on_response(resp):
        try:
            # salva lo SCRIPT-CHALLENGE (GET con v= e t=, corpo JS grande) accoppiato al payload
            if re.search(r"[?&]v=[^&]+&(?:amp;)?t=\d+", resp.url) or (re.search(r"[?&]t=\d+", resp.url) and resp.request.method == "GET"):
                try:
                    txt = resp.text() or ""
                    if len(txt) > 50000 and "function" in txt[:5000]:
                        t = re.search(r"[?&]t=(\d+)", resp.url)
                        fn = f"seccpt_script_{t.group(1) if t else 'live'}.js"
                        with open(fn, "w", encoding="utf-8") as fh:
                            fh.write(txt)
                        events.append({"kind": "script", "url": resp.url, "file": fn, "len": len(txt)})
                        print(f"[script] challenge script salvato: {len(txt)}B -> {fn}")
                except Exception:
                    pass
            # salva ANCHE gli script JS grandi (bmak _abck): endpoint /akam/ o script senza t=, QUALSIASI resource_type.
            try:
                u = resp.url
                is_akam = "/akam/" in u
                if (("fansale.it" in u) and resp.request.method == "GET" and not re.search(r"[?&]t=\d+", u)
                        and (is_akam or (resp.request.resource_type == "script"))):
                    txt = resp.text() or ""
                    # /akam/ = bmak di sicuro -> salva senza check 'function'; altri script -> richiedi 'function'
                    if len(txt) > 15000 and (is_akam or "function" in txt[:5000]):
                        seg = re.sub(r"[?#].*$", "", u).rstrip("/").split("/")[-1][:24] or "aux"
                        fn = f"bmak_script_{seg}.js"
                        if not os.path.exists(fn):
                            with open(fn, "w", encoding="utf-8") as fh:
                                fh.write(txt)
                            events.append({"kind": "bmak_script", "url": u, "file": fn, "len": len(txt)})
                            print(f"[bmak] script JS salvato: {len(txt)}B -> {fn}  {u[:60]}")
            except Exception:
                pass
            if is_challenge(resp.url):
                events.append({"kind": "response", "status": resp.status, "url": resp.url})
            # salva il DOCUMENTO HTML dell'interstitial (non il CSS): contiene i parametri challenge
            # inline (ak_cpr / cpr_chlge / il blob che diventa il seed). Filtro per resource_type document.
            try:
                rt = ""
                try:
                    rt = resp.request.resource_type
                except Exception:
                    rt = ""
                body = None
                if rt == "document" and "fansale.it" in resp.url:
                    body = resp.text() or ""
                    is_inter = any(m in body for m in ("sec-if-cpt", "behavioral-content", "cpr_chlge",
                                                       "ak_cpr", "bazadebezolkohpepadr", "sec-cpt-if"))
                    if is_inter:
                        tt = re.search(r"[?&]t=(\d+)", resp.url)
                        fn = f"interstitial_doc_{tt.group(1) if tt else 'live'}.html"
                        with open(fn, "w", encoding="utf-8") as fh:
                            fh.write(body)
                        events.append({"kind": "interstitial_doc", "url": resp.url, "file": fn, "len": len(body)})
                        print(f"[interstitial] DOCUMENTO salvato: {len(body)}B -> {fn}")
            except Exception:
                pass
        except Exception:
            pass

    with sync_playwright() as p:
        launch = {"headless": not args.headful}
        if args.exe:
            launch["executable_path"] = args.exe   # Chromium specifico (es. Chrome for Testing 146/150)
            print(f"[exe] uso executable: {args.exe}")
        elif args.channel:
            launch["channel"] = args.channel
        if proxy:
            launch["proxy"] = proxy
        browser = p.chromium.launch(**launch)
        if args.native:
            print("[native] nessun override UA/viewport: uso i default reali di Chrome")
            ctx = browser.new_context(locale="it-IT", timezone_id="Europe/Rome")
        else:
            ctx = browser.new_context(user_agent=UA, locale="it-IT", timezone_id="Europe/Rome",
                                      viewport={"width": 1920, "height": 1040})
        # MOVE 3b: cattura i TIPI di evento registrati (addEventListener) per capire se i 2 nomi
        # garbled dell'harness sono errori di decode (browser=ASCII) o legittimi (browser=non-ASCII).
        if args.record_reads:
            ctx.add_init_script(
                "(function(){try{if(window.__ae)return;window.__ae=1;window.__aetypes=[];"
                "var O=EventTarget.prototype.addEventListener;"
                "EventTarget.prototype.addEventListener=function(t){try{window.__aetypes.push(String(t));}catch(e){}return O.apply(this,arguments);};"
                "try{O.toString=function(){return 'function addEventListener() { [native code] }';};}catch(e){}"
                "}catch(e){}})();"
            )
        # LISTENER PASSIVO per catturare U3 reale = detail dell'evento ak_cpr_chlg_init (e 'message').
        # Non manomette prototype -> non triggera integrity. Serializza detail/data in localStorage.
        ctx.add_init_script(
            "(function(){try{if(window.__u3)return;window.__u3=1;"
            "function ser(o){try{var seen=[];return JSON.stringify(o,function(k,v){"
            "if(typeof v==='function')return '[fn]';if(typeof v==='object'&&v){if(seen.indexOf(v)>=0)return '[circ]';seen.push(v);}return v;});}catch(e){return '[err:'+e+']';}}"
            "function cap(tag){return function(e){try{var d=(e&&e.detail!==undefined)?e.detail:(e&&e.data!==undefined?e.data:e);"
            "var cur=localStorage.getItem('__u3cap')||'';localStorage.setItem('__u3cap',cur+tag+'|'+ser(d)+'\\n');}catch(x){}};}"
            "['ak_cpr_chlg_init','ak_cpr_chlg_resp','message'].forEach(function(ev){try{window.addEventListener(ev,cap(ev),true);}catch(x){}});"
            "}catch(e){}})();"
        )
        # --capresp: cattura il detail REALE di ak_cpr_chlg_* avvolgendo dispatchEvent GLOBALE
        # (+ CustomEvent): il listener window passivo non scatta se l'evento e' dispatchato su un
        # altro target. toString spoofato a [native code] per ridurre il rilevamento integrity.
        if args.capresp:
            ctx.add_init_script(
                "(function(){try{if(window.__dc)return;window.__dc=1;"
                "function ser(o){try{var seen=[];return JSON.stringify(o,function(k,v){"
                "if(typeof v==='function')return '[fn]';if(typeof v==='object'&&v){if(seen.indexOf(v)>=0)return '[circ]';seen.push(v);}return v;});}catch(e){return '[err:'+e+']';}}"
                "function rec(w,e){try{if(!e)return;var t=String(e.type||'');if(!/ak_cpr|chlg/i.test(t))return;"
                "var d=(e.detail!==undefined)?e.detail:(e.data!==undefined?e.data:null);"
                "var cur=localStorage.getItem('__dispcap')||'';localStorage.setItem('__dispcap',cur+w+'|'+t+'|'+ser(d)+'\\n');}catch(x){}}"
                "var D=EventTarget.prototype.dispatchEvent;EventTarget.prototype.dispatchEvent=function(e){try{rec('disp',e);}catch(x){}return D.apply(this,arguments);};"
                "try{EventTarget.prototype.dispatchEvent.toString=function(){return 'function dispatchEvent() { [native code] }';};}catch(e){}"
                "var C=window.CustomEvent;if(C){window.CustomEvent=function(t,i){try{rec('new',{type:t,detail:i&&i.detail});}catch(x){}return new C(t,i);};"
                "window.CustomEvent.prototype=C.prototype;try{window.CustomEvent.toString=function(){return 'function CustomEvent() { [native code] }';};}catch(e){}}"
                "}catch(e){}})();"
            )
        # --capsend: localizza la FUNZIONE di encode loggando body + stack al momento della POST
        # del sensore (XHR/fetch/sendBeacon). Match: url /akam/, body con sensor_data, o POST grande
        # (>=500B, cosi' prende anche il cifrario sec-cpt che NON contiene 'sensor_data').
        if args.capsend:
            ctx.add_init_script(
                "(function(){try{if(window.__sc)return;window.__sc=1;var N=0;"
                "function logsend(w,u,body,isPost){try{"
                "if(!(/\\/akam\\//i.test(u)||/sensor_data/.test(body)||(isPost&&body.length>=500)))return;"
                "if(N++>20)return;var st='';try{st=(new Error()).stack||'';}catch(e){}"
                "var cur=localStorage.getItem('__sendcap')||'';"
                "localStorage.setItem('__sendcap',cur+'=== '+w+' '+String(u).slice(0,170)+'\\nBODYLEN='+body.length+'\\nBODY='+body.slice(0,500)+'\\nSTACK='+String(st).slice(0,1500)+'\\n\\n');}catch(x){}}"
                "var XP=XMLHttpRequest.prototype,_op=XP.open,_sn=XP.send;"
                "XP.open=function(m,u){try{this.__m=m;this.__u=u;}catch(e){}return _op.apply(this,arguments);};"
                "XP.send=function(b){try{logsend('xhr',this.__u||'',(b==null?'':''+b),String(this.__m||'').toUpperCase()==='POST');}catch(e){}return _sn.apply(this,arguments);};"
                "try{XP.open.toString=function(){return 'function open() { [native code] }';};XP.send.toString=function(){return 'function send() { [native code] }';};}catch(e){}"
                "var _f=window.fetch;if(_f){window.fetch=function(u,o){try{var url=(typeof u==='string')?u:((u&&u.url)||'');var m=(o&&o.method)||'GET';var body=(o&&o.body!=null)?(''+o.body):'';logsend('fetch',url,body,String(m).toUpperCase()==='POST');}catch(e){}return _f.apply(this,arguments);};try{window.fetch.toString=function(){return 'function fetch() { [native code] }';};}catch(e){}}"
                "try{var NB=navigator.sendBeacon;if(NB){navigator.sendBeacon=function(u,d){try{logsend('beacon',''+u,(d!=null?''+d:''),true);}catch(e){}return NB.apply(navigator,arguments);};}}catch(e){}"
                "}catch(e){}})();"
            )
        # cattura il PLAINTEXT del cifrario sec-cpt via hook charCodeAt -> localStorage
        # (sopravvive al reload dell'interstitial). Stringhe distinte >=250 char.
        # NB: questo hook manomette String.prototype.charCodeAt -> Akamai puo' rilevarlo.
        # Con --clean lo saltiamo per isolare se il blocco dipende dalla manomissione.
        if args.clean:
            print("[clean] hook charCodeAt DISATTIVATO (nessuna cattura plaintext, test pulito)")
        if not args.clean:
            ctx.add_init_script(
            "(function(){try{var W=window;if(W.__capHooked)return;W.__capHooked=1;W.__capseen={};"
            "var _o=String.prototype.charCodeAt;String.prototype.charCodeAt=function(i){try{var s=''+this;"
            "if(s.length>=250){var key=s.length+':'+s.slice(0,20);if(!W.__capseen[key]){W.__capseen[key]=1;"
            "try{var cur=localStorage.getItem('__cap')||'';localStorage.setItem('__cap',cur+s.length+'|'+s+'\\n');}catch(e){}}}"
            "}catch(e){}return _o.apply(this,arguments);};"
            "try{String.prototype.charCodeAt.toString=function(){return 'function charCodeAt() { [native code] }';};}catch(e){}"
            "}catch(e){}})();"
        )
        # MOVE 3c: hook fromCharCode (con cui il decoder COSTRUISCE i risultati) -> cattura la sequenza
        # ordinata dei char-code decodificati del browser (cap 150k). Diff con l'harness sullo stesso script.
        if args.record_reads:
            ctx.add_init_script(
                "(function(){try{if(window.__fcc)return;window.__fcc=1;var buf=[];var _o=String.fromCharCode;"
                "function flush(){try{localStorage.setItem('__fcccap',JSON.stringify(buf.slice(0,150000)));}catch(e){}}"
                "String.fromCharCode=function(){try{if(buf.length<150000){for(var i=0;i<arguments.length;i++)buf.push(arguments[i]|0);if(buf.length%2000<arguments.length)flush();}}catch(e){}return _o.apply(String,arguments);};"
                "try{String.fromCharCode.toString=function(){return 'function fromCharCode() { [native code] }';};}catch(e){}"
                "try{window.addEventListener('pagehide',flush,true);window.addEventListener('beforeunload',flush,true);window.addEventListener('visibilitychange',flush,true);}catch(e){}"
                "try{setInterval(flush,500);}catch(e){}"
                "}catch(e){}})();"
            )
        page = ctx.new_page()
        page.on("request", on_request)
        page.on("response", on_response)
        page.on("response", on_response_dump)
        if args.capmc8:
            page.on("response", on_capmc8)
            print("[capmc8] attivo: salvo /_sec/cpr/* (params) e lo stage mC8 (URL con &x=) appena arrivano")
        # --cdptrace: CDP passivo. requestWillBeSent.initiator.stack + setAsyncCallStackDepth
        # => catena di chiamata ASYNC che porta al POST del sensor (chi lo scatena / cosa aspetta).
        cdp_hits = []

        def _fmt_stack(stk, depth=0):
            lines = []
            if not stk:
                return lines
            for fr in (stk.get("callFrames") or [])[:8]:
                fn = fr.get("functionName") or "(anon)"
                short = (fr.get("url") or "").split("/")[-1][:46] or "?"
                lines.append(f"{'  ' * depth}{fn} @ {short}:{fr.get('lineNumber', 0) + 1}:{fr.get('columnNumber', 0) + 1}")
            par = stk.get("parent")
            if par:
                lines.append(f"{'  ' * depth}-- async: {par.get('description', '?')} --")
                lines += _fmt_stack(par, depth + 1)
            return lines

        def _on_rws(params):
            try:
                req = params.get("request", {}) or {}
                url = req.get("url", "")
                is_post = req.get("method") == "POST"
                # cattura TUTTE le POST verso fansale.it ESCLUSA la telemetria GA (sst/collect/gtag),
                # cosi' prendiamo sec-cpt e bmak a prescindere dalla forma d'URL
                interesting = (("fansale.it" in url and "sst.fansale" not in url
                                and "/g/collect" not in url) or "/akam/" in url) and \
                    "googletagmanager" not in url
                if is_post and interesting:
                    init = params.get("initiator", {}) or {}
                    cdp_hits.append({"url": url, "itype": init.get("type"),
                                     "has_t": bool(re.search(r"[?&]t=\d+", url)),
                                     "is_akam": "/akam/" in url,
                                     "stack": _fmt_stack(init.get("stack"))})
            except Exception:
                pass

        if args.cdptrace:
            try:
                _client = ctx.new_cdp_session(page)
                _client.send("Debugger.enable")
                _client.send("Debugger.setAsyncCallStackDepth", {"maxDepth": 32})
                _client.send("Network.enable")
                _client.on("Network.requestWillBeSent", _on_rws)
                print("[cdptrace] CDP attivo: traccio initiator.stack ASYNC delle POST sec-cpt/akam")
            except Exception as e:
                print(f"[cdptrace] setup fallito: {e}")

        # --cdpbreak: breakpoint XHR '?t=' -> al pause cattura stack sync + asyncStackTrace (radice=kickoff)
        # + scope best-effort dei frame top; poi rimuove il breakpoint e fa resume (pausa unica).
        break_dump = []
        if args.cdpbreak:
            try:
                _bclient = ctx.new_cdp_session(page)
                _bclient.send("Debugger.enable")
                _bclient.send("Debugger.setAsyncCallStackDepth", {"maxDepth": 128})
                _bdone = {"v": False}

                def _dump_scope(fr, idx):
                    rows = []
                    for sc in (fr.get("scopeChain") or []):
                        if sc.get("type") not in ("local", "closure", "block"):
                            continue
                        oid = (sc.get("object") or {}).get("objectId")
                        if not oid:
                            continue
                        try:
                            res = _bclient.send("Runtime.getProperties",
                                                {"objectId": oid, "ownProperties": True, "generatePreview": False})
                        except Exception:
                            continue
                        parts = []
                        for p in (res.get("result") or []):
                            v = p.get("value") or {}
                            if v.get("type") in ("number", "string", "boolean"):
                                parts.append(f"{p.get('name')}={v.get('value')}")
                        if parts:
                            rows.append(f"  [f{idx}/{fr.get('functionName') or '?'}/{sc.get('type')}] " + " | ".join(parts[:80]))
                    return rows

                def _on_paused(params):
                    try:
                        if not _bdone["v"]:
                            frames = params.get("callFrames", []) or []
                            L = [f"PAUSED reason={params.get('reason')} data={params.get('data', {})}"]
                            for i, fr in enumerate(frames[:10]):
                                loc = fr.get("location", {}) or {}
                                L.append(f"  #{i} {fr.get('functionName') or '(anon)'} @ L{loc.get('lineNumber', 0) + 1}:C{loc.get('columnNumber', 0) + 1}")
                            ast = params.get("asyncStackTrace")
                            d = 0
                            while ast and d < 60:
                                L.append(f"  -- async: {ast.get('description', '?')} --")
                                for fr in (ast.get("callFrames") or [])[:6]:
                                    loc = fr.get("location", {}) or {}
                                    L.append(f"     {fr.get('functionName') or '(anon)'} @ L{loc.get('lineNumber', 0) + 1}:C{loc.get('columnNumber', 0) + 1}")
                                ast = ast.get("parent")
                                d += 1
                            for i, fr in enumerate(frames[:4]):
                                L += _dump_scope(fr, i)
                            break_dump.append("\n".join(L))
                            _bdone["v"] = True
                            try:
                                _bclient.send("DOMDebugger.removeXHRBreakpoint", {"url": "?t="})
                            except Exception:
                                pass
                    except Exception as e:
                        break_dump.append(f"[err paused: {e}]")
                    finally:
                        try:
                            _bclient.send("Debugger.resume")
                        except Exception:
                            pass

                _bclient.on("Debugger.paused", _on_paused)
                _bclient.send("DOMDebugger.setXHRBreakpoint", {"url": "?t="})
                print("[cdpbreak] breakpoint XHR '?t=' armato (pausa 1 volta al submit sec-cpt, poi resume)")
            except Exception as e:
                print(f"[cdpbreak] setup fallito: {e}")

        # --capzc: cattura PASSIVA del self-hash d'integrita' ZC()=A()-B() (DA VALIDARE sul tuo lato).
        # Fase 1 (setup qui, pre-goto): sessione CDP + Debugger.enable + raccolta degli scriptId via
        # Debugger.scriptParsed (lo script VM interno e' un eval generato a runtime). Fase 2 dopo il goto.
        zc_dump = []
        zc_scripts = []            # [{scriptId, url}]
        _zclient = None
        if args.capzc:
            try:
                _zclient = ctx.new_cdp_session(page)
                _zclient.send("Debugger.enable")
                def _on_script(params):
                    try:
                        zc_scripts.append({"scriptId": params.get("scriptId"),
                                           "url": params.get("url") or ""})
                    except Exception:
                        pass
                _zclient.on("Debugger.scriptParsed", _on_script)
                print("[capzc] Debugger abilitato: raccolgo gli script (fase 1 scoperta dopo il load)")
            except Exception as e:
                print(f"[capzc] setup fase 1 fallito: {e}")

        # --fccbind: cattura fromCharCode del browser LIVE via binding (sopravvive reload/Queue-it).
        # La fromCharCode avvolta batch-chiama window.__fccpush(JSON) -> callback Python che accumula.
        fcc_codes = []
        if args.fccbind:
            try:
                def _fccpush(payload):
                    try:
                        fcc_codes.extend(json.loads(payload))
                    except Exception:
                        pass
                page.expose_function("__fccpush", _fccpush)
                ctx.add_init_script(
                    "(function(){try{if(window.__fb)return;window.__fb=1;var _o=String.fromCharCode,batch=[];"
                    "function flush(){try{if(batch.length&&window.__fccpush){var b=batch;batch=[];window.__fccpush(JSON.stringify(b));}}catch(e){}}"
                    "String.fromCharCode=function(){try{for(var i=0;i<arguments.length;i++)batch.push(arguments[i]|0);if(batch.length>=400)flush();}catch(e){}return _o.apply(String,arguments);};"
                    "try{String.fromCharCode.toString=function(){return 'function fromCharCode() { [native code] }';};}catch(e){}"
                    "try{setInterval(flush,250);}catch(e){}"
                    "try{document.addEventListener('visibilitychange',flush,true);window.addEventListener('pagehide',flush,true);window.addEventListener('beforeunload',flush,true);}catch(e){}"
                    "}catch(e){}})();"
                )
                print("[fccbind] binding __fccpush attivo: fromCharCode del browser streammato live")
            except Exception as e:
                print(f"[fccbind] setup fallito: {e}")
        try:
            page.goto(HOME, wait_until="domcontentloaded", timeout=45000)
        except Exception as e:
            print(f"[warn] goto: {e}")
        page.wait_for_timeout(args.wait)       # lascia risolvere l'interstitial

        # --capmc8: pausa interattiva: naviga/risolvi il sec-cpt A MANO nel browser headful; i handler
        # on_capmc8 salvano /_sec/cpr/* e lo stage mC8 appena la VM li richiede. Rileva se c'e' un sec-cpt attivo.
        if args.capmc8:
            import sys as _sys2

            def _looks_seccpt():
                try:
                    html = page.content()
                except Exception:
                    return False, 0
                markers = ("sec-bc-tile", "sec-if-cpt", "progress-button", "ak_cpr", "sec-cpt",
                           "Powered and protected")
                return (any(m in html for m in markers) and len(html) < 20000), (len(html) if html else 0)

            act, ln = _looks_seccpt()
            print(f"[capmc8] pagina: {ln}B | sec-cpt attivo: {act}")
            try:
                if _sys2.stdin and _sys2.stdin.isatty():
                    print("[capmc8] >>> Nel browser headful: naviga alla pagina gated finche' NON compare il sec-cpt "
                          "(interstitial corto, 'Powered and protected by Akamai'), poi RISOLVILO/ASPETTA che completi "
                          "(il reload). I file seccpt_cpr_*.json / seccpt_mc8_*.js vengono salvati quando la VM li "
                          "richiede. Premi INVIO QUI quando hai finito (o se il sec-cpt non compare).")
                    try:
                        input()
                    except Exception:
                        pass
                    print("[capmc8] fine pausa; proseguo col dump.")
                else:
                    print("[capmc8] (non-interattivo) attendo 300s per lasciar completare un eventuale sec-cpt...")
                    page.wait_for_timeout(300000)
            except Exception as e:
                print(f"[capmc8] pausa: {e}")

        # --capzc: FASE 1 scoperta (regex sulla firma hash memoizzata) + FASE 2 lettura (breakpoint passivo + reload).
        if args.capzc and _zclient is not None:
            import re as _re
            import sys as _sys
            # Manuale: dai tempo di risolvere l'interstitial a mano, cosi' la VM esegue e crea l'eval interno.
            try:
                if _sys.stdin and _sys.stdin.isatty():
                    input("[capzc] Risolvi/attendi l'interstitial nel browser FINCHE' la challenge e' partita "
                          "(NON Access Denied), poi premi INVIO per la scoperta ZC...")
                else:
                    page.wait_for_timeout(8000)
            except Exception:
                page.wait_for_timeout(8000)
            # firma memoizzata self-reassign: X(){var b;b=A()-B();return X=function(){return b;},b;}
            # due forme (nomi ruotano): dichiarazione `function X(){...}` e assegnazione `X=function(){...}`.
            ZC_RES = [
                _re.compile(r"function\s+([A-Za-z0-9_$]+)\s*\(\)\s*\{var ([A-Za-z0-9_$]+);\s*\2\s*=\s*"
                            r"[A-Za-z0-9_$]+\(\)\s*-\s*[A-Za-z0-9_$]+\(\);\s*return \1\s*=\s*function\s*\(\)\s*"
                            r"\{return \2;\}\s*,\s*\2;\}"),
                _re.compile(r"([A-Za-z0-9_$]+)\s*=\s*function\s*\(\)\s*\{var ([A-Za-z0-9_$]+);\s*\2\s*=\s*"
                            r"[A-Za-z0-9_$]+\(\)\s*-\s*[A-Za-z0-9_$]+\(\);\s*return \1\s*=\s*function\s*\(\)\s*"
                            r"\{return \2;\}\s*,\s*\2;\}"),
            ]
            # fallback piu' largo: una var assegnata a differenza-di-due-chiamate, poi self-reassign con quella var
            ZC_LOOSE = _re.compile(r"\{var ([A-Za-z0-9_$]+);\s*\1\s*=\s*[A-Za-z0-9_$]+\(\)\s*-\s*[A-Za-z0-9_$]+\(\);"
                                   r"\s*return [A-Za-z0-9_$]+\s*=\s*function")
            best = None   # (src_len, scriptId, url, fn_name, var_name, line, col, snippet)
            seen = set()
            # DIAGNOSTICA: elenca gli script raccolti (per capire se l'eval VM interno c'e')
            zc_dump.append("[capzc] script raccolti (len | url | head):")
            for sc in list(zc_scripts):
                sid = sc.get("scriptId")
                if not sid or sid in seen:
                    continue
                seen.add(sid)
                try:
                    src = _zclient.send("Debugger.getScriptSource", {"scriptId": sid}).get("scriptSource") or ""
                except Exception:
                    continue
                zc_dump.append(f"   len={len(src)} url={ (sc.get('url') or '(eval/anon)')[:60] } head={src[:50]!r}")
                m = None
                for rx in ZC_RES:
                    m = rx.search(src)
                    if m:
                        break
                if not m:
                    lm = ZC_LOOSE.search(src)
                    if lm:
                        zc_dump.append(f"   [LOOSE] possibile hash-mem @len={len(src)} off={lm.start()}: "
                                       f"{src[lm.start():lm.start()+120]!r}")
                    continue
                ret_off = src.find("return " + m.group(1) + "=", m.start())
                if ret_off < 0:
                    ret_off = m.start()
                line = src.count("\n", 0, ret_off)
                col = ret_off - (src.rfind("\n", 0, ret_off) + 1)
                cand = (len(src), sid, sc.get("url") or "", m.group(1), m.group(2), line, col,
                        src[m.start():m.start() + 90])
                if best is None or cand[0] > best[0]:   # preferisci lo script piu' grande (= programma VM)
                    best = cand
            if best is None:
                zc_dump.append("[capzc] FASE 1: nessuna funzione-hash memoizzata trovata. Cause probabili: (a) la VM "
                               "sec-cpt NON ha eseguito (sessione bloccata/Access Denied -> niente eval interno); "
                               "(b) struttura diversa (vedi righe [LOOSE] e la lista script sopra). Serve un run su "
                               "sessione in cui la challenge gira davvero (headful, risolvi l'interstitial a mano).")
                print(zc_dump[-1])
            else:
                _, sid, url, fnm, vnm, line, col, snip = best
                zc_dump.append(f"[capzc] FASE 1: hash trovato fn={fnm} var={vnm} @script({len(url)and url or sid}) "
                               f"L{line}:C{col} | {snip!r}")
                print(zc_dump[-1])
                # FASE 2: breakpoint PASSIVO (urlRegex per sopravvivere al reload/re-parse), poi reload, leggi var.
                _zresult = {"val": None}
                _zdone = {"v": False}
                def _on_zpaused(params):
                    try:
                        if _zdone["v"]:
                            return
                        frames = params.get("callFrames", []) or []
                        if not frames:
                            return
                        cfid = frames[0].get("callFrameId")
                        r = _zclient.send("Debugger.evaluateOnCallFrame",
                                          {"callFrameId": cfid, "expression": vnm,
                                           "returnByValue": True, "silent": True})
                        val = ((r or {}).get("result") or {}).get("value")
                        # leggi anche le due meta' A()-B() se possibile (cross-check), best-effort
                        zc_dump.append(f"[capzc] FASE 2: PAUSE in {frames[0].get('functionName') or '?'} -> "
                                       f"{vnm} = {val}")
                        _zresult["val"] = val
                        _zdone["v"] = True
                    except Exception as e:
                        zc_dump.append(f"[capzc] FASE 2 err paused: {e}")
                        _zdone["v"] = True
                    finally:
                        try:
                            _zclient.send("Debugger.resume")
                        except Exception:
                            pass
                try:
                    _zclient.on("Debugger.paused", _on_zpaused)
                    # urlRegex: se lo script ha un url usalo, altrimenti 'evalmachine|VM' (eval anonimi)
                    urlrx = _re.escape(url) if url else "evalmachine|^$|VM\\d*"
                    _zclient.send("Debugger.setBreakpointByUrl",
                                  {"urlRegex": urlrx, "lineNumber": line, "columnNumber": col})
                    print(f"[capzc] FASE 2: breakpoint passivo armato (urlRegex={urlrx[:40]} L{line}:C{col}); ricarico...")
                    try:
                        page.goto(HOME, wait_until="domcontentloaded", timeout=45000)
                    except Exception as e:
                        zc_dump.append(f"[capzc] reload: {e}")
                    page.wait_for_timeout(max(args.wait, 4000))
                    if _zresult["val"] is not None:
                        zc_dump.append(f"[capzc] >>> ZC = {_zresult['val']}  "
                                       f"(se != 37 -> ZCVAL={_zresult['val']} in harness_clean.js; se == 37 -> "
                                       f"la divergenza NON e' ZC)")
                        print(zc_dump[-1])
                    else:
                        zc_dump.append("[capzc] FASE 2: nessun pause catturato (il breakpoint non ha agganciato il "
                                       "reparse: la colonna puo' essere shiftata, o lo script e' un eval senza url "
                                       "stabile). Prova a rifare con l'url corretto o aumenta il wait.")
                        print(zc_dump[-1])
                except Exception as e:
                    zc_dump.append(f"[capzc] FASE 2 setup fallito: {e}")
                    print(zc_dump[-1])
            try:
                with open("ak_cpr_zc.txt", "w", encoding="utf-8") as _f:
                    _f.write("\n".join(zc_dump))
                print("[capzc] dump -> ak_cpr_zc.txt")
            except Exception:
                pass

        # VALIDAZIONE _abck: l'harvest da HOME passiva salva un cookie ~-1~ (NON validato) -> 403 sulle
        # pagine gated. Qui interagiamo (nutre il sensore comportamentale) e polliamo finche' il 2o campo
        # di _abck != -1, poi (opzionale) visitiamo la pagina gated. Consigliato: --headful --native --validate.
        def abck_state():
            try:
                for c in ctx.cookies():
                    if c["name"] == "_abck":
                        parts = c["value"].split("~")
                        return (parts[1] if len(parts) > 1 else "?"), c["value"]
            except Exception:
                pass
            return None, ""
        if args.validate:
            if not args.headful:
                print("[validate] ATTENZIONE: senza --headful il sensore comportamentale puo' NON validare")
            fld, _ = abck_state()
            print(f"[validate] _abck campo iniziale = {fld} (-1 = non validato)")
            import time as _t
            t_end = _t.time() + args.validate_timeout
            vw = page.viewport_size or {"width": 1280, "height": 720}
            step = 0
            visited_gated = False
            while _t.time() < t_end:
                step += 1
                # interazione realistica: movimenti mouse + scroll (feed al sensore comportamentale)
                try:
                    import random as _r
                    for _ in range(6):
                        page.mouse.move(_r.randint(5, vw["width"] - 5), _r.randint(5, vw["height"] - 5),
                                        steps=_r.randint(3, 8))
                        page.wait_for_timeout(_r.randint(120, 320))
                    page.mouse.wheel(0, _r.randint(200, 700))
                except Exception as e:
                    print(f"[validate] interazione: {e}")
                page.wait_for_timeout(1200)
                fld, val = abck_state()
                print(f"[validate] step {step} _abck campo = {fld}")
                if fld not in (None, "-1", "?"):
                    print(f"[validate] _abck VALIDATO (campo={fld}) dopo ~{step} step")
                    break
                # a meta' tempo, prova a navigare alla pagina gated per forzare la challenge
                if not visited_gated and _t.time() > t_end - args.validate_timeout / 2 and args.gated_url:
                    visited_gated = True
                    try:
                        print(f"[validate] navigo gated: {args.gated_url}")
                        page.goto(args.gated_url, wait_until="domcontentloaded", timeout=45000)
                        page.wait_for_timeout(2000)
                    except Exception as e:
                        print(f"[validate] goto gated: {e}")
            fld, _ = abck_state()
            if fld in (None, "-1", "?"):
                print(f"[validate] NON validato (campo={fld}): l'identita' salvata reggera' solo pagine non-gated. "
                      f"Riprova con --headful e/o aumenta --validate-timeout; se resta -1, la validazione richiede "
                      f"un'azione specifica (login/add-to-cart) da fare a mano nel browser headful.")
            else:
                print(f"[validate] OK: salvo un _abck validato (campo={fld})")

            # SONDA DEFINITIVA: con i cookie+TLS del BROWSER ma SENZA eseguire JS (ctx.request),
            # rifai home e gated. Isola se lo stato "sec-cpt risolto" e' PORTABILE (cookie) o
            # legato alla CONNESSIONE/sessione.
            #  - passa  -> i cookie bastano e il TLS del browser conta (curl_cffi non lo replica) => serve match TLS
            #  - fallisce-> il solve e' per-connessione/per-challenge => replay impossibile, serve solve live (sensor)
            try:
                for label, u in [("home", HOME), ("gated", args.gated_url)]:
                    rr = ctx.request.get(u, headers={"referer": HOME})
                    body = rr.text()
                    isint = ("sec-if-cpt" in body) or ("behavioral-content" in body)
                    print(f"[sonda ctx.request] {label}: status={rr.status} interstitial={isint} len={len(body)}")
            except Exception as e:
                print(f"[sonda ctx.request] errore: {e}")

        # stato finale: interstitial o contenuto reale?
        try:
            html = page.content() or ""
            solved = "sec-if-cpt" not in html and "behavioral-content" not in html
            print(f"[stato] interstitial risolto? {solved} (len pagina {len(html)})")
            if len(html) < 2000:
                import re as _r2
                txt = _r2.sub(r"\s+", " ", _r2.sub(r"<[^>]+>", " ", html)).strip()
                print(f"[stato] CONTENUTO pagina corta: {txt[:400]!r}")
                try:
                    tit = page.title()
                    print(f"[stato] <title>: {tit!r}")
                except Exception:
                    pass
        except Exception:
            pass
        try:
            cookies = {c["name"]: c["value"] for c in ctx.cookies()}
            print(f"[cookies finali] { {k: v[:30] for k,v in cookies.items()} }")
        except Exception:
            cookies = {}
        # HARVEST IDENTITA' COERENTE: UA + client-hints reali della sessione che ha PASSATO fansale.
        # Serve a replicare in curl_cffi un fingerprint coerente (TLS impersonate + header = stessa
        # versione Chrome). Solo con --native l'identita' e' quella reale del browser (non override).
        try:
            ident = page.evaluate(
                "(function(){var d=(navigator.userAgentData||{});"
                "var hp=null;try{}catch(e){}"
                "return {ua:navigator.userAgent, platform:(d.platform||navigator.platform||''),"
                " mobile:!!d.mobile, brands:(d.brands||[]), language:navigator.language,"
                " languages:navigator.languages, hc:navigator.hardwareConcurrency,"
                " dm:navigator.deviceMemory, vendor:navigator.vendor,"
                " baz:(typeof window.bazadebezolkohpepadr!=='undefined'?String(window.bazadebezolkohpepadr):null)};})()"
            )
            baz_val = ident.get("baz")
            print(f"[baz] bazadebezolkohpepadr={baz_val}")
            # ricostruisci sec-ch-ua dai brands (ordine/escape come li espone il browser)
            sch = ", ".join(f'"{b.get("brand","")}";v="{b.get("version","")}"' for b in (ident.get("brands") or []))
            m = re.search(r"Chrome/(\d+)", ident.get("ua", ""))
            ident["chrome_major"] = int(m.group(1)) if m else None
            ident["sec_ch_ua"] = sch
            ident["cookies_validati"] = cookies
            with open("harvested_identity.json", "w", encoding="utf-8") as fh:
                json.dump(ident, fh, indent=1, ensure_ascii=False)
            print(f"[identity] Chrome {ident['chrome_major']} | platform={ident['platform']!r} "
                  f"| sec-ch-ua={sch!r}")
            print(f"[identity] UA={ident['ua']!r}")
            print("[identity] salvata -> harvested_identity.json (UA+client-hints+cookie validati)")
        except Exception as e:
            print(f"[identity] harvest fallito: {e}")
        # MOVE 3: dump DIRETTO dei valori reali delle prop-chiave (robusto, no getter-wrapping)
        if args.record_reads:
            try:
                vals = page.evaluate(
                    "(function(){var o={};function s(k,f){try{o[k]=f();}catch(e){o[k]='ERR';}}"
                    "s('navigator.userAgent',function(){return navigator.userAgent});"
                    "s('navigator.platform',function(){return navigator.platform});"
                    "s('navigator.language',function(){return navigator.language});"
                    "s('navigator.languages',function(){return JSON.stringify(navigator.languages)});"
                    "s('navigator.hardwareConcurrency',function(){return navigator.hardwareConcurrency});"
                    "s('navigator.deviceMemory',function(){return navigator.deviceMemory});"
                    "s('navigator.vendor',function(){return navigator.vendor});"
                    "s('navigator.maxTouchPoints',function(){return navigator.maxTouchPoints});"
                    "s('navigator.webdriver',function(){return navigator.webdriver});"
                    "s('navigator.appVersion',function(){return navigator.appVersion});"
                    "s('navigator.plugins.length',function(){return navigator.plugins.length});"
                    "s('navigator.pdfViewerEnabled',function(){return navigator.pdfViewerEnabled});"
                    "s('document.referrer',function(){return document.referrer});"
                    "s('document.cookie',function(){return document.cookie});"
                    "s('document.title',function(){return document.title});"
                    "s('document.readyState',function(){return document.readyState});"
                    "s('document.visibilityState',function(){return document.visibilityState});"
                    "s('document.hidden',function(){return document.hidden});"
                    "s('document.hasFocus',function(){return document.hasFocus()});"
                    "s('document.characterSet',function(){return document.characterSet});"
                    "s('document.compatMode',function(){return document.compatMode});"
                    "s('document.activeElement.tagName',function(){return document.activeElement&&document.activeElement.tagName});"
                    "s('performance.timeOrigin',function(){return performance.timeOrigin});"
                    "s('performance.now',function(){return performance.now()});"
                    "s('window.innerWidth',function(){return window.innerWidth});"
                    "s('window.innerHeight',function(){return window.innerHeight});"
                    "s('window.outerWidth',function(){return window.outerWidth});"
                    "s('window.outerHeight',function(){return window.outerHeight});"
                    "s('window.devicePixelRatio',function(){return window.devicePixelRatio});"
                    "s('window.screenX',function(){return window.screenX});"
                    "s('window.screenY',function(){return window.screenY});"
                    "s('screen.width',function(){return screen.width});"
                    "s('screen.height',function(){return screen.height});"
                    "s('screen.availWidth',function(){return screen.availWidth});"
                    "s('screen.availHeight',function(){return screen.availHeight});"
                    "s('screen.colorDepth',function(){return screen.colorDepth});"
                    "return o;})()"
                )
                import json as _json2
                with open("env_reads.json", "w", encoding="utf-8") as fh:
                    _json2.dump(vals, fh, indent=1, ensure_ascii=False)
                print(f"[env-reads] dump diretto {len(vals)} valori -> env_reads.json")
                for k, v in vals.items():
                    print(f"   {k} = {str(v)[:70]}")
                # MOVE 3c: sequenza fromCharCode (output del decoder) per diff con l'harness
                try:
                    fcc = page.evaluate("(function(){try{var s=localStorage.getItem('__fcccap');return s?JSON.parse(s):(window.__fccbuf||[]);}catch(e){return [];}})()")
                    sc = next((e for e in events if e.get("kind") == "script"), None)
                    scfile = sc["file"] if sc else None
                    with open("fromcharcode_browser.json", "w", encoding="utf-8") as fh:
                        _json2.dump({"script": scfile, "codes": fcc}, fh)
                    print(f"[fromCharCode] catturati {len(fcc)} char-code del browser -> fromcharcode_browser.json")
                    print(f"[fromCharCode] script di QUESTA challenge = {scfile} (gira l'harness su questo per il diff)")
                    # anteprima come stringa (primi 120 char stampabili)
                    prev = "".join(chr(c) if 32 <= c < 127 else "." for c in fcc[:120])
                    print(f"[fromCharCode] preview: {prev!r}")
                except Exception as e:
                    print(f"[fromCharCode] fallito: {e}")
                # event-type registrati (per il test garbled=errore vs legittimo)
                try:
                    aetypes = page.evaluate("(function(){try{return window.__aetypes||[];}catch(e){return [];}})()")
                    distinct = sorted(set(aetypes))
                    nonascii = [t for t in distinct if any(ord(c) > 126 or ord(c) < 32 for c in t)]
                    with open("event_types.json", "w", encoding="utf-8") as fh:
                        _json2.dump(distinct, fh, indent=1, ensure_ascii=False)
                    print(f"[event-types] {len(distinct)} tipi distinti registrati -> event_types.json")
                    print(f"   ASCII: {[t for t in distinct if t not in nonascii]}")
                    print(f"   NON-ASCII (codes): {[[ord(c) for c in t] for t in nonascii]}")
                except Exception as e:
                    print(f"[event-types] fallito: {e}")
            except Exception as e:
                print(f"[env-reads] fallito: {e}")
        # leggi U3 reale catturato (detail degli eventi ak_cpr_chlg_init)
        try:
            u3 = page.evaluate("(function(){try{return localStorage.getItem('__u3cap')||'';}catch(e){return '';}})()")
            if u3:
                with open("u3_capture.txt", "w", encoding="utf-8") as fh:
                    fh.write(u3)
                u3lines = [l for l in u3.split("\n") if l.strip()]
                print(f"[U3] catturati {len(u3lines)} eventi challenge -> u3_capture.txt")
                for l in u3lines[:4]:
                    print(f"   {l[:160]}")
            else:
                print("[U3] nessun evento ak_cpr_chlg_init catturato (forse non dispatchato in questa challenge)")
        except Exception as e:
            print(f"[U3] lettura fallita: {e}")
        # --capresp: leggi gli eventi ak_cpr_chlg_* catturati a livello dispatchEvent/CustomEvent
        if args.capresp:
            try:
                dc = page.evaluate("(function(){try{return localStorage.getItem('__dispcap')||'';}catch(e){return '';}})()")
                if dc:
                    with open("ak_cpr_events.txt", "w", encoding="utf-8") as fh:
                        fh.write(dc)
                    dclines = [l for l in dc.split("\n") if l.strip()]
                    print(f"[capresp] catturati {len(dclines)} eventi ak_cpr_chlg_* (dispatchEvent/CustomEvent) -> ak_cpr_events.txt")
                    for l in dclines[:6]:
                        print(f"   {l[:220]}")
                else:
                    print("[capresp] nessun evento ak_cpr_chlg_* dispatchato: l'encode NON passa per un DOM event "
                          "(trigger interno/callback diretto)")
            except Exception as e:
                print(f"[capresp] lettura fallita: {e}")
        # --capsend: leggi le POST sensore intercettate (body + stack della funzione di encode)
        if args.capsend:
            try:
                sc = page.evaluate("(function(){try{return localStorage.getItem('__sendcap')||'';}catch(e){return '';}})()")
                if sc:
                    with open("ak_cpr_send.txt", "w", encoding="utf-8") as fh:
                        fh.write(sc)
                    blocks = [b for b in sc.split("\n\n") if b.strip()]
                    print(f"[capsend] catturate {len(blocks)} POST sensore/akam -> ak_cpr_send.txt")
                    for b in blocks[:3]:
                        print("   " + b.replace("\n", " | ")[:280])
                else:
                    print("[capsend] nessuna POST intercettata (sensore via canale non hookato / img-beacon?)")
            except Exception as e:
                print(f"[capsend] lettura fallita: {e}")
        # --cdptrace: dumpa le catene initiator (async) delle POST sensor
        if args.cdptrace:
            try:
                if cdp_hits:
                    with open("ak_cpr_cdp.txt", "w", encoding="utf-8") as fh:
                        for h in cdp_hits:
                            fh.write(f"=== {h['itype']} {h['url'][:170]}\n")
                            fh.write("\n".join(h["stack"]) + "\n\n")
                    print(f"[cdptrace] {len(cdp_hits)} POST sensor tracciate -> ak_cpr_cdp.txt")
                    # preferisci la sec-cpt (?t=), poi una non-akam (candidata sec-cpt), poi la prima
                    sec = (next((h for h in cdp_hits if h.get("has_t")), None)
                           or next((h for h in cdp_hits if not h.get("is_akam")), None)
                           or cdp_hits[0])
                    tag = "sec-cpt (?t=)" if sec.get("has_t") else ("non-akam (candidata sec-cpt)" if not sec.get("is_akam") else "bmak/akam")
                    print(f"[cdptrace] catena {tag} — {sec['url'][:90]}")
                    for ln in sec["stack"][:24]:
                        print("   " + ln)
                    if not any(h.get("has_t") for h in cdp_hits):
                        print("[cdptrace] NB: nessuna POST sec-cpt ?t= in questo run (challenge PoW non servita) "
                              "-> rilancia finche' non la vedi")
                else:
                    print("[cdptrace] nessuna POST sec-cpt/akam tracciata")
            except Exception as e:
                print(f"[cdptrace] lettura fallita: {e}")
        # --cdpbreak: dumpa il pause catturato (kickoff + scope)
        if args.cdpbreak:
            try:
                if break_dump:
                    with open("ak_cpr_break.txt", "w", encoding="utf-8") as fh:
                        fh.write("\n\n".join(break_dump))
                    print("[cdpbreak] pause catturato -> ak_cpr_break.txt")
                    for ln in break_dump[0].split("\n")[:45]:
                        print("   " + ln)
                    # estrai la tupla (v,t,pgm,z7m,D8m) per la correlazione del seed -> pgm_samples.json
                    import re as _re2
                    blob = break_dump[0]

                    def _grab(nm):
                        mm = _re2.search(r"(?:^|[|\s])" + nm + r"=([^|\n]*)", blob)
                        return mm.group(1).strip() if mm else None

                    mv = _re2.search(r"[?&]v=([0-9a-f]{8}-[0-9a-f-]{23,27})", blob)
                    row = {"v": mv.group(1) if mv else None,
                           "t": _grab("chlgeId") or _grab("dwm"),
                           "pgm": _grab("pgm"), "D8m": _grab("D8m"),
                           "context": _grab("context"), "z7m": (_grab("z7m") or "")[:240]}
                    try:
                        arr = json.load(open("pgm_samples.json", encoding="utf-8"))
                    except Exception:
                        arr = []
                    arr.append(row)
                    json.dump(arr, open("pgm_samples.json", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
                    print(f"[cdpbreak] tupla salvata ({len(arr)} tot) -> pgm_samples.json : "
                          f"v={row['v']} t={row['t']} pgm={row['pgm']}")
                else:
                    print("[cdpbreak] nessun pause (submit ?t= non avvenuto in questo run; rilancia)")
            except Exception as e:
                print(f"[cdpbreak] lettura fallita: {e}")
        # --fccbind: scrivi lo stream fromCharCode del browser catturato live
        if args.fccbind:
            try:
                sc = next((e for e in events if e.get("kind") == "script"), None)
                scfile = sc.get("file") if sc else None
                with open("fromcharcode_browser.json", "w", encoding="utf-8") as fh:
                    json.dump({"script": scfile, "codes": fcc_codes}, fh)
                print(f"[fccbind] {len(fcc_codes)} char-code live -> fromcharcode_browser.json ; script={scfile}")
            except Exception as e:
                print(f"[fccbind] lettura fallita: {e}")
        # leggi il plaintext catturato da localStorage (sopravvive al reload)
        try:
            cap = page.evaluate("(function(){try{return localStorage.getItem('__cap')||'';}catch(e){return '';}})()")
            if cap:
                with open("seccpt_plaintext.txt", "w", encoding="utf-8") as fh:
                    fh.write(cap)
                lines = [l for l in cap.split("\n") if l.strip()]
                print(f"[plaintext] catturate {len(lines)} stringhe >=250 -> seccpt_plaintext.txt")
                for l in lines[:6]:
                    pfx = l.split("|", 1)
                    print(f"   len {pfx[0]}: {pfx[1][:70]!r}" if len(pfx) == 2 else f"   {l[:70]}")
            else:
                print("[plaintext] nessuna cattura in localStorage")
        except Exception as e:
            print(f"[plaintext] lettura fallita: {e}")
        ctx.close(); browser.close()

    with open("seccpt_solve.json", "w", encoding="utf-8") as fh:
        json.dump({"events": events, "cookies": cookies}, fh, indent=1)

    with open("network_dump.json", "w", encoding="utf-8") as fh:
        json.dump(netdump, fh, indent=1, ensure_ascii=False)
    akam = [e for e in netdump if "/akam/" in e["url"]]
    seccpt = [e for e in netdump if "sec-cpt" in e["url"] or re.search(r"[?&]t=\d+", e["url"])]
    print(f"[netdump] {len(netdump)} risposte fansale -> network_dump.json "
          f"(akam={len(akam)}, sec-cpt/t={len(seccpt)})")
    for e in akam[:3]:
        print(f"   [akam] {e['method']} {e['status']} {e['url'][:70]} blen={e.get('blen')}")

    # estrai il POST sec-cpt, DECIFRA (seed 2748) e ACCODA un campione a seccpt_samples.json
    sc = next((e for e in events if e["kind"] == "seccpt_post"), None)
    if sc:
        import re as _re
        v = _re.search(r"[?&]v=([^&]+)", sc["url"])
        t = _re.search(r"[?&]t=(\d+)", sc["url"])
        # il POST non ha v: recuperalo dallo script-GET con lo stesso t
        if not v and t:
            tval = t.group(1)
            for e in events:
                if e.get("kind") in ("script", "request", "response") and ("v=" in str(e.get("url", ""))):
                    mt = _re.search(r"[?&]t=(\d+)", str(e["url"]))
                    if mt and mt.group(1) == tval:
                        v = _re.search(r"[?&]v=([^&]+)", str(e["url"]))
                        if v:
                            break
        raw = sc["post_data"]
        cipher = ""
        i = raw.find('"body":"')
        if i >= 0:
            val = raw[i + 8:]
            val = val[:val.rfind('"')] if val.rfind('"') > 0 else val
            o = []; k = 0; mp = {'"': '"', "\\": "\\", "/": "/", "n": "\n", "t": "\t", "r": "\r"}
            while k < len(val):
                if val[k] == "\\" and k + 1 < len(val):
                    o.append(mp.get(val[k + 1], val[k + 1])); k += 2
                else:
                    o.append(val[k]); k += 1
            cipher = "".join(o)
        payload = ""
        used_seed = None
        try:
            from akamai_cipher import AkamaiPayloadCipher
            # Scansione seed: 2515 e' il seed noto. Se non rende campi validi, il seed e'
            # cambiato per-challenge -> bruteforce l'intero spazio LCG (0..0x7FFFFF) finche'
            # il decrypt contiene molti campi "XXnnn": (segno di plaintext corretto).
            def score(txt):
                return len(_re.findall(r'"[A-Za-z]{2}\d{2,3}":', txt))
            best = AkamaiPayloadCipher(seed=2515).decrypt(cipher)
            if score(best) >= 50:
                payload, used_seed = best, 2515
            else:
                print("[sample] seed 2515 NON valido su questa challenge -> bruteforce seed...")
                for s in range(0x7FFFFF + 1):
                    cand = AkamaiPayloadCipher(seed=s).decrypt(cipher)
                    if score(cand) >= 50:
                        payload, used_seed = cand, s
                        print(f"[sample] SEED TROVATO: {s}  (campi={score(cand)})")
                        break
                if used_seed is None:
                    payload = best
                    print("[sample] nessun seed trovato in 0..0x7FFFFF (cifrario/costanti cambiati?)")
        except Exception as e:
            print(f"[sample] decrypt fallita: {e}")
        names = _re.findall(r'"([A-Za-z]{2}\d{2,3})":', payload)
        sample = {"v": v.group(1) if v else None, "t": t.group(1) if t else None,
                  "cipher_len": len(cipher), "payload": payload, "seed": used_seed,
                  "baz": locals().get("baz_val"),
                  "prefix": (names[0][:2] if names else None), "nfields": len(names)}
        try:
            samples = json.load(open("seccpt_samples.json", encoding="utf-8"))
        except Exception:
            samples = []
        samples.append(sample)
        json.dump(samples, open("seccpt_samples.json", "w", encoding="utf-8"), indent=1)
        print(f"[sample] accodato: v={sample['v']} t={sample['t']} seed={sample['seed']} "
              f"prefix={sample['prefix']} campi={sample['nfields']} | TOTALE campioni: {len(samples)}")
    else:
        print("[sample] nessun POST sec-cpt catturato")

    # SENSOR _abck (bmak): salva i body INTERI catturati -> ak_sensor_samples.json (per RE del generatore)
    abck = [e for e in events if e.get("kind") == "abck_sensor"]
    if abck:
        try:
            prev = json.load(open("ak_sensor_samples.json", encoding="utf-8"))
        except Exception:
            prev = []
        for e in abck:
            prev.append({"url": e["url"], "headers": e.get("headers", {}), "post_data": e["post_data"]})
        json.dump(prev, open("ak_sensor_samples.json", "w", encoding="utf-8"), indent=1)
        lens = [len(e["post_data"]) for e in abck]
        print(f"[abck] {len(abck)} sensor_data INTERI salvati (len={lens}) -> ak_sensor_samples.json (tot {len(prev)})")
    else:
        print("[abck] nessun POST sensor_data catturato in questo run")


if __name__ == "__main__":
    main()
