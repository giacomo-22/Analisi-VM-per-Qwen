"""
Cattura decode-ORACLE del bmak: in Chrome reale (env fedele) wrappa String.fromCharCode
(toString spoofato a '[native code]' -> il self-hash del bmak, che hasha il PROPRIO toString,
resta corretto) e logga TUTTI i codici. In parallelo salva il bmak ESATTO servito (bmak_live.js)
per allineare l'harness. Output: fromcharcode_browser.json {script:'bmak_live.js', codes:[...]}.

NB: strumento di ANALISI. L'init-script e' un "tell" lato-accettazione, ma a noi serve solo che
il bmak DECODIFICHI correttamente le sue stringhe (env fedele) e produca lo stream fromCharCode.

Uso: python capture_fcc_oracle.py --proxy-index 3 --headful --settle 8
"""
from __future__ import annotations
import argparse, json, os, sys, time
from proxies import pick_proxy_dict

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = "https://www.fansale.it/"
CFT = os.path.join(HERE, "cft_chrome150", "chrome-win64", "chrome.exe")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")

# Logger iniettato a document_start, PRIMA del bmak. Wrappa fromCharCode su window/self/globalThis,
# spoofa toString a nativo (cosi' i check d'integrita' toString()==='[native code]' passano e
# l'hash che alimenta il decode resta corretto). NON tocca il sorgente del bmak.
INIT_JS = r"""
(function(){
  try{
    var g = (typeof window!=='undefined')?window:self;
    if(g.__fccInstalled) return; g.__fccInstalled = true;
    g.__fcc = [];
    var real = g.String.fromCharCode;
    var wrap = function(){
      try{ for(var i=0;i<arguments.length;i++) g.__fcc.push(arguments[i]|0); }catch(e){}
      return real.apply(g.String, arguments);
    };
    try{ Object.defineProperty(wrap,'name',{value:'fromCharCode'}); }catch(e){}
    wrap.toString = function(){ return 'function fromCharCode() { [native code] }'; };
    try{ wrap.toString.toString = function(){ return 'function toString() { [native code] }'; }; }catch(e){}
    try{ g.String.fromCharCode = wrap; }catch(e){}
  }catch(e){}
})();
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy-index", type=int, default=3)
    ap.add_argument("--headful", action="store_true")
    ap.add_argument("--settle", type=int, default=8, help="secondi di attesa dopo il load")
    ap.add_argument("--plain", action="store_true", help="usa playwright normale (onora add_init_script; patchright lo strippa)")
    args = ap.parse_args()

    if args.plain:
        from playwright.sync_api import sync_playwright
        driver = "playwright"
    else:
        try:
            from patchright.sync_api import sync_playwright
            driver = "patchright"
        except Exception:
            from playwright.sync_api import sync_playwright
            driver = "playwright"
    proxy = pick_proxy_dict("proxies.txt", index=args.proxy_index)
    print(f"[cfg] driver={driver} proxy_index={args.proxy_index} "
          f"host={(proxy or {}).get('server','(nessuno)')} (credenziali nascoste)")

    live_scripts = []  # (url, len) salvati

    with sync_playwright() as p:
        launch_kw = {"headless": not args.headful, "proxy": proxy,
                     "ignore_default_args": ["--enable-automation"]}
        if os.path.exists(CFT):
            launch_kw["executable_path"] = CFT
        browser = p.chromium.launch(**launch_kw)
        context = browser.new_context(user_agent=UA, locale="it-IT",
                                      timezone_id="Europe/Rome",
                                      viewport={"width": 1920, "height": 1040})
        page = context.new_page()
        # patchright strippa add_init_script -> inietto via CDP raw (document_start), piu' affidabile
        cdp = None
        try:
            cdp = context.new_cdp_session(page)
            cdp.send("Page.enable")
            cdp.send("Page.addScriptToEvaluateOnNewDocument", {"source": INIT_JS})
            print("[inj] CDP addScriptToEvaluateOnNewDocument OK")
        except Exception as e:
            print("[inj] CDP fallita, fallback add_init_script:", str(e)[:80])
            context.add_init_script(INIT_JS)

        def on_response(resp):
            try:
                u = resp.url
                req = resp.request
                if ("fansale.it" in u and req.method == "GET" and "?t=" not in u
                        and "&t=" not in u):
                    ct = (resp.headers or {}).get("content-type", "")
                    if "javascript" in ct or u.rstrip("/").split("/")[-1].isalnum():
                        body = resp.text()
                        if body and len(body) > 100000 and "function" in body[:3000]:
                            fn = "bmak_live.js"
                            with open(os.path.join(HERE, fn), "w", encoding="utf-8") as fh:
                                fh.write(body)
                            live_scripts.append((u, len(body)))
                            print(f"[live] bmak salvato {len(body)}B <- {u[:80]} -> {fn}")
            except Exception as e:
                print("[live] err", str(e)[:80])

        page.on("response", on_response)

        print("[nav] navigo HOME...")
        try:
            page.goto(HOME, wait_until="domcontentloaded", timeout=40000)
        except Exception as e:
            print("[nav] goto err (continuo):", str(e)[:100])
        time.sleep(args.settle)
        # prova a stimolare un po' di attivita' (muovi mouse) per far decodificare i path evento
        try:
            for i in range(6):
                page.mouse.move(300 + i * 40, 240 + i * 15)
                time.sleep(0.15)
        except Exception:
            pass
        time.sleep(1.0)

        try:
            diag = page.evaluate("() => ({installed: !!window.__fccInstalled, fccType: typeof window.__fcc, "
                                 "fccLen: (window.__fcc||[]).length, fccSrc: String.fromCharCode.toString().slice(0,70), "
                                 "nWorkers: (performance.getEntriesByType?performance.getEntriesByType('resource').filter(e=>/blob:/.test(e.name)).length:0)})")
            print("[diag]", json.dumps(diag))
        except Exception as e:
            print("[diag] err:", str(e)[:100])
        try:
            codes = page.evaluate("() => (window.__fcc||[]).slice(0)")
        except Exception as e:
            codes = []
            print("[fcc] evaluate err:", str(e)[:100])
        title = ""
        try:
            title = page.title()
        except Exception:
            pass
        print(f"[stato] title={title!r} | fromCharCode catturati={len(codes)} | script live={len(live_scripts)}")

        script_name = "bmak_live.js" if live_scripts else "bmak_script_direct.js"
        out = {"script": script_name, "codes": codes}
        with open(os.path.join(HERE, "fromcharcode_browser.json"), "w", encoding="utf-8") as fh:
            json.dump(out, fh)
        print(f"[fcc] salvato -> fromcharcode_browser.json (script={script_name}, {len(codes)} codici)")
        try:
            context.close(); browser.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
