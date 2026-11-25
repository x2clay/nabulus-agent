import sys, json, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from playwright.sync_api import sync_playwright
from browser import hardened_context
BASE = "https://cortisol.gg"
with sync_playwright() as p:
    with hardened_context(p, system_mode=True) as ctx:
        pg = ctx.new_page()
        pg.goto(BASE + "/", wait_until="domcontentloaded", timeout=45000); pg.wait_for_timeout(3500)
        for t in ["Anmelden","Log in","Login","Sign in","Einloggen","Register","Registrieren"]:
            try:
                el = pg.get_by_text(t, exact=False).first
                if el and el.is_visible(): el.click(timeout=3000); pg.wait_for_timeout(2000); break
            except Exception: pass
        info = pg.evaluate("""() => {
            const inputs=[...document.querySelectorAll('input')].map(i=>({type:i.type,name:i.name,ph:i.placeholder,id:i.id}));
            const btns=[...document.querySelectorAll('button,[role=button]')].map(b=>({t:(b.innerText||'').slice(0,30),disabled:b.disabled}));
            const iframes=[...document.querySelectorAll('iframe')].map(f=>f.src).filter(Boolean);
            const cap=/turnstile|hcaptcha|recaptcha|challenges\\.cloudflare/i;
            const html=document.documentElement.innerHTML;
            const capHit=['turnstile','hcaptcha','recaptcha','cf-turnstile','g-recaptcha'].filter(k=>html.toLowerCase().includes(k));
            return {url:location.href, inputs:inputs.slice(0,15), btns:btns.slice(0,15),
                    iframes:iframes.filter(s=>cap.test(s)), captcha_markers:capHit};
        }""")
        print(json.dumps(info, indent=2))
        pg.close()
print("DONE")
