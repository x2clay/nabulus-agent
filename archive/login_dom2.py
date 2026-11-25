#!/usr/bin/env python3
"""login_dom2.py - read-only DOM snapshot of the cortisol login modal, to see whether the submit
button is Turnstile-gated (disabled, empty cf-turnstile-response) or just a selector miss. No creds,
no submit, nothing written. Scope: cortisol.gg only."""
from __future__ import annotations
import sys, json, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from playwright.sync_api import sync_playwright
from browser import HARDENED_ARGS, SERVICE_ARGS

BASE = "https://cortisol.gg"
FALLBACK_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
PROFILE = r"C:\Users\Laith\nabulus-agent\.cortisol_profile"
TRIGGERS = ["Log in", "Login", "Sign in", "Anmelden", "Einloggen"]

SNAP_JS = r"""() => {
  const btns = [...document.querySelectorAll('button, input[type=submit]')]
    .filter(b => b.offsetParent !== null)
    .map(b => ({text: (b.innerText||b.value||'').trim().slice(0,30),
                disabled: b.disabled, ariaDisabled: b.getAttribute('aria-disabled')}));
  const inputs = [...document.querySelectorAll('input')]
    .map(i => ({type: i.type, name: i.name||'', ph: (i.placeholder||'').slice(0,20)}));
  const tsIframe = !!document.querySelector('iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"]');
  const tsWidget = !!document.querySelector('.cf-turnstile, [data-sitekey]');
  const tsResp = document.querySelector('input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
  return {buttons: btns, inputs: inputs,
          turnstile_iframe: tsIframe, turnstile_widget: tsWidget,
          turnstile_response_len: tsResp ? (tsResp.value||'').length : null};
}"""


def main():
    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            PROFILE, channel="chrome", headless=True, args=HARDENED_ARGS + SERVICE_ARGS,
            user_agent=FALLBACK_UA, ignore_https_errors=True, service_workers="block",
            timezone_id="America/New_York", locale="en-US")
        page = ctx.new_page()
        page.goto(BASE + "/", wait_until="domcontentloaded", timeout=45000)
        page.wait_for_timeout(3500)
        for t in TRIGGERS:
            try:
                el = page.get_by_text(t, exact=False).first
                if el and el.is_visible():
                    el.click(timeout=4000); page.wait_for_timeout(1500); break
            except Exception: continue
        page.wait_for_timeout(5000)   # give Turnstile a chance to auto-solve
        print(json.dumps(page.evaluate(SNAP_JS), indent=2))
        ctx.close()


if __name__ == "__main__":
    main()
