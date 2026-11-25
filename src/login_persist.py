#!/usr/bin/env python3
"""login_persist.py - log the agent in ONCE inside a persistent Chrome profile (real Chrome,
managed-Turnstile friendly), then MEASURE token lifetime + any refresh path. For an authorized,
operator-owned target (cortisol.gg).

Goal: find out whether the browser can mint and KEEP its own session so the operator never has to
hand-feed a cb_token again. Two things this answers:
  1) Does a real-Chrome login pass Turnstile (managed mode) without a solver? (no solver, no spoof)
  2) Is the cb_token short-lived? Does the SPA auto-refresh it (any /refresh call)? -> tells us if a
     warm persistent profile self-sustains, or if we need a re-login-on-401 daemon.

Creds: read from --creds (JSON {"email","password"}); file DELETED immediately after read. The token
is NEVER printed or logged - only booleans, statuses, lengths, cookie NAMES, and refresh-call paths.
Scope-gated to cortisol.gg.
"""
from __future__ import annotations
import sys, json, time, argparse, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from playwright.sync_api import sync_playwright
from browser import HARDENED_ARGS, SERVICE_ARGS

BASE = "https://cortisol.gg"
FALLBACK_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
PROFILE = r"C:\Users\Laith\nabulus-agent\.cortisol_profile"
LOGIN_TRIGGERS = ["Log in", "Login", "Sign in", "Anmelden", "Einloggen"]
SUBMIT_TEXTS = ["Log in", "Login", "Sign in", "Anmelden", "Einloggen", "Continue", "Weiter"]

TOK_JS = "() => (localStorage.getItem('cb_token')||'').length"
ME_JS = """async () => {
  const tok = localStorage.getItem('cb_token')||'';
  try { const r = await fetch('/api/me',{headers: tok?{'Authorization':'Bearer '+tok}:{}});
        return r.status; } catch(e){ return -1; }
}"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--creds", required=True)
    ap.add_argument("--scope", default="scope_cortisol.json")
    ap.add_argument("--watch", type=int, default=150, help="seconds to watch token lifetime")
    ap.add_argument("--headful", action="store_true", help="run a real visible Chrome (session 1 desktop)")
    ap.add_argument("--out", default="login_persist_result.json")
    a = ap.parse_args()

    scope = json.loads(pathlib.Path(a.scope).read_text())
    if "cortisol.gg" not in scope.get("authorized_assets", []):
        print("REFUSED: cortisol.gg not in scope"); return 2

    cp = pathlib.Path(a.creds)
    creds = json.loads(cp.read_text())
    try: cp.unlink()
    except Exception: pass
    email, password = creds["email"], creds["password"]

    events = {"login_status": None, "captcha": False, "refresh_calls": [], "auth_endpoints": []}

    with sync_playwright() as p:
        launch_args = list(HARDENED_ARGS)
        if not a.headful:
            launch_args += SERVICE_ARGS
        ctx = p.chromium.launch_persistent_context(
            PROFILE, channel="chrome", headless=not a.headful,
            args=launch_args, user_agent=FALLBACK_UA,
            ignore_https_errors=True, service_workers="block",
            timezone_id="America/New_York", locale="en-US")
        page = ctx.new_page()

        def on_resp(resp):
            u = resp.url
            if "/api/auth/login" in u or "/api/login" in u:
                events["login_status"] = resp.status
                events["auth_endpoints"].append(u.replace(BASE, ""))
                try:
                    j = resp.json()
                    e = (j.get("error") or j.get("message") or "").lower()
                    if any(w in e for w in ("captcha","human","mensch","turnstile","verify")):
                        events["captcha"] = True
                except Exception: pass
            if "refresh" in u.lower() and "/api" in u:
                events["refresh_calls"].append(u.replace(BASE, "") + f"->{resp.status}")
        page.on("response", on_resp)

        page.goto(BASE + "/", wait_until="domcontentloaded", timeout=45000)
        page.wait_for_timeout(3500)

        # open login UI
        opened = False
        for t in LOGIN_TRIGGERS:
            try:
                el = page.get_by_text(t, exact=False).first
                if el and el.is_visible():
                    el.click(timeout=4000); opened = True; page.wait_for_timeout(1500); break
            except Exception: continue
        if not opened:
            try: page.goto(BASE + "/login", wait_until="domcontentloaded", timeout=20000); page.wait_for_timeout(2000)
            except Exception: pass

        fill_err = None
        try:
            page.locator("input[type=email], input[name=email]").first.fill(email, timeout=8000)
            page.locator("input[type=password], input[name=password]").first.fill(password, timeout=8000)
        except Exception as e:
            fill_err = str(e)[:120]

        # wait (up to 30s) for Turnstile (managed/invisible) to populate its hidden token
        TS_JS = ("() => { const e = document.querySelector("
                 "'input[name=\"cf-turnstile-response\"],textarea[name=\"cf-turnstile-response\"]');"
                 " return e ? (e.value||'').length : -1; }")
        ts_len, ts_wait = 0, 0
        for i in range(30):
            ts_len = page.evaluate(TS_JS)
            if ts_len and ts_len > 10:
                ts_wait = i; break
            page.wait_for_timeout(1000)
        events["turnstile_token"] = {"len": ts_len, "secs_to_solve": ts_wait if ts_len > 10 else None}

        # click the modal submit specifically (uppercase "SIGN IN"), not the nav "Sign in"
        clicked = page.evaluate("""() => {
          const b = [...document.querySelectorAll('button')].find(x =>
            (x.innerText||'').trim().toUpperCase() === 'SIGN IN' && x.offsetParent !== null);
          if (b) { b.click(); return true; } return false;
        }""")
        events["submit_clicked"] = clicked
        if not clicked:
            try: page.keyboard.press("Enter")
            except Exception: pass

        # wait for token to appear
        got = 0
        for _ in range(20):
            got = page.evaluate(TOK_JS)
            if got and got > 10: break
            page.wait_for_timeout(1000)

        result = {"headful": a.headful, "fill_error": fill_err,
                  "turnstile_token": events.get("turnstile_token"), "submit_clicked": events.get("submit_clicked"),
                  "login_status": events["login_status"], "captcha_blocked": events["captcha"],
                  "auth_endpoints": events["auth_endpoints"],
                  "got_token": bool(got and got > 10), "token_len": got}

        # measure lifetime + refresh behavior
        timeline = []
        if got and got > 10:
            t0 = time.time()
            while time.time() - t0 < a.watch:
                st = page.evaluate(ME_JS)
                ln = page.evaluate(TOK_JS)
                timeline.append({"t": round(time.time()-t0), "me": st, "tok_len": ln})
                if st != 200:   # died or rotated-and-failed
                    time.sleep(5)
                else:
                    time.sleep(15)
            result["refresh_calls"] = events["refresh_calls"]
            result["timeline"] = timeline
            # dump cookie names only (never values) in case login set one
            result["cookies"] = [{"name": c.get("name"), "httpOnly": c.get("httpOnly")} for c in ctx.cookies()]

        try: pathlib.Path(a.out).write_text(json.dumps(result, indent=2))
        except Exception: pass
        print(json.dumps(result, indent=2))
        ctx.close()


if __name__ == "__main__":
    main()
