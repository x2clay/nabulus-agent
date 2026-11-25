#!/usr/bin/env python3
"""persist_test.py - PROVE whether a seeded-once live browser is a persistent cortisol session.

The agent never logs in (Turnstile is cleared once by the operator in a real browser; the session is
handed over via the bookmarklet). This seeds that live session into a persistent Chrome profile and
keeps the browser ALIVE, exactly like leaving a tab open. Every 20s it checks two things side by side:

  * LIVE  : fetch /api/me using whatever cb_token is in localStorage RIGHT NOW (rides SPA renewal)
  * ORIG  : fetch /api/me using the ORIGINAL copied token, frozen at seed time (a static copy)

If LIVE stays 200 after ORIG starts failing -> the SPA renews the session in a live browser, so a
kept-alive browser = a durable login. If both die together -> the token is simply long/short-lived
and there is no live renewal. Either way we get the truth, and the number.

Seed (--seed): bookmarklet blob {"ls":{...}, "ua":...}. Deleted after read. Tokens never printed.
Scope-gated to cortisol.gg. Read-only GET.
"""
from __future__ import annotations
import sys, json, argparse, pathlib, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from playwright.sync_api import sync_playwright
from browser import HARDENED_ARGS, SERVICE_ARGS

BASE = "https://cortisol.gg"
FALLBACK_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
PROFILE = r"C:\Users\Laith\nabulus-agent\.cortisol_profile"

# fetch /api/me with the CURRENT localStorage token; also report current token length
LIVE_JS = """async () => {
  const tok = localStorage.getItem('cb_token') || '';
  let st = 0; try { const r = await fetch('/api/me',{headers: tok?{'Authorization':'Bearer '+tok}:{}}); st = r.status; } catch(e){ st = -1; }
  return {status: st, tok_len: tok.length};
}"""
# fetch /api/me with a FIXED token passed in (the original copy)
ORIG_JS = """async (tok) => {
  let st = 0; try { const r = await fetch('/api/me',{headers:{'Authorization':'Bearer '+tok}}); st = r.status; } catch(e){ st = -1; }
  return st;
}"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", default="scope_cortisol.json")
    ap.add_argument("--seed", required=True)
    ap.add_argument("--minutes", type=int, default=15)
    ap.add_argument("--out", default="persist_test_result.json")
    a = ap.parse_args()

    scope = json.loads(pathlib.Path(a.scope).read_text())
    if "cortisol.gg" not in scope.get("authorized_assets", []):
        print("REFUSED: cortisol.gg not in scope"); return 2

    sf = pathlib.Path(a.seed); seed = json.loads(sf.read_text())
    try: sf.unlink()
    except Exception: pass
    ls = seed.get("ls", {}) or {}
    orig_tok = ls.get("cb_token")
    ua = seed.get("ua") or FALLBACK_UA
    if not orig_tok:
        print("NO cb_token in seed"); return 1
    # keep only string values for localStorage seeding
    ls = {k: v for k, v in ls.items() if isinstance(v, str)}

    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            PROFILE, channel="chrome", headless=True, args=HARDENED_ARGS + SERVICE_ARGS,
            user_agent=ua, ignore_https_errors=True, service_workers="block",
            timezone_id="America/New_York", locale="en-US")
        ctx.add_init_script("(() => { const ls = %s; try{for (const [k,v] of Object.entries(ls)) "
                            "localStorage.setItem(k, v);}catch(e){} })()" % json.dumps(ls))
        page = ctx.new_page()
        page.goto(BASE + "/", wait_until="domcontentloaded", timeout=45000)
        page.wait_for_timeout(4000)   # SPA boot + apply seeded session

        first = page.evaluate(LIVE_JS)
        print(f"[cortisol] boot: live /api/me={first['status']} tok_len={first['tok_len']}")
        if first["status"] != 200:
            pathlib.Path(a.out).write_text(json.dumps({"boot": first, "note": "seeded token not live on boot"}))
            print("[cortisol] seeded token already dead on boot - grab a fresher one"); ctx.close(); return 1

        timeline = []
        t0 = time.time(); end = t0 + a.minutes * 60
        live_last_alive = 0; orig_last_alive = 0; rotated_at = None
        while time.time() < end:
            el = round(time.time() - t0)
            live = page.evaluate(LIVE_JS)
            orig = page.evaluate(ORIG_JS, orig_tok)
            if live["status"] == 200: live_last_alive = el
            if orig == 200: orig_last_alive = el
            if rotated_at is None and live["tok_len"] and orig_tok and live["tok_len"] != len(orig_tok):
                rotated_at = el
            timeline.append({"t": el, "live": live["status"], "orig": orig, "tok_len": live["tok_len"]})
            print(f"  t={el}s live={live['status']} orig={orig} tok_len={live['tok_len']}")
            if live["status"] != 200:
                break
            time.sleep(20)

        renewal_proven = (orig_last_alive < live_last_alive) or (rotated_at is not None and live_last_alive >= a.minutes*60 - 25)
        out = {"boot": first, "minutes_watched": a.minutes,
               "live_last_alive_s": live_last_alive, "orig_last_alive_s": orig_last_alive,
               "token_rotated_at_s": rotated_at,
               "live_still_alive_at_end": timeline[-1]["live"] == 200 if timeline else False,
               "renewal_proven": bool(renewal_proven), "timeline": timeline}
        pathlib.Path(a.out).write_text(json.dumps(out, indent=2))
        print(json.dumps({k: out[k] for k in ("live_last_alive_s","orig_last_alive_s",
              "token_rotated_at_s","live_still_alive_at_end","renewal_proven")}, indent=2))
        print("DONE")
        ctx.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
