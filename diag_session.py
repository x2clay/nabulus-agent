#!/usr/bin/env python3
"""diag_session.py - read-only diagnostic for the cortisol persistent profile.
Answers: is this profile already authed, and is there a refresh mechanism (cookies)?
Prints only NON-SENSITIVE facts: cookie NAMES + flags (never values), token PRESENCE/length
(never the token), /api/me status. Scope-gated. Nothing written, nothing logged.
"""
from __future__ import annotations
import sys, json, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from playwright.sync_api import sync_playwright
from browser import HARDENED_ARGS, SERVICE_ARGS

BASE = "https://cortisol.gg"
FALLBACK_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
PROFILE = r"C:\Users\Laith\nabulus-agent\.cortisol_profile"

ME_JS = """async () => {
  const tok = localStorage.getItem('cb_token') || '';
  let me = {status: 0, authed: false};
  try {
    const r = await fetch('/api/me', {headers: tok ? {'Authorization':'Bearer '+tok} : {}});
    me.status = r.status;
    if (r.status === 200) { const j = await r.json(); me.authed = !!(j && j.user); if (me.authed) me.username = j.user.username; }
  } catch(e) { me.err = String(e).slice(0,80); }
  return me;
}"""

LS_JS = """() => {
  const out = {};
  for (const k of Object.keys(localStorage)) {
    const v = localStorage.getItem(k) || '';
    out[k] = v.length;   // length only, never the value
  }
  return out;
}"""


def main():
    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            PROFILE, channel="chrome", headless=True,
            args=HARDENED_ARGS + SERVICE_ARGS, user_agent=FALLBACK_UA,
            ignore_https_errors=True, service_workers="block",
            timezone_id="America/New_York", locale="en-US")
        page = ctx.new_page()
        page.goto(BASE + "/", wait_until="domcontentloaded", timeout=45000)
        page.wait_for_timeout(4000)   # let SPA boot + apply any stored session

        ls = page.evaluate(LS_JS)
        me = page.evaluate(ME_JS)
        # cookies: names + flags only, NEVER values
        cookies = ctx.cookies()
        cookie_meta = [{"name": c.get("name"), "httpOnly": c.get("httpOnly"),
                        "domain": c.get("domain"), "expires": c.get("expires")}
                       for c in cookies]
        print(json.dumps({
            "me": me,
            "localStorage_keys_and_lengths": ls,
            "has_cb_token": "cb_token" in ls and ls.get("cb_token", 0) > 10,
            "cookies": cookie_meta,
        }, indent=2))
        ctx.close()


if __name__ == "__main__":
    main()
