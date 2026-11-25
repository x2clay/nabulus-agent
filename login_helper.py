#!/usr/bin/env python3
"""login_helper.py - obtain a real session token by driving the hardened browser through a
CAPTCHA-gated login, for an AUTHORIZED, operator-owned target. The agent cannot call a
CAPTCHA-protected /login API directly; a genuine browser session can pass a managed/non-interactive
challenge (Turnstile-style) on its own. No fingerprint spoofing, no solver service - if the
challenge is interactive (image grid), this will simply fail and say so.

Credentials are read from --creds (JSON: {"accounts":[{"email","password"}]}), and that file is
DELETED immediately after reading. Only the resulting bearer token(s) are written to --out. Nothing
is logged persistently and nothing leaves the box except the login request to the target itself.
"""
from __future__ import annotations
import sys, os, json, time, argparse, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from playwright.sync_api import sync_playwright
from browser import hardened_context

BASE = "https://cortisol.gg"
LOGIN_TRIGGERS = ["Anmelden", "Log in", "Login", "Sign in", "Einloggen"]
SUBMIT_TEXTS = ["Anmelden", "Log in", "Login", "Sign in", "Einloggen", "Weiter", "Continue"]


def grab_token_from_storage(page):
    try:
        return page.evaluate(
            """() => {
                for (const k of Object.keys(localStorage)) {
                    const v = localStorage.getItem(k) || '';
                    if (/token/i.test(k) && v.length > 20) return v;
                    try { const o = JSON.parse(v); if (o && o.token) return o.token; } catch(e){}
                }
                return null;
            }"""
        )
    except Exception:
        return None


def login_once(ctx, email, password):
    page = ctx.new_page()
    captured = {"token": None, "login_status": None, "captcha": False}

    def on_resp(resp):
        u = resp.url
        if "/api/auth/login" in u:
            captured["login_status"] = resp.status
            try:
                j = resp.json()
                if isinstance(j, dict):
                    if j.get("token"):
                        captured["token"] = j["token"]
                    err = (j.get("error") or "").lower()
                    if "mensch" in err or "captcha" in err or "human" in err:
                        captured["captcha"] = True
            except Exception:
                pass
    page.on("response", on_resp)

    page.goto(BASE + "/", wait_until="domcontentloaded", timeout=45000)
    page.wait_for_timeout(3000)

    # open the login UI (SPA modal/route)
    opened = False
    for t in LOGIN_TRIGGERS:
        try:
            el = page.get_by_text(t, exact=False).first
            if el and el.is_visible():
                el.click(timeout=4000); opened = True; page.wait_for_timeout(1500); break
        except Exception:
            continue
    if not opened:
        try:
            page.goto(BASE + "/login", wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(2000)
        except Exception:
            pass

    # fill credentials
    try:
        page.locator("input[type=email], input[name=email]").first.fill(email, timeout=8000)
        page.locator("input[type=password], input[name=password]").first.fill(password, timeout=8000)
    except Exception as e:
        captured["fill_error"] = str(e)[:120]

    page.wait_for_timeout(2500)   # let any Turnstile widget auto-execute

    # submit
    for t in SUBMIT_TEXTS:
        try:
            btn = page.get_by_role("button", name=t, exact=False).first
            if btn and btn.is_visible():
                btn.click(timeout=4000); break
        except Exception:
            continue
    else:
        try: page.keyboard.press("Enter")
        except Exception: pass

    # wait for login to resolve
    for _ in range(20):
        if captured["token"]:
            break
        tok = grab_token_from_storage(page)
        if tok:
            captured["token"] = tok; break
        page.wait_for_timeout(1000)
    page.close()
    return captured


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--creds", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    cp = pathlib.Path(a.creds)
    accounts = json.loads(cp.read_text())["accounts"]
    try:
        cp.unlink()                 # delete creds file immediately after reading
    except Exception:
        pass

    results = []
    with sync_playwright() as p:
        with hardened_context(p, system_mode=True) as ctx:
            for acc in accounts:
                r = login_once(ctx, acc["email"], acc["password"])
                results.append({"email_hint": acc["email"][:3] + "***", "got_token": bool(r.get("token")),
                                "login_status": r.get("login_status"), "captcha_blocked": r.get("captcha"),
                                "fill_error": r.get("fill_error"), "token": r.get("token")})
                print(f"[login] {acc['email'][:3]}*** token={bool(r.get('token'))} "
                      f"status={r.get('login_status')} captcha={r.get('captcha')} fillerr={r.get('fill_error')}")
    pathlib.Path(a.out).write_text(json.dumps(results, indent=2))
    print("[login] DONE")


if __name__ == "__main__":
    main()
