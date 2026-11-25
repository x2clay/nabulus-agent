"""Open a host in a headless browser, or sign in when an account is supplied.

The default pass stores no credentials. It records the pages, the scripts,
and the calls the page made so the empty-jar check can request them with
no cookie. Scanners receive a cookie only after accounts.json supplies one.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re

import surface

AGENT = pathlib.Path(__file__).resolve().parent
SESSIONS = AGENT / "sessions"
ACCOUNTS = AGENT / "accounts.json"

EXAMPLE = {
    "host": "app.example.com",
    "login_url": "https://app.example.com/login",
    "username": "",
    "password": "",
    "username_selector": "input[type=email], input[name=username], input[name=email]",
    "password_selector": "input[type=password]",
    "submit_selector": "button[type=submit], input[type=submit]",
    "success_url_contains": "",
}


# Drop host ICE candidates so a page cannot read this machine's local addresses.
_LEAK_JS = """
(() => {
  const leak = (cand) => {
    const s = (cand && cand.candidate) || "";
    return /\\btyp host\\b/i.test(s);
  };
  const patch = (name) => {
    const Orig = window[name];
    if (typeof Orig !== "function") return;
    const Next = function (cfg) {
      const pc = new Orig(cfg);
      let handler = null;
      Object.defineProperty(pc, "onicecandidate", {
        configurable: true,
        get() { return handler; },
        set(fn) {
          handler = (ev) => {
            if (ev && leak(ev.candidate)) return;
            if (typeof fn === "function") fn(ev);
          };
        },
      });
      const origAdd = pc.addEventListener.bind(pc);
      pc.addEventListener = (type, fn, ...rest) => {
        if (type !== "icecandidate" || typeof fn !== "function") return origAdd(type, fn, ...rest);
        return origAdd(type, (ev) => { if (!ev || !leak(ev.candidate)) fn(ev); }, ...rest);
      };
      return pc;
    };
    Next.prototype = Orig.prototype;
    window[name] = Next;
  };
  patch("RTCPeerConnection");
  patch("webkitRTCPeerConnection");
})();
"""

# Real Chrome device profiles. Pixel 7 stays on the Chrome engine; an iPhone UA on Chrome mismatches.
_PROFILES = (
    ("Desktop Chrome", "Win32"),
    ("Pixel 7", "Linux armv8l"),
)


def _stealth(page, platform: str = "Win32") -> None:
    try:
        from playwright_stealth import Stealth
        Stealth(
            navigator_languages_override=("en-US", "en"),
            navigator_platform_override=platform,
        ).apply_stealth_sync(page)
        return
    except Exception:
        pass
    try:
        from playwright_stealth import stealth_sync
        stealth_sync(page)
    except Exception:
        return


def _blocked(title: str, sample: str) -> bool:
    blob = f"{title}\n{sample}".lower()
    markers = (
        "security checkpoint",
        "just a moment",
        "attention required",
        "verify you are human",
        "cf-challenge",
        "checking your browser",
    )
    return any(marker in blob for marker in markers)


def open_host(host: str, max_pages: int = 12, state_path: str | None = None) -> dict:
    """Open the host in a real browser and record the app, not the block page.

    CLI scanners get the challenge. The browser records the calls the page
    itself makes, the scripts it loads, and the routes named in those scripts.
    """
    from playwright.sync_api import sync_playwright
    from urllib.parse import urlparse
    import os

    netloc = host.strip().lower()
    host = netloc.split(":")[0]
    SESSIONS.mkdir(parents=True, exist_ok=True)
    landed = ""
    title = ""
    sample = ""
    nav_error = ""
    found: list[str] = []
    scripts: list[str] = []
    observed: list[str] = []
    calls: list[dict] = []
    call_keys: set[tuple] = set()
    seen: set[str] = set()
    cookies: list = []
    ua = ""
    profile_used = ""
    jar: dict[str, str] = {}
    tries: list[str] = []
    # Fresh browser every time. No Chrome user-data dir, so this does not carry personal cookies,
    # account sync, or the Windows username. Timezone and language are a generic US desktop, not the host clock.
    launch_args = [
        "--disable-blink-features=AutomationControlled",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-sync",
        "--no-first-run",
        "--disable-background-networking",
        "--lang=en-US",
    ]

    def add(url: str) -> None:
        if not url or url in seen or not _same_site(url, host):
            return
        if len(found) >= 80:
            return
        seen.add(url)
        found.append(url)

    def reset() -> None:
        nonlocal landed, title, sample, nav_error, ua
        landed = ""
        title = ""
        sample = ""
        nav_error = ""
        ua = ""
        found.clear()
        scripts.clear()
        observed.clear()
        calls.clear()
        call_keys.clear()
        seen.clear()
        jar.clear()

    stealth_cm = None
    try:
        from playwright_stealth import Stealth
        stealth_cm = Stealth(navigator_languages_override=("en-US", "en")).use_sync(sync_playwright())
    except Exception:
        stealth_cm = None
    playwright_cm = stealth_cm if stealth_cm is not None else sync_playwright()
    with playwright_cm as p:
        browser = p.chromium.launch(headless=True, channel="chrome", args=launch_args)
        context = None
        page = None
        for name, platform in _PROFILES:
            if context:
                context.close()
            reset()
            if name not in p.devices:
                tries.append(f"{name}:missing")
                continue
            device = dict(p.devices[name])
            device.pop("default_browser_type", None)
            ua = device.get("user_agent") or ""
            _state = {"storage_state": state_path} if state_path and os.path.exists(state_path) else {}
            context = browser.new_context(
                **device,
                **_state,
                locale="en-US",
                timezone_id="America/New_York",
                ignore_https_errors=True,
                color_scheme="light",
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
            )
            context.add_init_script(_LEAK_JS)
            page = context.new_page()
            _stealth(page, platform)
            profile_used = name

            def _on_response(response) -> None:
                try:
                    for c in response.header_values("set-cookie"):
                        pair = c.split(";", 1)[0]
                        if "=" in pair:
                            cname, value = pair.split("=", 1)
                            if cname.strip():
                                jar[cname.strip()] = value.strip()
                except Exception:
                    pass
                try:
                    kind = response.request.resource_type
                except Exception:
                    kind = ""
                if kind == "document":
                    add(response.url)
                elif kind == "script" and _same_site(response.url, host) and response.url not in scripts and len(scripts) < 20:
                    scripts.append(response.url)
                try:
                    record = _same_site(response.url, host) and surface.worth_recording(kind, response.request.method, response.url, response.request.headers)
                except Exception:
                    record = False
                if record:
                    if len(calls) < 40:
                        kept = surface.replay_headers(response.request.headers)
                        action = ""
                        for hkey, hval in kept.items():
                            if hkey.lower() == "next-action":
                                action = hval
                        key = ((response.request.method or "GET").upper(), response.url.split("#", 1)[0], action)
                        if key not in call_keys:
                            call_keys.add(key)
                            try:
                                raw_body = response.request.post_data or ""
                            except Exception:
                                raw_body = ""
                            if not isinstance(raw_body, str):
                                raw_body = ""
                            calls.append({
                                "method": key[0],
                                "url": key[1],
                                "headers": kept,
                                "body": raw_body[:4000],
                            })
                            if response.url not in observed and len(observed) < 40:
                                observed.append(response.url)

            page.on("response", _on_response)
            try:
                _authority = netloc.split("/")[0]
                _hp = _authority.split(":")[0]
                _internal = (":" in _authority or _hp in ("localhost", "127.0.0.1", "::1")
                             or _hp.startswith("127.") or _hp.startswith("10.") or _hp.startswith("192.168."))
                _primary = ("http://" if _internal else "https://") + netloc + "/"
                _alt = ("https://" if _internal else "http://") + netloc + "/"
                try:
                    page.goto(_primary, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    page.goto(_alt, wait_until="domcontentloaded", timeout=45000)
                page.wait_for_timeout(4000)
                landed = page.url
                title = page.title()
                try:
                    sample = page.inner_text("body")[:400]
                except Exception:
                    sample = ""
                if _blocked(title, sample):
                    page.wait_for_timeout(6000)
                    landed = page.url
                    title = page.title()
                    try:
                        sample = page.inner_text("body")[:400]
                    except Exception:
                        sample = ""
            except Exception as exc:
                nav_error = str(exc).splitlines()[0][:160]
            blocked_now = bool(nav_error) or _blocked(title, sample) or (not found and not jar and not landed)
            note = nav_error or ("blocked" if _blocked(title, sample) else ("empty" if blocked_now else "open"))
            tries.append(f"{name}:{note[:80]}")
            if not blocked_now:
                break

        blocked = bool(nav_error) or _blocked(title, sample) or (not landed and not found and not jar)
        if landed and not blocked and page is not None:
            add(landed)
            try:
                hrefs = page.eval_on_selector_all(
                    "a[href], form[action]",
                    "els => els.map(e => e.href || e.action || '')",
                )
            except Exception:
                hrefs = []
            for href in hrefs:
                add(href)
            try:
                dom_scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)") or []
            except Exception:
                dom_scripts = []
            for src in dom_scripts:
                if isinstance(src, str) and _same_site(src, host) and src not in scripts and len(scripts) < 20:
                    scripts.append(src)
            # Clicks, not full reloads, so the app router emits its own RSC fetches.
            clicked = 0
            try:
                anchors = page.locator("a[href]").all()
            except Exception:
                anchors = []
            for loc in anchors:
                if clicked >= 6:
                    break
                try:
                    href = loc.get_attribute("href") or ""
                except Exception:
                    continue
                if not href.startswith("/") or href.startswith("//") or '"' in href:
                    continue
                lower = href.lower()
                if lower.endswith((".pdf", ".svg", ".png", ".jpg", ".css", ".js", ".ico")):
                    continue
                try:
                    loc.click(timeout=4000)
                    page.wait_for_timeout(1200)
                    clicked += 1
                except Exception:
                    continue
            queue = [u for u in found if _same_site(u, host)][:max_pages]
            visited: set[str] = set()
            for url in queue:
                if url in visited:
                    continue
                visited.add(url)
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    continue
                try:
                    hrefs = page.eval_on_selector_all(
                        "a[href], form[action]",
                        "els => els.map(e => e.href || e.action || '')",
                    )
                except Exception:
                    hrefs = []
                for href in hrefs:
                    add(href)
        if context is not None:
            cookies = context.cookies()
        if page is not None:
            try:
                for bit in (page.evaluate("() => document.cookie") or "").split(";"):
                    if "=" in bit:
                        cname, value = bit.split("=", 1)
                        if cname.strip():
                            jar[cname.strip()] = value.strip()
            except Exception:
                pass
        browser.close()

    for c in cookies:
        if c.get("name"):
            jar[c["name"]] = c.get("value") or ""
    if not landed and not found and not jar:
        blocked = True
    header = "; ".join(f"{cname}={value}" for cname, value in jar.items() if cname)
    hosts = {netloc}
    landed_host = (urlparse(landed).netloc or "").lower()
    if landed_host:
        hosts.add(landed_host)
    for h in hosts:
        if header:
            (SESSIONS / f"{h}.cookie").write_text(header, encoding="utf-8")
        if ua:
            (SESSIONS / f"{h}.ua").write_text(ua, encoding="utf-8")
        if profile_used:
            (SESSIONS / f"{h}.profile").write_text(profile_used, encoding="utf-8")
        (SESSIONS / f"{h}.urls.json").write_text(json.dumps(found, indent=2), encoding="utf-8")
        (SESSIONS / f"{h}.scripts.json").write_text(json.dumps(scripts, indent=2), encoding="utf-8")
        (SESSIONS / f"{h}.observed.json").write_text(json.dumps(observed, indent=2), encoding="utf-8")
        (SESSIONS / f"{h}.calls.json").write_text(json.dumps(calls, indent=2), encoding="utf-8")
    err_out = " | ".join(tries)[:220] if blocked and tries else nav_error
    return {
        "host": host,
        "landed": landed,
        "title": title,
        "profile": profile_used,
        "blocked": blocked,
        "cookies": len(jar),
        "urls": len(found),
        "scripts": len(scripts),
        "observed": len(observed),
        "sample": (sample or "")[:500],
        "error": err_out,
    }


def ua_for(host: str) -> str:
    path = SESSIONS / f"{host.lower()}.ua"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace").strip()


def cookie_for(host: str) -> str:
    path = SESSIONS / f"{host.lower()}.cookie"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace").strip()


def _json_list(path: pathlib.Path) -> list[str]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return [u for u in data if isinstance(u, str)]


def scripts_for(host: str) -> list[str]:
    return _json_list(SESSIONS / f"{host.lower()}.scripts.json")


def observed_for(host: str) -> list[str]:
    return _json_list(SESSIONS / f"{host.lower()}.observed.json")


def calls_for(host: str) -> list[dict]:
    path = SESSIONS / f"{host.lower()}.calls.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [row for row in data if isinstance(row, dict) and str(row.get("url") or "").startswith("http")]


def supplied_login(host: str) -> bool:
    """True only when the operator put a credential for this host in accounts.json."""
    if not ACCOUNTS.exists():
        return False
    try:
        data = json.loads(ACCOUNTS.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    rows = data if isinstance(data, list) else [data]
    host = host.lower().split(":")[0]
    for row in rows:
        if not isinstance(row, dict):
            continue
        named = str(row.get("host") or "").lower().split(":")[0]
        if not named or not (named == host or host.endswith("." + named) or named.endswith("." + host)):
            continue
        if any(str(row.get(key) or "").strip() for key in ("password", "token", "cookie")):
            return True
    return False


def urls_for(host: str) -> list[str]:
    path = SESSIONS / f"{host.lower()}.urls.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [u for u in data if isinstance(u, str)]


def apply_cookie(tool: str, args: list[str], cookie: str, ua: str = "") -> list[str]:
    if cookie and "cookie" not in " ".join(args).lower():
        if tool in {"httpx", "katana", "nuclei", "ffuf", "feroxbuster", "hakrawler"}:
            args = [*args, "-H", f"Cookie: {cookie}"]
        elif tool == "curl":
            args = ["-H", f"Cookie: {cookie}", *args]
        elif tool == "sqlmap":
            args = [*args, "--cookie", cookie]
        elif tool == "dalfox":
            args = [*args, "--cookie", cookie]
    if ua and "user-agent" not in " ".join(args).lower():
        if tool in {"httpx", "katana", "nuclei", "ffuf", "feroxbuster"}:
            args = [*args, "-H", f"User-Agent: {ua}"]
        elif tool == "curl":
            args = ["-A", ua, *args]
        elif tool == "sqlmap":
            args = [*args, "--user-agent", ua]
    return args


def _same_site(url: str, host: str) -> bool:
    m = re.match(r"https?://([^/]+)", url or "", re.I)
    if not m:
        return False
    got = m.group(1).split(":")[0].lower()
    host = host.lower()
    return got == host or got.endswith("." + host)


def login_one(account: dict, headed: bool, max_pages: int) -> dict:
    from playwright.sync_api import sync_playwright

    host = account["host"].strip().lower()
    user = account.get("username") or ""
    password = account.get("password") or ""
    if not user or not password:
        raise SystemExit(f"{host}: put username and password in accounts.json")

    SESSIONS.mkdir(parents=True, exist_ok=True)
    state_path = SESSIONS / f"{host}.storage.json"
    shot = SESSIONS / f"{host}.png"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headed)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(account["login_url"], wait_until="domcontentloaded", timeout=45000)
        page.locator(account["username_selector"]).first.fill(user, timeout=15000)
        page.locator(account["password_selector"]).first.fill(password, timeout=15000)
        page.locator(account["submit_selector"]).first.click(timeout=15000)
        try:
            page.wait_for_load_state("networkidle", timeout=20000)
        except Exception:
            page.wait_for_timeout(2000)
        final = page.url
        marker = (account.get("success_url_contains") or "").strip()
        ok = (marker in final) if marker else (final.rstrip("/") != account["login_url"].rstrip("/"))
        page.screenshot(path=str(shot), full_page=False)

        found: list[str] = []
        seen_pages = 0
        queue = [final]
        visited = set()
        while queue and seen_pages < max_pages:
            url = queue.pop(0)
            if url in visited or not _same_site(url, host):
                continue
            visited.add(url)
            seen_pages += 1
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=20000)
            except Exception:
                continue
            hrefs = page.eval_on_selector_all(
                "a[href], form[action]",
                "els => els.map(e => e.href || e.action || '')",
            )
            for href in hrefs:
                if href and _same_site(href, host) and href not in found:
                    found.append(href)
                    if href not in visited:
                        queue.append(href)
        context.storage_state(path=str(state_path))
        cookies = context.cookies()
        browser.close()

    header = "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))
    (SESSIONS / f"{host}.cookie").write_text(header, encoding="utf-8")
    (SESSIONS / f"{host}.urls.json").write_text(json.dumps(found, indent=2), encoding="utf-8")
    return {
        "host": host,
        "ok": ok,
        "landed": final,
        "cookies": len(cookies),
        "urls": len(found),
        "screenshot": str(shot),
    }


def browser_check() -> int:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("about:blank")
        title = page.evaluate("() => 'ready'")
        browser.close()
    print("browser", title)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--headed", action="store_true", help="show the window instead of headless")
    ap.add_argument("--pages", type=int, default=25, help="how many in-app pages to collect after login")
    ap.add_argument("--check", action="store_true", help="launch headless chromium and exit")
    args = ap.parse_args()
    if args.check:
        return browser_check()
    if not ACCOUNTS.exists():
        example = AGENT / "accounts.example.json"
        example.write_text(json.dumps([EXAMPLE], indent=2), encoding="utf-8")
        raise SystemExit(f"missing {ACCOUNTS.name}. Filled the shape into {example.name}. Copy it to accounts.json.")
    accounts = json.loads(ACCOUNTS.read_text(encoding="utf-8"))
    if isinstance(accounts, dict):
        accounts = [accounts]
    for account in accounts:
        result = login_one(account, args.headed, args.pages)
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
