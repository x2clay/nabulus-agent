#!/usr/bin/env python3
r"""cors_harness.py - CORS misconfiguration detector (black-box, anonymous).

Pre-auth class: anonymous probing, enterprise threat model. The exploitable CORS bug
is an endpoint that REFLECTS an arbitrary request Origin into Access-Control-Allow-Origin
AND answers Access-Control-Allow-Credentials: true -- that lets any attacker-controlled
site read a victim's authenticated responses cross-origin. Discovers candidate endpoints
from the crawl, a small API-path wordlist, and NABLUS_SEEDS, then tests each.

Confirm oracle (low-FP by construction):
  * send TWO distinct, attacker-controlled Origins; a finding requires the app to reflect
    BOTH verbatim into ACAO (proves arbitrary reflection, not a fixed allowlist that our
    single guess happened to match) AND return ACAC: true on at least one.
  * OR: send `Origin: null`; a finding requires ACAO == "null" AND ACAC: true (the sandbox-
    iframe bypass). ACAO "*" is NOT a credentialed finding (browsers reject *+credentials),
    and reflection WITHOUT credentials is a lead, not a finding -- neither is emitted.
Read-only (GET + an OPTIONS preflight), does not follow redirects.
"""
from __future__ import annotations  # noqa
import os, json, time, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlparse, parse_qsl
from html.parser import HTMLParser

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\cors_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
PACE = 0.02

# Two distinct attacker origins; reflecting BOTH proves arbitrary reflection.
EVIL1 = "https://evil-a.nablus-attacker.example"
EVIL2 = "https://evil-b.nablus-attacker.example"
NULL_ORIGIN = "null"
# common API/config endpoints that frequently carry credentialed CORS
API_PATHS = ["/api/config", "/api/me", "/api/user", "/api/account", "/api/profile",
             "/api/session", "/api/settings", "/api/notes", "/api/status", "/api/data",
             "/api/token", "/api/whoami", "/api/v1/config", "/api/admin/export", "/api/flag"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, origin, method="GET"):
    if PACE:
        time.sleep(PACE)
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _NoRedirect())
    headers = {"Origin": origin}
    if method == "OPTIONS":
        headers["Access-Control-Request-Method"] = "GET"
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        r = op.open(req, timeout=10)
        return r.status, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception:
        return 0, {}


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for k in ("href", "action", "src"):
            if a.get(k):
                self.hrefs.append(a[k])


def _plain_fetch(url):
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        r = op.open(urllib.request.Request(url), timeout=10)
        return r.read(120000).decode("utf-8", "replace")
    except Exception:
        return ""


def candidates():
    seen, frontier, urls = set(), [BASE + "/"], set()
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 15:
                continue
            seen.add(u)
            urls.add(u.split("?")[0])
            body = _plain_fetch(u)
            p = _Links()
            try:
                p.feed(body)
            except Exception:
                pass
            for h in p.hrefs:
                link = urljoin(u, h).split("#")[0]
                if link.startswith(BASE) and link not in seen and "logout" not in link.lower():
                    nxt.append(link)
                    urls.add(link.split("?")[0])
        frontier = nxt
    for s in SEEDS:
        full = s if "://" in s else BASE + ("" if s.startswith("/") else "/") + s
        urls.add(full.split("?")[0])
    for pth in API_PATHS:
        urls.add(BASE + pth)
    return sorted(urls)


def _acao(hdrs):
    return hdrs.get("access-control-allow-origin", "")


def _acac(hdrs):
    return (hdrs.get("access-control-allow-credentials", "") or "").strip().lower() == "true"


def confirm(url):
    # arbitrary reflection: both distinct evil origins reflected verbatim + credentials
    reflected = []
    creds = False
    for origin in (EVIL1, EVIL2):
        for method in ("GET", "OPTIONS"):
            st, hdrs = fetch(url, origin, method)
            if not hdrs:
                continue
            if _acao(hdrs) == origin:
                reflected.append(origin)
                creds = creds or _acac(hdrs)
                break
    if len(set(reflected)) >= 2 and creds:
        return {"kind": "arbitrary-origin reflection + credentials",
                "acao": "<reflected request Origin>", "acac": "true",
                "origins_reflected": sorted(set(reflected))}
    # null-origin bypass
    for method in ("GET", "OPTIONS"):
        st, hdrs = fetch(url, NULL_ORIGIN, method)
        if hdrs and _acao(hdrs).strip().lower() == "null" and _acac(hdrs):
            return {"kind": "null-origin + credentials", "acao": "null", "acac": "true",
                    "origins_reflected": ["null"]}
    return None


def main():
    cands = candidates()
    findings, tested = [], set()
    print(f"target: {BASE} | candidates: {len(cands)}")
    for url in cands:
        if url in tested:
            continue
        tested.add(url)
        proof = confirm(url)
        if proof:
            findings.append({"class": "cors-misconfig", "severity": "high", "endpoint": url,
                             "param": None, "identity": "anon", "proof": proof,
                             "proof_request": f"GET {url}  (Origin: {EVIL1})",
                             "validated_by": f"app allows cross-origin credentialed reads via {proof['kind']}",
                             "confirmed": True})
            print(f"[cors] CONFIRMED: {urlparse(url).path}  [{proof['kind']}]")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[cors] confirmed cors-misconfig findings: {len(findings)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
