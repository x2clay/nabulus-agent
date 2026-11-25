#!/usr/bin/env python3
r"""unauth_exposure_harness.py - sensitive-file / unauth-exposure detector (black-box, anonymous).

Pre-auth class, highest real-bounty EV: an anonymous client reaching a file that leaks
secrets - .env, .git, backups/db dumps, cloud creds, phpinfo, framework config. This is the
single most-paid duplicate-resistant anon finding, so it is the first arm of the anon arsenal.

Surface: every path in a wordlist (default sensitive.txt) + crawl-discovered same-origin paths
+ NABLUS_SEEDS, probed with NO cookie (pure anonymous).

Confirm oracle (content is the proof - deterministic, precision-first):
  A candidate is CONFIRMED only when an anonymous GET returns a live (non-soft-404) 200/206
  whose BODY matches a positive secret-content signature (env assignments, PRIVATE KEY block,
  git config/index, SQL dump markers, AWS/cloud creds, phpinfo, generic api-key/bearer/token).
  A reachable-but-benign anon file (robots.txt, humans.txt, sitemap.xml, an empty/soft-404
  page) matches no signature and is NEVER confirmed - that is the precision guarantee. A
  sensitive-looking PATH with no secret content is at most a lead, not a finding.

Read-only (GET), no writes, single-shot per path. Soft-404 calibrated so an app that 200s
every path (SPA/catch-all) does not drown the result in false exposures.
"""
from __future__ import annotations  # noqa
import os, re, json, time, random, string, http.cookiejar
import urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlparse, parse_qsl
from html.parser import HTMLParser

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\unauth_findings.json"
HERE = pathlib.Path(__file__).resolve().parent
WORDLIST = pathlib.Path(os.environ.get("NABLUS_WORDLIST", str(HERE / "sensitive.txt")))
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
PACE = 0.02
UA = "nabulus-unauth/1.0 (authorized-security-test)"

# positive secret-content signatures -> (name, severity). Order = reporting priority.
SIGNATURES = [
    ("private-key", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws-credentials", "critical",
     re.compile(r"(?i)aws_secret_access_key\s*=|AKIA[0-9A-Z]{16}")),
    ("sql-dump", "high",
     re.compile(r"(?im)^(?:INSERT INTO|CREATE TABLE|DROP TABLE)\s|-- (?:MySQL dump|PostgreSQL database dump)|^CREATE TABLE")),
    ("git-config", "high",
     re.compile(r"\[core\][\s\S]{0,80}repositoryformatversion|^ref:\s+refs/", re.M)),
    ("dotenv-secret", "high",
     re.compile(r"(?im)^[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|DATABASE_URL|DB_PASS|API)[A-Z0-9_]*\s*=\s*\S")),
    ("generic-secret", "high",
     re.compile(r"(?i)(?:api[_-]?key|client[_-]?secret|secret[_-]?key|authorization:\s*bearer|"
                r"xox[baprs]-|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{30,})")),
    ("phpinfo", "medium", re.compile(r"<title>phpinfo\(\)|PHP Version\s*</td>")),
    ("ds-store", "low", re.compile(r"^\x00\x00\x00\x01Bud1")),
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, follow=False):
    if PACE:
        time.sleep(PACE)
    handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
    if not follow:
        handlers.append(_NoRedirect())
    op = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        r = op.open(req, timeout=12)
        return r.status, dict(r.headers), r.read(200000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(200000) if e.fp else b"")
    except Exception:
        return 0, {}, b""


def calibrate():
    """soft-404 fingerprint: apps that 200 every path shouldn't yield phantom exposures."""
    lens = []
    for _ in range(3):
        p = "/" + "".join(random.choices(string.ascii_lowercase, k=18))
        st, _h, body = fetch(BASE + p, follow=True)
        lens.append((st, len(body)))
    return {"status": lens[0][0], "len": sum(l for _, l in lens) // len(lens)}


def is_soft_404(status, body, fp):
    return status == fp["status"] and abs(len(body) - fp["len"]) < 64


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for k in ("href", "src"):
            if a.get(k):
                self.hrefs.append(a[k])


def crawl_paths():
    seen, frontier, paths = set(), [BASE + "/"], set()
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 15:
                continue
            seen.add(u)
            st, _h, body = fetch(u, follow=True)
            if st not in (200, 301, 302, 303, 307, 308):
                continue
            paths.add(urlparse(u).path)
            p = _Links()
            try:
                p.feed(body.decode("utf-8", "replace"))
            except Exception:
                pass
            for h in p.hrefs:
                link = urljoin(u, h).split("#")[0].split("?")[0]
                if link.startswith(BASE) and link not in seen and "logout" not in link.lower():
                    nxt.append(link)
        frontier = nxt
    return paths


def wordlist_paths():
    if not WORDLIST.exists():
        return set()
    out = set()
    for ln in WORDLIST.read_text(encoding="utf-8", errors="replace").splitlines():
        p = ln.strip()
        if p and not p.startswith("#"):
            out.add("/" + p.lstrip("/"))
    return out


def match_signature(body):
    for name, sev, rx in SIGNATURES:
        try:
            if rx.search(body.decode("latin-1", "replace")):
                return name, sev
        except Exception:
            continue
    return None, None


def main():
    fp = calibrate()
    paths = set(crawl_paths()) | wordlist_paths()
    for s in SEEDS:
        paths.add(urlparse(s if "://" in s else "/" + s.lstrip("/")).path or s)
    findings, tested = [], set()
    print(f"target: {BASE} | 404fp: {fp} | candidate paths: {len(paths)}")
    for p in sorted(paths):
        url = BASE + (p if p.startswith("/") else "/" + p)
        if url in tested:
            continue
        tested.add(url)
        st, _h, body = fetch(url, follow=False)
        if st not in (200, 206) or not body or is_soft_404(st, body, fp):
            continue
        name, sev = match_signature(body)
        if not name:
            continue
        findings.append({"class": "unauth-exposure", "severity": sev, "endpoint": url,
                         "param": None, "identity": "anon",
                         "proof": {"signature": name, "status": st, "len": len(body)},
                         "proof_request": f"GET {url}  (no auth)",
                         "validated_by": f"anonymous GET returned {name} secret content",
                         "confirmed": True})
        print(f"[unauth] CONFIRMED: {urlparse(url).path}  [{name}/{sev}]  ({len(body)}B)")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[unauth] confirmed unauth-exposure findings: {len(findings)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
