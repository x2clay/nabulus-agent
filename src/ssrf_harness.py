#!/usr/bin/env python3
r"""ssrf_harness.py - server-side request forgery detector (black-box, anonymous).

Pre-auth class. Injects a URL pointing at an out-of-band (OOB) listener into every url-ish
parameter of every candidate endpoint. A finding is emitted ONLY when the TARGET SERVER itself
contacts our OOB listener for that exact injection's unique marker -> the server made an outbound
request on attacker-controlled input = SSRF, proven, no guessing.

Confirm oracle (zero-FP by construction):
  * every injection carries a UNIQUE marker as the leftmost DNS label of its OOB payload.
  * a callback is attributed to the (endpoint, param) that produced it; ONLY markers we generated
    count (interactsh base self-checks have no marker label and are ignored by oob.InteractshOOB).
  * a reflected/echoed URL, a 200 with no callback, or an allowlisted-host refusal is NEVER a
    finding -- without the server reaching OUR unique canary there is no proof.

Impact is capped at PROOF: we never point injections at cloud metadata (169.254.169.254) or
internal services, and we never escalate. OOB egress + client must be verified on the box first.

Self-contained pipeline stage: reads NABLUS_TARGET / NABLUS_SEEDS, writes ssrf_findings.json.
Reuses the stdlib-only InteractshOOB driver from oob.py (client lifecycle + marker correlation).
"""
from __future__ import annotations  # noqa
import os, json, time, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib, uuid
from urllib.parse import urljoin, urlsplit
from html.parser import HTMLParser
from oob import InteractshOOB

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\ssrf_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
ITSH_CLIENT = os.environ.get("NABLUS_ITSH_CLIENT",
                             r"C:\Users\Laith\nabulus-tools\bin\interactsh-client.exe")
ITSH_SERVER = os.environ.get("NABLUS_ITSH_SERVER") or None   # default: public oast.*
WORKDIR = os.path.dirname(os.path.abspath(__file__))
PACE = 0.02
POLL_WAIT = 14.0

# endpoints that commonly fetch a client-supplied URL server-side
FETCH_PATHS = ["/api/fetch", "/api/preview", "/api/proxy", "/api/url", "/api/load",
               "/api/image", "/api/thumbnail", "/api/webhook", "/api/callback",
               "/api/import", "/api/feed", "/api/render", "/fetch", "/proxy", "/render"]
# url-ish parameter names to inject (leftmost = most common)
PARAMS = ["url", "uri", "link", "src", "dest", "destination", "redirect", "redirect_url",
          "returnUrl", "next", "img", "image", "imageUrl", "host", "domain", "callback",
          "webhook", "fetch", "load", "u", "feed", "to", "out", "target", "site", "proxy",
          "dataurl", "file", "path"]


def _marker() -> str:
    return "s" + uuid.uuid4().hex[:10]           # DNS-label-safe, unique per injection


def do(url):
    if PACE:
        time.sleep(PACE)
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        r = op.open(urllib.request.Request(url, headers={"User-Agent": "nablus-ssrf/1.0"}),
                    timeout=10)
        return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


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
        for k in ("href", "action", "src"):
            if a.get(k):
                self.hrefs.append(a[k])


def _feed(body):
    p = _Links()
    try:
        p.feed(body)
    except Exception:
        pass
    return p.hrefs


def candidates():
    """Endpoint paths worth probing: fetch-ish wordlist + crawl + seeds."""
    paths, seen, frontier = set(FETCH_PATHS), set(), [BASE + "/"]
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 15:
                continue
            seen.add(u)
            for h in _feed(_plain_get(u)):
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
    print(f"target: {BASE} | SSRF candidate endpoints: {len(cands)} | params/endpoint: {len(PARAMS)}")

    provider = InteractshOOB(ITSH_CLIENT, WORKDIR, server=ITSH_SERVER, poll_wait=POLL_WAIT)
    try:
        provider.start()
    except Exception as exc:
        print(f"[ssrf] ABORT: interactsh unavailable ({exc!r}); cannot prove SSRF -> 0 findings")
        pathlib.Path(OUT).write_text("[]", encoding="utf-8")
        return 0
    print(f"[ssrf] OOB session domain: {provider.domain}")

    injected = {}                                # marker -> (endpoint_path, param)
    try:
        for path in cands:
            for p in PARAMS:
                marker = _marker()
                payload = provider.payload(marker)          # http://<marker>.<domain>/<marker>
                url = BASE + path + "?" + urllib.parse.urlencode({p: payload})
                do(url)
                injected[marker] = (path, p)
        provider.wait()                          # let DNS/HTTP callbacks land
        # second settle+poll in case of DNS propagation lag
        seen = provider.seen_markers()
        if not seen:
            time.sleep(5)
            seen = provider.seen_markers()

        findings = []
        emitted = set()
        for marker, (path, p) in injected.items():
            if marker not in seen or path in emitted:
                continue
            emitted.add(path)                    # one finding per endpoint (first proven param)
            evidence = provider.interactions_for(marker)
            proto = ",".join(sorted({e.get("protocol", "?") for e in evidence})) or "oob"
            findings.append({
                "class": "ssrf", "severity": "high", "endpoint": BASE + path, "param": p,
                "identity": "anon",
                "proof": {"marker": marker, "oob_payload": provider.payload(marker),
                          "protocols": proto, "interactions": evidence},
                "proof_request": f"GET {BASE + path}?{p}=http://{marker}.{provider.domain}/",
                "validated_by": (f"out-of-band {proto} callback to our unique canary "
                                 f"{marker}.{provider.domain} -> server made an outbound request "
                                 f"on attacker-controlled '{p}' (SSRF)"),
                "confirmed": True,
            })
            print(f"[ssrf] CONFIRMED: {path} param={p}  (OOB {proto} via {marker})")
    finally:
        provider.stop()

    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[ssrf] confirmed SSRF findings: {len(findings)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
