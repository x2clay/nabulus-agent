#!/usr/bin/env python3
"""redirect_probe.py - open-redirect detector for ?next=/redirect=-style params.

Deterministic: injects a canary host into the param and inspects the server's own 3xx Location.
A finding is CONFIRMED only when the server issues a 3xx whose Location points at the attacker-
controlled canary host. Body-reflection into a redirect-capable sink is reported separately as a
low-confidence CANDIDATE (confirmed:false), never as a proven bug.

Never follows redirects, so the canary host (.invalid, non-resolving) is never actually contacted.
Scope-gated. Routes through the box egress (Mullvad), so the target sees the VPN exit IP.
"""
from __future__ import annotations
import sys, json, argparse, pathlib, urllib.parse, urllib.request, urllib.error
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from runner import Scope
from authz_probe import in_scope

MARK = "canary-redirect-test.invalid"
CANARIES = [f"https://{MARK}/x", f"//{MARK}/x", f"/\\{MARK}/x", f"https:{MARK}/x"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _fetch(url):
    op = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        r = op.open(req, timeout=12)
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(4096).decode(errors="replace")
    except urllib.error.HTTPError as e:
        hdr = {k.lower(): v for k, v in (e.headers or {}).items()}
        body = e.read(4096).decode(errors="replace") if e.fp else ""
        return e.code, hdr, body
    except Exception as ex:
        return None, {}, repr(ex)


def check(target, param, assets):
    host = urllib.parse.urlparse(target).hostname
    if host and not in_scope(assets, host):
        print(f"REFUSED: {host} not in scope")
        return []
    findings = []
    for c in CANARIES:
        u = target + ("&" if "?" in target else "?") + urllib.parse.urlencode({param: c})
        st, hdr, body = _fetch(u)
        loc = hdr.get("location", "")
        if st and 300 <= st < 400 and MARK in loc:
            findings.append({"class": "open-redirect", "severity": "medium", "endpoint": target,
                             "param": param, "proof_request": f"GET {u}",
                             "proof_response": f"HTTP {st} Location: {loc}",
                             "validated_by": "server issued a 3xx redirect to an attacker-controlled host",
                             "confirmed": True})
            print(f"[redir] OPEN REDIRECT CONFIRMED param={param} -> {loc}")
            return findings
        if MARK in body and ("http-equiv=\"refresh\"" in body.lower() or "window.location" in body.lower()
                             or "location.href" in body.lower()):
            findings.append({"class": "open-redirect", "subtype": "client-side-candidate", "severity": "low",
                             "endpoint": target, "param": param, "proof_request": f"GET {u}",
                             "note": "canary reflected into a redirect-capable client sink; needs manual confirm",
                             "confirmed": False})
            print(f"[redir] CANDIDATE client-side redirect reflection param={param} (unconfirmed)")
            return findings
    print(f"[redir] no open redirect on param={param}")
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--param", default="next")
    ap.add_argument("--scope", default="scope.json")
    ap.add_argument("--out", default="redirect_findings.json")
    a = ap.parse_args()
    scope = Scope(json.loads(pathlib.Path(a.scope).read_text()))
    f = check(a.target, a.param, scope.assets)
    pathlib.Path(a.out).write_text(json.dumps(f, indent=2))
    print(f"[redir] {len(f)} finding(s) -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
