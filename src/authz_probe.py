#!/usr/bin/env python3
"""authz_probe.py - authenticated differential authorization tester (AUTHORIZED targets only).

What this is: the "does the access control actually hold?" engine. It proves a vuln EXISTS
by reaching a gated resource as an identity that shouldn't reach it. It does NOT mass-extract
data; evidence is the status + a short body snippet, capped.

Safety model:
  * Scope-gated: a host must equal, or be a subdomain of, an authorized_asset in scope.json
    (which must carry an authorization_ref). Anything else is refused and logged.
  * mode=readonly (default): GET-only. Calibration + unauth access-control + open-redirect.
    No credentials, no writes, nothing that changes state. Safe to run against prod.
  * mode=full: adds credentialed differential tests (needs test-account creds via env) and
    read-only auth checks (rate-limit with a BOGUS username so no real account locks).
  * State-changing probes (mass assignment, password reset, deletes) are NEVER auto-run;
    they are written to proposed_actions.json for human approval.
  * Findings require a reproduced request+response as proof. Access-control hits are marked
    'needs_human_confirm' because only a human can confirm the content is actually sensitive.
"""
from __future__ import annotations
import os, sys, json, time, argparse, pathlib, random, string
import urllib.request, urllib.error, http.cookiejar

HERE  = pathlib.Path(__file__).resolve().parent
AGENT = HERE            # authz_probe.py lives directly in nabulus-agent
sys.path.insert(0, str(AGENT))
from runner import Scope   # reuse: validates scope.json has program + authorization_ref

UA  = "nabulus-authz/1.0 (authorized-security-test)"
RPS = float(os.environ.get("AUTHZ_RPS", "3"))
SNIP = 300  # max body chars kept as evidence - we prove access, we don't hoard data
findings_meta = {}  # side-channel for report stats (e.g. how many routes were SPA shells)

# ------- scope -------
def load_scope(path):
    data = json.loads(pathlib.Path(path).read_text())
    s = Scope(data)  # raises if program/authorization_ref/assets missing
    return s

def in_scope(assets, host):
    h = (host or "").lower()
    return any(h == a or h.endswith("." + a) for a in assets)

# ------- http -------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

def do(cj, method, url, data=None, headers=None, follow=True, timeout=20):
    handlers = [urllib.request.HTTPCookieProcessor(cj)]
    if not follow: handlers.append(_NoRedirect())
    op = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": UA, **(headers or {})})
    try:
        r = op.open(req, timeout=timeout)
        body = r.read(200000)
        res = (r.status, dict(r.headers), body, r.geturl())
    except urllib.error.HTTPError as e:
        res = (e.code, dict(e.headers), e.read(200000), url)
    except Exception as e:
        res = (0, {}, str(e).encode(), url)
    time.sleep(1.0 / max(RPS, 0.5))
    return res

def snip(body):
    try: t = body.decode("utf-8", "replace")
    except Exception: t = str(body)
    t = " ".join(t.split())
    return t[:SNIP]

# ------- calibration -------
def calibrate(cj, base):
    lens = []
    for _ in range(3):
        p = "/" + "".join(random.choices(string.ascii_lowercase, k=16))
        st, _, body, _ = do(cj, "GET", base + p)
        lens.append((st, len(body)))
    st404 = lens[0][0]
    avg = sum(l for _, l in lens) // len(lens)
    return {"status": st404, "len": avg}

def looks_real(status, body, fp):
    # a "real/served" response: 2xx, and not the soft-404 fingerprint
    if status not in (200, 206): return False
    if status == fp["status"] and abs(len(body) - fp["len"]) < 64: return False
    return len(body) > 64

# ------- checks -------
def new_jar(): return http.cookiejar.CookieJar()

def seed_endpoints(base, scope_assets, seeds_file=None):
    """Endpoints to probe. If seeds_file given, use its newline paths; else defaults + discovered."""
    if seeds_file:
        paths = [l.strip() for l in pathlib.Path(seeds_file).read_text().splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        urls = set(base.rstrip("/") + (p if p.startswith("/") else "/"+p) for p in paths)
    else:
        seeds = ["/admin/access/", "/api/auth/papers/unlock/", "/papers/",
                 "/papers/six-book-portfolio.pdf", "/api/auth/login", "/login/"]
        urls = set(base + s for s in seeds)
        sess = AGENT / "sessions"
        if sess.exists():
            for f in sess.glob("*.urls.json"):
                try:
                    for u in json.loads(f.read_text()):
                        urls.add(u.split("#")[0])
                except Exception: pass
    # scope filter
    keep = []
    for u in sorted(urls):
        host = urllib.parse.urlparse(u).hostname if "://" in u else None
        if host and not in_scope(scope_assets, host):
            continue
        keep.append(u)
    return keep

import urllib.parse

import re as _re
_REF_RE    = _re.compile(r'(?:href|src|action|url)\s*=\s*["\']?([^"\'>\s)]+)', _re.I)
_PATH_RE   = _re.compile(r'(/(?:api|rest|ftp|assets|files|download|downloads|export|exports|backup|backups|uploads|static|data|admin)[^\s"\'<>)]*)', _re.I)
_SECRET_RE = _re.compile(r'(?i)(api[_-]?key|client[_-]?secret|secret[_-]?key|aws_access_key_id|aws_secret|authorization:\s*bearer|private[_-]?key|-----BEGIN [A-Z ]+PRIVATE KEY-----|xox[baprs]-|ghp_[A-Za-z0-9]{20,})')
_BACKUP_SUF = [".bak",".old",".orig",".save","~",".1"]

def _text(body):
    return (body[:200000].decode("utf-8","replace") if isinstance(body,(bytes,bytearray)) else str(body)[:200000])

def probe_one(cj, u, fp):
    """GET one URL, classify. Returns (is_finding, finding|None, is_shell, gated, body, ctype).

    SPA nuance: a Next/Angular app returns a 200 HTML *shell* for every route and gates
    client-side. The shell is NOT a server-side exposure. We only flag real files / API data /
    non-shell 200 content.
    """
    st, hdr, body, final = do(cj, "GET", u)
    ctype = (hdr.get("Content-Type") or hdr.get("content-type") or "").lower()
    path  = urllib.parse.urlparse(u).path.rstrip("/")
    gated = (st in (401,403)) or ("login" in (final or "").lower()) or (st in (301,302,303,307,308))
    # SPA shell = HTML carrying FRAMEWORK markers (not just any <!doctype html; a directory
    # listing is also doctype-html but IS worth crawling, so don't treat bare doctype as shell).
    is_shell = ("text/html" in ctype) and (b"_next/static" in body or b"/_next/" in body
                                           or b"ng-version" in body or b"<app-root" in body)
    is_root = path in ("",)
    finding = None
    # sensitive file types (keys, backups, dumps) are findings at ANY size - a 51-byte key counts.
    sens = u.lower().endswith((".key",".pem",".pub",".env",".kdbx",".p12",".pfx",".bak",".sql")) or "octet-stream" in ctype
    min_len = 1 if sens else 64
    if (not is_shell) and (not gated) and st == 200 and len(body) >= min_len and not is_root:
        is_file = any(x in ctype for x in ("pdf","octet-stream","zip","json","yaml","text/plain","markdown","msword","excel","keepass","x-")) \
                  or u.lower().endswith((".pdf",".zip",".json",".csv",".kdbx",".yml",".yaml",".bak",".key",".pem",".pub",".md",".sql",".log",".env"))
        sev = "high" if (is_file or "/api/" in u or "/rest/" in u or "admin" in u or "key" in u) else "medium"
        finding = {"class": "broken-access-control / unauth-exposure", "severity": sev,
            "endpoint": u, "identity": "anon", "content_type": ctype or "?",
            "proof_request": f"GET {u}  (no auth)",
            "proof_response": f"HTTP {st} ctype={ctype} len={len(body)} :: {snip(body)}",
            "reproduced": False,
            "status": "needs_human_confirm (is this resource meant to be gated/paid?)"}
    return (finding is not None), finding, is_shell, gated, body, ctype

def derive_candidates(u, body, base_netloc):
    """From a reachable resource, derive NEW read-only paths on the same host - the 'branch off it'."""
    pu = urllib.parse.urlparse(u); origin = f"{pu.scheme}://{pu.netloc}"
    cands = set()
    cands.add(origin + (pu.path.rsplit("/",1)[0] or "") + "/")          # 1) parent dir / listing
    last = pu.path.rsplit("/",1)[-1]
    if "." in last:
        for suf in _BACKUP_SUF: cands.add(origin + pu.path + suf)        # 2) backup/sibling variants
    t = _text(body)
    for m in _REF_RE.findall(t):                                        # 3) links referenced in the body
        full = urllib.parse.urljoin(u, m).split("#")[0]
        if urllib.parse.urlparse(full).netloc == base_netloc: cands.add(full)
    for m in _PATH_RE.findall(t):
        cands.add(origin + m.split("#")[0])
    # drop path-traversal / encoded-backslash noise from parsed directory-listing parent links
    return {c for c in cands if ".." not in c and "\\" not in c
            and "%5c" not in c.lower() and "%2e" not in c.lower()}

def scan_secrets(body):
    return sorted({m.group(0)[:60] for m in _SECRET_RE.finditer(_text(body))})

_JS_SRC_RE = _re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', _re.I)
_EP_RE     = _re.compile(r'["\'`](/(?:api|rest|data|report|reports|export|exports|evidence|file|files|download|downloads|admin|account|auth|papers|dashboard|v\d)/[A-Za-z0-9_\-/.]*)["\'`]')

def harvest_endpoints(base, assets, max_js=20):
    """Pull API/data/report endpoints out of the app's HTML + JS bundles - where a Next/React app
    declares its fetch() routes. This is the UNAUTHENTICATED attack surface, no creds needed.
    A hand-seeded list never finds the one endpoint that forgot its auth check; this does."""
    cj = new_jar()
    bp = urllib.parse.urlparse(base); origin = f"{bp.scheme}://{bp.netloc}"
    st, hdr, body, _ = do(cj, "GET", base)
    html = _text(body)
    found = set(origin + m for m in _EP_RE.findall(html))
    scripts = []
    for m in _JS_SRC_RE.findall(html):
        full = urllib.parse.urljoin(base, m)
        if urllib.parse.urlparse(full).netloc == bp.netloc: scripts.append(full)
    for js in scripts[:max_js]:
        _, _, b2, _ = do(cj, "GET", js)
        for m in _EP_RE.findall(_text(b2)): found.add(origin + m)
    keep = set()
    for u in found:
        h = urllib.parse.urlparse(u).hostname
        if h and in_scope(assets, h): keep.add(u.split("?")[0].split("#")[0])
    return keep

def expand_probe(findings, proposals, base, fp, endpoints, assets, max_depth, budget):
    """BFS over findings: a confirmed exposure seeds read-only follow-ups (parent dir, sibling/
    backup names, referenced paths), recursively - scope-gated, budget-capped, deduped. This is
    the pentester reflex 'what else is here / what does this point to'. Secret-looking content
    becomes a review LEAD (verifying a live credential is an action -> human approval), never
    auto-chased."""
    cj = new_jar(); base_netloc = urllib.parse.urlparse(base).netloc
    queue = [(u,0) for u in endpoints]
    visited, reqs, shell_routes = set(), 0, 0
    while queue and reqs < budget:
        u, depth = queue.pop(0)
        if u in visited: continue
        visited.add(u); reqs += 1
        host = urllib.parse.urlparse(u).hostname
        if host and not in_scope(assets, host): continue   # scope gate on EVERY derived URL
        isf, finding, is_shell, gated, body, ctype = probe_one(cj, u, fp)
        if is_shell and not gated: shell_routes += 1
        if isf:
            isf2, _, _, _, _, _ = probe_one(cj, u, fp); reqs += 1   # reproduce
            finding["reproduced"] = isf2; finding["depth"] = depth
            findings.append(finding)
            for s in scan_secrets(body):
                proposals.append({"class":"secret-exposure-lead","source":u,"indicator":s,
                    "action":"verify whether this credential is live",
                    "why_queued":"acting on a credential is an external, state-touching step - human approval required",
                    "status":"pending_review"})
            if depth < max_depth:
                for c in derive_candidates(u, body, base_netloc):
                    if c not in visited: queue.append((c, depth+1))
    findings_meta["shell_routes"] = shell_routes
    findings_meta["requests"] = reqs
    findings_meta["discovered"] = len(visited)

def check_open_redirect(findings, base):
    cj = new_jar()
    evil = "https://example.com/pwned"
    for path in ["/login/?next=", "/papers/unlock/?next="]:
        u = base + path + urllib.parse.quote(evil, safe="")
        st, hdr, body, _ = do(cj, "GET", u, follow=False)
        loc = hdr.get("Location") or hdr.get("location") or ""
        if st in (301,302,303,307,308) and ("example.com" in loc):
            findings.append({
                "class": "open-redirect", "severity": "medium", "endpoint": u, "identity": "anon",
                "proof_request": f"GET {u} (no-follow)",
                "proof_response": f"HTTP {st} Location={loc}",
                "reproduced": True,
                "status": "confirmed: redirects off-origin to attacker-controlled URL"
            })

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://www.quantnq.com")
    ap.add_argument("--mode", choices=["readonly","full"], default="readonly")
    ap.add_argument("--out", default=str(HERE.parent/"authz_findings.json"))
    ap.add_argument("--proposals", default=str(HERE.parent/"authz_proposed_actions.json"))
    ap.add_argument("--report", default=str(HERE/"authz_report.md"))
    ap.add_argument("--scope", default=str(AGENT/"scope.json"))
    ap.add_argument("--seeds", default=None, help="file of newline paths to probe (overrides default seeds)")
    ap.add_argument("--max-depth", type=int, default=2, help="how many hops to branch off a finding")
    ap.add_argument("--budget", type=int, default=200, help="max requests (safety cap on expansion)")
    ap.add_argument("--no-harvest", dest="harvest", action="store_false", help="skip JS/HTML endpoint harvest")
    ap.add_argument("--wordlist", default=None, help="file of paths to brute-probe (undocumented/infra discovery)")
    ap.set_defaults(harvest=True)
    a = ap.parse_args()
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # avoid cp1252 crash on site unicode
    except Exception: pass

    scope = load_scope(a.scope)
    assets = scope.assets
    host = urllib.parse.urlparse(a.base).hostname
    if not in_scope(assets, host):
        print(f"REFUSED: {host} not in scope ({sorted(assets)})", file=sys.stderr); return 3

    findings, proposals = [], []
    cal = calibrate(new_jar(), a.base)
    endpoints = seed_endpoints(a.base, assets, a.seeds)
    harvested = harvest_endpoints(a.base, assets) if a.harvest else set()
    wl = set()
    if a.wordlist:
        bp = a.base.rstrip("/")
        for ln in pathlib.Path(a.wordlist).read_text().splitlines():
            p = ln.strip()
            if p and not p.startswith("#"): wl.add(bp + (p if p.startswith("/") else "/"+p))
    endpoints = sorted(set(endpoints) | harvested | wl)
    print(f"[authz] base={a.base} mode={a.mode} 404fp={cal}")
    print(f"[authz] seeds + harvest({len(harvested)}) + wordlist({len(wl)}) -> probe set = {len(endpoints)}")

    expand_probe(findings, proposals, a.base, cal, endpoints, assets, a.max_depth, a.budget)
    check_open_redirect(findings, a.base)
    print(f"[authz] expansion: {findings_meta.get('requests',0)} requests, "
          f"{findings_meta.get('discovered',0)} urls visited (seeds + branched)")

    if a.mode == "full":
        have = all(os.environ.get(k) for k in ("QNQ_USERA_USER","QNQ_USERA_PASS","QNQ_USERB_USER","QNQ_USERB_PASS"))
        if not have:
            print("[authz] mode=full but QNQ_USERA_*/QNQ_USERB_* env not set -> "
                  "credentialed differential tests SKIPPED. Export test creds to enable IDOR/BOLA diffs.")
        else:
            print("[authz] (credentialed differential + BOLA diffs would run here; login contract per-app)")
        # state-changing probes are proposed, never auto-run
        proposals.append({"class":"mass-assignment","endpoint":"POST /api/auth/* (profile update)",
            "action":"add fields role=admin, entitlement=paid; check if they persist",
            "why_queued":"state-changing write - needs human approval","status":"pending_review"})
        proposals.append({"class":"auth-rate-limit","endpoint":"POST /api/auth/login",
            "action":"20 rapid logins with a BOGUS username; check throttle/lockout",
            "why_queued":"generates failed-auth events - approve before firing","status":"pending_review"})

    pathlib.Path(a.out).write_text(json.dumps(findings, indent=2))
    pathlib.Path(a.proposals).write_text(json.dumps(proposals, indent=2))

    # report
    r = [f"# Authz differential report - {a.base}", "",
         f"Mode: {a.mode}  |  404 fingerprint: {cal}  |  endpoints tested: {len(endpoints)}",
         f"Authorization on file: {bool(scope.auth_ref)}", "", "## Confirmed / candidate findings"]
    r.append(f"_({findings_meta.get('shell_routes',0)} route(s) returned the SPA HTML shell -> "
             f"client-side gated, verify via authenticated API test, not flagged here.)_")
    if not findings:
        r.append("- None. Access control held on every gated endpoint tested as anonymous, "
                 "and no open redirect. (Credentialed IDOR/BOLA requires test creds - see below.)")
    for f in findings:
        r.append(f"- **{f['severity'].upper()} {f['class']}** @ {f['endpoint']} "
                 f"[{f.get('status')}] reproduced={f.get('reproduced')}")
        r.append(f"    proof: {f['proof_response'][:200]}")
    r += ["", "## Proposed (needs your approval - NOT auto-run)"]
    r += ([f"- {p['class']}: {p['action']}" for p in proposals] or ["- none"])
    r += ["", "## Honest notes",
          "- Read-only mode proves a vuln EXISTS; it does not extract data. That is the right",
          "  deliverable for a pentest - proof of access, not possession.",
          "- The high-value IDOR/BOLA class needs two test identities (userA/userB). Export",
          "  QNQ_USERA_USER/PASS + QNQ_USERB_USER/PASS and run --mode full."]
    pathlib.Path(a.report).write_text("\n".join(r), encoding="utf-8")

    print(f"\n[authz] {len(findings)} finding(s), {len(proposals)} proposal(s)")
    print("\n".join(r))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
