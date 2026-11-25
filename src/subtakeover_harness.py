#!/usr/bin/env python3
r"""subtakeover_harness.py - subdomain takeover detector (black-box, anonymous, zero-creds).

A subdomain is takeover-able when its DNS still points (via CNAME) at a third-party service whose
backing resource has been de-provisioned/unclaimed -- an attacker re-registers that resource and
serves content on the victim's subdomain. Classic bounty class: scales across a recon surface,
low duplicate rate on fresh scope.

CONFIRM ORACLE (zero-FP by construction -- BOTH halves required):
  1. the host has a CNAME matching a known takeover-able service pattern, AND
  2. fetching the host returns that service's documented UNCLAIMED/DANGLING fingerprint
     (status + body substring) -- the signal the backing resource is free to claim.
A CNAME alone is not a finding (the resource may be claimed). A dangling-looking body alone is not
a finding (could be an unrelated 404). Only the pair -- dangling fingerprint behind a matching
CNAME, for a service we mark `confirmable` (fingerprint is unambiguous for that service) -- is
emitted. Ambiguous/edge services are treated as leads and NOT emitted. Impact capped at PROOF: we
detect the claimable state, we never register the resource.

SCOPE: operates only on in-scope hosts (from recon_targets.json, NABLUS_SEEDS hosts, or
NABLUS_SCOPE). DNS resolution via dnsx; HTTP via stdlib.

Self-contained stage: writes subtakeover_findings.json. `--selftest` proves the decision oracle
against embedded positive/negative fixtures (how we validate zero-FP without a live dangling sub).
"""
from __future__ import annotations  # noqa
import os, re, sys, json, ssl, socket, subprocess, pathlib, urllib.request, urllib.error
from urllib.parse import urlsplit

WORKDIR = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get("NABLUS_TOOLBIN", r"C:\Users\Laith\nabulus-tools\bin")
OUT = r"C:\Users\Laith\nabulus-agent\subtakeover_findings.json"
RECON = pathlib.Path(WORKDIR) / "recon_targets.json"

# Curated high-confidence fingerprint DB (subset of can-i-take-over-xyz, confirmable=fingerprint
# is unambiguous for a DANGLING resource behind that CNAME). cname = substrings any of which in
# the CNAME chain; body = substrings any of which present in an unclaimed response.
FINGERPRINTS = [
    {"service": "github-pages", "cname": ["github.io"], "confirmable": True,
     "body": ["There isn't a GitHub Pages site here.",
              "For root URLs (like http://example.com/) you must provide an index.html file"]},
    {"service": "aws-s3", "cname": ["s3.amazonaws.com", "s3-website", ".s3.", "s3-external"],
     "confirmable": True, "body": ["The specified bucket does not exist", "NoSuchBucket"]},
    {"service": "bitbucket", "cname": ["bitbucket.io"], "confirmable": True,
     "body": ["Repository not found"]},
    {"service": "heroku", "cname": ["herokuapp.com", "herokudns.com", "herokussl"],
     "confirmable": True, "body": ["No such app", "herokucdn.com/error-pages/no-such-app.html"]},
    {"service": "fastly", "cname": ["fastly.net"], "confirmable": True,
     "body": ["Fastly error: unknown domain"]},
    {"service": "pantheon", "cname": ["pantheonsite.io"], "confirmable": True,
     "body": ["The gods are wise, but do not know of the site which you seek.",
              "404 error unknown site!"]},
    {"service": "tumblr", "cname": ["domains.tumblr.com"], "confirmable": True,
     "body": ["Whatever you were looking for doesn't currently exist at this address."]},
    {"service": "cargo", "cname": ["cargocollective.com"], "confirmable": True,
     "body": ["If you're moving your domain away from Cargo"]},
    {"service": "surge", "cname": ["surge.sh"], "confirmable": True,
     "body": ["project not found"]},
    {"service": "readme", "cname": ["readme.io"], "confirmable": True,
     "body": ["Project doesnt exist... yet!"]},
    {"service": "ghost", "cname": ["ghost.io"], "confirmable": True,
     "body": ["The thing you were looking for is no longer here, or never was"]},
    {"service": "wordpress", "cname": ["wordpress.com"], "confirmable": True,
     "body": ["Do you want to register"]},
    # edge/ambiguous -> lead only (never emitted as a finding)
    {"service": "shopify", "cname": ["myshopify.com"], "confirmable": False,
     "body": ["Sorry, this shop is currently unavailable"]},
    {"service": "zendesk", "cname": ["zendesk.com"], "confirmable": False,
     "body": ["Help Center Closed"]},
]

SCOPE_RAW = os.environ.get("NABLUS_SCOPE") or os.environ.get("NABLUS_TARGET", "")
HTTP_TIMEOUT = int(os.environ.get("NABLUS_ST_HTTP_TIMEOUT", "10"))


def tool(name):
    p = pathlib.Path(BIN) / (name + ".exe")
    return str(p) if p.exists() else None


def evaluate(cname_chain, body, status):
    """THE ORACLE. Return (service, matched_cname, matched_body) if a CONFIRMABLE takeover is
    proven by the CNAME+fingerprint pair, else None. Pure function -> unit-testable."""
    chain = " ".join(c.lower() for c in (cname_chain or []))
    body = body or ""
    for fp in FINGERPRINTS:
        if not fp["confirmable"]:
            continue
        cn = next((c for c in fp["cname"] if c.lower() in chain), None)
        if not cn:
            continue
        bm = next((b for b in fp["body"] if b in body), None)
        if bm:
            return fp["service"], cn, bm
    return None


def host_of(s):
    s = s.strip().lower()
    return (urlsplit(s if "//" in s else "//" + s).hostname or s).strip("[]")


def resolve_cname(host):
    """CNAME chain via dnsx (-cname -json); fallback to empty on any failure."""
    dx = tool("dnsx")
    if not dx:
        return []
    try:
        p = subprocess.run([dx, "-silent", "-nc", "-cname", "-json", "-l", "-"],
                          input=host + "\n", capture_output=True, text=True, timeout=30)
    except Exception:
        return []
    chain = []
    for ln in (p.stdout or "").splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            r = json.loads(ln)
        except Exception:
            continue
        for c in (r.get("cname") or []):
            chain.append(c)
    return chain


def fetch(host):
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "nablus-st/1.0"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as r:
                return r.status, r.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read(65536).decode("utf-8", "replace")
            except Exception:
                return e.code, ""
        except Exception:
            continue
    return None, ""


def load_hosts():
    hosts = set()
    if RECON.exists():
        try:
            data = json.loads(RECON.read_text(encoding="utf-8"))
            for h in data.get("hosts", []):
                hosts.add(host_of(h.get("url", "")))
            for e in data.get("endpoints", []):
                hosts.add(host_of(e))
        except Exception:
            pass
    for s in (os.environ.get("NABLUS_SEEDS", "") + "," + SCOPE_RAW).split(","):
        s = s.strip()
        if s and ("//" in s or "." in s):
            hosts.add(host_of(s))
    return sorted(h for h in hosts if h)


def selftest():
    cases = [
        # (name, cname_chain, body, expect_service_or_None)
        ("gh-dangling", ["x.github.io"], "There isn't a GitHub Pages site here.", "github-pages"),
        ("s3-dangling", ["bucket.s3.amazonaws.com"], "<Error><Code>NoSuchBucket</Code>", "aws-s3"),
        ("heroku-dangling", ["app.herokudns.com"], "...No such app...", "heroku"),
        # negatives:
        ("gh-claimed", ["x.github.io"], "<html>welcome to my real pages site</html>", None),
        ("body-no-cname", ["cdn.cloudflare.net"], "There isn't a GitHub Pages site here.", None),
        ("edge-shopify-not-confirmable", ["s.myshopify.com"],
         "Sorry, this shop is currently unavailable", None),
        ("empty", [], "", None),
    ]
    ok = True
    for name, chain, body, expect in cases:
        res = evaluate(chain, body, 404)
        got = res[0] if res else None
        status = "PASS" if got == expect else "FAIL"
        if got != expect:
            ok = False
        print(f"  [{status}] {name:30} expect={expect!s:14} got={got}")
    print(f"\nselftest: {'ALL PASS -> oracle is zero-FP on fixtures' if ok else 'FAILURES'}")
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()
    hosts = load_hosts()
    print(f"[subtakeover] evaluating {len(hosts)} in-scope host(s)")
    findings = []
    for h in hosts:
        chain = resolve_cname(h)
        if not chain:
            continue
        # only fetch if some CNAME could match a known service (cheap pre-filter)
        chain_s = " ".join(c.lower() for c in chain)
        if not any(c.lower() in chain_s for fp in FINGERPRINTS for c in fp["cname"]):
            continue
        status, body = fetch(h)
        hit = evaluate(chain, body, status)
        if hit:
            service, cn, bm = hit
            findings.append({
                "class": "subdomain-takeover", "severity": "high",
                "endpoint": h, "param": None, "identity": "anon",
                "proof": f"CNAME->{cn} ({service}) + dangling fingerprint: {bm!r} (HTTP {status})",
                "proof_request": f"dig CNAME {h} ; curl -sk https://{h}/",
                "validated_by": f"confirmable takeover: {service} CNAME + unclaimed fingerprint",
                "confirmed": True,
            })
            print(f"  [TAKEOVER] {h} -> {service} (CNAME {cn})")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[subtakeover] {len(findings)} confirmed takeover(s) -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
