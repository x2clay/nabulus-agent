#!/usr/bin/env python3
"""sqli_probe.py - SQL-injection detector using sqlmap as the DETERMINISTIC validator.

sqlmap is not a guesser: it only reports a parameter as an injection point after it has PROVEN a
differential (boolean/error/time) or actually retrieved out-of-band / in-band data. That proof is
exactly the oracle this toolkit requires, so here sqlmap is the validator and this module is the
scope-gated, safe-by-default driver around it.

Safety / doctrine:
  * Scope-gated: refuses any host not in scope BEFORE invoking sqlmap.
  * PROOF not extraction: runs at low level/risk, detection only. It does NOT dump tables, read
    files, run --os-shell, or enumerate data. Those are destructive/high-impact and stay
    human-gated - the finding stops at "this parameter is injectable, here is sqlmap's proof."
  * --batch (no prompts), --flush-session (clean each run), bounded technique set.
  * Egress is the box's (Mullvad) exit; for real engagements allowlist that IP with the client.

Query (GET) params are tested from the URL; a POST body can be supplied with --data.
"""
from __future__ import annotations
import sys, os, re, json, argparse, pathlib, subprocess, urllib.parse
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from runner import Scope
from authz_probe import in_scope

SQLMAP = r"C:\Users\Laith\nabulus-tools\github\sqlmapproject__sqlmap\sqlmap.py"

# sqlmap prints one block per proven injection point. These anchors appear ONLY after proof.
_POINT = re.compile(r"sqlmap identified the following injection point", re.I)
_PARAM = re.compile(r"^Parameter:\s*(?P<name>.+?)\s*\((?P<place>[A-Z]+)\)", re.M)
_TYPE = re.compile(r"^\s*Type:\s*(?P<t>.+)$", re.M)
_TITLE = re.compile(r"^\s*Title:\s*(?P<t>.+)$", re.M)


def run_sqlmap(target, data, level, risk, technique, timeout, python_exe):
    args = [python_exe, SQLMAP, "-u", target, "--batch", "--flush-session",
            f"--level={level}", f"--risk={risk}", f"--technique={technique}",
            "--disable-coloring", "--answers=crack=N,dict=N",
            "--threads=2", "--timeout=15", "--retries=1"]
    if data:
        args += ["--data", data]
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        return p.stdout + "\n" + p.stderr
    except subprocess.TimeoutExpired as e:
        return (e.stdout or "") + "\n[sqli] sqlmap timed out"


def parse_points(out):
    """Extract proven injection points from sqlmap output. Empty list = not vulnerable."""
    if not _POINT.search(out):
        return []
    points = []
    for m in _PARAM.finditer(out):
        # grab the block after this Parameter line up to the next Parameter or blank gap
        start = m.end()
        nxt = _PARAM.search(out, start)
        block = out[start:nxt.start()] if nxt else out[start:start + 1200]
        points.append({
            "parameter": m.group("name"),
            "place": m.group("place"),           # GET / POST / etc
            "types": _TYPE.findall(block),
            "titles": _TITLE.findall(block),
        })
    return points


def probe(target, data, assets, level, risk, technique, timeout, python_exe):
    host = urllib.parse.urlparse(target).hostname
    if host and not in_scope(assets, host):
        print(f"REFUSED: {host} not in scope")
        return []
    print(f"[sqli] sqlmap level={level} risk={risk} technique={technique} -> {target}")
    out = run_sqlmap(target, data, level, risk, technique, timeout, python_exe)
    points = parse_points(out)
    findings = []
    for pt in points:
        findings.append({
            "class": "sqli", "severity": "critical", "endpoint": target,
            "parameter": pt["parameter"], "place": pt["place"],
            "injection_types": pt["types"], "proof_titles": pt["titles"],
            "validated_by": "sqlmap confirmed injection point (differential/time/error proof)",
            "confirmed": True,
            "note": "Detection only - no data dumped. Exploitation/impact is human-gated.",
        })
        print(f"[sqli] CONFIRMED injectable: {pt['parameter']} ({pt['place']}) types={pt['types']}")
    if not findings:
        print("[sqli] no injection point proven")
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="URL incl. query string to test")
    ap.add_argument("--data", default=None, help="POST body (tests its params instead/also)")
    ap.add_argument("--scope", default="benchmark/scope_bench.json")
    ap.add_argument("--out", default="sqli_findings.json")
    ap.add_argument("--level", type=int, default=2)
    ap.add_argument("--risk", type=int, default=1)
    ap.add_argument("--technique", default="BEST", help="sqlmap techniques: B/E/U/S/T (no Q by default)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--python", default=sys.executable)
    a = ap.parse_args()
    scope = Scope(json.loads(pathlib.Path(a.scope).read_text()))
    f = probe(a.target, a.data, scope.assets, a.level, a.risk, a.technique, a.timeout, a.python)
    pathlib.Path(a.out).write_text(json.dumps(f, indent=2))
    print(f"[sqli] {len(f)} confirmed SQLi finding(s) -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
