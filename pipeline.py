#!/usr/bin/env python3
"""pipeline.py - Nablus coordinated scan (the thing that makes the detectors work
together). Runs the black-box harnesses and the white-box SAST stream as stages, then
RECONCILES their outputs into one report:

  black-box : idor_harness.py  -> idor_findings.json   (confirmed cross-user reads)
              sqli_harness.py  -> sqli_findings.json   (sqlmap-proven injections)
  white-box : sast_scan.py     -> sast_findings.json   (dangerous sinks in source)

Reconciliation merges the streams and CROSS-LINKS them: a white-box sink whose param
matches a black-box PoC is marked corroborated ("the code smells here AND we proved
it live"), which is the highest-confidence finding class. Each stage is a subprocess,
so one failing stage never takes down the others or the validated detectors.

Scope is still enforced inside each stage (runner.Scope / in_scope); this orchestrator
only sequences them. Target generalization (beyond the range BASE) is a follow-up.
"""
from __future__ import annotations
import sys, json, subprocess, argparse, pathlib

ROOT = pathlib.Path(__file__).resolve().parent


def run_stage(name, argv, out_file, timeout=1800):
    print(f"\n=== stage: {name} ===")
    try:
        subprocess.run([sys.executable, *argv], cwd=str(ROOT), timeout=timeout)
    except Exception as e:
        print(f"[pipeline] {name} failed: {str(e)[:160]}")
    p = ROOT / out_file
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return []
    print(f"[pipeline] {name}: no output file ({out_file})")
    return []


def reconcile(idor, sqli, sast):
    findings = []
    for f in idor:
        if f.get("confirmed"):
            findings.append({"class": "idor", "stream": "black-box", "confirmed": True,
                             "endpoint": f.get("url"), "param": f.get("id"),
                             "detail": f"{f.get('basis')} ({f.get('dir')})"})
    for f in sqli:
        if f.get("confirmed"):
            findings.append({"class": "sqli", "stream": "black-box", "confirmed": True,
                             "endpoint": f.get("endpoint"), "param": f.get("parameter"),
                             "detail": ", ".join(f.get("injection_types", []))})
    for f in sast:
        findings.append({"class": f.get("class"), "stream": "white-box", "confirmed": False,
                         "endpoint": None, "param": ";".join(f.get("param_hints", [])) or None,
                         "file": f.get("file"), "line": f.get("line"), "func": f.get("func"),
                         "detail": f"{f.get('tool')}:{f.get('rule')}"})

    # cross-link: white-box sink param matched by a black-box PoC of the same class
    bb = [(f["class"], (f.get("param") or "")) for f in findings
          if f["stream"] == "black-box" and f.get("param")]
    for f in findings:
        if f["stream"] == "white-box" and f.get("param"):
            hints = [h for h in f["param"].split(";") if h]
            for cls, bbparam in bb:
                if cls == f["class"] and any(h == bbparam for h in hints):
                    f["corroborated"] = f"black-box PoC confirms this sink (param={bbparam})"
                    break
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=None, help="target source path for the white-box stream")
    ap.add_argument("--skip-blackbox", action="store_true")
    ap.add_argument("--out", default="nablus_report.json")
    a = ap.parse_args()

    idor = sqli = []
    if not a.skip_blackbox:
        idor = run_stage("black-box IDOR", ["idor_harness.py"], "idor_findings.json")
        sqli = run_stage("black-box SQLi", ["sqli_harness.py"], "sqli_findings.json")
    sast = []
    if a.source:
        sast = run_stage("white-box SAST", ["sast_scan.py", "--source", a.source,
                                            "--out", "sast_findings.json"], "sast_findings.json")
    else:
        print("\n[pipeline] no --source given; skipping white-box stream")

    findings = reconcile(idor, sqli, sast)
    (ROOT / a.out).write_text(json.dumps(findings, indent=2), encoding="utf-8")

    confirmed = [f for f in findings if f.get("confirmed")]
    corrob = [f for f in findings if f.get("corroborated")]
    print("\n" + "=" * 56)
    print("NABLUS COORDINATED SCAN - RECONCILED REPORT")
    print("=" * 56)
    print(f"total findings: {len(findings)}  |  black-box confirmed: {len(confirmed)}  |  "
          f"corroborated (both streams): {len(corrob)}")
    for f in confirmed:
        print(f"  [CONFIRMED] {f['class']:5} {f.get('endpoint')} param={f.get('param')}  <{f['detail']}>")
    for f in corrob:
        print(f"  [BOTH]      {f['class']:5} {f.get('file')}:{f.get('line')} "
              f"param={f.get('param')}  -> {f['corroborated']}")
    wb_only = [f for f in findings if f["stream"] == "white-box" and not f.get("corroborated")]
    if wb_only:
        print(f"  white-box-only leads (code sinks, no live PoC yet): {len(wb_only)}")
        for f in wb_only[:10]:
            print(f"     {f['class']:5} {pathlib.Path(f['file']).name if f.get('file') else '?'}:{f.get('line')} "
                  f"({f['detail']}) params={f.get('param')}")
    print(f"\nfull report -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
