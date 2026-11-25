#!/usr/bin/env python3
"""benchmark.py - score authz_probe against a labeled vulnerable app (ground truth).

Runs authz_probe (readonly) against --base using a benchmark scope + seeds, then compares the
flagged endpoints to a truth file -> recall / precision / FP-rate. Flags not in the truth file
are listed as 'needs-review' (not auto-counted as FP) because truth is only as complete as we
label it. This is your tuning loop: change a heuristic -> re-run -> watch the numbers move.
"""
import sys, json, subprocess, pathlib, argparse
from urllib.parse import urlparse

HERE  = pathlib.Path(__file__).resolve().parent
AGENT = HERE.parent
PY    = sys.executable

def norm(u):
    p = urlparse(u if "://" in u else "http://x" + (u if u.startswith("/") else "/"+u))
    return ((p.path or "/").rstrip("/") or "/").lower()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base",  default="http://127.0.0.1:3000")
    ap.add_argument("--truth", default=str(HERE/"juiceshop_truth.json"))
    ap.add_argument("--seeds", default=str(HERE/"juiceshop_seeds.txt"))
    ap.add_argument("--scope", default=str(HERE/"scope_bench.json"))
    a = ap.parse_args()
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass

    out = str(HERE/"bench_findings.json")
    cmd = [PY, str(AGENT/"authz_probe.py"), "--base", a.base, "--mode", "readonly",
           "--scope", a.scope, "--seeds", a.seeds, "--out", out,
           "--report", str(HERE/"bench_authz_report.md"),
           "--proposals", str(HERE/"bench_proposed.json")]
    print("[bench] running:", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(r.stdout[-1500:]);
    if r.stderr.strip(): print("[bench][stderr]", r.stderr[-800:])

    findings = json.loads(pathlib.Path(out).read_text()) if pathlib.Path(out).exists() else []
    flagged  = {norm(f["endpoint"]) for f in findings}
    truth    = json.loads(pathlib.Path(a.truth).read_text())
    expected = {norm(t["path"]) for t in truth["should_flag"]}
    neg      = {norm(x) for x in truth.get("should_not_flag", [])}

    tp     = flagged & expected
    missed = expected - flagged
    fp     = flagged & neg
    review = flagged - expected - neg

    recall    = len(tp)/len(expected) if expected else 0.0
    pden      = len(tp)+len(fp)
    precision = (len(tp)/pden) if pden else 1.0

    lines = [
      "", "================ BENCHMARK SCORECARD ================",
      f"app={truth.get('app')}  base={a.base}",
      f"flagged={len(flagged)}  labeled_should_flag={len(expected)}  labeled_should_not={len(neg)}",
      f"TRUE POSITIVES ({len(tp)}/{len(expected)}): {sorted(tp)}",
      f"MISSED          ({len(missed)}): {sorted(missed)}",
      f"FALSE POSITIVES ({len(fp)}): {sorted(fp)}",
      f"NEEDS REVIEW (flagged, unlabeled) ({len(review)}): {sorted(review)}",
      f"RECALL={recall:.0%}   PRECISION(labeled)={precision:.0%}",
      "====================================================",
      "Tune: MISSED -> detector too strict/missing a check. FALSE POSITIVES -> add a rule-out",
      "to skills/false_positives.md and the code. NEEDS REVIEW -> label them into the truth file.",
    ]
    report = "\n".join(lines)
    print(report)
    (HERE/"benchmark_scorecard.md").write_text(report, encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
