#!/usr/bin/env python3
"""skilleval.py - the 'provably useful' gate.

A skill (or any config/wordlist/payload change) is kept only if it MEASURABLY improves
findings against ground truth. This scores a black-box pipeline run against a known-answer
target using the existing engine.bench scorer, so the output is a NUMBER (recall / precision
/ fp-rate), not an opinion. Run it before and after a change; the delta is the skill's lift.

  baseline:  py -3 skilleval.py --run --out baseline.json
  candidate: <add/edit a skill>  then  py -3 skilleval.py --run --out candidate.json
  the lift = candidate.recall - baseline.recall  (at equal-or-better precision)

Reads the reconciled nablus_report.json (black-box findings only - this is the black-box
product; white-box leads are excluded from the black-box score on purpose).
"""
from __future__ import annotations
import sys, json, argparse, subprocess, pathlib

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from engine.contracts import Finding, Severity, VulnClass          # noqa: E402
from engine.bench.answerkey import AnswerKey                        # noqa: E402
from engine.bench.scoring import score                             # noqa: E402

# our report's coarse class -> the contracts VulnClass value the answer key uses
CLASS_MAP = {
    "idor": "idor-enumeration", "sqli": "injection", "injection": "injection",
    "xss": "xss-reflected", "ssrf": "ssrf", "cmdi": "injection",
    "business-logic": "business-logic", "bulk": "bulk-user-disclosure",
    "auth": "auth-jwt", "cors": "cors-misconfig",
}


def report_to_findings(report):
    out = []
    for f in report:
        if f.get("stream") != "black-box":
            continue                                    # black-box product; score black-box only
        cls = CLASS_MAP.get(f.get("class"), "injection")
        try:
            vc = VulnClass(cls)
        except ValueError:
            continue
        out.append(Finding(vuln_class=vc, severity=Severity.HIGH,
                           endpoint=f.get("endpoint") or "", summary=f.get("detail") or "",
                           confirmed=bool(f.get("confirmed"))))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default="nablus_range_key.json")
    ap.add_argument("--report", default="nablus_report.json")
    ap.add_argument("--run", action="store_true", help="run pipeline.py fresh before scoring")
    ap.add_argument("--source", default=None, help="passed to pipeline --source (optional white-box)")
    ap.add_argument("--out", default=None, help="write the scorecard JSON here")
    a = ap.parse_args()

    if a.run:
        argv = [sys.executable, "pipeline.py"]
        if a.source:
            argv += ["--source", a.source]
        subprocess.run(argv, cwd=str(HERE))

    report = json.loads((HERE / a.report).read_text(encoding="utf-8"))
    key = AnswerKey.load(HERE / a.key)
    findings = report_to_findings(report)
    card = score(key, findings, mode="no_web_search")

    print(f"\n== skill-eval: {key.target} (clean target => genuine discovery) ==")
    print(f"recall={card.recall}  precision={card.precision}  fp_rate={card.fp_rate}")
    print(f"TP={card.true_positives}  FN={card.false_negatives}  FP={card.false_positives}")
    print(f"found:  {list(card.found)}")
    print(f"missed: {list(card.missed)}   <- coverage gaps = the skills/detectors worth adding next")
    if card.spurious:
        print(f"false alarms: {list(card.spurious)}")
    if a.out:
        (HERE / a.out).write_text(json.dumps({
            "target": card.target, "recall": card.recall, "precision": card.precision,
            "fp_rate": card.fp_rate, "tp": card.true_positives, "fn": card.false_negatives,
            "fp": card.false_positives, "found": list(card.found), "missed": list(card.missed),
        }, indent=2), encoding="utf-8")
        print(f"scorecard -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
