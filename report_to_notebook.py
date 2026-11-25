#!/usr/bin/env python3
r"""report_to_notebook.py - adapt pipeline.py's reconciled output (nablus_report.json) into the
bench UI's notebook.json shape {target, tests, leads, proofs} that bench_bridge.material() feeds to
the DeepSeek extraction reviewer and that the download reads.

ADDITIVE + the seam only: it does NOT touch pipeline.py, the DeepSeek flow (material/deepseek_talk/
prompts/scope frame), findings.json, or schema.json. It just translates the new scanner's findings
into the format the existing DeepSeek validation stage already consumes, so swapping the finder to
pipeline.py changes nothing downstream.

Run from the repo root (cwd=root), after pipeline.py writes nablus_report.json:
  py -3 report_to_notebook.py
"""
from __future__ import annotations
import json, os, time, pathlib

HERE = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))


def _load(name):
    try:
        return json.loads((HERE / name).read_text(encoding="utf-8"))
    except Exception:
        return None


def main():
    report = _load("nablus_report.json") or []
    run = _load("_run.json") or {}
    target = run.get("target", "") if isinstance(run, dict) else ""
    now = time.strftime("%Y-%m-%dT%H:%M:%S")

    tests, leads, proofs = [], [], []
    for f in report:
        if not isinstance(f, dict):
            continue
        cls = f.get("class") or "finding"
        ep = f.get("endpoint") or ""
        param = f.get("param")
        detail = f.get("detail") or ""
        stream = f.get("stream")
        confirmed = bool(f.get("confirmed"))
        tag = "CONFIRMED " if confirmed else ""
        # tests: material() prints "tool target result" -> gives DeepSeek the one-line summary
        tests.append({"tool": cls, "target": ep,
                      "result": f"{tag}{cls}: {detail}".strip(), "when": now, "stream": stream})
        if confirmed:
            # leads: material() prints the full json -> gives DeepSeek the evidence to reason over
            leads.append({"vulnerability": cls, "tool": cls, "where": ep, "param": param,
                          "signal": detail, "stream": stream, "confirmed": True, "when": now})
            proofs.append({"class": cls, "endpoint": ep, "param": param, "detail": detail,
                           "stream": stream, "confirmed": True, "when": now})

    notebook = {"target": target, "generated": now, "source": "pipeline.py",
                "tests": tests, "leads": leads, "proofs": proofs}
    (HERE / "notebook.json").write_text(json.dumps(notebook, indent=2), encoding="utf-8")
    print(f"[report_to_notebook] {len(report)} finding(s) -> notebook.json "
          f"({len(leads)} confirmed, {len(tests)} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
