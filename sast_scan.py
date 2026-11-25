#!/usr/bin/env python3
"""sast_scan.py - Nablus white-box stream.

Runs semgrep (local custom nablus_rules.yml) + bandit over target SOURCE, normalizes
both tools into one list of white-box findings, and attaches a best-effort (route,
param) attack-path hint so a source sink can be reconciled with a black-box PoC.

Offline: semgrep uses only the local rules file (no registry/network). White-box
findings are LEADS (a dangerous sink in the code), not confirmed vulns - the confirm
oracles (sqli_harness/sqlmap, idor_harness) still have to reproduce them live.
"""
from __future__ import annotations
import sys, os, re, json, subprocess, argparse, pathlib

HERE = pathlib.Path(__file__).resolve().parent
RULES = str(HERE / "nablus_rules.yml")

# param-name extractors: Flask-ish .get("x"), the range's _qp(qs,"x"), params["x"]
_PARAM = re.compile(
    r'(?:_qp\(\s*\w+\s*,\s*|\.get\(\s*|request\.(?:args|values|form)\.get\(\s*|params\[\s*)'
    r'["\']([A-Za-z_][\w-]*)["\']')
_DEF = re.compile(r'^(\s*)def\s+(\w+)\s*\(')


def _json_run(args, timeout=180):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        txt = p.stdout.strip()
        # bandit/semgrep may prepend progress to stdout on some setups; grab the JSON tail
        i = txt.find("{")
        return json.loads(txt[i:]) if i >= 0 else {}
    except Exception as e:
        print(f"[sast] tool error ({args[0]}): {str(e)[:120]}")
        return {}


def _enclosing(lines, lineno):
    """Return (func_name, body_lines) for the def enclosing a 1-indexed line."""
    start = None
    for i in range(min(lineno, len(lines)) - 1, -1, -1):
        m = _DEF.match(lines[i])
        if m:
            start = i
            indent = len(m.group(1))
            name = m.group(2)
            break
    if start is None:
        return None, []
    end = len(lines)
    for j in range(start + 1, len(lines)):
        s = lines[j]
        if s.strip() and (len(s) - len(s.lstrip())) <= indent and _DEF.match(s):
            end = j
            break
    return name, lines[start:end]


def _params_for(src_file, lineno, cache):
    if src_file not in cache:
        try:
            cache[src_file] = pathlib.Path(src_file).read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            cache[src_file] = []
    lines = cache[src_file]
    func, body = _enclosing(lines, lineno)
    params = sorted({m.group(1) for ln in body for m in _PARAM.finditer(ln)})
    return func, params


def scan(source):
    findings, cache = [], {}

    sg = _json_run(["semgrep", "--config", RULES, "--json", "--quiet", source])
    for r in sg.get("results", []):
        f = r["start"]["line"]
        path = r.get("path", source)
        func, params = _params_for(path, f, cache)
        findings.append({
            "class": (r.get("extra", {}).get("metadata", {}) or {}).get("class", "sast"),
            "tool": "semgrep", "rule": r["check_id"].split(".")[-1],
            "file": path, "line": f, "func": func, "param_hints": params,
            "severity": r.get("extra", {}).get("severity", "ERROR"),
            "code": (r.get("extra", {}).get("lines", "") or "").strip()[:160],
            "stream": "white-box", "confirmed": False,
        })

    bd = _json_run(["bandit", "-r", "-f", "json", source])
    SQLI_TESTS = {"B608"}  # string-based SQL construction
    for r in bd.get("results", []):
        tid = r.get("test_id", "")
        cls = "sqli" if tid in SQLI_TESTS else "sast"
        path = r.get("filename", source)
        ln = r.get("line_number", 0)
        func, params = _params_for(path, ln, cache)
        findings.append({
            "class": cls, "tool": "bandit", "rule": tid,
            "file": path, "line": ln, "func": func, "param_hints": params,
            "severity": r.get("issue_severity", ""),
            "code": (r.get("code", "") or "").strip().splitlines()[-1][:160] if r.get("code") else "",
            "stream": "white-box", "confirmed": False,
        })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, help="path to target source (file or dir)")
    ap.add_argument("--out", default="sast_findings.json")
    a = ap.parse_args()
    fs = scan(a.source)
    pathlib.Path(a.out).write_text(json.dumps(fs, indent=2), encoding="utf-8")
    bycls = {}
    for f in fs:
        bycls[f["class"]] = bycls.get(f["class"], 0) + 1
    print(f"[sast] white-box findings: {len(fs)} {bycls} -> {a.out}")
    for f in fs[:20]:
        print(f"  {f['class']:6} {f['tool']:8} {pathlib.Path(f['file']).name}:{f['line']} "
              f"func={f['func']} params={f['param_hints']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
