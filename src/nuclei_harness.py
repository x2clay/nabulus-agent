#!/usr/bin/env python3
r"""nuclei_harness.py - external-scanner breadth layer (black-box, anonymous, zero-creds).

This is NOT a bespoke confirm-oracle detector like the others; it is the BREADTH arm. It drives
the local nuclei binary (v3.x, 14k community templates on the box) against the in-scope target(s)
and parses the structured JSONL. nuclei's value is coverage: known CVEs, exposed files/secrets,
default logins, security-misconfig, subdomain takeover -- the long tail our bespoke detectors
don't each hand-roll.

Confirm oracle (by construction): a nuclei finding is only emitted when a TEMPLATE MATCHER FIRED
on a real response from the target. A matcher firing is a deterministic, replayable reproduction
(request + matched-at + extracted value + curl-command are all captured), so every emitted finding
is confirmed:True with a concrete proof. Info-level fingerprinting is excluded by default -- we
report vulns/exposures, not "this server runs nginx".

SCORING SEAM: these findings are emitted into the report with stream="scanner", NOT "black-box".
skilleval scores only stream=="black-box" (our bespoke confirm-oracle detectors), so nuclei is
reported ALONGSIDE the scored product as independent corroboration without polluting precision.
A nuclei exposure hit on /.env that overlaps our unauth-exposure detector is corroboration, not
a double-count and not a false positive.

SCOPE: nuclei is pointed ONLY at NABLUS_TARGET + NABLUS_SEEDS (the authorized hosts). Redirect
following is OFF so it cannot wander off-scope. Rate-limited and bounded.

Self-contained pipeline stage: reads NABLUS_TARGET / NABLUS_SEEDS, writes nuclei_findings.json.
"""
from __future__ import annotations  # noqa
import os, json, subprocess, tempfile, pathlib

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
OUT = r"C:\Users\Laith\nabulus-agent\nuclei_findings.json"
WORKDIR = os.path.dirname(os.path.abspath(__file__))

NUCLEI_BIN = os.environ.get("NABLUS_NUCLEI_BIN",
                            r"C:\Users\Laith\nabulus-tools\bin\nuclei.exe")
TEMPLATES = os.environ.get("NABLUS_NUCLEI_TEMPLATES", r"C:\Users\Laith\nuclei-templates")
SEVERITY = os.environ.get("NABLUS_NUCLEI_SEVERITY", "low,medium,high,critical")
TAGS = os.environ.get("NABLUS_NUCLEI_TAGS", "").strip()          # empty = all templates
NO_OOB = os.environ.get("NABLUS_NUCLEI_NO_OOB", "").strip() in ("1", "true", "yes")
RATE = os.environ.get("NABLUS_NUCLEI_RATE", "150")
CONC = os.environ.get("NABLUS_NUCLEI_CONC", "25")
# per-run wall clock cap (s); nuclei's own -timeout is per-request
RUN_TIMEOUT = int(os.environ.get("NABLUS_NUCLEI_RUN_TIMEOUT", "1500"))


def classify(template_id: str, tags, template_path: str, severity: str) -> str:
    """Coarse, human-readable class; the exact template id is kept in proof/template."""
    tid = (template_id or "").upper()
    tagset = set()
    if isinstance(tags, str):
        tagset = {t.strip().lower() for t in tags.split(",") if t.strip()}
    elif isinstance(tags, (list, tuple)):
        tagset = {str(t).strip().lower() for t in tags}
    tp = (template_path or "").replace("\\", "/").lower()
    if tid.startswith("CVE-") or "cve" in tagset:
        return template_id                      # the CVE id itself is the most useful class
    if "takeover" in tagset or "takeover" in tp:
        return "subdomain-takeover"
    if tagset & {"exposure", "exposures", "files", "backup", "config", "disclosure"} or "/exposures/" in tp:
        return "exposure"
    if "default-login" in tagset or tagset & {"default", "creds"}:
        return "default-login"
    if tagset & {"misconfig", "misconfiguration"} or "/misconfiguration/" in tp:
        return "misconfig"
    if "ssrf" in tagset:
        return "ssrf"
    if "injection" in tagset or "sqli" in tagset:
        return "injection"
    if "xss" in tagset:
        return "xss"
    return "nuclei-" + (severity or "unknown")


def run_nuclei(targets):
    _fd, _tp = tempfile.mkstemp(suffix=".txt", dir=WORKDIR, prefix="nuclei_tgt_")
    os.close(_fd)                       # close the OS fd or Windows won't let us unlink it later
    tf = pathlib.Path(_tp)
    tf.write_text("\n".join(targets) + "\n", encoding="utf-8")
    argv = [
        NUCLEI_BIN,
        "-l", str(tf),
        "-jsonl",                 # structured output on stdout
        "-silent",                # suppress banner/progress (logs still go to stderr)
        "-no-color",
        "-disable-update-check",
        "-irr",                   # include request/response -> gives curl-command for proof
        "-severity", SEVERITY,
        "-timeout", "10",
        "-retries", "1",
        "-rate-limit", RATE,
        "-concurrency", CONC,
        # stay on-scope: default behaviour does not chase redirects off the given targets
    ]
    # templates dir (fall back to nuclei's own config dir if ours is absent)
    if TEMPLATES and pathlib.Path(TEMPLATES).exists():
        argv += ["-t", TEMPLATES]
    if TAGS:
        argv += ["-tags", TAGS]
    if NO_OOB:
        argv += ["-ni"]           # disable interactsh (blind templates become non-firing)
    try:
        proc = subprocess.run(argv, cwd=WORKDIR, capture_output=True, text=True,
                              timeout=RUN_TIMEOUT)
    except FileNotFoundError:
        print(f"[nuclei] binary not found: {NUCLEI_BIN} -> no scan")
        tf.unlink(missing_ok=True)
        return []
    except subprocess.TimeoutExpired as e:
        print(f"[nuclei] run hit {RUN_TIMEOUT}s cap; parsing partial output")
        out = e.stdout or ""
        tf.unlink(missing_ok=True)
        return out.splitlines() if isinstance(out, str) else []
    tf.unlink(missing_ok=True)
    if proc.stderr:
        tail = proc.stderr.strip().splitlines()[-2:]
        if tail:
            print("[nuclei] " + " | ".join(tail))
    return proc.stdout.splitlines()


def parse(lines):
    findings, seen = [], set()
    for ln in lines:
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            r = json.loads(ln)
        except Exception:
            continue
        info = r.get("info") or {}
        tid = r.get("template-id") or r.get("templateID") or ""
        matched = r.get("matched-at") or r.get("host") or ""
        key = (tid, matched)
        if key in seen:
            continue
        seen.add(key)
        sev = (info.get("severity") or "unknown").lower()
        cls = classify(tid, info.get("tags"), r.get("template-path") or r.get("template"), sev)
        extracted = r.get("extracted-results") or []
        matcher = r.get("matcher-name") or ""
        name = info.get("name") or tid
        proof = f"{name}"
        if matcher:
            proof += f" [matcher={matcher}]"
        if extracted:
            proof += f" extracted={extracted[:3]}"
        findings.append({
            "class": cls,
            "severity": sev,
            "endpoint": matched,
            "param": None,
            "identity": "anon",
            "template": tid,
            "proof": proof,
            "proof_request": r.get("curl-command") or r.get("request") or "",
            "validated_by": f"nuclei template {tid} matcher fired",
            "confirmed": True,
        })
    return findings


def main():
    targets = [BASE] + SEEDS
    lines = run_nuclei(targets)
    findings = parse(lines)
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    bysev = {}
    for f in findings:
        bysev[f["severity"]] = bysev.get(f["severity"], 0) + 1
    print(f"[nuclei] {len(findings)} confirmed finding(s) over {len(targets)} target(s): {bysev}")
    for f in findings[:15]:
        print(f"  [{f['severity']:8}] {f['class']:22} {f['endpoint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
