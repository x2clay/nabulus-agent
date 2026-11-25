#!/usr/bin/env python3
"""nabulus-agent triage: turn findings.json into a human-readable prioritized report.

  * Reads findings.json (latest result by default).
  * Builds a plain security-assessment prompt (no euphemism, no exploit/exfil framing).
  * Calls DeepSeek for the writeup (key from DEEPSEEK_API_KEY). --mock skips the network call.
  * Does NOT execute any tools. Proposed next steps are written to proposed_actions.json as a
    review list (status=pending_review); a human approves, and approved runs still go through
    the scope-gated gateway, which re-checks authorization before executing.
"""
from __future__ import annotations
import os, sys, json, argparse, pathlib, urllib.request

HERE  = pathlib.Path(__file__).resolve().parent
AGENT = HERE.parent

SYSTEM = ("You are a security assessment assistant. You receive scan findings for an "
          "ENGAGEMENT THE OPERATOR IS AUTHORIZED TO TEST. Produce a concise, factual, "
          "defensive remediation report: for each finding give severity, what it means, and "
          "how the asset owner should fix or verify it. Do not provide exploitation steps. If "
          "you suggest further scans, list them as reviewable proposals within authorized scope only.")

def load_findings(path):
    data = json.loads(pathlib.Path(path).read_text())
    if isinstance(data, list):
        return data[-1] if data else {}
    return data

def build_prompt(entry):
    lines = [f"Target: {entry.get('target','?')}",
             f"Asset type: {entry.get('asset_type','?')}",
             f"Program: {entry.get('program','?')}",
             f"Authorization ref present: {bool(entry.get('authorization_ref'))}",
             "", "Surface (only in-scope assets are actively scanned):"]
    for s in entry.get("surface", [])[:50]:
        lines.append(f"  - [{s.get('kind')}] {s.get('value')} in_scope={s.get('in_scope')}")
    lines += ["", "Findings:"]
    for f in entry.get("findings", []):
        lines.append(f"  - [{f.get('severity')}/{f.get('type')}] {f.get('tool')}: {f.get('evidence')}")
    lines += ["", "Write the prioritized remediation report. Then propose any follow-up SCANS "
              "(tool + target) strictly within the authorized scope, as a review list."]
    return "\n".join(lines)

def call_deepseek(prompt):
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        raise RuntimeError("DEEPSEEK_API_KEY not set")
    payload = json.dumps({"model":"deepseek-chat",
        "messages":[{"role":"system","content":SYSTEM},{"role":"user","content":prompt}],
        "temperature":0.2,"stream":False}).encode()
    req = urllib.request.Request("https://api.deepseek.com/chat/completions", data=payload,
        headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"]

def mock_report(entry):
    t = entry.get("target","?")
    finds = entry.get("findings", [])
    ports = [s["value"] for s in entry.get("surface",[]) if s.get("kind")=="port" and s.get("in_scope")]
    out = [f"# Assessment report — {t} (MOCK)", "",
           f"Scope program: {entry.get('program','?')}  |  authorization on file: {bool(entry.get('authorization_ref'))}",
           "", "## Prioritized observations"]
    if not finds:
        out.append("- No confirmed findings this cycle; surface mapped only.")
    for f in finds:
        out.append(f"- **{f.get('severity','info').upper()}** ({f.get('tool')}): {f.get('evidence')}")
        out.append(f"    Remediation: confirm this service is intended to be exposed; patch/restrict as appropriate.")
    out += ["", "## Exposed ports (in-scope)", "  " + (", ".join(ports) or "none"),
            "", "## Notes",
            "- Out-of-scope hosts found during recon were recorded but NOT scanned.",
            "- Follow-up scans below are PROPOSALS for human review; none run automatically."]
    return "\n".join(out)

def mock_proposals(entry):
    t = entry.get("target","?")
    return [{"tool":"nuclei","args":["-u",t,"-severity","medium,high,critical"],"target":t,
             "rationale":"Template-based vuln check on the authorized host; medium+ severity only.",
             "status":"pending_review"}]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default=str(AGENT/"findings.json"))
    ap.add_argument("--mock", action="store_true", help="no network call; deterministic sample output")
    ap.add_argument("--out", default=str(HERE/"triage_report.md"))
    ap.add_argument("--proposals", default=str(HERE/"proposed_actions.json"))
    a = ap.parse_args()

    entry = load_findings(a.findings)
    prompt = build_prompt(entry)
    print("===== PROMPT SENT TO MODEL =====\n" + prompt + "\n================================\n")

    if a.mock or not os.environ.get("DEEPSEEK_API_KEY"):
        mode, report, proposals = "MOCK", mock_report(entry), mock_proposals(entry)
    else:
        mode, report, proposals = "LIVE (DeepSeek)", call_deepseek(prompt), []

    pathlib.Path(a.out).write_text(report, encoding="utf-8")
    pathlib.Path(a.proposals).write_text(json.dumps(proposals, indent=2), encoding="utf-8")

    print(f"===== REPORT ({mode}) -> {a.out} =====\n{report}")
    print(f"\n===== PROPOSED ACTIONS (review only) -> {a.proposals} =====\n{json.dumps(proposals, indent=2)}")
    print("\nNote: proposals do NOT auto-run. Approved items must be POSTed to the scope-gated "
          "gateway, which re-checks authorization before executing. In LIVE mode, findings are "
          "sent to DeepSeek (external) — only run that against data you're cleared to share.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
