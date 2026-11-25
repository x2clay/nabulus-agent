#!/usr/bin/env python3
r"""report_builder.py - submittable report + CVSS from confirmed findings.

ADDITIVE and READ-ONLY. Reads the reconciled detector output (nablus_report.json by default) and
emits a submission-ready report: per-finding title, CVSS v3.1 vector + base score + severity,
affected endpoint/param, evidence, reproduction, impact, and remediation. Writes submission_report.md
and submission_report.json.

DOES NOT TOUCH the DeepSeek flow: it never reads or writes findings.json / schema.json / the
extractor/confirm prompts. It only consumes the black-box reconciled report (class/endpoint/param/
proof/validated_by/confirmed) and produces a NEW, separate artifact. CVSS is computed with the
official CVSS v3.1 base formula (deterministic, no LLM) from a per-class default base vector that a
human can adjust per target.

  py -3 report_builder.py                       # range: nablus_report.json -> submission_report.*
  py -3 report_builder.py --in quantnq_report_reconciled.json --out-md q.md --out-json q.json
"""
from __future__ import annotations  # noqa
import os, sys, json, math, argparse, datetime, pathlib

HERE = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))

# ---- CVSS v3.1 base-score engine (official formula) -----------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}          # scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}           # scope Changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss_base(vector: str):
    """vector like 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N' -> (score, severity)."""
    m = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
    scope_changed = m.get("S", "U") == "C"
    pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
    iss = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + expl), 10))
    else:
        score = _roundup(min(impact + expl, 10))
    return score, severity_band(score)


def severity_band(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ---- per-class profiles: default base vector + title/impact/remediation ----------------------
PROFILES = {
    "ssrf": ("Server-Side Request Forgery", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
             "The server fetches an attacker-supplied URL, enabling access to internal services, "
             "cloud metadata, and the internal network from the server's trust position.",
             "Enforce an allowlist of permitted hosts/schemes; resolve and validate the destination "
             "before fetching; block link-local/internal ranges; disable unused URL schemes."),
    "unauth-exposure": ("Unauthenticated Exposure of Sensitive Resource", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
             "A sensitive file/endpoint is reachable with no authentication, disclosing secrets or data.",
             "Require authentication/authorization; remove the artifact from the web root; rotate any "
             "exposed secrets."),
    "exposure": ("Exposed Sensitive File", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
             "A sensitive file is served publicly, disclosing credentials or internal data.",
             "Remove from web root, restrict access, rotate exposed secrets."),
    "cors": ("CORS Misconfiguration (credentialed cross-origin read)", "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
             "The app reflects arbitrary origins with credentials, letting a malicious site read "
             "authenticated responses on behalf of a victim.",
             "Reflect only an explicit allowlist of trusted origins; never combine "
             "Access-Control-Allow-Credentials:true with a reflected/`*` origin."),
    "authbypass": ("Authentication/Authorization Bypass", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
             "An access-control check is bypassable (e.g. trusted header spoofing), granting anonymous "
             "access to a gated resource.",
             "Do not trust client-supplied headers (X-Forwarded-For, etc.) for authz; enforce access "
             "control server-side on every request."),
    "open-redirect": ("Open Redirect", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
             "A redirect parameter sends users to an attacker-controlled host, aiding phishing and "
             "OAuth token theft.",
             "Allowlist redirect targets or use relative paths only; reject absolute external URLs."),
    "subdomain-takeover": ("Subdomain Takeover", "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
             "A dangling DNS record points to an unclaimed third-party service an attacker can claim, "
             "serving content on the victim's subdomain.",
             "Remove the dangling DNS record or reclaim the backing resource; audit DNS for other "
             "dangling records."),
    "idor": ("Insecure Direct Object Reference / Broken Object-Level Authorization",
             "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
             "An object identifier can be manipulated to read another user's data.",
             "Enforce per-object ownership checks server-side; use unguessable identifiers as defense "
             "in depth."),
    "sqli": ("SQL Injection", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "User input reaches a SQL query unparameterized, allowing data theft or modification.",
             "Use parameterized queries / prepared statements; validate input; least-privilege DB user."),
    "xss": ("Reflected Cross-Site Scripting", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
             "Unsanitized input is reflected into the page and executes in the victim's browser.",
             "Context-aware output encoding; Content-Security-Policy; validate/sanitize input."),
    "business-logic": ("Business-Logic Flaw", "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
             "A transaction/workflow can be tampered to an unintended, advantageous state.",
             "Enforce invariants server-side; re-validate price/quantity/state transitions."),
    "bulk": ("Bulk Sensitive-Data Disclosure", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
             "An endpoint returns sensitive records in bulk beyond the caller's entitlement.",
             "Enforce authorization and pagination/row-level scoping on data endpoints."),
    "misconfig": ("Security Misconfiguration", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
             "A misconfiguration weakens the security posture of the asset.",
             "Apply hardening guidance for the affected component."),
}
_NUCLEI_SEV_VECTOR = {   # fallback vectors for scanner findings carrying only a severity word
    "critical": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "high": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "medium": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "low": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
}


def profile_for(f):
    cls = (f.get("class") or "").lower()
    if cls in PROFILES:
        return PROFILES[cls]
    # scanner/nuclei or CVE class: title from class, vector from severity
    sev = (f.get("severity") or "medium").lower()
    vec = _NUCLEI_SEV_VECTOR.get(sev, _NUCLEI_SEV_VECTOR["medium"])
    title = f.get("class") if cls.startswith("cve-") else (f.get("class") or "Finding").replace("-", " ").title()
    return (title, vec, f.get("detail") or "See evidence.",
            "Review the referenced advisory/template and apply the vendor remediation.")


def _synth_repro(f):
    ep = f.get("endpoint") or ""
    if not ep:
        return ""
    p = f.get("param")
    return f'curl -sik "{ep}?{p}=FUZZ"' if p else f'curl -sik "{ep}"'


def build(report):
    items = []
    for f in report:
        if not f.get("confirmed"):
            continue
        title, vector, impact, remediation = profile_for(f)
        score, band = cvss_base(vector)
        repro = f.get("proof_request") or f.get("validated_by") or _synth_repro(f)
        items.append({
            "title": title,
            "class": f.get("class"),
            "stream": f.get("stream"),
            "cvss_v31": {"vector": f"CVSS:3.1/{vector}", "base_score": score, "severity": band},
            "endpoint": f.get("endpoint"),
            "param": f.get("param"),
            "evidence": f.get("detail") or f.get("proof"),
            "reproduction": repro,
            "impact": impact,
            "remediation": remediation,
        })
    items.sort(key=lambda x: x["cvss_v31"]["base_score"], reverse=True)
    return items


def to_md(items, src):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    out = [f"# Security Assessment - Submittable Report", "",
           f"_Generated {now} from `{src}` | {len(items)} confirmed finding(s)_", "",
           "Each finding below was reproduced by a deterministic oracle (confirmed). CVSS v3.1 base "
           "vectors are per-class defaults - adjust to the target's real context before submission.", ""]
    for i, it in enumerate(items, 1):
        c = it["cvss_v31"]
        out += [f"## {i}. {it['title']} - {c['severity']} ({c['base_score']})", "",
                f"- **Class:** `{it['class']}`" + (f" | _{it['stream']}_" if it.get("stream") else ""),
                f"- **CVSS v3.1:** `{c['vector']}` -> **{c['base_score']} {c['severity']}**",
                f"- **Affected:** `{it['endpoint']}`" + (f" (param `{it['param']}`)" if it.get("param") else ""),
                f"- **Evidence:** {it['evidence']}",
                f"- **Reproduction:** `{it['reproduction']}`",
                f"- **Impact:** {it['impact']}",
                f"- **Remediation:** {it['remediation']}", ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="nablus_report.json")
    ap.add_argument("--out-md", default="submission_report.md")
    ap.add_argument("--out-json", default="submission_report.json")
    a = ap.parse_args()
    src = HERE / a.inp
    if not src.exists():
        print(f"[report] input not found: {src}"); return 1
    report = json.loads(src.read_text(encoding="utf-8"))
    items = build(report)
    (HERE / a.out_json).write_text(json.dumps({"source": a.inp, "count": len(items),
                                   "findings": items}, indent=2), encoding="utf-8")
    (HERE / a.out_md).write_text(to_md(items, a.inp), encoding="utf-8")
    print(f"[report] {len(items)} confirmed finding(s) -> {a.out_md} + {a.out_json}")
    for it in items:
        c = it["cvss_v31"]
        print(f"  {c['base_score']:>4} {c['severity']:8} {it['class']:20} {it['endpoint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
