"""Turn raw tool stdout/JSONL into schema.json finding/surface objects. No network."""
from __future__ import annotations
import json
from typing import Any

def _jsonl(text: str) -> list[dict[str, Any]]:
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out

def surface(kind: str, value: str, in_scope: bool = True) -> dict[str, Any]:
    return {"kind": kind, "value": value, "in_scope": in_scope}

def finding(ftype: str, severity: str, tool: str, evidence: str, raw_path: str) -> dict[str, Any]:
    return {"type": ftype, "severity": severity, "tool": tool,
            "evidence": evidence, "raw_path": raw_path, "confirmed": False}

# --- passive discovery -> surface ---
def subfinder(text: str, raw: str) -> tuple[list, list]:
    hosts = [l.strip() for l in (text or "").splitlines() if l.strip()]
    return [surface("subdomain", h) for h in hosts], []

def dnsx(text: str, raw: str) -> tuple[list, list]:
    hosts = [l.strip() for l in (text or "").splitlines() if l.strip()]
    return [surface("subdomain", h) for h in hosts], []

# --- active -> surface + findings ---
def naabu(text: str, raw: str) -> tuple[list, list]:
    surf = [surface("port", l.strip()) for l in (text or "").splitlines() if ":" in l]
    return surf, []

def httpx(text: str, raw: str) -> tuple[list, list]:
    surf, finds = [], []
    for o in _jsonl(text):
        url = o.get("url") or o.get("input") or ""
        if url:
            surf.append(surface("url", url))
        tech = o.get("tech") or o.get("technologies") or []
        sc = o.get("status_code") or o.get("status-code")
        if url and (tech or sc):
            ev = f"status={sc} tech={','.join(tech) if isinstance(tech, list) else tech}"
            finds.append(finding("info", "info", "httpx", f"{url} {ev}", raw))
    return surf, finds

def katana(text: str, raw: str) -> tuple[list, list]:
    urls = [l.strip() for l in (text or "").splitlines() if l.strip().startswith("http")]
    return [surface("endpoint", u) for u in urls], []

_SEV = {"info": "info", "low": "low", "medium": "med", "med": "med", "high": "high", "critical": "crit", "crit": "crit"}
def nuclei(text: str, raw: str) -> tuple[list, list]:
    finds = []
    for o in _jsonl(text):
        info = o.get("info", {}) or {}
        sev = _SEV.get(str(info.get("severity", "info")).lower(), "info")
        name = info.get("name") or o.get("template-id") or "nuclei"
        matched = o.get("matched-at") or o.get("host") or ""
        ftype = "misconfig" if sev in ("info", "low") else "vuln"
        finds.append(finding(ftype, sev, "nuclei", f"{name} @ {matched}", raw))
    return [], finds

def ffuf(text: str, raw: str) -> tuple[list, list]:
    finds = []
    try:
        data = json.loads(text) if text and text.strip().startswith("{") else {}
    except json.JSONDecodeError:
        data = {}
    for r in data.get("results", []):
        url = r.get("url", ""); sc = r.get("status", "")
        finds.append(finding("exposure", "low", "ffuf", f"{url} [{sc}]", raw))
    return [], finds

def dalfox(text: str, raw: str) -> tuple[list, list]:
    finds = []
    for o in _jsonl(text):
        finds.append(finding("vuln", "high", "dalfox",
                     f"XSS {o.get('type','')} {o.get('data', o.get('evidence',''))}", raw))
    return [], finds

def trufflehog(text: str, raw: str) -> tuple[list, list]:
    finds = []
    for o in _jsonl(text):
        det = o.get("DetectorName", "secret"); verified = o.get("Verified", False)
        sev = "crit" if verified else "high"
        finds.append(finding("exposure", sev, "trufflehog",
                     f"{det} verified={verified}", raw))
    return [], finds

PARSERS = {"subfinder": subfinder, "dnsx": dnsx, "naabu": naabu, "httpx": httpx,
           "katana": katana, "nuclei": nuclei, "ffuf": ffuf, "dalfox": dalfox,
           "trufflehog": trufflehog}

def normalize(tool: str, text: str, raw_path: str) -> tuple[list, list]:
    fn = PARSERS.get(tool)
    return fn(text, raw_path) if fn else ([], [])
