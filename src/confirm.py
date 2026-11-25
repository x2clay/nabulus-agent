"""Free, model-free confirmation of bench leads.

No DeepSeek, no local LLM, no cloud credits. A lead goes in; we run a
deterministic tool and return the SAME shape proof_loop.prove returns, so the
prove loop in autonomous.py can treat a free confirm and a paid one
identically.

Each path runs a real, independent re-check -- not the probe that first
raised the lead:
  - injection -> sqlmap --batch on the URL; confirmed only when sqlmap itself
                 reports the parameter injectable.
  - traversal -> curl the exact URL again; confirmed only when OS file
                 markers survive this independent re-fetch.
  - xss       -> dalfox only ever emits on a verified reflected POC, so a
                 dalfox lead is passed through confirmed.
Anything else is left unconfirmed for the opt-in DeepSeek pass.

The sqlmap verdict regex is duplicated from autonomous.interesting() on
purpose: importing autonomous here would be a circular import, and the gate
is one line we want to keep identical on both sides.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import probes
import surface

# Same gate autonomous.interesting() uses for a sqlmap run. "resumed ... from
# stored session" covers a repeat run that hits sqlmap's session cache instead
# of re-emitting "identified"/"is vulnerable".
_SQLMAP_HIT = re.compile(r"is vulnerable|(identified|resumed) the following injection point", re.I)
_SQLMAP_NEG = re.compile(r"not injectable|do not appear to be injectable", re.I)

# A URL whose query carries an injection probe (quote, boolean, comment).
_INJECT_HINT = re.compile(r"[?&][^=&]+=[^&]*('|%27|\bAND\b|\bOR\b|1=1|1=2|--|%2d%2d|#)", re.I)
# A URL whose query carries a traversal / file-read probe.
_TRAVERSAL_HINT = re.compile(r"\.\.(/|\\|%2f|%5c)|win\.ini|boot\.ini|/etc/passwd|%00|php://|file://", re.I)

_MARKERS = ("[fonts]", "[extensions]", "[mci extensions]",
            "for 16-bit app support", "[boot loader]",
            "root:x:0:0", "daemon:x:")


def _result(confirmed: bool, extracted: str, response: list, reason: str) -> dict:
    """Shape matches proof_loop.prove so callers need no branching."""
    return {
        "confirmed": confirmed,
        "extracted": extracted or "",
        "response": response or [],
        "reason": reason,
        "free": True,
    }


def _url_of(item: dict) -> str:
    url = (item.get("matched") or "").strip()
    if url.startswith("http"):
        return url
    match = re.search(r"https?://\S+", item.get("evidence") or "")
    return match.group(0) if match else ""


def _status_of(item: dict) -> int:
    match = re.search(r"status=(\d+)", item.get("evidence") or "")
    return int(match.group(1)) if match else 0


def _marker_span(body: str) -> str:
    low = body.lower()
    for needle in _MARKERS:
        idx = low.find(needle)
        if idx >= 0:
            return body[idx:idx + 200]
    return body[:200]


def _joined(rows: list) -> str:
    return "\n".join(str(row.get("output") or "") for row in rows if isinstance(row, dict))


# Cut a query value at the first injection artifact so sqlmap gets a clean,
# dynamic baseline instead of the quote/boolean payload that first threw the
# 500. An empty or 0 value is nudged to 1 so sqlmap does not read the param as
# static (a 0/empty row often renders the same page as the baseline).
_PAYLOAD_CUT = re.compile(r"""['"<>;)]|\s|%27|%22|%00|\bAND\b|\bOR\b|--|#|/\*""", re.I)


def _clean_seed(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.query:
        return url
    pairs = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        clean = _PAYLOAD_CUT.split(value, 1)[0]
        if clean in ("", "0"):
            clean = "1"
        pairs.append((key, clean))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def confirm(item: dict, execute) -> dict:
    """execute(commands) -> list of {tool, args, output}; scope-guarded upstream."""
    tool = item.get("tool")
    url = _url_of(item)
    status = _status_of(item)
    evidence = item.get("evidence") or ""

    # dalfox emits only on a verified reflected-XSS POC.
    if tool == "dalfox":
        return _result(True, evidence[:400], [], "dalfox verified reflected xss")
    # A sqlmap lead already means sqlmap found the param injectable.
    if tool == "sqlmap":
        return _result(True, evidence[-800:], [], "sqlmap injectable")

    # Reflected-XSS lead from the deterministic probe battery. Re-send the
    # canary URL through the scope-guarded fetch (curl) and require the
    # unescaped break-out to survive on this independent request. No dalfox,
    # no model. Must be checked BEFORE the injection branch because the XSS
    # payload's quote would otherwise trip the sqlmap path.
    if evidence.startswith("suspect-xss"):
        if not url or "__form=" in url:
            return _result(False, "", [], "form-based xss not auto-confirmable yet")
        rows = execute([{"tool": "curl", "args": [url]}])
        body = _joined(rows).lower().encode("utf-8", "replace")
        if probes._XSS_RAW in body:
            return _result(True, "reflected unescaped: " + probes.XSS_CANARY, rows, "xss canary reflected unescaped on re-fetch")
        return _result(False, "", rows, "xss canary not reflected on re-fetch")

    if not url:
        return _result(False, "", [], "no url in lead")

    # Traversal / file disclosure: re-fetch and confirm markers persist.
    traversal = bool(_TRAVERSAL_HINT.search(url)) or (status == 200 and tool == "emptyjar" and not _INJECT_HINT.search(url))
    if traversal:
        rows = execute([{"tool": "curl", "args": [url]}])
        body = _joined(rows)
        if surface._file_markers(body.encode("utf-8", "replace")):
            return _result(True, _marker_span(body), rows, "file markers survive independent re-fetch")
        return _result(False, "", rows, "no file markers on re-fetch")

    # Injection: let sqlmap decide. No --smart -- the param is already a lead,
    # so its basic heuristic must never let sqlmap skip it.
    if status >= 500 or _INJECT_HINT.search(url) or tool in {"curl", "emptyjar", "arjun"}:
        rows = execute([{
            "tool": "sqlmap",
            "args": ["-u", _clean_seed(url), "--batch", "--level", "2", "--risk", "2", "--threads", "8"],
        }])
        out = _joined(rows)
        if _SQLMAP_HIT.search(out) and not _SQLMAP_NEG.search(out):
            return _result(True, out[-800:], rows, "sqlmap confirms injectable")
        return _result(False, "", rows, "sqlmap did not confirm")

    return _result(False, "", [], "lead shape not auto-confirmable")
