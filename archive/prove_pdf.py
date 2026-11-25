"""Run extractor.prove on the unauthenticated PDF lead. Prints a short result, never the API key."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
import zlib
from pathlib import Path

AGENT = Path(r"C:\Users\Laith\nabulus-agent")
sys.path.insert(0, str(AGENT))
os.chdir(AGENT)

import autonomous  # noqa: E402
import proof_loop as extractor  # noqa: E402

URL = "https://www.quantnq.com/papers/six-book-portfolio.pdf"


def pdf_text(data: bytes) -> str:
    chunks: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        raw = match.group(1).strip(b"\r\n")
        variants = [raw]
        for attempt in (lambda b: zlib.decompress(b), lambda b: zlib.decompress(b, -15)):
            try:
                variants.append(attempt(raw))
            except Exception:
                pass
        for blob in variants:
            for literal in re.findall(rb"\((?:\\.|[^\\)]){4,}\)", blob):
                body = literal[1:-1]
                body = re.sub(
                    rb"\\([nrtbf()\\])",
                    lambda m: {
                        b"n": b"\n",
                        b"r": b"\r",
                        b"t": b"\t",
                        b"b": b"\b",
                        b"f": b"\f",
                        b"(": b"(",
                        b")": b")",
                        b"\\": b"\\",
                    }.get(m.group(1), m.group(1)),
                    body,
                )
                chunks.append(body.decode("latin1", errors="ignore"))
            for hexed in re.findall(rb"<([0-9A-Fa-f\s]{8,})>", blob):
                compact = re.sub(rb"\s+", b"", hexed)
                if len(compact) % 2:
                    continue
                try:
                    rawb = bytes.fromhex(compact.decode())
                except ValueError:
                    continue
                chunks.append(rawb.decode("utf-16-be", errors="ignore"))
    text = "\n".join(chunks)
    text = re.sub(r"[^\x09\x0a\x0d\x20-\x7e]+", " ", text)
    text = re.sub(r"[ ]{2,}", " ", text).strip()
    return text[:7000]


def fetch_anon(url: str) -> tuple[int, str, int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "nabulus-prove", "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=40) as resp:
        data = resp.read()
        status = getattr(resp, "status", 200)
        ctype = resp.headers.get("Content-Type", "")
    text = pdf_text(data) if data.startswith(b"%PDF") or "pdf" in ctype.lower() else ""
    return status, ctype, len(data), text


def execute(commands: list) -> list[dict]:
    ran = []
    assets = execute.assets
    raw = execute.raw
    for command in commands:
        if not isinstance(command, dict):
            continue
        args = [str(a) for a in command.get("args") or []]
        blob = " ".join(args)
        out = autonomous.guarded(command, assets, raw)
        if URL.split("/", 3)[-1] in blob or ".pdf" in blob.lower():
            try:
                status, ctype, size, text = fetch_anon(URL)
                head = f"anon GET {URL}\nHTTP {status} content-type={ctype} bytes={size}\n"
                body = f"PDF_TEXT:\n{text}" if text else "PDF_TEXT:\n(no extractable text operators)\n" + (out or "")[:500]
                out = head + body
            except Exception as exc:
                out = f"{out}\n[pdf text fetch failed] {type(exc).__name__}: {exc}"
        ran.append({
            "tool": command.get("tool"),
            "args": command.get("args"),
            "output": (out or "")[:8000],
        })
        print(f"ran {command.get('tool')} chars={len(out or '')}", flush=True)
    return ran


def main() -> int:
    autonomous.load_env(AGENT / "local.env")
    scope = autonomous.load_scope(AGENT / "scope.json")
    execute.assets = scope["_assets"]
    execute.raw = AGENT / "raw"
    print(f"deepseek={extractor.enabled()} model={os.environ.get('DEEPSEEK_MODEL', 'default')}", flush=True)
    lead = {
        "program": scope.get("program"),
        "authorization_ref": scope.get("authorization_ref"),
        "authorized_assets": sorted(scope["_assets"]),
        "lead": {
            "tool": "curl",
            "severity": "high",
            "matched": URL,
            "evidence": (
                "Unauthenticated GET of this PDF returned HTTP 200 application/pdf, about 200000 bytes. "
                "It is supposed to be paywalled. Fetch it again with no cookies. "
                "Quote a sentence of the document text from the tool output. "
                "A content-type line is not enough."
            ),
        },
    }
    result = extractor.prove(lead, execute, rounds=4)
    slim = {
        "confirmed": result.get("confirmed"),
        "extracted": result.get("extracted"),
        "reason": result.get("reason"),
        "skipped": result.get("skipped"),
        "statuses": [],
    }
    for row in result.get("rounds") or []:
        decision = row.get("decision") or row.get("verdict")
        if isinstance(decision, dict):
            slim["statuses"].append({
                "status": decision.get("status"),
                "what": (decision.get("what_to_prove") or "")[:240],
                "extracted": (decision.get("extracted") or "")[:300],
                "tools": [c.get("tool") for c in (decision.get("commands") or []) if isinstance(c, dict)],
            })
    dest = AGENT / "prove_pdf_result.json"
    dest.write_text(json.dumps(slim, indent=2), encoding="utf-8")
    print(json.dumps(slim, indent=2), flush=True)
    return 0 if result.get("confirmed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
