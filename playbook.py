"""One published skill at a time, turned into empty-jar HTTP requests.

Skill text is copied from usestrix/strix (Apache-2.0):
frameworks/nextjs.md, vulnerabilities/authentication_jwt.md, vulnerabilities/idor.md.
The Strix CLI is not used.

DeepSeek reads a single skill file and returns concrete requests.
autonomous.py executes them after the shape catalog. A skill that returns
no data is finished. The local 14B is not given these files.
"""
from __future__ import annotations

import json
import pathlib

import extractor

ROOT = pathlib.Path(__file__).resolve().parent / "skills"
GENERIC = (
    "The host is an ordinary web application. Do not assume a framework. "
    "Use only the recorded calls and the routes in the user message. "
    "Propose HTTP requests the catalog did not already send."
)


def fingerprint(scripts: list[str], sample: str = "", headers: dict | None = None) -> str:
    """Stack name from scripts and response text. Empty of any host-specific route."""
    parts = [sample or ""]
    parts.extend(scripts or [])
    for key, value in (headers or {}).items():
        parts.append(f"{key}:{value}")
    blob = " ".join(parts).lower()
    if any(bit in blob for bit in ("/_next/", "__next_data__", "__next_f", "next.js")):
        return "next"
    if any(bit in blob for bit in ("wp-content", "wp-includes")):
        return "wordpress"
    if any(bit in blob for bit in ("csrfmiddlewaretoken", "django")):
        return "django"
    return "generic"


def chosen(stack: str) -> str:
    """One playbook for this stack. Next.js is not the default."""
    if stack == "next":
        return "nextjs"
    return "generic"

INSTRUCTION = (
    "Apply the playbook below to the host in the user message. "
    "Reply with one JSON object and nothing else: "
    '{"requests":[{"method":"GET","url":"https://host/path","headers":{},"body":""}]}. '
    "At most 8 requests. Every url stays on that host. "
    "Send no Cookie header. Do not invent an account, password, or session. "
    "Do not name a scanner. You cannot open a browser. "
    "The catalog already sent GET, POST, PUT, PATCH, DELETE, and OPTIONS "
    "with an empty JSON body and Authorization: Bearer null, and no cookie. "
    "Propose only requests the playbook still calls for. "
    'If nothing else is worth sending, return {"requests":[]}.'
)


def text_for(name: str) -> str:
    if name == "generic":
        return GENERIC
    path = ROOT / f"{name}.md"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def ask(name: str, skill: str, summary: str, call=None) -> str:
    """Return the model text. call(messages) is the test double."""
    if not skill:
        return ""
    messages = [
        {"role": "system", "content": INSTRUCTION + "\n\nPlaybook " + name + ":\n\n" + skill},
        {"role": "user", "content": summary[:12000]},
    ]
    try:
        if call is not None:
            raw = call(messages)
            return raw if isinstance(raw, str) else json.dumps(raw)
        if not extractor.enabled():
            print(f"skill {name} skipped no deepseek", flush=True)
            return ""
        return json.dumps(extractor._ask(messages))
    except Exception as exc:
        print(f"skill {name} error {type(exc).__name__}", flush=True)
        return ""
