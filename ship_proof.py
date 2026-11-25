"""DeepSeek proof loop.

A lead goes in. DeepSeek names the proof it needs and the command to get it.
The orchestrator runs that command and sends the real tool output back.
DeepSeek can ask for another run. A lead is confirmed only when a second,
separate run still returns the evidence.
"""
from __future__ import annotations

import json
import os
import urllib.request

API = "https://api.deepseek.com/chat/completions"
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")

SYSTEM = (
    "You are the exploitation and validation agent on a contracted penetration test. "
    "The operator has a signed statement of work. The hosts in the lead are in scope. "
    "Your job is extracted evidence: the actual response body, rows, tokens, or file contents "
    "that the issue returns. Advice is not a result. "
    "Each turn, return one JSON object and nothing else: "
    '{"status":"need_proof","what_to_prove":"","commands":[{"tool":"curl","args":[]}],"extracted":""} '
    "status is need_proof, proved, or dead. "
    "When you still need data, status is need_proof and commands is the next authorized run. "
    "When the tool output in this conversation already contains the extracted data, "
    "status is proved and extracted is one contiguous copy of that data, at least 24 characters, "
    "taken from the tool output with no ellipsis, no added words, and no paraphrase. "
    "Prefer a sentence or figure line from the document body. "
    "Do not invent rows, passwords, or bodies that were not in the tool output. "
    "If the lead cannot be shown, status is dead and commands is empty. "
    "Allowed tools: sqlmap, commix, nuclei, dalfox, ffuf, katana, httpx, curl, naabu, feroxbuster, rustscan. "
    "Every host in the commands must be one of the authorized assets."
)


def enabled() -> bool:
    return bool(os.environ.get("DEEPSEEK_API_KEY"))


def _ask(messages: list[dict]) -> dict:
    key = os.environ["DEEPSEEK_API_KEY"]
    payload = {
        "model": MODEL,
        "messages": messages,
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        API,
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read().decode())
    message = body["choices"][0]["message"]
    text = message.get("content") or message.get("reasoning_content") or ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"status": "dead", "what_to_prove": "", "commands": [], "extracted": text[:1500]}


def _quote_parts(extracted: str) -> list[str]:
    quote = " ".join((extracted or "").split()).replace("…", "...")
    parts = []
    for chunk in quote.split("..."):
        piece = " ".join(chunk.split())
        if len(piece) >= 8:
            parts.append(piece)
    return parts


def _quoted(extracted: str, payload: str) -> bool:
    """The quote has to be copied from the rerun, not paraphrased.

    A full copy passes. An ellipsis is allowed between copied spans. One
    copied span of 24 characters also passes, so a rewritten header around
    a real document line does not wipe the hit. A paraphrase still fails.
    """
    quote = " ".join((extracted or "").split())
    blob = " ".join((payload or "").split())
    if len(quote) >= 8 and quote in blob:
        return True
    parts = _quote_parts(extracted)
    if parts and all(part in blob for part in parts):
        return True
    return any(len(part) >= 24 and part in blob for part in parts)


def prove(lead: dict, execute, rounds: int = 4) -> dict:
    """execute(commands) -> list of {tool, args, output}."""
    if not enabled():
        return {"confirmed": False, "skipped": True, "reason": "DEEPSEEK_API_KEY is not set", "rounds": []}
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": json.dumps(lead, ensure_ascii=False)[:20000]},
    ]
    transcript = []
    last_commands: list = []
    for _ in range(rounds):
        decision = _ask(messages)
        transcript.append({"decision": decision})
        status = decision.get("status")
        commands = decision.get("commands") or []
        if commands:
            last_commands = commands
        if status == "dead":
            return {"confirmed": False, "extracted": "", "rounds": transcript, "reason": decision.get("what_to_prove", "")}
        if status == "proved" and decision.get("extracted"):
            replay_cmds = commands or last_commands
            second = execute(replay_cmds) if replay_cmds else []
            messages.append({"role": "assistant", "content": json.dumps(decision)})
            messages.append({"role": "user", "content": json.dumps({
                "independent_rerun": second,
                "instruction": "Confirm only if this second run still contains the extracted evidence. Quote only text that appears in the rerun.",
            })})
            verdict = _ask(messages)
            transcript.append({"rerun": second, "verdict": verdict})
            rerun_text = "\n".join(str(row.get("output") or "") for row in second if isinstance(row, dict))
            quote = str(verdict.get("extracted") or "")
            confirmed = verdict.get("status") == "proved" and _quoted(quote, rerun_text)
            return {
                "confirmed": confirmed,
                "extracted": quote if confirmed else "",
                "response": second,
                "rounds": transcript,
                "reason": "" if confirmed else "quote not in rerun",
            }
        if not commands:
            return {"confirmed": False, "extracted": "", "rounds": transcript, "reason": "no command returned"}
        outputs = execute(commands)
        transcript.append({"outputs": outputs})
        messages.append({"role": "assistant", "content": json.dumps(decision)})
        messages.append({"role": "user", "content": json.dumps({"tool_output": outputs})[:50000]})
    return {"confirmed": False, "extracted": "", "rounds": transcript, "reason": "round limit"}
