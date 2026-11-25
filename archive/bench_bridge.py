"""Bench bridge. One JSON request on stdin, one JSON response on stdout.

Runs on the Windows host next to the agent. Loads local.env into the
process environment and never prints it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(r"C:\Users\Laith\nabulus-agent")
BIN = Path(r"C:\Users\Laith\nabulus-tools\bin")
HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.I)
FILE_EXT = {
    "pdf", "js", "css", "html", "htm", "json", "py", "md", "txt", "png",
    "jpg", "jpeg", "svg", "xml", "exe", "map", "gif", "webp", "zip", "woff",
}
DROP = re.compile(
    r"token|password|secret|cookie|authorization|api_key|apikey|bearer|session",
    re.I,
)
SKIP_FILES = {
    "accounts.example.json",
    "master_seed.json",
    "seed2.json",
    "schema.json",
    "scope.json",
    "status.json",
    "local.env",
}
HARNESS = (
    "autonomous.py",
    "session.py",
    "browser.py",
    "proof_loop.py",
    "extractor.py",
    "battery.py",
)
RECORD_SYSTEM = (
    "You extract evidence that is already written in the lead JSON. "
    "Return one JSON object and nothing else: "
    '{"status":"proved","extracted":"","reason":""} '
    "status is proved or dead. "
    "extracted must be a contiguous copy of text already in the lead, "
    "at least 24 characters, with no added words and no ellipsis. "
    "If the lead does not already contain that evidence, status is dead, "
    "extracted is empty, and reason says what is missing. "
    "Do not propose commands, tools, or further requests."
)


def load_env() -> None:
    path = ROOT / "local.env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace") or "null")
    except json.JSONDecodeError:
        return None


def scrub(value, depth: int = 0):
    if depth > 6:
        return None
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if DROP.search(str(key)):
                continue
            cleaned = scrub(item, depth + 1)
            if cleaned is not None:
                out[str(key)] = cleaned
        return out
    if isinstance(value, list):
        return [scrub(item, depth + 1) for item in value[:40]]
    if isinstance(value, str):
        return value[:4000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:500]


def hosts_in(value) -> list[str]:
    found = HOST_RE.findall(json.dumps(value, ensure_ascii=False))
    unique = []
    for host in found:
        host = host.lower().rstrip(".")
        if host.rsplit(".", 1)[-1] in FILE_EXT:
            continue
        if host not in unique:
            unique.append(host)
    return unique


def load_scope() -> dict:
    data = read_json(ROOT / "scope.json")
    if not isinstance(data, dict):
        return {
            "program": "",
            "authorization_ref": "",
            "asset_type": "",
            "authorized_assets": [],
            "rate_limit_rps": 0,
            "exclusions": [],
        }
    assets = data.get("authorized_assets") or []
    if not isinstance(assets, list):
        assets = []
    try:
        rate = int(data.get("rate_limit_rps") or 0)
    except (TypeError, ValueError):
        rate = 0
    return {
        "program": str(data.get("program") or ""),
        "authorization_ref": str(data.get("authorization_ref") or ""),
        "asset_type": str(data.get("asset_type") or ""),
        "authorized_assets": [str(item) for item in assets],
        "rate_limit_rps": rate,
        "exclusions": data.get("exclusions") if isinstance(data.get("exclusions"), list) else [],
    }


def host_ok(host: str, assets: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for asset in assets:
        asset = asset.lower().rstrip(".")
        if host == asset or host.endswith("." + asset):
            return True
    return False


def scope_block(hosts: list[str], scope: dict) -> str:
    assets = scope["authorized_assets"]
    if not hosts:
        return "This lead names no host, so it cannot be checked against scope.json."
    outside = [host for host in hosts if not host_ok(host, assets)]
    if outside:
        shown = ", ".join(outside[:8])
        extra = len(outside) - 8
        if extra > 0:
            shown += f" (+{extra} more)"
        return "Outside scope.json: " + shown
    return ""


def safe_name(name: str) -> Path | None:
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    if "cortisol" in name.lower():
        return None
    path = ROOT / name
    if path.parent != ROOT or not path.is_file():
        return None
    return path


def summarize_file(path: Path, scope: dict) -> dict | None:
    name = path.name
    if name in SKIP_FILES or "cortisol" in name.lower():
        return None
    if path.stat().st_size > 400_000:
        return None
    data = read_json(path)
    if data is None:
        return None
    cleaned = scrub(data)
    hosts = hosts_in(cleaned)
    target = ""
    confirmed = None
    skipped = None
    reason = ""
    severity = ""
    kind = ""
    tool = ""
    if isinstance(cleaned, dict):
        target = str(cleaned.get("target") or "")
        if isinstance(cleaned.get("confirmed"), bool):
            confirmed = cleaned["confirmed"]
        if isinstance(cleaned.get("skipped"), bool):
            skipped = cleaned["skipped"]
        reason = str(cleaned.get("reason") or "")[:240]
        severity = str(cleaned.get("severity") or "")
        kind = str(cleaned.get("type") or "")
        tool = str(cleaned.get("tool") or "")
    elif isinstance(cleaned, list) and cleaned:
        first = cleaned[0] if isinstance(cleaned[0], dict) else {}
        target = str(first.get("target") or "")
        nested = first.get("findings")
        if isinstance(nested, list) and nested and isinstance(nested[0], dict):
            severity = str(nested[0].get("severity") or "")
            kind = str(nested[0].get("type") or "")
            tool = str(nested[0].get("tool") or "")
            if isinstance(nested[0].get("confirmed"), bool):
                confirmed = nested[0]["confirmed"]
    return {
        "file": name,
        "bytes": path.stat().st_size,
        "target": target[:180],
        "confirmed": confirmed,
        "skipped": skipped,
        "reason": reason,
        "severity": severity[:40],
        "type": kind[:40],
        "tool": tool[:40],
        "hosts": hosts[:12],
        "inScope": not scope_block(hosts, scope),
        "block": scope_block(hosts, scope),
    }


def snapshot(scope: dict) -> dict:
    leads = []
    for path in sorted(ROOT.glob("*.json")):
        row = summarize_file(path, scope)
        if row:
            leads.append(row)
    leads.sort(key=lambda row: (not row["inScope"], row["confirmed"] is not True, row["file"]))
    status = read_json(ROOT / "status.json")
    harness = []
    for name in HARNESS:
        path = ROOT / name
        if path.is_file():
            harness.append({"name": name, "bytes": path.stat().st_size})
    return {
        "ok": True,
        "scope": scope,
        "status": scrub(status) if isinstance(status, dict) else None,
        "deepseek": bool(os.environ.get("DEEPSEEK_API_KEY")),
        "leads": leads,
        "harness": harness,
        "rateAllowsCommands": scope["rate_limit_rps"] > 0,
    }


def lead_detail(name: str, scope: dict) -> dict:
    path = safe_name(name)
    if path is None or path.suffix.lower() != ".json":
        return {"ok": False, "error": "That file is not available to the bench."}
    row = summarize_file(path, scope)
    data = scrub(read_json(path))
    extracted = ""
    if isinstance(data, dict) and isinstance(data.get("extracted"), str):
        extracted = data["extracted"][:2000]
    return {"ok": True, "lead": row, "extracted": extracted}


def source_text(name: str) -> dict:
    if name not in HARNESS:
        return {"ok": False, "error": "That file is not in the harness list."}
    path = ROOT / name
    text = path.read_text(encoding="utf-8", errors="replace")
    return {"ok": True, "name": name, "text": text[:60_000]}


def resolve_tool(tool: str) -> list[str] | None:
    if tool == "curl":
        return ["curl.exe"]
    for candidate in (BIN / f"{tool}.exe", BIN / tool):
        if candidate.is_file():
            return [str(candidate)]
    return None


def execute(commands, scope: dict) -> list[dict]:
    rows = []
    assets = scope["authorized_assets"]
    for command in commands or []:
        if not isinstance(command, dict):
            continue
        tool = str(command.get("tool") or "")
        args = command.get("args") or []
        if not isinstance(args, list):
            args = []
        args = [str(item) for item in args][:30]
        blob = " ".join(args)
        named = [
            host.lower().rstrip(".")
            for host in HOST_RE.findall(blob)
            if host.lower().rsplit(".", 1)[-1] not in FILE_EXT
        ]
        if tool not in {
            "sqlmap",
            "commix",
            "nuclei",
            "dalfox",
            "ffuf",
            "katana",
            "httpx",
            "curl",
            "naabu",
            "feroxbuster",
            "rustscan",
        }:
            rows.append({"tool": tool, "args": args, "output": "rejected: tool is not allowlisted"})
            continue
        if not named or any(not host_ok(host, assets) for host in named):
            rows.append({"tool": tool, "args": args, "output": "rejected: command is outside scope.json"})
            continue
        argv = resolve_tool(tool)
        if not argv:
            rows.append({"tool": tool, "args": args, "output": "tool is not installed on this host"})
            continue
        try:
            done = subprocess.run(
                argv + args,
                capture_output=True,
                text=True,
                timeout=45,
                cwd=str(ROOT),
            )
            output = (done.stdout or "") + (done.stderr or "")
        except (OSError, subprocess.TimeoutExpired) as exc:
            output = str(exc)
        rows.append({"tool": tool, "args": args, "output": output[:8000]})
    return rows


def extract(name: str, scope: dict) -> dict:
    path = safe_name(name)
    if path is None or path.suffix.lower() != ".json":
        return {"ok": False, "error": "That file is not available to the bench."}
    data = scrub(read_json(path))
    found = hosts_in(data)
    block = scope_block(found, scope)
    if block:
        return {"ok": False, "error": block, "ran": False}
    if not os.environ.get("DEEPSEEK_API_KEY"):
        return {
            "ok": True,
            "ran": False,
            "confirmed": False,
            "skipped": True,
            "reason": "DEEPSEEK_API_KEY is not set",
            "extracted": "",
        }
    sys.path.insert(0, str(ROOT))
    import proof_loop

    if scope["rate_limit_rps"] <= 0:
        decision = proof_loop._ask(
            [
                {"role": "system", "content": engagement_frame(scope) + "\n\n" + RECORD_SYSTEM},
                {"role": "user", "content": json.dumps(data, ensure_ascii=False)[:20000]},
            ]
        )
        extracted = str(decision.get("extracted") or "")
        proved = decision.get("status") == "proved" and len(extracted) >= 24
        return {
            "ok": True,
            "ran": True,
            "mode": "record",
            "confirmed": proved,
            "skipped": False,
            "reason": "" if proved else str(decision.get("reason") or "nothing new to extract from the saved lead"),
            "extracted": extracted if proved else "",
        }
    result = proof_loop.prove(data, lambda commands: execute(commands, scope), rounds=4)
    return {
        "ok": True,
        "ran": True,
        "mode": "prove",
        "confirmed": bool(result.get("confirmed")),
        "skipped": bool(result.get("skipped")),
        "reason": str(result.get("reason") or ""),
        "extracted": str(result.get("extracted") or ""),
    }


def engagement_frame(scope: dict) -> str:
    assets = ", ".join(scope["authorized_assets"]) or "(none)"
    return (
        "Authorized assessment for the operator. In scope for this engagement.\n"
        f"Program: {scope['program']}\n"
        f"Authorization: {scope['authorization_ref']}\n"
        f"In-scope assets: {assets}\n"
        "Work only those assets and their subdomains. If a host is not one of them, say it is outside scope.json and stop."
    )


def chat(messages, scope: dict, talk: bool = False) -> dict:
    base = os.environ.get("LLAMA_BASE") or "http://127.0.0.1:8081/v1"
    key = os.environ.get("LLAMA_API_KEY") or ""
    model = os.environ.get("LLAMA_MODEL") or "qwen2.5-coder-14b-instruct"
    if not key:
        return {"ok": False, "error": "The on-host model key is not set."}
    framed = engagement_frame(scope)
    leads = snapshot(scope)["leads"]
    index = "\n".join(
        f"- {row['file']} in_scope={row['inScope']} confirmed={row['confirmed']} hosts={', '.join(row['hosts'][:4])}"
        for row in leads[:24]
    )
    if talk:
        system = (
            framed
            + "\n\nYou are Nablus. The operator is watching a scan that is already running. "
            "Answer in plain sentences about what the log and the saved leads show. "
            "A recent log tail may be in the question. "
            "Do not start a scan, do not name a command to run, and do not extract a lead. "
            "If a step failed, say which step and what the log shows.\n"
            "Saved lead files:\n"
            + index
        )
    else:
        system = (
            framed
            + "\n\nYou are Nablus. Talk with the operator in plain sentences. "
            "Saved lead files:\n"
            + index
            + "\nIf the operator wants a saved lead extracted, end with one line: ACTION extract <filename>\n"
            "Do not invent an extraction quote. Do not write an ACTION line for anything else."
        )
    cleaned = []
    for message in messages[-16:]:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        content = str(message.get("content") or "")[:8000]
        if role in {"user", "assistant"} and content.strip():
            cleaned.append({"role": role, "content": content})
    if not cleaned:
        return {"ok": False, "error": "Write a message first."}
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}, *cleaned],
        "temperature": 0.3,
        "max_tokens": 1200,
    }
    req = urllib.request.Request(
        base.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            body = json.loads(resp.read().decode())
        text = body["choices"][0]["message"].get("content") or ""
    except Exception as exc:
        return {"ok": False, "error": f"The on-host model did not answer ({type(exc).__name__})."}
    action = re.search(r"(?m)^ACTION extract\s+(\S+)\s*$", text)
    file_name = action.group(1) if action else ""
    if action:
        text = re.sub(r"(?m)^ACTION extract\s+\S+\s*$", "", text).strip()
    last_user = next((item["content"] for item in reversed(cleaned) if item["role"] == "user"), "")
    if not file_name and re.search(r"extract|deepseek|hand\s*off", last_user, re.I):
        named = next((row["file"] for row in leads if row["file"].lower() in last_user.lower()), "")
        confirmed = next((row["file"] for row in leads if row["inScope"] and row["confirmed"] is True), "")
        in_scope = next((row["file"] for row in leads if row["inScope"]), "")
        file_name = named or confirmed or in_scope
    extraction = None
    if file_name and not talk:
        extraction = extract(file_name, scope)
        extraction["file"] = file_name
    return {"ok": True, "text": text, "frame": framed, "extraction": extraction}


def ensure_bench() -> None:
    path = ROOT / "autonomous.py"
    text = path.read_text(encoding="utf-8")
    if "add_argument(\"--bench\"" not in text:
        anchor = "ap.add_argument(\"--self-test\", action=\"store_true\")\n"
        if anchor not in text:
            raise RuntimeError("scanner entry point changed; bench flag was not added")
        text = text.replace(
            anchor,
            anchor + "    ap.add_argument(\"--bench\", action=\"store_true\")\n",
            1,
        )
    marker = '            print(f"cycle {cycle} host {host}", flush=True)\n'
    toolkit = "".join([
        '            print(f"cycle {cycle} host {host}", flush=True)\n',
        '            if args.bench and host not in scanned:\n',
        '                try:\n',
        '                    print(f"toolkit {host} recon", flush=True)\n',
        '                    apex = host.count(".") <= 2\n',
        '                    for tool, job_text in run_jobs(recon_jobs(host, "", "", apex), raw_dir, host, f"c{cycle}"):\n',
        '                        remember(notebook, cycle_findings, blobs, tool, host, job_text)\n',
        '                    print(f"toolkit {host} content", flush=True)\n',
        '                    pages = session.urls_for(host)\n',
        '                    for tool, job_text in run_jobs(content_jobs(host, "", "", raw_dir, f"c{cycle}", pages), raw_dir, host, f"c{cycle}"):\n',
        '                        remember(notebook, cycle_findings, blobs, tool, host, job_text)\n',
        '                    nuclei = nuclei_cmd(host, "")\n',
        '                    if nuclei:\n',
        '                        print(f"toolkit {host} nuclei", flush=True)\n',
        '                        nuclei_text = run(nuclei, 900, raw_dir / f"nuclei_{host.replace(\':\', \'_\')}_c{cycle}.out")\n',
        '                        print(f"nuclei {host} {one_line(\'nuclei\', nuclei_text)}", flush=True)\n',
        '                        remember(notebook, cycle_findings, blobs, "nuclei", host, nuclei_text)\n',
        '                    publish("toolkit", len(cycle_findings), 0)\n',
        '                except Exception as exc:\n',
        '                    print(f"toolkit {host} failed {type(exc).__name__}: {exc}", flush=True)\n',
    ])
    if "toolkit {host} recon" not in text:
        if marker not in text:
            raise RuntimeError("scanner loop changed; toolkit pass was not added")
        text = text.replace(marker, toolkit, 1)
    blind = '''        if not saw_app:
            print("stop: the browser cannot see the app, so more tool calls will not either", flush=True)
            publish("blind", len(cycle_findings), 0)
            break
'''
    blind_new = '''        if not saw_app and not args.bench:
            print("stop: the browser cannot see the app, so more tool calls will not either", flush=True)
            publish("blind", len(cycle_findings), 0)
            break
        if not saw_app and args.bench:
            print("browser blind; toolkit pass already ran", flush=True)
'''
    if blind in text:
        text = text.replace(blind, blind_new, 1)
    prove_anchor = "        proved = 0\n"
    prove_gate = '''        if args.bench:
            print(f"cycle {cycle}: toolkit finished, {len(cycle_findings)} notes", flush=True)
            publish("toolkit-finished", len(cycle_findings), 0)
            break
        proved = 0
'''
    if "toolkit finished" not in text:
        if prove_anchor not in text:
            raise RuntimeError("scanner prove step changed; early stop was not removed")
        text = text.replace(prove_anchor, prove_gate, 1)
    path.write_text(text, encoding="utf-8")


def clean_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    host = re.sub(r"^https?://", "", host)
    host = host.split("/")[0].split(":")[0]
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,24}", host):
        return ""
    if host.rsplit(".", 1)[-1] in FILE_EXT:
        return ""
    return host


def scan(targets: list, hours: float) -> dict:
    hosts = []
    for item in targets:
        raw = str(item).strip().lower()
        if "cortisol" in raw:
            return {"ok": False, "error": "That host stays off this bench."}
        host = clean_host(raw)
        if host and host not in hosts:
            hosts.append(host)
    if not hosts:
        return {"ok": False, "error": "Enter a target host."}
    try:
        hours = float(hours)
    except (TypeError, ValueError):
        hours = 2
    hours = min(8, max(0.5, hours))
    try:
        ensure_bench()
    except Exception as exc:
        return {"ok": False, "error": f"Bench patch did not apply: {exc}"}
    scope = load_scope()
    scope["authorized_assets"] = hosts
    (ROOT / "scope.json").write_text(json.dumps(scope, indent=2), encoding="utf-8")
    runid = f"{hosts[0]}_{__import__('time').strftime('%Y%m%d-%H%M%S')}"
    (ROOT / "runs").mkdir(exist_ok=True)
    (ROOT / "_run.json").write_text(json.dumps({"runid": runid, "target": hosts[0]}), encoding="utf-8")
    launch = ROOT / "bench-launch.ps1"
    launch.write_text(
        "\n".join([
            'param([double]$Hours = 2)',
            '$agent = "C:\\Users\\Laith\\nabulus-agent"',
            'Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*autonomous.py*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }',
            "Start-Sleep -Seconds 1",
            '$out = Join-Path $agent "run.out"',
            '$err = Join-Path $agent "run.err"',
            'Set-Content -Path $out -Value "" -Encoding utf8',
            'Set-Content -Path $err -Value "" -Encoding utf8',
            '$cmd = "cmd.exe /c set PYTHONUNBUFFERED=1&& py -3 -u `"$agent\\autonomous.py`" --bench --hours $Hours > `"$out`" 2> `"$err`""',
            '$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }',
            'Write-Output $r.ProcessId',
            "",
        ]),
        encoding="utf-8",
    )
    done = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(launch), "-Hours", str(hours)],
        capture_output=True,
        text=True,
        timeout=40,
    )
    pid = (done.stdout or "").strip().splitlines()
    return {
        "ok": done.returncode == 0 and bool(pid),
        "pid": pid[-1] if pid else "",
        "targets": hosts,
        "hours": hours,
        "frame": engagement_frame(load_scope()),
        "error": "" if done.returncode == 0 else (done.stderr or "scan did not start")[-500:],
    }


def stop_scan() -> dict:
    script = (
        'Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*autonomous.py*" } | '
        'ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; $_.ProcessId }'
    )
    done = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {"ok": True, "stopped": [line.strip() for line in (done.stdout or "").splitlines() if line.strip()]}


def read_from(path: Path, offset: int) -> tuple[str, int]:
    if not path.exists():
        return "", 0
    size = path.stat().st_size
    if offset < 0 or offset > size:
        offset = 0
    with path.open("rb") as handle:
        handle.seek(offset)
        chunk = handle.read(120_000)
    return chunk.decode("utf-8", errors="replace"), offset + len(chunk)


def running() -> bool:
    done = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         '(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*autonomous.py*" }).ProcessId'],
        capture_output=True,
        text=True,
        timeout=20,
    )
    return bool((done.stdout or "").strip())


def log_slice(out_offset: int, err_offset: int) -> dict:
    out, out_at = read_from(ROOT / "run.out", int(out_offset or 0))
    err, err_at = read_from(ROOT / "run.err", int(err_offset or 0))
    status = read_json(ROOT / "status.json")
    phase = ""
    if isinstance(status, dict):
        phase = str(status.get("phase") or status.get("cycle") or "")
    return {
        "ok": True,
        "out": out,
        "err": err,
        "outOffset": out_at,
        "errOffset": err_at,
        "running": running(),
        "phase": phase,
        "findings": (ROOT / "notebook.json").is_file() or (ROOT / "findings.json").is_file(),
    }


_SECRET_VALUE = re.compile(
    r"(token|password|secret|cookie|authorization|api[_-]?key|bearer|session)\s*[:=]\s*\S+",
    re.I,
)


def redact(value, depth: int = 0):
    if depth > 12:
        return None
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if DROP.search(str(key)):
                continue
            cleaned = redact(item, depth + 1)
            if cleaned is not None:
                out[str(key)] = cleaned
        return out
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value]
    if isinstance(value, str):
        return _SECRET_VALUE.sub(r"\1=[redacted]", value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)


def findings_document() -> dict:
    """Per-run report built from the toolkit's notebook (where --bench writes),
    filtered to the current run's target. Falls back to the engine's findings.json
    only when the toolkit wrote nothing, so the download reflects the scan the
    operator just ran instead of a stale engine store."""
    run = read_json(ROOT / "_run.json")
    runid = run.get("runid") if isinstance(run, dict) else None
    target = (run.get("target") if isinstance(run, dict) else None) or ""
    if not runid:
        runid = "findings_" + __import__("time").strftime("%Y%m%d-%H%M%S")

    notebook = read_json(ROOT / "notebook.json")
    doc: dict = {
        "target": target,
        "runid": runid,
        "generated": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
        "leads": [],
        "tests": [],
        "proofs": [],
    }

    def for_target(row: object) -> bool:
        if not isinstance(row, dict):
            return False
        if not target:
            return True
        blob = (str(row.get("target") or "") + " " + json.dumps(row, ensure_ascii=False)).lower()
        return target.lower() in blob

    if isinstance(notebook, dict):
        for row in notebook.get("tests") or []:
            if not for_target(row):
                continue
            doc["tests"].append(row)
            result = str(row.get("result") or "").lower()
            if "lead" in result or "vulnerab" in result or "inject" in result:
                doc["leads"].append({
                    "tool": row.get("tool"),
                    "where": row.get("target"),
                    "signal": row.get("result"),
                    "when": row.get("when"),
                })
        for row in notebook.get("leads") or []:
            if for_target(row):
                doc["leads"].append(row)
        for row in notebook.get("proofs") or []:
            if for_target(row):
                doc["proofs"].append(row)

    if not doc["tests"] and not doc["leads"]:
        engine = read_json(ROOT / "findings.json")
        if engine is not None:
            doc["engine_findings"] = engine

    if not doc["tests"] and not doc["leads"] and "engine_findings" not in doc:
        return {"ok": False, "error": "no findings for this run yet."}

    text = json.dumps(redact(doc), ensure_ascii=False, indent=2)
    name = f"{runid}.findings.json"
    # archive this scan's report under its own name so later scans never clobber it
    try:
        runs = ROOT / "runs"
        runs.mkdir(exist_ok=True)
        (runs / name).write_text(text, encoding="utf-8")
    except OSError:
        pass
    return {"ok": True, "text": text, "bytes": len(text.encode("utf-8")), "name": name}


def material(scope: dict) -> dict:
    notebook = read_json(ROOT / "notebook.json")
    lines = [engagement_frame(scope), ""]
    if isinstance(notebook, dict):
        for row in (notebook.get("tests") or [])[-80:]:
            if not isinstance(row, dict):
                continue
            lines.append(f"{row.get('tool')} {row.get('target')} {str(row.get('result') or '')[:240]}")
        for row in (notebook.get("leads") or [])[-40:]:
            if isinstance(row, dict):
                lines.append("lead " + json.dumps(scrub(row), ensure_ascii=False)[:800])
    text = "\n".join(lines)[:24000]
    return {"ok": True, "text": text, "frame": engagement_frame(scope)}


def deepseek_talk(messages, material_text: str, scope: dict) -> dict:
    key = os.environ.get("DEEPSEEK_API_KEY") or ""
    if not key:
        return {"ok": False, "error": "DEEPSEEK_API_KEY is not set. Nothing was written."}
    model = os.environ.get("DEEPSEEK_MODEL") or "deepseek-flash"
    system = (
        engagement_frame(scope)
        + "\n\nYou are the extraction reviewer for this engagement. "
        "The operator tells you what to extract and what to leave, and when to check again. "
        "When they ask you to double-check or triple-check, go back through the material and say what still holds. "
        "Quote only text that appears in the material. "
        "If they say skip something, skip it on this pass and on later passes unless they take the skip back. "
        "If the material does not contain the evidence, say it is not there. "
        "Do not propose a new scan command. "
        "Write plain sentences. "
        "Nothing you write is stored on the scan host."
    )
    thread = [{"role": "system", "content": system}]
    if material_text:
        thread.append({"role": "user", "content": "Scan material:\n" + str(material_text)[:24000]})
    for message in messages[-16:]:
        if not isinstance(message, dict):
            continue
        role = "assistant" if message.get("role") == "assistant" else "user"
        content = str(message.get("content") or "")[:8000]
        if content.strip():
            thread.append({"role": role, "content": content})
    payload = {"model": model, "messages": thread, "temperature": 0.2, "max_tokens": 1800}
    req = urllib.request.Request(
        "https://api.deepseek.com/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            body = json.loads(resp.read().decode())
        text = body["choices"][0]["message"].get("content") or ""
    except Exception as exc:
        return {"ok": False, "error": f"DeepSeek did not answer ({type(exc).__name__})."}
    return {"ok": True, "text": text, "frame": engagement_frame(scope)}


def main() -> None:
    os.chdir(ROOT)
    load_env()
    request = json.loads(sys.stdin.read() or "{}")
    scope = load_scope()
    op = request.get("op")
    if op == "snapshot":
        response = snapshot(scope)
    elif op == "lead":
        response = lead_detail(str(request.get("file") or ""), scope)
    elif op == "source":
        response = source_text(str(request.get("file") or ""))
    elif op == "extract":
        response = extract(str(request.get("file") or ""), scope)
    elif op == "chat":
        response = chat(request.get("messages") or [], scope, talk=bool(request.get("talk")))
    elif op == "scan":
        response = scan(request.get("targets") or [], request.get("hours") or 2)
    elif op == "stop":
        response = stop_scan()
    elif op == "log":
        response = log_slice(request.get("outOffset") or 0, request.get("errOffset") or 0)
    elif op == "material":
        response = material(scope)
    elif op == "findings":
        response = findings_document()
    elif op == "deepseek":
        response = deepseek_talk(request.get("messages") or [], str(request.get("material") or ""), scope)
    else:
        response = {"ok": False, "error": "unknown op"}
    sys.stdout.write(json.dumps(response, ensure_ascii=False))


if __name__ == "__main__":
    main()
