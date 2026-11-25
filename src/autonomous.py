#!/usr/bin/env python3
"""Unattended finder. Runs for hours against scope.json.

The map and the HTTP shape catalog run with an empty cookie jar.
DeepSeek then applies one published skill at a time and returns HTTP requests.
A lead is confirmed only when a second run still contains the extracted quote.
No request rate cap. The only gate is the signed host list.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import battery
import confirm as freeconfirm
import proof_loop as extractor
import playbook
import probes
import session
import surface

AGENT = pathlib.Path(__file__).resolve().parent
BIN = pathlib.Path(os.environ.get("NABULUS_BIN", r"C:\Users\Laith\nabulus-tools\bin"))
SQLMAP = pathlib.Path(r"C:\Users\Laith\nabulus-tools\github\sqlmapproject__sqlmap\sqlmap.py")
COMMIX = pathlib.Path(r"C:\Users\Laith\nabulus-tools\github\commixproject__commix\commix.py")
RAFT = pathlib.Path(r"C:\Users\Laith\nabulus-tools\wordlists\raft-medium-directories.txt")
WORDS = RAFT if RAFT.exists() else pathlib.Path(r"C:\Users\Laith\nabulus-tools\wordlists\common.txt")
SENSITIVE = pathlib.Path(r"C:\Users\Laith\nabulus-tools\wordlists\sensitive.txt")
NUCLEI_TEMPLATES = pathlib.Path(r"C:\Users\Laith\nuclei-templates")
PY = "py"

HOST_RE = re.compile(r"https?://([^/\s:]+)|(?<![/\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)
ALLOW = {
    "sqlmap", "commix", "nuclei", "dalfox", "ffuf", "katana", "httpx", "curl",
    "naabu", "rustscan", "feroxbuster", "gau", "amass", "hakrawler", "arjun",
}
PARAMS = ("id", "q", "search", "file", "path", "page", "user", "name", "email", "token", "template", "doc", "key", "callback")


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def load_env(path: pathlib.Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def load_scope(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    assets = {a.strip().lower().rstrip(".") for a in data.get("authorized_assets", []) if a.strip()}
    if not assets:
        raise SystemExit("scope.json authorized_assets is empty. Put the signed host there, then start.")
    data["_assets"] = assets
    return data


def in_scope(host: str, assets: set[str]) -> bool:
    host = host.lower().split(":")[0].rstrip(".")
    return any(host == a or host.endswith("." + a) for a in assets)


def hosts_in(text: str) -> list[str]:
    found = []
    for a, b in HOST_RE.findall(text or ""):
        h = (a or b).lower()
        if h and h not in found:
            found.append(h)
    return found


# BELOW_NORMAL_PRIORITY_CLASS: run every tool (and its children, e.g. dalfox's
# headless Chrome, which inherit the class) below foreground priority so a heavy
# scan can never starve sshd -- this is the fix for the "Windows paused your
# stuff" SSH-reset lockout. 0 on non-Windows so the code still runs anywhere.
_BELOW_NORMAL = 0x00004000 if sys.platform == "win32" else 0


def run(cmd: list[str], timeout: int, raw: pathlib.Path) -> str:
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", creationflags=_BELOW_NORMAL)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            out = (stdout or "") + ("\n" + stderr if stderr else "")
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, text=True)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except Exception:
                stdout, stderr = "", ""
            out = (stdout or "") + ("\n" + stderr if stderr else "") + "\n[timeout]"
    except OSError as e:
        out = f"[exec error] {e}"
    if "-o" in cmd:
        slot = cmd.index("-o")
        if slot + 1 < len(cmd):
            side = pathlib.Path(cmd[slot + 1])
            if side.is_file():
                extra = side.read_text(encoding="utf-8", errors="replace")
                if extra.strip():
                    out += "\n" + extra
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(out, encoding="utf-8", errors="replace")
    return out


def exe(name: str) -> pathlib.Path | None:
    for base in (BIN, pathlib.Path(r"C:\Users\Laith\go\bin")):
        p = base / f"{name}.exe"
        if p.exists():
            return p
    return None


def add_job(jobs: list, tool: str, args: list[str], timeout: int, cookie: str, ua: str = "") -> None:
    binary = exe(tool)
    if binary:
        jobs.append((tool, [str(binary), *session.apply_cookie(tool, args, cookie, ua)], timeout))


def run_jobs(jobs: list[tuple[str, list[str], int]], raw_dir: pathlib.Path, host: str, tag: str, on_done=None) -> list[tuple[str, str]]:
    results = []
    if not jobs:
        return results
    # 3, not 6: six heavy tools at once (two port scanners + katana + dalfox
    # swarm) saturated the box and Windows throttled inbound SSH to resets.
    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = {}
        for i, (tool, cmd, timeout) in enumerate(jobs):
            futs[pool.submit(run, cmd, timeout, raw_dir / f"{tool}_{host}_{tag}_{i}.out")] = tool
        for fut in as_completed(futs):
            tool = futs[fut]
            text = fut.result()
            print(f"{tool} {host} {one_line(tool, text)}", flush=True)
            results.append((tool, text))
            if on_done:
                try:
                    on_done(tool)
                except Exception:
                    pass
    return results


def recon_jobs(host: str, cookie: str, ua: str, apex: bool) -> list[tuple[str, list[str], int]]:
    jobs: list[tuple[str, list[str], int]] = []
    add_job(jobs, "subfinder", ["-d", host, "-silent", "-all"], 300, cookie, ua)
    # Web bench: scan the web ports, not top-1000, and run ONE port scanner.
    # Two full scanners (naabu+rustscan) at max rate were pure box thrash for
    # no added signal on an HTTP target. rustscan stays available as a manual
    # follow-up; it is just not scheduled in the auto pass.
    add_job(jobs, "naabu", ["-host", host, "-silent", "-rate", "1000", "-p", "80,443,8000,8080,8443,8888,3000,5000"], 180, cookie, ua)
    add_job(jobs, "httpx", ["-u", f"https://{host}", "-u", f"http://{host}", "-json", "-silent", "-title", "-tech-detect", "-status-code", "-follow-redirects"], 180, cookie, ua)
    if apex:
        add_job(jobs, "gau", ["--subs", host], 180, cookie, ua)
        add_job(jobs, "amass", ["enum", "-passive", "-d", host, "-timeout", "4"], 240, cookie, ua)
    return jobs


def content_jobs(host: str, cookie: str, ua: str, raw_dir: pathlib.Path, tag: str, page_urls: list[str]) -> list[tuple[str, list[str], int]]:
    """Crawl the pages the browser already opened.

    A root wordlist against this stack returns one block response thousands of
    times, so it is not scheduled. Directory tools stay available as follow-ups
    on a URL that already behaved differently.
    """
    jobs: list[tuple[str, list[str], int]] = []
    pages = [u for u in page_urls if u.startswith("http")][:8]
    targets = pages or [surface._base(host)]
    for url in targets[:3]:
        add_job(jobs, "katana", ["-u", url, "-silent", "-d", "2", "-jc", "-kf", "all", "-timeout", "10"], 300, cookie, ua)
    queried = 0
    for url in pages:
        if "?" not in url or queried >= 2:
            continue
        queried += 1
        # --worker 20 (operator ceiling 20-25; raised from 8 after priority fix
        # the SSH-reset lockout tonight). Proving the full pipeline end-to-end on a
        # lighter setting first; raise toward 20 once a clean scan is confirmed
        # stable. Peak dalfox streams = queried(2) x worker(8) = 16, within pool 3.
        add_job(jobs, "dalfox", ["url", url, "--format", "jsonl", "--silence", "--worker", "20", "--timeout", "10"], 180, cookie, ua)
    return jobs


def nuclei_cmd(host: str, cookie: str, ua: str = "") -> list[str] | None:
    binary = exe("nuclei")
    if not binary:
        return None
    args = ["-u", surface._base(host), "-jsonl", "-silent", "-severity", "low,medium,high,critical", "-c", "15", "-timeout", "10", "-retries", "1"]
    if NUCLEI_TEMPLATES.exists():
        args += ["-t", str(NUCLEI_TEMPLATES)]
    return [str(binary), *session.apply_cookie("nuclei", args, cookie, ua)]


def run_hakrawler(host: str, cookie: str, ua: str, raw_dir: pathlib.Path) -> str:
    binary = exe("hakrawler")
    if not binary:
        return ""
    cmd = [str(binary), "-d", "2", "-insecure", "-u"]
    try:
        p = subprocess.run(
            cmd,
            input=surface._base(host) + "/\n",
            capture_output=True,
            text=True,
            timeout=180,
            encoding="utf-8",
            errors="replace",
        )
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    except (subprocess.TimeoutExpired, OSError) as exc:
        out = f"[hakrawler] {exc}"
    path = raw_dir / f"hakrawler_{host}.out"
    path.write_text(out, encoding="utf-8", errors="replace")
    return out


def _code_size(line: str) -> tuple[int, int]:
    parts = (line or "").strip().split()
    if len(parts) < 2 or not parts[0].isdigit():
        return 0, 0
    try:
        return int(parts[0]), int(float(parts[1]))
    except ValueError:
        return 0, 0


def real_change(base: str, got: str) -> bool:
    """A few bytes on the same 403 is the wall echoing the query string."""
    base_status, base_size = _code_size(base)
    got_status, got_size = _code_size(got)
    if not base_status or not got_status:
        return False
    if base_status != got_status:
        return True
    if base_status in {301, 302, 307, 308, 401, 403}:
        return False
    if base_size <= 0:
        return False
    return abs(got_size - base_size) >= max(200, int(base_size * 0.15))


def replay(urls: list[str], assets: set[str], raw_dir: pathlib.Path) -> str:
    """Fetch the browser's own URLs with its user agent and keep the answer shape."""
    lines = []
    seen: set[str] = set()
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if url in seen or not in_scope(host, assets):
            continue
        seen.add(url)
        if len(seen) > 12:
            break
        raw = guarded({
            "tool": "curl",
            "args": ["--max-time", "20", "-L", "--max-redirs", "2", "-w", "\n__META__ %{http_code} %{size_download} %{content_type}", url],
        }, assets, raw_dir)
        body, _, meta = (raw or "").rpartition("__META__")
        parts = meta.strip().split()
        code = parts[0] if parts and parts[0].isdigit() else "0"
        size = parts[1] if len(parts) > 1 else "0"
        ctype = parts[2] if len(parts) > 2 else ""
        if code in {"401", "403", "0"}:
            lines.append(f"wall {url} status={code} size={size}")
            continue
        excerpt = ""
        if code == "500" or "json" in ctype.lower():
            excerpt = " ".join(body.split())[:400]
        lines.append(f"{url} status={code} size={size} type={ctype} {excerpt}".strip())
    text = "\n".join(lines)
    (raw_dir / "replay.out").write_text(text, encoding="utf-8")
    return text


def discover_params(urls: list[str], assets: set[str], cookie: str, ua: str, raw_dir: pathlib.Path) -> str:
    """Record a parameter only when the status or the body actually changes."""
    lines = []
    checked = 0
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if not in_scope(host, assets) or "?" in url:
            continue
        if checked >= 6:
            break
        checked += 1
        base = guarded({"tool": "curl", "args": ["--max-time", "15", "-o", "NUL", "-w", "%{http_code} %{size_download}", url]}, assets, raw_dir)
        base_line = ((base or "").strip().splitlines() or [""])[-1]
        if _code_size(base_line)[0] in {0, 401, 403}:
            continue
        for name in PARAMS:
            probe = url + "?" + f"{name}=1"
            got = guarded({"tool": "curl", "args": ["--max-time", "15", "-o", "NUL", "-w", "%{http_code} %{size_download}", probe]}, assets, raw_dir)
            got_line = ((got or "").strip().splitlines() or [""])[-1]
            if real_change(base_line, got_line):
                lines.append(f"{probe} base={base_line} got={got_line}")
    text = "\n".join(lines)
    (raw_dir / "params.out").write_text(text, encoding="utf-8")
    return text


def urls_from(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"https?://[^\s\"']+", text or "")))


def one_line(tool: str, text: str) -> str:
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    if tool == "naabu":
        return f"{len(lines)} open ports"
    if tool in {"katana", "httpx"}:
        return f"{len(urls_from(text))} urls" if tool == "katana" else f"{len(lines)} responses"
    hits = interesting(tool, text)
    if hits:
        return f"{len(hits)} leads"
    if not lines:
        return "no output"
    return f"{len(lines)} lines"


def interesting(tool: str, text: str) -> list[dict]:
    found = []
    if tool == "nuclei":
        for line in text.splitlines():
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = o.get("info") or {}
            sev = str(info.get("severity", "info")).lower()
            if sev in {"medium", "high", "critical"}:
                found.append({
                    "tool": "nuclei",
                    "severity": sev,
                    "name": info.get("name"),
                    "matched": o.get("matched-at") or o.get("host"),
                    "evidence": (o.get("matcher-name") or "")[:400],
                })
    elif tool == "ffuf":
        rows = []
        blob = text[text.find("{"):text.rfind("}") + 1] if "{" in text else ""
        try:
            data = json.loads(blob) if blob else {}
        except json.JSONDecodeError:
            data = {}
        for row in data.get("results") or []:
            rows.append({
                "url": row.get("url") or "",
                "status": row.get("status"),
                "length": row.get("length"),
            })
        if not rows:
            for line in text.splitlines():
                m = re.match(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
                if m:
                    rows.append({"url": m.group(1), "status": int(m.group(2)), "length": int(m.group(3))})
        if len(rows) >= 12:
            sizes: dict[int, int] = {}
            for row in rows:
                try:
                    size = int(row.get("length") or 0)
                except (TypeError, ValueError):
                    size = 0
                sizes[size] = sizes.get(size, 0) + 1
            if sizes:
                baseline = max(sizes, key=sizes.get)
                if sizes[baseline] >= 12 and sizes[baseline] / len(rows) >= 0.75:
                    rows = [row for row in rows if int(row.get("length") or 0) != baseline]
        for row in rows:
            url = str(row.get("url") or "")
            try:
                status = int(row.get("status") or 0)
            except (TypeError, ValueError):
                status = 0
            # A 401 or 403 is the edge returning the same wall, including for a sensitive-looking name.
            if status in {0, 401, 403}:
                continue
            hot = any(bit in url.lower() for bit in (".env", ".git", ".sql", "wp-config", "phpinfo", "adminer", "id_rsa", ".bak", "swagger", "graphql"))
            found.append({
                "tool": "ffuf",
                "severity": "high" if hot else "low",
                "matched": url,
                "evidence": f"status={status} size={row.get('length')}",
            })
    elif tool == "feroxbuster":
        for line in text.splitlines():
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            status = int(row.get("status") or 0)
            url = str(row.get("url") or "")
            if status in {200, 204, 301, 302, 307, 500} and url:
                hot = any(bit in url.lower() for bit in (".env", ".git", ".sql", "wp-config", "phpinfo", "adminer", "id_rsa", ".bak"))
                found.append({"tool": "feroxbuster", "severity": "high" if hot else "low", "matched": url, "evidence": f"status={status}"})
    elif tool == "dalfox" and text.strip() and "timeout" not in text[:20]:
        for line in text.splitlines():
            if line.startswith("{"):
                found.append({"tool": "dalfox", "severity": "high", "evidence": line[:500]})
    elif tool == "arjun":
        for line in text.splitlines():
            if line.startswith("http"):
                found.append({"tool": "arjun", "severity": "medium", "matched": line.split()[0], "evidence": line[:300]})
    elif tool == "sqlmap" and re.search(r"is vulnerable|(identified|resumed) the following injection point", text, re.I) and not re.search(r"not injectable|do not appear to be injectable", text, re.I):
        found.append({"tool": "sqlmap", "severity": "high", "evidence": text[-1500:]})
    elif tool == "curl":
        for line in text.splitlines():
            if "status=500" in line or ("status=200" in line and "json" in line.lower()):
                url = line.split()[0] if line.startswith("http") else ""
                found.append({"tool": "curl", "severity": "medium", "matched": url, "evidence": line[:500]})
    elif tool == "emptyjar":
        for line in text.splitlines():
            if line.startswith("suspect-xss "):
                bits = line.split(" ", 2)
                url = bits[1] if len(bits) > 1 else ""
                found.append({"tool": "emptyjar", "severity": "high", "matched": url, "evidence": line[:500]})
                continue
            if line.startswith("suspect "):
                bits = line.split(" ", 2)
                url = bits[1] if len(bits) > 1 else ""
                found.append({"tool": "emptyjar", "severity": "medium", "matched": url, "evidence": line[:500]})
                continue
            if not (line.startswith("data ") or " data http" in line):
                continue
            if " data http" in line:
                url = line.split(" data ", 1)[1].split()[0]
            else:
                parts = line.split()
                url = parts[1] if len(parts) > 1 else ""
            found.append({"tool": "emptyjar", "severity": "high", "matched": url, "evidence": line[:500]})
    return found


def sqlmap_candidates(blobs: list[str], assets: set[str], limit: int = 5) -> list[str]:
    ranked = []
    for blob in blobs:
        for url in urls_from(blob):
            if "base=" not in blob and "got=" not in blob:
                continue
            if "?" not in url or url in ranked:
                continue
            host = (urlparse(url).hostname or "").lower()
            if not in_scope(host, assets):
                continue
            query = urlparse(url).query.lower()
            if any(bad in query for bad in ("google.", "gstatic.", "googleapis.")):
                continue
            score = sum(1 for name in PARAMS if f"{name}=" in query)
            if query.startswith("next=") and score == 0:
                continue
            ranked.append((score, url))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return [url for _, url in ranked[:limit]]


def run_sqlmap(url: str, raw_dir: pathlib.Path, extra: list[str] | None = None, cookie: str = "") -> str:
    if not SQLMAP.exists():
        return "[sqlmap missing]"
    safe = re.sub(r"[^\w.-]+", "_", url)[:80]
    cmd = [PY, "-3", str(SQLMAP), "-u", url, "--batch", "--smart", "--random-agent", "--threads", "8", "--level", "2", "--risk", "2"]
    if extra:
        cmd = [PY, "-3", str(SQLMAP), *extra]
    if cookie and "--cookie" not in cmd:
        cmd += ["--cookie", cookie]
    return run(cmd, 1200, raw_dir / f"sqlmap_{safe}.out")


def local_once(summary: str) -> str:
    """One model pass for HTTP requests the catalog did not already send."""
    base = os.environ.get("LLAMA_BASE", "")
    key = os.environ.get("LLAMA_API_KEY", "")
    model = os.environ.get("LLAMA_MODEL", "qwen2.5-coder-14b")
    if not base or not key:
        return ""
    system = (
        "Reply with JSON only: {\"requests\":[{\"method\":\"GET\",\"url\":\"https://host/path\",\"headers\":{},\"body\":\"\"}]}. "
        "The catalog already sent GET, POST, PUT, PATCH, DELETE, and OPTIONS, including an empty JSON body, with no cookie. "
        "Propose at most 8 requests that are not those. Every url must stay on the host in the summary. "
        "Do not name a scanner. If nothing else is worth sending, return {\"requests\":[]}."
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": summary[:12000]},
        ],
        "temperature": 0.2,
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
        return body["choices"][0]["message"].get("content") or ""
    except Exception as exc:
        print(f"model error {type(exc).__name__}", flush=True)
        return ""


def guarded(action: dict, assets: set[str], raw_dir: pathlib.Path) -> str:
    tool = str(action.get("tool", ""))
    args = [str(a) for a in action.get("args", [])]
    if tool not in ALLOW:
        return f"skip {tool}"
    blob = " ".join(args)
    mentioned = hosts_in(blob)
    if mentioned and not all(in_scope(h, assets) for h in mentioned):
        return f"refused out-of-scope {mentioned}"
    host_for_cookie = next((h for h in (mentioned or []) if in_scope(h, assets)), "")
    cookie = session.cookie_for(host_for_cookie) if host_for_cookie and session.supplied_login(host_for_cookie) else ""
    ua = session.ua_for(host_for_cookie) if host_for_cookie else ""
    args = session.apply_cookie(tool, args, cookie, ua)
    if tool == "sqlmap":
        return run_sqlmap(args[args.index("-u") + 1] if "-u" in args else "", raw_dir, args, cookie)
    if tool == "commix" and COMMIX.exists():
        return run([PY, "-3", str(COMMIX), *args, "--batch"], 900, raw_dir / "commix.out")
    stamp = str(time.time_ns())
    if tool == "arjun":
        return run([PY, "-3", "-m", "arjun", *args], 600, raw_dir / f"arjun_{stamp}.out")
    if tool == "curl":
        return run(["curl", "-sk", "--max-time", "30", *args], 40, raw_dir / f"curl_{stamp}.out")
    binary = exe(tool)
    if not binary:
        return f"missing {tool}"
    return run([str(binary), *args], 900, raw_dir / f"follow_{tool}_{stamp}.out")


def self_test() -> int:
    print("tools:")
    for name in ("subfinder", "dnsx", "naabu", "httpx", "katana", "nuclei", "ffuf", "feroxbuster", "dalfox", "rustscan"):
        print(f"  {name}: {'yes' if exe(name) else 'NO'}")
    print(f"  sqlmap: {'yes' if SQLMAP.exists() else 'NO'}")
    print(f"  commix: {'yes' if COMMIX.exists() else 'NO'}")
    print(f"  wordlist: {'yes' if WORDS.exists() else 'NO'}")
    print(f"  deepseek key: {'yes' if extractor.enabled() else 'no'}")
    base = os.environ.get("LLAMA_BASE", "")
    key = os.environ.get("LLAMA_API_KEY", "")
    model = os.environ.get("LLAMA_MODEL", "qwen2.5-coder-14b")
    print(f"  llama: {base or 'unset'} model={model}")
    if not base or not key:
        return 1
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with the single word ok."}],
        "max_tokens": 8,
        "temperature": 0,
    }
    req = urllib.request.Request(
        base.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read().decode())
    dt = time.time() - t0
    text = body["choices"][0]["message"].get("content", "")
    usage = body.get("usage") or {}
    print(f"  model reply: {text!r} in {dt:.1f}s usage={usage}")
    return 0


def names_from(text: str, assets: set[str]) -> list[str]:
    found = []
    for line in (text or "").splitlines():
        host = line.strip().lower().rstrip(".")
        if " " in host or "/" in host:
            continue
        if host and in_scope(host, assets) and host not in found:
            found.append(host)
    return found


def remember(notebook: dict, findings: list, blobs: list, tool: str, target: str, text: str) -> None:
    blobs.append(text or "")
    notebook["tests"].append({"when": now(), "tool": tool, "target": target, "result": one_line(tool, text or "")})
    findings.extend(interesting(tool, text or ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=3)
    ap.add_argument("--scope", default=str(AGENT / "scope.json"))
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--bench", action="store_true")
    args = ap.parse_args()

    load_env(AGENT / "local.env")
    load_env(pathlib.Path(r"C:\Users\Laith\llama-cpp\server.env"))
    if os.environ.get("LLAMA_API_KEY") and not os.environ.get("LLAMA_BASE"):
        os.environ["LLAMA_BASE"] = "http://127.0.0.1:8081/v1"
    os.environ.setdefault("LLAMA_MODEL", "qwen2.5-coder-14b-instruct")

    if args.self_test:
        return self_test()

    scope = load_scope(pathlib.Path(args.scope))
    assets: set[str] = scope["_assets"]
    raw_dir = AGENT / "raw"
    raw_dir.mkdir(exist_ok=True)
    deadline = time.time() + args.hours * 3600
    notebook_path = AGENT / "notebook.json"
    status_path = AGENT / "status.json"
    notebook = json.loads(notebook_path.read_text()) if notebook_path.exists() else {
        "assets": sorted(assets), "tests": [], "leads": [], "proofs": [],
    }
    cycle = 0

    def execute(commands: list) -> list[dict]:
        ran = []
        for command in commands:
            if not isinstance(command, dict):
                continue
            out = guarded(command, assets, raw_dir)
            ran.append({
                "tool": command.get("tool"),
                "args": command.get("args"),
                "output": (out or "")[-8000:],
            })
        return ran

    background: list[dict] = []
    tested_sql: set[str] = set()
    scanned: set[str] = set()
    opened: set[str] = set()
    tried: set[tuple] = set()
    empty_cycles = 0

    def publish(phase: str, leads: int, proved_n: int) -> None:
        notebook["tests"] = notebook["tests"][-200:]
        notebook_path.write_text(json.dumps(notebook, indent=2), encoding="utf-8")
        status_path.write_text(json.dumps({
            "updated": now(),
            "cycle": cycle,
            "phase": phase,
            "hours_left": round((deadline - time.time()) / 3600, 2),
            "leads_this_cycle": leads,
            "proved_this_cycle": proved_n,
            "deepseek": extractor.enabled(),
            "model": os.environ.get("LLAMA_MODEL"),
        }, indent=2), encoding="utf-8")

    def heartbeat(tool: str) -> None:
        # Per-tool status write so status.json advances WITHIN a phase, not just
        # at phase boundaries -- a long recon no longer looks like a wedge.
        try:
            status_path.write_text(json.dumps({
                "updated": now(),
                "cycle": cycle,
                "phase": f"tool:{tool}",
                "hours_left": round((deadline - time.time()) / 3600, 2),
            }, indent=2), encoding="utf-8")
        except OSError:
            pass

    def harvest() -> list[dict]:
        fresh = []
        still = []
        for job in background:
            if job["proc"].poll() is None:
                still.append(job)
                continue
            job["handle"].close()
            text = pathlib.Path(job["path"]).read_text(encoding="utf-8", errors="replace")
            print(f"nuclei {job['host']} {one_line('nuclei', text)}", flush=True)
            remember(notebook, fresh, [], "nuclei", job["host"], text)
        background[:] = still
        return fresh

    while time.time() < deadline:
        cycle += 1
        cycle_findings = []
        blobs = []
        cycle_findings.extend(harvest())
        queue = sorted(assets)
        seen: set[str] = set()
        saw_app = False
        while queue and len(seen) < 8 and time.time() < deadline:
            host = queue.pop(0)
            if host in seen:
                continue
            seen.add(host)
            cookie = ""
            if session.supplied_login(host) and session.cookie_for(host):
                cookie = session.cookie_for(host)
                notebook["tests"].append({"when": now(), "tool": "session", "target": host, "result": "signed in"})
            print(f"cycle {cycle} host {host}", flush=True)
            if args.bench and host not in scanned:
                try:
                    print(f"toolkit {host} recon", flush=True)
                    apex = host.count(".") <= 2
                    for tool, job_text in run_jobs(recon_jobs(host, "", "", apex), raw_dir, host, f"c{cycle}", on_done=heartbeat):
                        remember(notebook, cycle_findings, blobs, tool, host, job_text)
                    publish("toolkit-recon", len(cycle_findings), 0)
                    print(f"toolkit {host} content", flush=True)
                    pages = session.urls_for(host)
                    for tool, job_text in run_jobs(content_jobs(host, "", "", raw_dir, f"c{cycle}", pages), raw_dir, host, f"c{cycle}", on_done=heartbeat):
                        remember(notebook, cycle_findings, blobs, tool, host, job_text)
                    publish("toolkit-content", len(cycle_findings), 0)
                    nuclei = nuclei_cmd(host, "")
                    if nuclei:
                        print(f"toolkit {host} nuclei", flush=True)
                        # 420s cap (was 900): nuclei must not eat the whole bench
                        # window before the skill + confirm phase ever runs.
                        nuclei_text = run(nuclei, 420, raw_dir / f"nuclei_{host.replace(':', '_')}_c{cycle}.out")
                        print(f"nuclei {host} {one_line('nuclei', nuclei_text)}", flush=True)
                        remember(notebook, cycle_findings, blobs, "nuclei", host, nuclei_text)
                    publish("toolkit", len(cycle_findings), 0)
                except Exception as exc:
                    print(f"toolkit {host} failed {type(exc).__name__}: {exc}", flush=True)
            if host not in scanned:
                try:
                    info = session.open_host(host)
                except Exception as exc:
                    info = {}
                    print(f"browser {host} failed {type(exc).__name__}", flush=True)
                blocked = bool(info.get("blocked"))
                print(
                    f"browser {host} blocked={blocked} profile={info.get('profile') or '-'} urls={info.get('urls')} cookies={info.get('cookies')} err={info.get('error') or '-'}",
                    flush=True,
                )
                notebook["tests"].append({
                    "when": now(),
                    "tool": "browser",
                    "target": host,
                    "result": f"blocked={blocked} urls={info.get('urls')} cookies={info.get('cookies')}",
                })
                auth = session.supplied_login(host)
                cookie = session.cookie_for(host) if auth else ""
                ua = session.ua_for(host)
                print(f"mode {'auth' if auth else 'unauth'} {host}", flush=True)
                for extra_url in session.urls_for(host):
                    blobs.append(extra_url)
                pages = session.urls_for(host)
                if "ERR_NAME_NOT_RESOLVED" in (info.get("error") or ""):
                    print(f"skip {host}: name does not resolve", flush=True)
                    scanned.add(host)
                    continue
                if blocked and not cookie:
                    print(f"skip brute {host}: browser still sees the block page", flush=True)
                    if not saw_app:
                        notebook["blind"] = True
                else:
                    saw_app = True
                    opened.add(host)
                    notebook["blind"] = False
                    page_urls = session.urls_for(host)
                    mapped = surface.build_map(
                        host,
                        session.scripts_for(host),
                        session.observed_for(host) + page_urls,
                        surface.EmptyJar().get,
                    )
                    (raw_dir / f"map_{host.replace(':', '_')}.json").write_text(json.dumps(mapped, indent=2), encoding="utf-8")
                    checked = surface.audit(host, mapped)
                    jar = surface.EmptyJar()
                    control = jar.get(surface._base(host) + "/__nabulus_absent_battery")
                    shaped = battery.run(battery.targets(checked), jar, control.get("body") or b"")
                    checked = checked + shaped
                    calls = [
                        call for call in session.calls_for(host)
                        if surface._same_host(str(call.get("url") or ""), host)
                    ]
                    stack = playbook.fingerprint(session.scripts_for(host), info.get("sample") or "")
                    skill_name = playbook.chosen(stack)
                    extra: list[dict] = []
                    action_n = 0
                    if stack == "next":
                        ids = surface.mine_actions(session.scripts_for(host), jar.get)
                        action_n = len(ids)
                        extra = surface.action_posts(ids, info.get("landed") or (surface._base(host) + "/")) + surface.rsc_gets(mapped)
                    replayed = surface.replay(calls + extra, jar, control.get("body") or b"")
                    checked = checked + replayed
                    replay_data = sum(1 for line in replayed if line.startswith("replay data ") or " data http" in line)
                    print(
                        f"replay {host} stack={stack} calls={len(calls)} actions={action_n} sent={len(replayed)} data={replay_data}",
                        flush=True,
                    )
                    (raw_dir / f"emptyjar_{host.replace(':', '_')}.out").write_text("\n".join(checked), encoding="utf-8")
                    data_n = sum(1 for line in checked if line.startswith("data ") or " data " in line)
                    print(
                        f"map {host} endpoints={len(mapped)} scripts={info.get('scripts')} observed={info.get('observed')} shapes={len(shaped)} data={data_n}",
                        flush=True,
                    )
                    if checked:
                        remember(notebook, cycle_findings, blobs, "emptyjar", host, "\n".join(checked))
                    # Deterministic injection battery: error-based SQLi + reflected
                    # XSS canaries on GET params and discovered <form> POSTs. Free,
                    # no model, no scanner -- detection no longer depends on the LLM
                    # being up or on dalfox. Emits suspect/suspect-xss lines the
                    # existing interesting()/confirm path already consumes.
                    probe_lines: list[str] = []
                    probe_pool: list[str] = []
                    # Cast a wide net for parameterized URLs: browser-observed,
                    # battery targets, AND everything discovered by gau/katana in
                    # the blobs. testaspnet's ReadNews.aspx?id= only showed up in
                    # the discovered set, not the browser-observed one.
                    candidates = list(page_urls) + battery.targets(checked)
                    for line in checked:
                        candidates += urls_from(line)
                    for blob in blobs:
                        candidates += urls_from(blob)
                    for u in candidates:
                        if not (isinstance(u, str) and u.startswith("http") and "?" in u):
                            continue
                        if u in probe_pool:
                            continue
                        if in_scope((urlparse(u).hostname or "").lower(), assets):
                            probe_pool.append(u)
                    for u in probe_pool[:12]:
                        try:
                            probe_lines += probes.probe_query(u, jar)
                        except Exception as exc:
                            print(f"probe query {host} failed {type(exc).__name__}", flush=True)
                    sample_html = info.get("sample") or ""
                    if sample_html:
                        try:
                            probe_lines += probes.probe_forms(sample_html, surface._base(host) + "/", jar)
                        except Exception as exc:
                            print(f"probe forms {host} failed {type(exc).__name__}", flush=True)
                    if probe_lines:
                        print(f"probes {host} suspects={len(probe_lines)}", flush=True)
                        remember(notebook, cycle_findings, blobs, "emptyjar", host, "\n".join(probe_lines))
                    done = set()
                    for url in battery.targets(checked):
                        for _name, method, headers, _body in battery.SHAPES:
                            done.add((method, url, tuple(sorted(headers))))
                    summary = json.dumps({
                        "host": host,
                        "routes": mapped[:40],
                        "results": [line[:180] for line in checked[:40]],
                    })
                    skill_text = playbook.text_for(skill_name)
                    if not skill_text:
                        print(f"skill {skill_name} missing", flush=True)
                        raw_ideas = ""
                    else:
                        raw_ideas = playbook.ask(skill_name, skill_text, summary)
                        ideas = battery.accept_ideas(host, raw_ideas, done, limit=8)
                        print(f"skill {skill_name} ideas={len(ideas)}", flush=True)
                        hits = 0
                        for idea in ideas:
                            first = jar.request(idea["method"], idea["url"], headers=idea["headers"], data=idea["data"])
                            kind = surface.classify(int(first.get("status") or 0), first.get("headers") or {}, first.get("body") or b"", control.get("body") or b"")
                            if kind == "suspect":
                                second = jar.request(idea["method"], idea["url"], headers=idea["headers"], data=idea["data"])
                                kind2 = surface.classify(int(second.get("status") or 0), second.get("headers") or {}, second.get("body") or b"", control.get("body") or b"")
                                if kind2 != "suspect":
                                    print(f"skill {skill_name} flaky-suspect {idea['url']}", flush=True)
                                    continue
                                hits += 1
                                line = f"suspect {idea['url']} status={first.get('status')}"
                                print(f"skill {skill_name} {line}", flush=True)
                                remember(notebook, cycle_findings, blobs, "emptyjar", idea["url"], line)
                                continue
                            if kind != "data":
                                print(f"skill {skill_name} {kind} {idea['method']} {idea['url']} status={first.get('status')}", flush=True)
                                continue
                            second = jar.request(idea["method"], idea["url"], headers=idea["headers"], data=idea["data"])
                            if (second.get("body") or b"") != (first.get("body") or b""):
                                print(f"skill {skill_name} unstable {idea['url']}", flush=True)
                                continue
                            hits += 1
                            line = surface.receipt(idea["url"], int(first.get("status") or 0), first.get("headers") or {}, first.get("body") or b"")
                            print(f"skill {skill_name} {line}", flush=True)
                            remember(notebook, cycle_findings, blobs, "emptyjar", idea["url"], line)
                        print(f"skill {skill_name} done data={hits}", flush=True)
                    landed_host = (urlparse(info.get("landed") or "").hostname or "").lower()
                    if landed_host and in_scope(landed_host, assets) and landed_host not in scanned and landed_host not in queue and landed_host not in seen:
                        queue.append(landed_host)
                scanned.add(host)
            else:
                print(f"skip rescan {host}", flush=True)
                if host in opened:
                    saw_app = True
                for extra_url in session.urls_for(host):
                    blobs.append(extra_url)
            publish("scan", len(cycle_findings), 0)

        if not saw_app and not args.bench:
            print("stop: the browser cannot see the app, so more tool calls will not either", flush=True)
            publish("blind", len(cycle_findings), 0)
            break
        if not saw_app and args.bench:
            print("browser blind; toolkit pass already ran", flush=True)

        cycle_findings.extend(harvest())
        if args.bench:
            print(f"cycle {cycle}: toolkit finished, {len(cycle_findings)} notes", flush=True)
            publish("toolkit-finished", len(cycle_findings), 0)
        proved = 0
        checks = 0
        # Tighter caps under --bench so the prove pass cannot thrash the box
        # into the SSH lockout we hit before.
        check_cap = 3 if args.bench else 6
        prove_rounds = 2 if args.bench else 4
        prove_tools = {"sqlmap", "ffuf", "feroxbuster", "curl", "gau", "hakrawler", "arjun", "emptyjar"}
        # Free deterministic confirm (sqlmap / marker re-fetch / dalfox) runs on
        # EVERY scan at zero credit cost. DeepSeek is only the fallback for leads
        # the free pass cannot settle -- opt-in under --bench (NABLUS_BENCH_PROVE=1),
        # always available in full mode when the key is set.
        paid_ok = extractor.enabled() and (not args.bench or os.environ.get("NABLUS_BENCH_PROVE") == "1")
        if args.bench and not paid_ok:
            print("bench: free confirm only (set NABLUS_BENCH_PROVE=1 for DeepSeek fallback)", flush=True)
        for item in cycle_findings:
            if checks >= check_cap:
                break
            if item.get("severity") not in {"medium", "high", "critical"} and item.get("tool") not in prove_tools:
                continue
            checks += 1
            lead = {
                "program": scope.get("program"),
                "authorization_ref": scope.get("authorization_ref"),
                "authorized_assets": sorted(assets),
                "lead": item,
            }
            notebook["leads"].append({"when": now(), "lead": item, "status": "checking"})
            result = freeconfirm.confirm(item, execute)
            if not result.get("confirmed") and paid_ok:
                result = extractor.prove(lead, execute, rounds=prove_rounds)
            how = "free" if result.get("free") else "deepseek"
            status = f"proved-{how}" if result.get("confirmed") else "unconfirmed"
            notebook["leads"][-1]["status"] = status
            if result.get("confirmed"):
                proved += 1
                excerpt = ""
                for row in result.get("response") or []:
                    excerpt = (row.get("output") or "")[-2000:]
                notebook["proofs"].append({
                    "when": now(),
                    "lead": item,
                    "method": how,
                    "extracted": result.get("extracted"),
                    "response_excerpt": excerpt,
                })
        notebook["leads"] = notebook["leads"][-100:]
        notebook_path.write_text(json.dumps(notebook, indent=2), encoding="utf-8")
        status_path.write_text(json.dumps({
            "updated": now(),
            "cycle": cycle,
            "hours_left": round((deadline - time.time()) / 3600, 2),
            "leads_this_cycle": len(cycle_findings),
            "proved_this_cycle": proved,
            "deepseek": extractor.enabled(),
            "model": os.environ.get("LLAMA_MODEL"),
        }, indent=2), encoding="utf-8")
        print(f"cycle {cycle}: {len(cycle_findings)} leads, proved {proved}", flush=True)
        if proved == 0:
            print("stop: catalog finished, no unauthenticated data", flush=True)
        else:
            print(f"stop: proved {proved}", flush=True)
        break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
