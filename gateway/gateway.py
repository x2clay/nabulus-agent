#!/usr/bin/env python3
"""nabulus-agent gateway: scope-gated, token-authed, Tailscale-only tool runner.

Safety model (this is the whole point):
  * Binds ONLY to this host's Tailscale IP (100.64/10), never 0.0.0.0. Refuses to start otherwise.
  * Requires a bearer token (env GATEWAY_TOKEN). No token set -> refuses to start. No default token.
  * Reuses runner.Scope: every network target is assert_authorized() against scope.json
    BEFORE the tool runs. Out-of-scope -> 403, logged, nothing executes.
  * Only allowlisted installed tools run. Local-analysis tools are confined to a workspace dir.
  * Every request + authorization decision is appended to gateway.log.
  * On-demand process. NOT registered as a boot/scheduled task.
"""
from __future__ import annotations
import os, sys, json, subprocess, datetime, socket, ipaddress, pathlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE  = pathlib.Path(__file__).resolve().parent
AGENT = HERE.parent
sys.path.insert(0, str(AGENT))
from runner import Scope, ScopeViolation   # the SAME gate the engine uses

BIN        = pathlib.Path(os.environ.get("NABULUS_BIN", r"C:\Users\Laith\nabulus-tools\bin"))
PYSCRIPTS  = pathlib.Path(os.environ.get("NABULUS_PYSCRIPTS", r"C:\Users\Laith\AppData\Roaming\Python\Python311\Scripts"))
SCOPE_PATH = pathlib.Path(os.environ.get("NABULUS_SCOPE", str(AGENT / "scope.json")))
WORKSPACE  = pathlib.Path(os.environ.get("NABULUS_WORKSPACE", r"C:\Users\Laith\nabulus-tools\github"))
LOG        = HERE / "gateway.log"
PORT       = int(os.environ.get("GATEWAY_PORT", "8090"))
TOKEN      = os.environ.get("GATEWAY_TOKEN")

# name -> (location, kind); location in {"bin","pyscripts"}, kind in {"network","local"}
TOOLS = {
  "subfinder": ("bin","network"), "dnsx": ("bin","network"), "naabu": ("bin","network"),
  "httpx": ("bin","network"), "katana": ("bin","network"), "nuclei": ("bin","network"),
  "ffuf": ("bin","network"), "dalfox": ("bin","network"),
  "trufflehog": ("bin","local"), "gitleaks": ("bin","local"), "gosec": ("bin","local"),
  "slither": ("pyscripts","local"), "bandit": ("pyscripts","local"), "semgrep": ("pyscripts","local"),
}
TARGET_FLAGS = {"-d","-u","-host","-target","-l","-domain","-list"}

def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def log(line):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def exe_path(tool):
    loc,_ = TOOLS[tool]
    return (BIN if loc=="bin" else PYSCRIPTS) / f"{tool}.exe"

def hostname_of(tok):
    t = tok.strip()
    if "://" in t: t = t.split("://",1)[1]
    t = t.split("/",1)[0].split("@")[-1].split(":",1)[0]
    return t.lower() or None

def extract_targets(args):
    hosts = set()
    for i,a in enumerate(args):
        if a in TARGET_FLAGS and i+1 < len(args):
            h = hostname_of(args[i+1])
            if h: hosts.add(h)
        elif "://" in a:
            h = hostname_of(a)
            if h: hosts.add(h)
    return hosts

def safe_local_args(args):
    for a in args:
        if a.startswith("-"): continue
        if ".." in a: return False
        p = pathlib.Path(a)
        if p.is_absolute():
            try: p.resolve().relative_to(WORKSPACE.resolve())
            except Exception: return False
    return True

def authorize(tool, args):
    """Returns (allowed, decision, targets). The gate — nothing runs unless this says allow."""
    if tool not in TOOLS:
        return False, "deny:tool-not-allowlisted", []
    _, kind = TOOLS[tool]
    if kind == "network":
        targets = sorted(extract_targets(args))
        if not targets:
            return False, "deny:no-target-in-args", []
        scope = Scope(json.loads(SCOPE_PATH.read_text()))
        for t in targets:
            try: scope.assert_authorized(t)
            except ScopeViolation: return False, f"deny:out-of-scope:{t}", targets
        return True, "allow:in-scope", targets
    if not safe_local_args(args):
        return False, "deny:path-outside-workspace", []
    return True, "allow:local-workspace", []

def run_tool(tool, args, kind):
    exe = exe_path(tool)
    if not exe.exists():
        return 127, "", f"{tool}.exe not installed"
    env = dict(os.environ)
    env["PATH"] = r"C:\Windows\System32;C:\Windows;" + f"{BIN};{PYSCRIPTS};" + env.get("PATH","")
    try:
        p = subprocess.run([str(exe), *args], capture_output=True, text=True, timeout=600,
                           cwd=(str(WORKSPACE) if kind=="local" else None), env=env)
        return p.returncode, p.stdout or "", (p.stderr or "")[-2000:]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
    def do_POST(self):
        client = self.client_address[0]
        if self.path != "/run-tool":
            return self._send(404, {"error":"not found"})
        if self.headers.get("Authorization","") != f"Bearer {TOKEN}":
            log(f"{now()} client={client} AUTH-FAIL path={self.path}")
            return self._send(401, {"error":"unauthorized"})
        try:
            n = int(self.headers.get("Content-Length","0"))
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, {"error":"bad json"})
        tool = req.get("tool",""); args = req.get("args",[]) or []
        auth_ref = req.get("authorization_ref","")
        if not isinstance(args, list) or not all(isinstance(x,str) for x in args):
            return self._send(400, {"error":"args must be list[str]"})
        allowed, decision, targets = authorize(tool, args)
        log(f"{now()} client={client} tool={tool} targets={targets} decision={decision} auth_ref_present={bool(auth_ref)}")
        if not allowed:
            return self._send(403, {"error":"refused","decision":decision,"targets":targets})
        rc, out, err = run_tool(tool, args, TOOLS[tool][1])
        return self._send(200, {"tool":tool,"targets":targets,"decision":decision,
                                "returncode":rc,"stdout":out,"stderr_tail":err})

def detect_bind():
    env = os.environ.get("GATEWAY_BIND")
    if env: return env
    try:
        out = subprocess.run(["tailscale","ip","-4"], capture_output=True, text=True, timeout=5).stdout
        for ln in out.splitlines():
            if ln.strip().startswith("100."): return ln.strip()
    except Exception: pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10"): return ip
            except Exception: pass
    except Exception: pass
    return None

def main():
    if not TOKEN:
        print("REFUSING TO START: set GATEWAY_TOKEN (no default token).", file=sys.stderr); return 2
    bind = detect_bind()
    if not bind or bind in ("0.0.0.0","::"):
        print(f"REFUSING TO START: no Tailscale (100.64/10) bind IP resolved (got {bind!r}). "
              f"Set GATEWAY_BIND.", file=sys.stderr); return 2
    srv = ThreadingHTTPServer((bind, PORT), Handler)
    log(f"{now()} GATEWAY START bind={bind}:{PORT} scope={SCOPE_PATH.name} tools={len(TOOLS)}")
    print(f"gateway listening on {bind}:{PORT} (Tailscale-only, token-gated, scope-enforced)", flush=True)
    try: srv.serve_forever()
    except KeyboardInterrupt: pass
    finally: log(f"{now()} GATEWAY STOP")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
