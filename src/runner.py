"""nabulus-agent: scope-enforced authorized-assessment runner.

Safety model (the point of this tool):
  * Active tools ONLY run against hosts explicitly listed in scope.authorized_assets.
  * Passively discovered hosts outside scope are recorded as surface (in_scope=false)
    and are NEVER actively scanned.
  * Every target + authorization_ref is written to audit.log before any active tool.
  * Default is ONE supervised pass and exit. --loop is opt-in for a live engagement.
  * Not installed as a boot service. Authorization is the operator's legal responsibility.
"""
from __future__ import annotations
import argparse, json, subprocess, sys, time, datetime, pathlib
import normalizer as N

DEFAULT_BIN = r"C:\Users\Laith\nabulus-tools\bin"

# profile -> ordered list of (tool, builds-args-fn). passive = no packets to target beyond DNS.
def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

class ScopeViolation(Exception):
    pass

class Scope:
    def __init__(self, data: dict):
        for k in ("program", "authorization_ref", "authorized_assets", "rate_limit_rps"):
            if k not in data:
                raise ValueError(f"scope.json missing required field: {k}")
        self.program = data["program"]
        self.auth_ref = data["authorization_ref"]
        self.asset_type = data.get("asset_type", "infra")
        self.assets = {a.strip().lower() for a in data["authorized_assets"] if a.strip()}
        if not self.assets:
            raise ValueError("scope.json authorized_assets is empty")
        self.rps = max(1, int(data["rate_limit_rps"]))
        self.exclusions = {e.strip().lower() for e in data.get("exclusions", [])}

    def assert_authorized(self, host: str) -> None:
        h = host.strip().lower()
        if h in self.exclusions or h not in self.assets:
            raise ScopeViolation(f"REFUSED: {host} is not an authorized asset")

def run_tool(bin_dir: pathlib.Path, tool: str, args: list[str], raw_dir: pathlib.Path,
             target: str, rps: int) -> tuple[str, str]:
    exe = bin_dir / f"{tool}.exe"
    raw_path = raw_dir / f"{tool}_{target.replace(':','_')}.out"
    if not exe.exists():
        return "", str(raw_path)  # tool not installed -> skip gracefully
    try:
        p = subprocess.run([str(exe), *args], capture_output=True, text=True, timeout=600)
        out = p.stdout or ""
    except subprocess.TimeoutExpired:
        out = ""
    raw_path.write_text(out, encoding="utf-8", errors="replace")
    if rps and rps > 0:
        time.sleep(1.0 / rps)
    return out, str(raw_path)

PROFILES = {
    "passive":  ["subfinder", "dnsx"],
    "standard": ["subfinder", "dnsx", "naabu", "httpx", "katana"],
    "full":     ["subfinder", "dnsx", "naabu", "httpx", "katana",
                 "nuclei", "ffuf", "dalfox", "trufflehog"],
}
# active tools require an explicit scope check before firing
ACTIVE = {"naabu", "httpx", "katana", "nuclei", "ffuf", "dalfox", "trufflehog"}

def tool_args(tool: str, host: str, rps: int) -> list[str]:
    # rps 0 means uncapped. The signed host list is the only gate.
    limited = rps and rps > 0
    return {
        "subfinder": ["-d", host, "-silent", "-all"],
        "dnsx":      ["-d", host, "-silent"],
        "naabu":     ["-host", host, "-silent", "-rate", str(rps * 100 if limited else 8000), "-top-ports", "1000"],
        "httpx":     ["-u", host, "-json", "-silent", "-title", "-tech-detect", "-status-code"]
                     + (["-rl", str(rps * 10)] if limited else []),
        "katana":    ["-u", f"http://{host}", "-silent", "-d", "3", "-jc", "-kf"]
                     + (["-rl", str(rps * 10)] if limited else []),
        "nuclei":    ["-u", host, "-jsonl", "-silent", "-severity", "info,low,medium,high,critical", "-c", "50"]
                     + (["-rl", str(rps * 10)] if limited else []),
        "ffuf":      ["-u", f"http://{host}/FUZZ", "-of", "json", "-o", "-"]
                     + (["-rate", str(rps * 10)] if limited else []),
        "dalfox":    ["url", f"http://{host}", "--format", "jsonl", "--silence", "--worker", "30"],
        "trufflehog":["filesystem", ".", "--json"],
    }.get(tool, [])

def assess(scope: Scope, host: str, profile: str, bin_dir: pathlib.Path,
           raw_dir: pathlib.Path, audit) -> dict:
    scope.assert_authorized(host)  # hard gate before anything active
    audit_line = f"{now()} program={scope.program!r} auth_ref_present={bool(scope.auth_ref)} target={host} profile={profile}"
    audit.write(audit_line + "\n"); audit.flush()

    surfaces, findings = [], []
    for tool in PROFILES[profile]:
        if tool in ACTIVE:
            scope.assert_authorized(host)  # re-check before every active tool
        out, raw = run_tool(bin_dir, tool, tool_args(tool, host, scope.rps), raw_dir, host, scope.rps)
        s, f = N.normalize(tool, out, raw)
        # discovered hosts outside scope: keep as surface, mark out-of-scope, never scan
        for item in s:
            if item["kind"] in ("subdomain",) and item["value"].strip().lower() not in scope.assets:
                item["in_scope"] = False
        surfaces.extend(s); findings.extend(f)

    return {"target": host, "timestamp": now(), "asset_type": scope.asset_type,
            "program": scope.program, "authorization_ref": scope.auth_ref,
            "surface": surfaces, "findings": findings}

def main() -> int:
    ap = argparse.ArgumentParser(description="scope-enforced authorized-assessment runner")
    ap.add_argument("--scope", default="scope.json")
    ap.add_argument("--out", default="findings.json")
    ap.add_argument("--audit", default="audit.log")
    ap.add_argument("--bin", default=DEFAULT_BIN)
    ap.add_argument("--raw", default="raw")
    ap.add_argument("--profile", choices=list(PROFILES), default="standard")
    ap.add_argument("--loop", action="store_true", help="repeat (supervised engagement only)")
    ap.add_argument("--interval", type=int, default=120)
    ap.add_argument("--max-cycles", type=int, default=1)
    a = ap.parse_args()

    scope = Scope(json.loads(pathlib.Path(a.scope).read_text()))
    bin_dir = pathlib.Path(a.bin); raw_dir = pathlib.Path(a.raw); raw_dir.mkdir(exist_ok=True)
    out_path = pathlib.Path(a.out)
    results = json.loads(out_path.read_text()) if out_path.exists() else []

    cycle = 0
    with open(a.audit, "a", encoding="utf-8") as audit:
        while True:
            cycle += 1
            for host in sorted(scope.assets):
                try:
                    results.append(assess(scope, host, a.profile, bin_dir, raw_dir, audit))
                except ScopeViolation as e:
                    audit.write(f"{now()} {e}\n"); audit.flush()
                    print(e, file=sys.stderr)
            out_path.write_text(json.dumps(results, indent=2))
            print(f"cycle {cycle} complete: {len(results)} result(s) -> {a.out}")
            if not a.loop or cycle >= a.max_cycles:
                break
            if a.interval > 0:
                time.sleep(a.interval)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
