#!/usr/bin/env python3
r"""recon_harness.py - the discovery driver (black-box, anonymous, zero-creds).

Turns a ROOT SCOPE into the wide attack surface the detectors need: live hosts, endpoints, and
hidden parameters. This is the "scope / multi-host" arm of the bounty path -- the detectors are
only as good as the surface you point them at, and this is what finds the non-dupe surface.

Pipeline:
  subfinder   -> subdomains of each in-scope domain (skipped for bare IP/localhost scope)
  httpx       -> live-probe candidate hosts (status/title/tech); only live, in-scope hosts kept
  katana      -> crawl live hosts for endpoints (bounded depth/count)
  gau         -> passive URLs from wayback/CT for public domains (skipped for localhost)
  arjun       -> discover hidden GET params on a bounded set of endpoints (feeds EVERY detector)

SCOPE ENFORCEMENT (our own -- we do not use any external framework's RoE handling): every host
produced by any stage is filtered through an in-scope matcher derived from NABLUS_SCOPE before it
is probed, crawled, or reported. A domain root authorizes that domain and its subdomains; a bare
host or IP authorizes only that exact host. Nothing off-scope is ever contacted. This is a passive
mapping tool: it enumerates and probes, it does not attack -- the detectors do that, within scope.

Output artifact `recon_targets.json`:
  {"scope":[...], "hosts":[{url,status,title,tech}], "endpoints":[...urls...],
   "params":{url:[names...]}, "seeds":"ep1,ep2,..."}  <- `seeds` is NABLUS_SEEDS-ready.

Self-contained stage: reads NABLUS_SCOPE (fallback NABLUS_TARGET), writes recon_targets.json.
"""
from __future__ import annotations  # noqa
import os, re, json, subprocess, tempfile, ipaddress, pathlib
from urllib.parse import urlsplit

WORKDIR = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get("NABLUS_TOOLBIN", r"C:\Users\Laith\nabulus-tools\bin")
OUT = r"C:\Users\Laith\nabulus-agent\recon_targets.json"

SCOPE_RAW = os.environ.get("NABLUS_SCOPE") or os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099")
SCOPE = [s.strip() for s in SCOPE_RAW.split(",") if s.strip()]

KATANA_DEPTH = os.environ.get("NABLUS_RECON_DEPTH", "2")
MAX_ENDPOINTS = int(os.environ.get("NABLUS_RECON_MAX_EP", "200"))
ARJUN_MAX = int(os.environ.get("NABLUS_RECON_ARJUN_MAX", "8"))     # endpoints to param-mine
ARJUN_ON = os.environ.get("NABLUS_RECON_ARJUN", "1").strip() not in ("0", "false", "no")
STAGE_TIMEOUT = int(os.environ.get("NABLUS_RECON_STAGE_TIMEOUT", "300"))


def tool(name):
    p = pathlib.Path(BIN) / (name + ".exe")
    return str(p) if p.exists() else None


def _host_of(s: str) -> str:
    s = s.strip().lower()
    netloc = urlsplit(s if "//" in s else "//" + s)
    return (netloc.hostname or s).strip("[]")


def _is_ipish(h: str) -> bool:
    if h in ("localhost",):
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def build_scope(roots):
    """Return (in_scope(host)->bool, domains, exact_hosts)."""
    exact, domains = set(), set()
    for r in roots:
        h = _host_of(r)
        (exact if _is_ipish(h) else domains).add(h)

    def in_scope(host: str) -> bool:
        h = (host or "").strip().lower().strip("[]")
        if h in exact:
            return True
        return any(h == d or h.endswith("." + d) for d in domains)

    return in_scope, domains, exact


def run(argv, stdin_text=None, timeout=STAGE_TIMEOUT):
    try:
        p = subprocess.run(argv, cwd=WORKDIR, capture_output=True, text=True,
                           input=stdin_text, timeout=timeout)
        return p.stdout or ""
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired as e:
        return (e.stdout or "") if isinstance(e.stdout, str) else ""


def stage_subfinder(domains, in_scope):
    sf = tool("subfinder")
    if not sf or not domains:
        return set()
    hosts = set()
    for d in domains:
        out = run([sf, "-silent", "-d", d, "-duc", "-nc"])
        for ln in out.splitlines():
            h = ln.strip().lower()
            if h and in_scope(h):
                hosts.add(h)
    return hosts


def stage_httpx(candidate_hosts, in_scope):
    """Live-probe; return list of {url,status,title,tech} for live, in-scope hosts."""
    hx = tool("httpx")
    if not hx:
        return []
    feed = "\n".join(sorted(candidate_hosts)) + "\n"
    out = run([hx, "-silent", "-nc", "-json", "-timeout", "10", "-retries", "1",
               "-title", "-tech-detect", "-status-code", "-no-fallback"], stdin_text=feed)
    live = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            r = json.loads(ln)
        except Exception:
            continue
        url = r.get("url") or r.get("input") or ""
        if not in_scope(_host_of(url)):
            continue
        live.append({"url": url, "status": r.get("status_code") or r.get("status-code"),
                     "title": r.get("title") or "", "tech": r.get("tech") or r.get("technologies") or []})
    return live


def stage_katana(live_urls, in_scope):
    kt = tool("katana")
    if not kt or not live_urls:
        return set()
    fd, tp = tempfile.mkstemp(suffix=".txt", dir=WORKDIR, prefix="katana_")
    os.close(fd)
    pathlib.Path(tp).write_text("\n".join(live_urls) + "\n", encoding="utf-8")
    # -jc crawl js, -kf known files, bounded depth/concurrency, scope held by -fs fqdn + our filter
    out = run([kt, "-silent", "-nc", "-list", tp, "-d", KATANA_DEPTH, "-jc", "-kf", "all",
               "-c", "10", "-timeout", "10", "-fs", "fqdn"])
    pathlib.Path(tp).unlink(missing_ok=True)
    eps = set()
    for ln in out.splitlines():
        u = ln.strip()
        if u.startswith("http") and in_scope(_host_of(u)):
            eps.add(u)
    return eps


def stage_gau(domains, in_scope):
    g = tool("gau")
    if not g or not domains:
        return set()
    eps = set()
    for d in domains:
        out = run([g, "--subs", "--threads", "5", d])
        for ln in out.splitlines():
            u = ln.strip()
            if u.startswith("http") and in_scope(_host_of(u)):
                eps.add(u)
    return eps


def stage_arjun(endpoints):
    """Hidden GET-param discovery on a bounded set of endpoints (py -m arjun)."""
    if not ARJUN_ON or not endpoints:
        return {}
    params = {}
    picks = sorted(endpoints)[:ARJUN_MAX]
    for u in picks:
        fd, tp = tempfile.mkstemp(suffix=".json", dir=WORKDIR, prefix="arjun_")
        os.close(fd)
        run(["py", "-3", "-I", "-m", "arjun", "-u", u, "-m", "GET", "-oJ", tp,
             "--stable"], timeout=120)
        try:
            data = json.loads(pathlib.Path(tp).read_text(encoding="utf-8"))
            # arjun json: {url: {"params":[...], ...}} or {url:[...]}
            for k, v in data.items():
                names = v.get("params") if isinstance(v, dict) else v
                if names:
                    params[k] = sorted(set(names))
        except Exception:
            pass
        finally:
            pathlib.Path(tp).unlink(missing_ok=True)
    return params


def main():
    in_scope, domains, exact = build_scope(SCOPE)
    print(f"[recon] scope: domains={sorted(domains)} exact={sorted(exact)}")

    # 1) candidate hosts = scope roots + enumerated subdomains
    candidates = set(_host_of(r) for r in SCOPE) | stage_subfinder(domains, in_scope)
    # preserve scheme+port from roots for the probe feed
    feed_hosts = set(SCOPE) | candidates
    print(f"[recon] candidate hosts: {len(candidates)}")

    # 2) live probe
    hosts = stage_httpx(feed_hosts, in_scope)
    live_urls = [h["url"] for h in hosts] or [r for r in SCOPE]       # fall back to roots
    print(f"[recon] live hosts: {len(live_urls)}")

    # 3) crawl + 4) passive urls
    endpoints = set(live_urls)
    endpoints |= stage_katana(live_urls, in_scope)
    endpoints |= stage_gau(domains, in_scope)
    endpoints = set(sorted(endpoints)[:MAX_ENDPOINTS])
    print(f"[recon] endpoints discovered: {len(endpoints)}")

    # 5) param discovery
    params = stage_arjun(endpoints)
    print(f"[recon] endpoints with discovered params: {len(params)}")

    # seeds = endpoint paths (what the detectors consume via NABLUS_SEEDS)
    seeds = sorted({urlsplit(u).path for u in endpoints if urlsplit(u).path not in ("", "/")})
    artifact = {
        "scope": SCOPE,
        "hosts": hosts,
        "endpoints": sorted(endpoints),
        "params": params,
        "seeds": ",".join(seeds),
    }
    pathlib.Path(OUT).write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    print(f"[recon] wrote {OUT}: {len(seeds)} seed path(s), {len(hosts)} live host(s)")
    for u in sorted(endpoints)[:20]:
        print(f"    {u}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
