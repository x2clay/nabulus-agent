#!/usr/bin/env python3
"""crawl.py - browser-based endpoint & parameter discovery for SPAs.

Why a browser: a Next.js/React SPA renders routes client-side and talks to its backend via XHR/
fetch to /api/... - a static crawler (katana/httpx) sees only the shell HTML and MISSES the real
attack surface. We load pages in the hardened headless browser and record every in-scope network
request (document, XHR, fetch), keeping those that carry query params, hit /api-like paths, or use
a non-GET method. Those parameterized endpoints are what the vector probes should actually target.

Scope-gated (never records or navigates off the authorized apex). Read-only navigation; no form
submission, no state change. Output: endpoints.json = [{url, method, params, source}].
"""
from __future__ import annotations
import sys, json, argparse, pathlib, urllib.parse
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from runner import Scope
from authz_probe import in_scope
from browser import hardened_context
from playwright.sync_api import sync_playwright

_APIISH = ("/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/_next/data/")


def _key(u: str) -> str:
    p = urllib.parse.urlparse(u)
    return f"{p.scheme}://{p.netloc}{p.path}"


def crawl(seeds, assets, max_pages: int, out_path: str) -> dict:
    endpoints: dict[str, dict] = {}
    pages_links: set[str] = set()

    def record(url: str, method: str, source: str):
        p = urllib.parse.urlparse(url)
        if not (p.hostname and in_scope(assets, p.hostname)):
            return
        params = sorted(urllib.parse.parse_qs(p.query).keys())
        apiish = any(s in p.path.lower() for s in _APIISH)
        if not (params or apiish or method != "GET"):
            return
        k = _key(url) + ("?" + "&".join(params) if params else "")
        if k not in endpoints:
            endpoints[k] = {"url": url.split("#")[0], "path": p.path, "method": method,
                            "params": params, "source": source}

    to_visit, visited = list(seeds), set()
    with sync_playwright() as pw:
        with hardened_context(pw) as ctx:
            page = ctx.new_page()
            page.on("request", lambda r: record(r.url, r.method, "network"))
            while to_visit and len(visited) < max_pages:
                u = to_visit.pop(0).split("#")[0]
                if u in visited:
                    continue
                visited.add(u)
                hp = urllib.parse.urlparse(u)
                if not (hp.hostname and in_scope(assets, hp.hostname)):
                    continue
                try:
                    page.goto(u, wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(700)
                    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                except Exception:
                    continue
                for h in hrefs or []:
                    h = h.split("#")[0]
                    hp2 = urllib.parse.urlparse(h)
                    if hp2.scheme in ("http", "https") and hp2.hostname and in_scope(assets, hp2.hostname):
                        pages_links.add(h)
                        if h not in visited and h not in to_visit:
                            to_visit.append(h)

    result = {"pages_visited": sorted(visited), "endpoints": list(endpoints.values())}
    pathlib.Path(out_path).write_text(json.dumps(result, indent=2))
    print(f"[crawl] visited {len(visited)} page(s), found {len(endpoints)} parameterized/api endpoint(s)")
    for e in endpoints.values():
        print(f"  {e['method']:4} {e['path']}  params={e['params']}")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", nargs="+", required=True, help="seed URLs to start crawling")
    ap.add_argument("--scope", default="scope.json")
    ap.add_argument("--max-pages", type=int, default=40)
    ap.add_argument("--out", default="endpoints.json")
    a = ap.parse_args()
    scope = Scope(json.loads(pathlib.Path(a.scope).read_text()))
    # refuse any seed outside scope up front
    for s in a.seeds:
        h = urllib.parse.urlparse(s).hostname
        if h and not in_scope(scope.assets, h):
            print(f"REFUSED: seed {h} not in scope")
            return 2
    crawl(a.seeds, scope.assets, a.max_pages, a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
