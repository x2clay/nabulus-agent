"""One pass of request shapes against the mapped routes.

Each shape is sent once, with no cookie. A route whose GET was the HTML
wall is not sent again. A shape that returns data is sent a second time
and kept only when the bodies match. Nothing in here calls a scanner.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

import surface

# method, extra headers, body. GET with the default headers already ran.
SHAPES: list[tuple[str, str, dict, bytes | None]] = [
    ("get-json", "GET", {"Accept": "application/json"}, None),
    ("post-json", "POST", {"Content-Type": "application/json", "Accept": "application/json"}, b"{}"),
    ("put-json", "PUT", {"Content-Type": "application/json", "Accept": "application/json"}, b"{}"),
    ("patch-json", "PATCH", {"Content-Type": "application/json", "Accept": "application/json"}, b"{}"),
    ("delete", "DELETE", {"Accept": "application/json"}, None),
    ("options", "OPTIONS", {}, None),
    ("bearer-null", "GET", {"Authorization": "Bearer null", "Accept": "application/json"}, None),
]


def _api(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return "/api" in path or "graphql" in path or "/_next/data" in path


def targets(lines: list[str]) -> list[str]:
    """Routes whose first GET was not the HTML wall."""
    out: list[str] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("http"):
            continue
        kind, url = parts[0], parts[1]
        if kind == "data":
            continue
        if kind in {"empty", "error"} or _api(url):
            if url not in out:
                out.append(url)
    return out


def run(urls: list[str], jar: surface.EmptyJar, control: bytes) -> list[str]:
    lines: list[str] = []
    seen: set[tuple] = set()
    for url in urls:
        for name, method, headers, body in SHAPES:
            key = (method, url, tuple(sorted(headers)))
            if key in seen:
                continue
            seen.add(key)
            first = jar.request(method, url, headers=headers, data=body)
            kind = surface.classify(
                int(first.get("status") or 0),
                first.get("headers") or {},
                first.get("body") or b"",
                control,
            )
            if kind != "data":
                lines.append(f"{kind} {name} {method} {url} status={first.get('status')}")
                continue
            second = jar.request(method, url, headers=headers, data=body)
            if (second.get("body") or b"") != (first.get("body") or b""):
                lines.append(f"unstable {name} {method} {url} status={first.get('status')}")
                continue
            lines.append(name + " " + surface.receipt(url, int(first.get("status") or 0), first.get("headers") or {}, first.get("body") or b""))
    return lines


def accept_ideas(host: str, raw: str, already: set[tuple], limit: int = 8) -> list[dict]:
    """Keep novel in-scope HTTP requests. Drop scanner names and repeats."""
    start, end = raw.find("{"), raw.rfind("}")
    if start < 0:
        return []
    try:
        data = json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return []
    host = host.lower()
    kept: list[dict] = []
    allowed = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
    for item in data.get("requests") or []:
        if not isinstance(item, dict) or len(kept) >= limit:
            break
        method = str(item.get("method") or "GET").upper()
        url = str(item.get("url") or "")
        if method not in allowed or not url.startswith("http"):
            continue
        got = (urlparse(url).hostname or "").lower()
        if got != host and not got.endswith("." + host):
            continue
        headers = item.get("headers") if isinstance(item.get("headers"), dict) else {}
        headers = {
            str(k): str(v)[:200]
            for k, v in list(headers.items())[:6]
            if str(k).lower() not in {"cookie", "host"}
        }
        key = (method, url.split("#", 1)[0], tuple(sorted(headers)))
        if key in already:
            continue
        already.add(key)
        body = item.get("body")
        if isinstance(body, (dict, list)):
            payload = json.dumps(body).encode()[:2000]
        elif isinstance(body, str):
            payload = body.encode()[:2000]
        else:
            payload = None
        kept.append({"method": method, "url": url.split("#", 1)[0], "headers": headers, "data": payload})
    return kept
