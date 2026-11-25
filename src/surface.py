"""Unauthenticated endpoint map and empty-session check.

Script text and the calls the page made become a list of URLs.
Each candidate is requested twice with no Cookie header. Set-Cookie on
an answer is never sent again. A hit is recorded only when both answers
match and the body is neither a login wall nor the app's catch-all shell.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

_QUOTED_PATH = re.compile(r"""["'`](/(?:[^"'`\\\s]{1,160}))["'`]""")
_MAP_URL = re.compile(r"sourceMappingURL=([^\s\"'`]+)")
_STATIC = re.compile(
    r"\.(?:png|jpe?g|gif|webp|svg|ico|css|woff2?|ttf|eot|mp4|webm|map|txt)(?:\?|$)",
    re.I,
)
_ERR_KEYS = {
    "error", "errors", "message", "msg", "status", "code", "ok", "success",
    "detail", "title", "type", "statuscode", "errorcode", "timestamp", "path",
}
_LOGIN_LOC = ("/login", "/signin", "/sign-in", "/log-in", "/session/new")


def _base(host: str) -> str:
    """Scheme+authority for a scan target. Public bare hosts keep the historic
    https default; internal targets (localhost, explicit :port, private IP)
    use plain http. Accepts a full URL and returns it normalized."""
    h = (host or "").strip()
    if h.startswith("http://") or h.startswith("https://"):
        return h.rstrip("/")
    authority = h.split("/")[0]
    hostpart = authority.split(":")[0]
    internal = (
        ":" in authority
        or hostpart in ("localhost", "127.0.0.1", "::1")
        or hostpart.startswith("127.")
        or hostpart.startswith("10.")
        or hostpart.startswith("192.168.")
    )
    return ("http://" if internal else "https://") + h

def keep_path(path: str) -> bool:
    """A route worth requesting. Static build files are not routes."""
    if not path or not path.startswith("/") or path.startswith("//"):
        return False
    if any(bit in path for bit in ("..", " ", "\\", "${", "*", "<", ">", "{", "}", "$", "&")):
        return False
    lower = path.lower()
    if lower.startswith(("/_next/static/", "/static/", "/assets/", "/node_modules/")):
        return False
    if _STATIC.search(lower):
        return False
    if lower in {"/", "/favicon.ico", "/robots.txt"}:
        return False
    return True


_ACTION = re.compile(
    r"createServerReference\([\s\S]{0,160}?[\"']([0-9a-f]{32,64})[\"']",
    re.I,
)
_REPLAY_HEADERS = {
    "accept", "content-type", "rsc", "next-action", "next-router-state-tree",
    "next-router-prefetch", "next-router-segment-prefetch", "next-url",
}


def worth_recording(kind: str, method: str, url: str, headers: dict | None) -> bool:
    """True for a same-site call the empty jar should replay.

    Any xhr, fetch, other, or document request counts. Images, fonts, and
    stylesheets do not. Framework-specific headers are not required.
    """
    del method, headers
    kind = (kind or "").lower()
    path = (urlparse(url).path or "").lower()
    if _STATIC.search(path) or "/_next/static/" in path:
        return False
    return kind in {"xhr", "fetch", "other", "document"}


def replay_headers(headers: dict | None) -> dict:
    """Headers worth sending again. Cookie and host are never copied."""
    kept: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if str(key).lower() not in _REPLAY_HEADERS or len(kept) >= 8:
            continue
        kept[str(key)] = str(value)[:300]
    return kept


def action_ids(text: str) -> list[str]:
    found: list[str] = []
    for match in _ACTION.findall(text or ""):
        if match not in found:
            found.append(match)
        if len(found) >= 12:
            break
    return found


def mine_actions(scripts: list[str], fetch, limit_scripts: int = 10) -> list[str]:
    found: list[str] = []
    for src in scripts[:limit_scripts]:
        got = fetch(src) if src.startswith("http") else {"body": b""}
        body = got.get("body") or b""
        text = body if isinstance(body, str) else body[:400_000].decode("utf-8", "replace")
        for item in action_ids(text):
            if item not in found:
                found.append(item)
            if len(found) >= 8:
                return found
    return found


def rsc_gets(urls: list[str], limit: int = 12) -> list[dict]:
    """The GET a Next.js client sends when it navigates, for routes already on the map."""
    out: list[dict] = []
    seen: set[str] = set()
    for url in urls:
        base = str(url or "").split("#", 1)[0]
        if not base.startswith("http"):
            continue
        full = base if "_rsc=" in base else base + ("&" if "?" in base else "?") + "_rsc=1"
        if full in seen:
            continue
        seen.add(full)
        out.append({
            "method": "GET",
            "url": full,
            "headers": {"RSC": "1", "Accept": "text/x-component"},
            "body": "",
        })
        if len(out) >= limit:
            break
    return out


def action_posts(ids: list[str], page_url: str) -> list[dict]:
    """One empty server-action POST per id, aimed at the page that loaded it."""
    page = (page_url or "").split("#", 1)[0]
    if not page.startswith("http"):
        return []
    posts: list[dict] = []
    for action_id in ids[:8]:
        posts.append({
            "method": "POST",
            "url": page,
            "headers": {
                "Next-Action": action_id,
                "Accept": "text/x-component",
                "Content-Type": "text/plain;charset=UTF-8",
            },
            "body": "[]",
        })
    return posts


def paths_from_js(text: str) -> list[str]:
    found: list[str] = []
    for match in _QUOTED_PATH.findall(text or ""):
        path = match.split("?", 1)[0]
        if keep_path(path) and path not in found:
            found.append(path)
        if len(found) >= 80:
            break
    return found


def map_urls_from_js(text: str) -> list[str]:
    found: list[str] = []
    for raw in _MAP_URL.findall(text or ""):
        raw = raw.strip()
        if not raw or raw.startswith("data:"):
            continue
        if raw not in found:
            found.append(raw)
    return found


def paths_from_sourcemap(text: str) -> tuple[list[str], list[str]]:
    """Route paths found in a map, plus source file names for the receipt.

    File contents from the map are not returned.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], []
    if not isinstance(data, dict):
        return [], []
    names: list[str] = []
    routes: list[str] = []
    for src in data.get("sources") or []:
        if not isinstance(src, str):
            continue
        base = src.rsplit("/", 1)[-1]
        if base and base not in names and len(names) < 30:
            names.append(base)
    blob = "\n".join(s for s in (data.get("sourcesContent") or []) if isinstance(s, str))
    blob = blob[:1_500_000]
    for path in paths_from_js(blob):
        if path not in routes:
            routes.append(path)
    return routes, names


def _norm(body: bytes) -> bytes:
    return re.sub(rb"\s+", b" ", body[:200_000]).strip()


def _login_wall(status: int, body: bytes, location: str) -> bool:
    if status in {401, 403}:
        return True
    loc = (location or "").lower()
    if any(bit in loc for bit in _LOGIN_LOC):
        return True
    head = body[:12_000].lower()
    return b"type=\"password\"" in head or b"type='password'" in head or b"type=password" in head


def _walk_substance(obj, depth: int = 0) -> bool:
    if depth > 6:
        return False
    if isinstance(obj, list):
        return any(_walk_substance(item, depth + 1) for item in obj[:30])
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in _ERR_KEYS and not isinstance(value, (dict, list)):
                continue
            if isinstance(value, (dict, list)):
                if _walk_substance(value, depth + 1):
                    return True
                continue
            if isinstance(value, str) and len(value) >= 24:
                return True
            if value not in (None, "", False, True, 0):
                return True
        return False
    if isinstance(obj, str):
        return len(obj) >= 24
    return obj not in (None, "", False, True, 0)


def classify(status: int, headers: dict, body: bytes, control: bytes | None) -> str:
    """wall, shell, page, data, empty, or error."""
    if status <= 0:
        return "error"
    location = ""
    ctype = ""
    for key, value in headers.items():
        if key.lower() == "location":
            location = value
        elif key.lower() == "content-type":
            ctype = value.lower()
    wall = _login_wall(status, body, location)
    if status in {301, 302, 303, 307, 308}:
        return "wall" if wall else "page"
    if not body.strip():
        return "wall" if wall else "empty"
    if control is not None and _norm(body) == _norm(control) and control.strip():
        return "shell"
    try:
        parsed = json.loads(body[:700_000].decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeError):
        parsed = None
    if isinstance(parsed, dict) and "mappings" in parsed and isinstance(parsed.get("sources"), list):
        content = parsed.get("sourcesContent") or []
        if any(isinstance(item, str) and item.strip() for item in content):
            return "data"
        return "page"
    if isinstance(parsed, (dict, list)) and _walk_substance(parsed):
        return "data"
    if "json" in ctype and isinstance(parsed, (dict, list)):
        return "empty"
    # Error-based injection tell: a server fault the baseline did not throw
    # (id=1' -> 500). A LEAD for the prove phase, not a confirmed finding.
    if status >= 500 and not wall:
        return "suspect"
    # File-disclosure tell: a 200 that differs from the app shell and carries
    # OS/file markers (path traversal -> win.ini, /etc/passwd, boot.ini).
    if status == 200 and not wall:
        changed = control is None or _norm(body) != _norm(control)
        if changed and _file_markers(body):
            return "suspect"
    if wall or status >= 400:
        return "wall" if wall else "empty"
    return "page"


def _file_markers(body: bytes) -> bool:
    """A traversal/LFI payload returned real OS file content."""
    low = body[:4000].lower()
    needles = (b"[fonts]", b"[extensions]", b"[mci extensions]",
               b"for 16-bit app support", b"[boot loader]",
               b"root:x:0:0", b"daemon:x:")
    return any(n in low for n in needles)


def receipt(url: str, status: int, headers: dict, body: bytes) -> str:
    """Short proof line. Names and counts only, never the body."""
    ctype = ""
    for key, value in headers.items():
        if key.lower() == "content-type":
            ctype = value.split(";")[0].strip()
            break
    digest = hashlib.sha256(body).hexdigest()[:16]
    detail = ""
    try:
        parsed = json.loads(body[:700_000].decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeError):
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("sources"), list) and "mappings" in parsed:
        names = []
        for src in parsed.get("sources") or []:
            if isinstance(src, str):
                base = src.rsplit("/", 1)[-1]
                if base and base not in names and len(names) < 12:
                    names.append(base)
        detail = "sources=" + ",".join(names)
    elif isinstance(parsed, dict):
        keys = [str(k) for k in list(parsed.keys())[:12]]
        detail = "keys=" + ",".join(keys)
    elif isinstance(parsed, list):
        detail = f"items={len(parsed)}"
        if parsed and isinstance(parsed[0], dict):
            keys = [str(k) for k in list(parsed[0].keys())[:8]]
            detail += " keys=" + ",".join(keys)
    return f"data {url} status={status} bytes={len(body)} type={ctype} sha={digest} {detail}".strip()


class _StopLogin(urllib.request.HTTPRedirectHandler):
    """Follow ordinary redirects. Stop when the next hop is a login path.

    A fresh opener is built per request, and this handler never copies a
    Cookie header onto the next hop.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if any(bit in (newurl or "").lower() for bit in _LOGIN_LOC):
            return None
        return urllib.request.Request(
            newurl,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"},
            method="GET",
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class EmptyJar:
    """One request, no cookie carried in from the last one."""

    def __init__(self, timeout: int = 20, limit: int = 700_000):
        self.timeout = timeout
        self.limit = limit

    def get(self, url: str, hops: int = 4) -> dict:
        return self.request("GET", url, hops=hops)

    def request(self, method: str, url: str, headers: dict | None = None, data: bytes | None = None, hops: int = 4) -> dict:
        method = (method or "GET").upper()
        extra = {
            str(k): str(v)
            for k, v in (headers or {}).items()
            if str(k).lower() not in {"cookie", "host", "content-length", "connection"}
        }
        accept = "*/*"
        for key in list(extra):
            if key.lower() == "accept":
                accept = extra.pop(key)
        base_headers = {"User-Agent": "Mozilla/5.0", "Accept": accept, "Accept-Language": "en-US,en;q=0.9", **extra}
        current = url
        seen: set[str] = set()
        last = {"status": 0, "headers": {}, "body": b"", "url": url, "error": ""}
        redirector = _StopLogin() if method in {"GET", "HEAD"} else _NoRedirect()
        opener = urllib.request.build_opener(redirector, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        while hops > 0 and current not in seen:
            seen.add(current)
            hops -= 1
            req = urllib.request.Request(current, data=data if method not in {"GET", "HEAD"} else None, headers=base_headers, method=method)
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    body = resp.read(self.limit)
                    return {
                        "status": int(resp.status),
                        "headers": {k: v for k, v in resp.headers.items()},
                        "body": body,
                        "url": resp.geturl(),
                        "error": "",
                    }
            except urllib.error.HTTPError as exc:
                body = exc.read(self.limit) if exc.fp else b""
                headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
                status = int(exc.code)
                loc = headers.get("Location") or headers.get("location") or ""
                if status in {301, 302, 303, 307, 308} and loc:
                    nxt = urljoin(current, loc)
                    headers = {**headers, "Location": nxt}
                    if any(bit in nxt.lower() for bit in _LOGIN_LOC):
                        return {"status": status, "headers": headers, "body": body, "url": current, "error": ""}
                    current = nxt
                    last = {"status": status, "headers": headers, "body": body, "url": current, "error": ""}
                    continue
                return {"status": status, "headers": headers, "body": body, "url": current, "error": ""}
            except Exception as exc:
                return {"status": 0, "headers": {}, "body": b"", "url": current, "error": str(exc).splitlines()[0][:160]}
        return last


def _same_host(url: str, host: str) -> bool:
    got = (urlparse(url).hostname or "").lower()
    host = host.lower()
    return bool(got) and (got == host or got.endswith("." + host))


def build_map(host: str, scripts: list[str], observed: list[str], fetch) -> list[str]:
    """Turn script bodies and observed calls into absolute in-scope URLs.

    fetch(url) -> dict with body (bytes or str). Used for scripts and maps only.
    """
    host = host.lower().split(":")[0]
    urls: list[str] = []
    seen: set[str] = set()

    def add(url: str, allow_map: bool = False) -> None:
        if not url or url in seen or not url.startswith("http"):
            return
        if not _same_host(url, host):
            return
        path = urlparse(url).path or "/"
        if not allow_map and not keep_path(path):
            return
        seen.add(url)
        urls.append(url.split("#", 1)[0])

    for raw in observed:
        add(raw.split("#", 1)[0])
    maps: list[str] = []
    for src in scripts[:10]:
        if not _same_host(src, host):
            continue
        got = fetch(src)
        body = got.get("body") or b""
        if isinstance(body, str):
            text = body
        else:
            text = body[:400_000].decode("utf-8", "replace")
        base = src if src.startswith("http") else _base(host) + "/"
        for path in paths_from_js(text):
            add(urljoin(_base(host) + "/", path))
        for rel in map_urls_from_js(text):
            absolute = urljoin(base, rel)
            if _same_host(absolute, host) and absolute not in maps:
                maps.append(absolute)
    for src in maps[:6]:
        add(src, allow_map=True)
        got = fetch(src)
        body = got.get("body") or b""
        text = body if isinstance(body, str) else body[:1_500_000].decode("utf-8", "replace")
        routes, _names = paths_from_sourcemap(text)
        for path in routes:
            add(urljoin(_base(host) + "/", path))
    # Prefer calls the app made, then /api-like paths, and cap the list.
    def rank(url: str) -> tuple:
        path = urlparse(url).path.lower()
        api = 0 if ("/api" in path or "graphql" in path or "/_next/data" in path) else 1
        return (0 if url in set(observed) else 1, api, path)

    ordered = sorted(dict.fromkeys(urls), key=rank)
    return ordered[:40]


def audit(host: str, urls: list[str], jar: EmptyJar | None = None) -> list[str]:
    """Classify each URL. Data lines are the only leads."""
    jar = jar or EmptyJar()
    host = host.lower().split(":")[0]
    token = hashlib.sha256(host.encode()).hexdigest()[:8]
    control_url = _base(host) + f"/__nabulus_absent_{token}"
    control = jar.get(control_url)
    control_body = control.get("body") or b""
    lines: list[str] = []
    for url in urls:
        if not _same_host(url, host):
            continue
        first = jar.get(url)
        kind = classify(int(first.get("status") or 0), first.get("headers") or {}, first.get("body") or b"", control_body)
        if kind != "data":
            lines.append(f"{kind} {url} status={first.get('status')}")
            continue
        second = jar.get(url)
        if (second.get("body") or b"") != (first.get("body") or b""):
            lines.append(f"unstable {url} status={first.get('status')}")
            continue
        lines.append(receipt(url, int(first.get("status") or 0), first.get("headers") or {}, first.get("body") or b""))
    return lines


def replay(calls: list, jar: EmptyJar, control: bytes) -> list[str]:
    """Send captured calls once with no cookie. Data must match a second send."""
    lines: list[str] = []
    seen: set[tuple] = set()
    for call in calls[:24]:
        if not isinstance(call, dict):
            continue
        method = str(call.get("method") or "GET").upper()
        url = str(call.get("url") or "").split("#", 1)[0]
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} or not url.startswith("http"):
            continue
        headers = replay_headers(call.get("headers") if isinstance(call.get("headers"), dict) else {})
        action = ""
        for key, value in headers.items():
            if key.lower() == "next-action":
                action = value
        key = (method, url, action)
        if key in seen:
            continue
        seen.add(key)
        body = call.get("body")
        data = body.encode()[:4000] if isinstance(body, str) and body and method not in {"GET", "HEAD"} else None
        first = jar.request(method, url, headers=headers, data=data)
        kind = classify(int(first.get("status") or 0), first.get("headers") or {}, first.get("body") or b"", control)
        if kind != "data":
            lines.append(f"replay {kind} {method} {url} status={first.get('status')}")
            continue
        second = jar.request(method, url, headers=headers, data=data)
        if (second.get("body") or b"") != (first.get("body") or b""):
            lines.append(f"replay unstable {method} {url} status={first.get('status')}")
            continue
        lines.append("replay " + receipt(url, int(first.get("status") or 0), first.get("headers") or {}, first.get("body") or b""))
    return lines
