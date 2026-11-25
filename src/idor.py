"""Authenticated IDOR / BOLA detection: two sessions, free, deterministic.

Given two authenticated cookies (A and B) for an in-scope host plus A's observed
traffic, ask for each object A legitimately reaches: can B reach A's object?

  A->objA  : 200 + A's data (baseline).
  B->objA  : B's cookie, A's object id.
     200 and A's identifying marker present and B's marker absent -> CROSS_USER_IDOR
     200 and body ~= A's body                                     -> CROSS_USER_IDOR (shared)
     401/403/404 / login redirect                                 -> access control held
     else                                                          -> inconclusive

False positives are held down by markers: a real IDOR returns *A's* data to *B*,
so the cross response must carry A's marker and NOT B's. Emits 'suspect-idor'
lines the engine's interesting()/confirm path consumes; confirm re-runs the
cross request and requires the same marker split to survive. No model, no scanner.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

import surface

# A query/path token that looks like it names an owned object.
_ID_NAME = re.compile(r"(^|[_-])(id|uid|user|userid|account|acct|order|orderid|doc|docid|file|fileid|key|ref|uuid|guid|pid|invoice|ticket|msg|message|cart|customer)s?$", re.I)
_NUMERIC = re.compile(r"^\d{1,12}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_DENY_STATUS = {401, 403, 404, 302, 303, 307}


def _looks_ownable(value: str) -> bool:
    return bool(_NUMERIC.match(value) or _UUID.match(value))


def harvest_object_refs(calls: list, urls: list) -> list[dict]:
    """Requests that carry an id-like, ownable reference. One per (url shape)."""
    refs: list[dict] = []
    seen: set[str] = set()

    def consider(method: str, url: str, where: str, token: str):
        key = method + " " + url
        if key in seen:
            return
        seen.add(key)
        refs.append({"method": method.upper(), "url": url, "where": where, "id": token})

    # From captured XHR/fetch calls (richest: has method).
    for row in calls or []:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "")
        method = str(row.get("method") or "GET")
        if not url.startswith("http"):
            continue
        _scan_url(url, method, consider)
    # From plain observed URLs (GET).
    for url in urls or []:
        if isinstance(url, str) and url.startswith("http"):
            _scan_url(url, "GET", consider)
    return refs


def _scan_url(url: str, method: str, consider) -> None:
    parsed = urlparse(url)
    # id-like query params with an ownable value
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if _ID_NAME.search(key) and _looks_ownable(value):
            consider(method, url, f"query:{key}", value)
    # numeric / uuid path segments (/users/37, /orders/<uuid>)
    for seg in (parsed.path or "").split("/"):
        if _looks_ownable(seg):
            consider(method, url, "path", seg)


def _req(jar, method: str, url: str, cookie: str, data: bytes | None = None,
         ctype: str | None = None) -> dict:
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    if data is not None and ctype:
        headers["Content-Type"] = ctype
    return jar.request(method, url, headers=headers, data=data)


def _status(resp: dict) -> int:
    try:
        return int(resp.get("status") or 0)
    except (TypeError, ValueError):
        return 0


def _owned_ok(resp: dict) -> bool:
    """A's own object looks like real, non-trivial content (not a wall/empty)."""
    body = resp.get("body") or b""
    return _status(resp) == 200 and len(body.strip()) > 64


def classify_idor(a_self: dict, b_cross: dict, marker_a: str, marker_b: str) -> str:
    st = _status(b_cross)
    if st in _DENY_STATUS or st == 0:
        return "denied"
    body = (b_cross.get("body") or b"")
    low = body.lower()
    ma = (marker_a or "").lower().encode()
    mb = (marker_b or "").lower().encode()
    # Strongest signal: B received A's identifying data and not its own.
    if st == 200 and ma and ma in low and (not mb or mb not in low):
        return "cross_user_idor"
    # Fallback: identical normalized body to A's own view (shared object / no isolation).
    if st == 200 and surface._norm(body) == surface._norm(a_self.get("body") or b"") and body.strip():
        return "cross_user_idor"
    return "inconclusive"


def run_detailed(host: str, cookie_a: str, cookie_b: str, marker_a: str, marker_b: str,
                 calls: list, urls: list, jar, cap: int = 12, refs: list | None = None) -> list[dict]:
    """One A-self baseline + B-cross per ownable ref. Returns a dict per ref that
    A legitimately owns (200, non-trivial): the ref, the verdict, and B's status.
    Refs whose A-self is a wall/empty/404 are skipped (so synthesized misses drop
    out here). Keeps structure so the caller can confirm and count without the URL
    strings leaking into operator stdout.

    `refs`, when given, is used directly instead of harvest_object_refs -- for
    pre-vetted candidates (e.g. shapes already proven id-selective empirically),
    which is a stronger signal than the id-name heuristic and must not be
    re-filtered by it."""
    out: list[dict] = []
    use = (refs if refs is not None else harvest_object_refs(calls, urls))[:cap]
    for ref in use:
        a_self = _req(jar, ref["method"], ref["url"], cookie_a, ref.get("data"), ref.get("ctype"))
        if not _owned_ok(a_self):
            continue
        b_cross = _req(jar, ref["method"], ref["url"], cookie_b, ref.get("data"), ref.get("ctype"))
        verdict = classify_idor(a_self, b_cross, marker_a, marker_b)
        out.append({"ref": ref, "verdict": verdict, "b_status": _status(b_cross),
                    "a_bytes": len((a_self.get("body") or b"").strip())})
    return out


def run(host: str, cookie_a: str, cookie_b: str, marker_a: str, marker_b: str,
        calls: list, urls: list, jar, cap: int = 12) -> list[str]:
    lines: list[str] = []
    for d in run_detailed(host, cookie_a, cookie_b, marker_a, marker_b, calls, urls, jar, cap):
        if d["verdict"] == "cross_user_idor":
            ref = d["ref"]
            lines.append(f"suspect-idor {ref['url']} ref={ref['where']}={ref['id']} status={d['b_status']}")
    return lines


def confirm_idor(url: str, method: str, cookie_b: str, marker_a: str, marker_b: str, jar) -> bool:
    """Independent re-check: B's cookie must still return A's marker, not B's."""
    r = _req(jar, method, url, cookie_b)
    if _status(r) != 200:
        return False
    low = (r.get("body") or b"").lower()
    ma = (marker_a or "").lower().encode()
    mb = (marker_b or "").lower().encode()
    return bool(ma and ma in low and (not mb or mb not in low))


def _denied_to_anon(resp: dict) -> bool:
    """The resource refuses an unauthenticated caller -> it is access-controlled,
    not public. Covers status denials and HTML login-walls served with 200."""
    st = _status(resp)
    if st in _DENY_STATUS:
        return True
    loc = ""
    for k, v in (resp.get("headers") or {}).items():
        if k.lower() == "location":
            loc = v
    return surface._login_wall(st, resp.get("body") or b"", loc)


def confirm_idor2(url: str, method: str, cookie_a: str, cookie_b: str,
                  marker_a: str, marker_b: str, jar,
                  data: bytes | None = None, ctype: str | None = None) -> dict:
    """Marker-independent confirm. Fetches the object as A (owner baseline), as an
    anonymous caller, and as B (cross). Confirms when either:
      - MARKER:  B's body carries A's marker and not B's (object echoes owner); or
      - PRIVATE: anon is denied (object is access-controlled) AND B's body equals
                 A's body (B read A's private object).
    The anon-denied gate is what separates a real private-object leak from a
    public page, so no username in the object is needed."""
    a = _req(jar, method, url, cookie_a, data, ctype)
    if not _owned_ok(a):
        return {"confirmed": False, "basis": "a-not-owned"}
    b = _req(jar, method, url, cookie_b, data, ctype)
    if _status(b) != 200:
        return {"confirmed": False, "basis": "b-denied"}
    low = (b.get("body") or b"").lower()
    ma = (marker_a or "").lower().encode()
    mb = (marker_b or "").lower().encode()
    if ma and ma in low and (not mb or mb not in low):
        return {"confirmed": True, "basis": "marker"}
    anon = _req(jar, method, url, "", data, ctype)
    if _denied_to_anon(anon) and surface._norm(b.get("body") or b"") == surface._norm(a.get("body") or b""):
        return {"confirmed": True, "basis": "private-shared"}
    return {"confirmed": False, "basis": "public-or-distinct"}
