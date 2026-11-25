#!/usr/bin/env python3
r"""graphql_harness.py - GraphQL introspection-exposure detector (black-box, anonymous).

Confirm oracle (DETERMINISTIC, zero-FP): locate a GraphQL endpoint, send the standard introspection
query, and CONFIRM only when the server answers with a valid introspection schema - JSON whose
data.__schema.queryType.name is present and whose __schema.types is a non-empty list. That is proof
the schema is readable by an anonymous caller (maps the entire API surface - every type, field, and
mutation - for an attacker). Anything short of a real __schema (404, 400, auth error, disabled) is
NOT a finding.

Introspection exposure is reported as a medium: it is a confirmed misconfiguration and the standard
first step toward GraphQL authz/IDOR abuse, but is not itself data exfiltration. Self-contained:
NABLUS_TARGET / NABLUS_SEEDS, writes graphql_findings.json. `--selftest` = offline oracle check.
"""
from __future__ import annotations  # noqa
import os, sys, json, time, urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urlparse

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\graphql_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
PACE = 0.03

GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/gql", "/api/gql",
             "/graphql/console", "/index.php?graphql", "/api", "/graphql-api"]
INTROSPECT = ("query{__schema{queryType{name} types{name kind} "
              "mutationType{name}}}")


def endpoints():
    out = []
    for p in GQL_PATHS:
        out.append(BASE + p)
    for s in SEEDS:
        u = s if "://" in s else BASE + ("" if s.startswith("/") else "/") + s
        out.append(u.split("?")[0])
    seen, uniq = set(), []
    for u in out:
        if u not in seen:
            seen.add(u); uniq.append(u)
    return uniq


def post(url, query):
    if PACE:
        time.sleep(PACE)
    data = json.dumps({"query": query}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(400000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(400000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, ""


def get(url, query):
    if PACE:
        time.sleep(PACE)
    u = url + ("&" if "?" in url else "?") + urllib.parse.urlencode({"query": query})
    try:
        with urllib.request.urlopen(urllib.request.Request(u), timeout=10) as r:
            return r.status, r.read(400000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(400000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, ""


def introspection_ok(body):
    """Pure oracle. Return (type_count, query_type_name) if body is a real introspection schema, else None."""
    if not body or "__schema" not in body:
        return None
    try:
        doc = json.loads(body)
    except Exception:
        return None
    schema = (doc.get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        return None
    qt = schema.get("queryType")
    types = schema.get("types")
    if isinstance(qt, dict) and qt.get("name") and isinstance(types, list) and len(types) > 0:
        return len(types), qt["name"]
    return None


def main():
    findings = []
    eps = endpoints()
    print(f"target: {BASE} | graphql endpoints probed: {len(eps)}")
    for ep in eps:
        for how, fn in (("POST", post), ("GET", get)):
            st, body = fn(ep, INTROSPECT)
            res = introspection_ok(body)
            if res:
                tcount, qtname = res
                findings.append({"class": "graphql-introspection", "severity": "medium", "endpoint": ep,
                                 "param": None,
                                 "proof": {"method": how, "query_type": qtname, "types_exposed": tcount},
                                 "proof_request": f"{how} {ep}  body={{\"query\":\"{INTROSPECT[:40]}...\"}}",
                                 "validated_by": f"anonymous introspection returned full schema "
                                                 f"({tcount} types, queryType={qtname})",
                                 "confirmed": True})
                print(f"[graphql] CONFIRMED introspection: {ep} [{how}] -> {tcount} types")
                break
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[graphql] confirmed introspection findings: {len(findings)} -> {OUT}")
    return 0


def selftest():
    ok = True
    good = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"},
                                             "types": [{"name": "User", "kind": "OBJECT"},
                                                       {"name": "Query", "kind": "OBJECT"}],
                                             "mutationType": {"name": "Mutation"}}}})
    disabled = json.dumps({"errors": [{"message": "GraphQL introspection is not allowed"}]})
    empty_schema = json.dumps({"data": {"__schema": {"queryType": None, "types": []}}})
    not_json = "<html>404 Not Found</html>"
    cases = [
        ("introspection-enabled", good,         True),
        ("introspection-disabled", disabled,    False),
        ("empty-schema",          empty_schema, False),
        ("not-graphql",           not_json,     False),
        ("empty",                 "",           False),
    ]
    for name, body, want in cases:
        got = introspection_ok(body) is not None
        flag = "OK" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{flag}] {name}: ok={got} want={want}")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    raise SystemExit(main())
