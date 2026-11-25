#!/usr/bin/env python3
"""inject.py - shared INJECTION SURFACE engine for every vector probe.

Until now each probe only put its payload in a query-string param. Real APIs take input in many
places, and a vuln reachable only via a JSON body or a header is just as real. This module takes
ONE payload and expands it into injected request variants across the surfaces a server actually
parses:

  query   ?param=<payload>                       (GET)
  form    application/x-www-form-urlencoded body  (POST)
  json    application/json body field             (POST)
  header  common injectable request headers       (GET)
  path    trailing path segment  /.../<payload>   (GET)

It produces InjectedRequest specs only - it does NOT fire them. The caller issues each via its own
rate-limited, scope-gated HTTP (authz_probe.do), so every existing safety control still applies.
This keeps the deterministic-validator doctrine intact: broadening the surface changes only WHERE
the payload goes, never WHAT counts as proof.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import json, urllib.parse

ALL_SURFACES = ("query", "form", "json", "header", "path")

# Headers servers commonly trust / reflect / route on. Injecting here catches SSRF via routing
# headers, XSS via reflected Referer, host-header attacks, etc.
INJECTABLE_HEADERS = [
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host",
    "X-Original-URL", "X-Rewrite-URL", "X-Api-Version", "True-Client-IP",
    "CF-Connecting-IP", "Forwarded", "Referer", "Origin", "User-Agent",
]


@dataclass(frozen=True)
class InjectedRequest:
    surface: str                       # query|form|json|header|path
    location: str                      # param / header name / "path"
    method: str                        # GET|POST
    url: str
    data: bytes | None = None
    headers: dict = field(default_factory=dict)

    def describe(self) -> str:
        if self.surface == "query" or self.surface == "path":
            return f"{self.method} {self.url}"
        if self.surface == "header":
            return f"{self.method} {self.url}  [{self.location}: <payload>]"
        body = self.data.decode("utf-8", "replace") if self.data else ""
        return f"{self.method} {self.url}  ({self.surface} body: {body[:200]})"


def _with_query(base_url: str, param: str, value: str) -> str:
    sep = "&" if "?" in base_url else "?"
    return base_url + sep + urllib.parse.urlencode({param: value})


def _append_path(base_url: str, value: str) -> str:
    parts = urllib.parse.urlsplit(base_url)
    path = parts.path.rstrip("/") + "/" + urllib.parse.quote(value, safe="")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


def build_injections(base_url: str, value: str, *, surfaces=("query",),
                     query_params=None, form_params=None,
                     json_template=None, headers_list=None) -> list[InjectedRequest]:
    """Expand one payload `value` into injected requests across `surfaces`.

    query_params / form_params : param-name lists to inject into (one request per name).
    json_template              : dict whose EACH top-level field is replaced by `value`, one
                                 request per field. If None and 'json' requested, a single
                                 {"<field>": value} body is sent for each query param name.
    headers_list               : header names (defaults to INJECTABLE_HEADERS).
    """
    out: list[InjectedRequest] = []
    qp = query_params or []
    for s in surfaces:
        if s == "query":
            for p in qp:
                out.append(InjectedRequest("query", p, "GET", _with_query(base_url, p, value)))
        elif s == "path":
            out.append(InjectedRequest("path", "path", "GET", _append_path(base_url, value)))
        elif s == "form":
            for p in (form_params or qp):
                body = urllib.parse.urlencode({p: value}).encode()
                out.append(InjectedRequest("form", p, "POST", base_url, data=body,
                                           headers={"Content-Type": "application/x-www-form-urlencoded"}))
        elif s == "json":
            fields = list(json_template.keys()) if json_template else (form_params or qp)
            for p in fields:
                doc = dict(json_template) if json_template else {}
                doc[p] = value
                body = json.dumps(doc).encode()
                out.append(InjectedRequest("json", p, "POST", base_url, data=body,
                                           headers={"Content-Type": "application/json"}))
        elif s == "header":
            for h in (headers_list or INJECTABLE_HEADERS):
                out.append(InjectedRequest("header", h, "GET", base_url, headers={h: value}))
    return out
