#!/usr/bin/env python3
r"""ssti_harness.py - Server-Side Template Injection detector (black-box, anonymous).

Confirm oracle (DETERMINISTIC, zero-FP): we inject a template expression whose VALUE a template
engine COMPUTES but a plain string echo cannot. Payloads wrap an arithmetic expression a*b with
random 3-digit operands in each major engine's delimiter ({{ }}, ${ }, #{ }, <%= %>, @( ), ...).
A finding is CONFIRMED only when the response contains the arithmetic PRODUCT a*b as a standalone
integer token AND does NOT contain the literal expression string - i.e. the engine evaluated it,
it was not merely reflected. A param that echoes the payload verbatim is a LEAD, not a finding.

Random operands per request make a coincidental product astronomically unlikely, and the "literal
absent" clause rules out plain reflection. In-band/reflected only; blind SSTI needs OOB (separate).

Self-contained harness: reads NABLUS_TARGET / NABLUS_SEEDS, writes ssti_findings.json. `--selftest`
runs the oracle against fixtures with no network.
"""
from __future__ import annotations  # noqa
import os, re, sys, json, time, random, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl
from html.parser import HTMLParser

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\ssti_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
PACE = 0.02

# engine delimiter wrappers; EXPR is replaced by the arithmetic expression string
WRAPPERS = [
    "{{EXPR}}",        # Jinja2, Twig, Nunjucks, Liquid, Django
    "${EXPR}",         # Freemarker, JSP-EL, Mako, Thymeleaf (preprocessing), Velocity-ish
    "#{EXPR}",         # Ruby ERB-interp, JSF/Spring EL
    "<%= EXPR %>",     # ERB, EJS
    "@(EXPR)",         # Razor
    "*{EXPR}",         # Thymeleaf selection
    "~{EXPR}",         # Thymeleaf fragment
    "{EXPR}",          # bare brace (some simple engines)
    "[[${EXPR}]]",     # Thymeleaf inlined
]
SSTI_PARAMS = ["name", "q", "search", "query", "s", "message", "msg", "text", "content", "title",
               "comment", "input", "data", "value", "page", "template", "tpl", "view", "lang",
               "email", "user", "username", "greeting", "subject", "body", "nickname", "preview"]


def make_payloads():
    """One batch of (wrapper_name, payload_string, literal_expr, product) with fresh random operands."""
    a, b = random.randint(211, 499), random.randint(503, 997)
    expr = f"{a}*{b}"
    product = a * b
    out = []
    for w in WRAPPERS:
        out.append((w, w.replace("EXPR", expr), expr, product))
    return out


def _computed(body, literal, product):
    """Pure oracle. True iff the engine COMPUTED the product (present as a standalone integer token)
    and the literal expression is ABSENT (so it was evaluated server-side, not merely reflected)."""
    if not body or literal in body:
        return False
    return re.search(r"(?<!\d)" + re.escape(str(product)) + r"(?!\d)", body) is not None


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
    req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(200000).decode("utf-8", "replace") if e.fp else "")
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
        for pn in SSTI_PARAMS:
            cands.add((stem, pn))
    return sorted(cands)


def confirm(base, param, cookie):
    for w, payload, literal, product in make_payloads():
        u = f"{base}?{urlencode({param: payload})}"
        _st, body = fetch(u, cookie)
        if _computed(body, literal, product):
            return {"engine_delim": w, "payload": payload, "expected": product,
                    "evidence": f"{product} rendered from {literal}"}
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
            findings.append({"class": "ssti", "severity": "high", "endpoint": base, "param": param,
                             "proof": proof,
                             "proof_request": f"GET {base}?{param}={proof['payload']}",
                             "validated_by": f"template engine computed {proof['expected']} "
                                             f"({proof['engine_delim']}) - arithmetic evaluated server-side",
                             "confirmed": True})
            print(f"[ssti] CONFIRMED: {urlparse(base).path}?{param}=  {proof['engine_delim']} -> {proof['expected']}")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[ssti] confirmed SSTI findings: {len(findings)} -> {OUT}")
    return 0


def selftest():
    a, b = 311, 907
    expr, product = f"{a}*{b}", a * b                 # 282077
    ok = True
    cases = [
        ("evaluated",  f"<h1>Hello {product}!</h1>",                 expr, product, True),
        ("reflected",  f"<h1>Hello {{{{{expr}}}}}</h1>",             expr, product, False),
        ("absent",     "<h1>Hello world</h1>",                       expr, product, False),
        ("substring",  f"<p>order #{product}0 shipped</p>",          expr, product, False),  # boundary guard
        ("both",       f"<p>{product} from {expr}</p>",              expr, product, False),  # literal present -> lead
    ]
    for name, body, lit, prod, want in cases:
        got = _computed(body, lit, prod)
        flag = "OK" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{flag}] {name}: computed={got} want={want}")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    raise SystemExit(main())
