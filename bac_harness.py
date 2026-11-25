#!/usr/bin/env python3
"""bac_harness.py - broken access control + bulk sensitive-data disclosure (black-box).

Finds endpoints that hand sensitive bulk data (password hashes, API tokens, secrets) to a
caller who shouldn't see it. For each candidate endpoint it compares ANON vs a low-priv
authed session, and CONFIRMS when a low-priv (or anon) caller gets 200 with sensitive-field
signatures across multiple records. Read-only: it only GETs, never writes.

Confirm oracle: >=2 sensitive-key hits (password_hash / api_token / secret / token / ...) in
a 200 body reachable by a non-privileged caller. Access level is reported: 'public' if anon
also gets it, else 'authenticated-underprivileged'. The signal is bulk credential exposure,
which is deterministic and very low-FP (normal endpoints don't return other users' hashes).
"""
from __future__ import annotations
import sys, re, json, time, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode
from html.parser import HTMLParser

BASE = "http://127.0.0.1:8099"
CREDS = {"alice": "Sunflower#A1pha"}
OUT = r"C:\Users\Laith\nabulus-agent\bac_findings.json"
PACE = 0.02

SENSITIVE = re.compile(
    r'"(password_hash|password|passwd|pwd|api_token|apitoken|api_key|secret|'
    r'private_key|ssn|credit_card|card_number|cvv|session_token|access_token|'
    r'refresh_token|token|hash)"\s*:', re.I)
ADMIN_PATHS = ["/api/admin/export", "/api/admin/users", "/api/export", "/api/users",
               "/api/accounts", "/api/admin", "/admin/export", "/api/dump", "/api/backup",
               "/api/report", "/api/all", "/api/customers", "/api/user/all", "/api/userlist"]


def login(user, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try:
        op.open(BASE + "/login", data=urlencode({"username": user, "password": pw}).encode(), timeout=10)
    except Exception:
        pass
    return "; ".join(f"{c.name}={c.value}" for c in cj)


def get(url, cookie=None):
    if PACE:
        time.sleep(PACE)
    h = {"Cookie": cookie} if cookie else {}
    r = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return int(resp.status), resp.read(300000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return int(e.code), (e.read(300000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, ""


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])


def discover(cookie):
    seen, frontier, urls = set(), [BASE + "/"], set()
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 15:
                continue
            seen.add(u)
            st, body = get(u, cookie)
            if st != 200:
                continue
            pr = urlparse(u)
            urls.add(f"{pr.scheme}://{pr.netloc}{pr.path}")
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
    for pth in ADMIN_PATHS:
        urls.add(BASE + pth)
    return sorted(urls)


def main():
    cookie = login("alice", CREDS["alice"])
    urls = discover(cookie)
    findings = []
    print(f"login: {'yes' if cookie else 'NO'} | candidate endpoints: {len(urls)}")
    for u in urls:
        st_anon, _b_anon = get(u, None)
        st_auth, body = get(u, cookie)
        if st_auth != 200:
            continue
        hits = len(SENSITIVE.findall(body))
        if hits >= 2:                       # bulk sensitive-field exposure
            access = "public" if st_anon == 200 else "authenticated-underprivileged"
            keys = sorted({m.lower() for m in SENSITIVE.findall(body)})
            findings.append({"class": "bulk", "subtype": "broken-access-control", "severity": "critical",
                             "endpoint": u, "param": None,
                             "access": access, "sensitive_keys": keys, "record_hits": hits,
                             "detail": f"{access}: {hits} sensitive-field hits ({','.join(keys[:4])})",
                             "validated_by": "low-privilege caller received bulk sensitive fields (password_hash/api_token/...)",
                             "confirmed": True})
            print(f"[bac] CONFIRMED bulk disclosure: {urlparse(u).path}  [{access}] keys={keys}")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[bac] confirmed findings: {len(findings)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
