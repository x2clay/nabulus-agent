#!/usr/bin/env python3
r"""jwt_harness.py - JWT weak-signing-key detector (black-box).

Confirm oracle (DETERMINISTIC, zero-FP via exact HMAC verification): harvest JWTs from Set-Cookie
headers, Authorization-ish cookies, and response bodies during an anonymous crawl. For each HS256/
HS384/HS512 token, recompute the HMAC over header.payload using a curated wordlist of common signing
secrets. A finding is CONFIRMED only when a candidate secret reproduces the token's EXACT signature -
that is cryptographic proof the app signs with a guessable key, so any attacker can forge tokens
(privilege escalation / full auth bypass). HMAC verification is exact: no false positives possible.

A token we simply observed, or one signed with alg:none, is recorded as a LEAD (not confirmed) - we
do not have a protected endpoint + claim to deterministically prove acceptance of a forged token
black-box, so we never claim it. Self-contained: NABLUS_TARGET / NABLUS_SEEDS. `--selftest` = offline.
"""
from __future__ import annotations  # noqa
import os, re, sys, json, time, hmac, base64, hashlib, http.cookiejar
import urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urljoin, urlparse, urlencode
from html.parser import HTMLParser

BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
OUT = r"C:\Users\Laith\nabulus-agent\jwt_findings.json"
SEEDS = [s.strip() for s in os.environ.get("NABLUS_SEEDS", "").split(",") if s.strip()]
PACE = float(os.environ.get("NABLUS_PACE", "0.02"))

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{6,}")
_ALG = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
SECRETS = ["secret", "password", "changeme", "admin", "123456", "jwt", "key", "test", "qwerty",
           "your-256-bit-secret", "your_jwt_secret", "supersecret", "s3cr3t", "secretkey",
           "mysecret", "jwtsecret", "token", "default", "private", "signature", "hmac", "shhhh",
           "p@ssw0rd", "letmein", "root", "null", "none", "0", "1234567890", "secret123",
           "jwt-secret", "access_token_secret", "refresh_token_secret", "CHANGE_ME"]


def _b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def crack(token):
    """Pure oracle. Return (secret, alg) if a wordlist secret reproduces the signature, else None."""
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64url_decode(h_b64))
    except Exception:
        return None
    alg = (header.get("alg") or "").upper()
    fn = _ALG.get(alg)
    if not fn:
        return None                                   # not HS* -> weak-secret crack N/A here
    signing_input = f"{h_b64}.{p_b64}".encode()
    want = _b64url_decode(sig_b64)
    for secret in SECRETS:
        got = hmac.new(secret.encode(), signing_input, fn).digest()
        if hmac.compare_digest(got, want):
            return secret, alg
    return None


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.hrefs = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("href"):
            self.hrefs.append(a["href"])


def fetch(url, cookie):
    if PACE:
        time.sleep(PACE)
    try:
        req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(200000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, {}, ""


def harvest(cookie):
    """Collect candidate JWTs + where each came from, from an anon crawl."""
    seen, frontier, tokens = set(), [BASE + "/", BASE + "/login", BASE + "/api"], {}
    for s in SEEDS:
        frontier.append(s if "://" in s else BASE + ("" if s.startswith("/") else "/") + s)
    # the login attempt may itself set a token cookie
    cj = http.cookiejar.CookieJar()
    try:
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        op.open(BASE + "/login", data=urlencode(
            {"username": os.environ.get("NABLUS_USER", "alice"),
             "password": os.environ.get("NABLUS_PASS", "Sunflower#A1pha")}).encode(), timeout=8)
    except Exception:
        pass
    for c in cj:
        for m in _JWT.findall(c.value or ""):
            tokens.setdefault(m, f"cookie:{c.name}")
    for _ in range(2):
        nxt = []
        for u in frontier:
            if u in seen or len(seen) >= 18:
                continue
            seen.add(u)
            st, hdrs, body = fetch(u, cookie)
            blob = (hdrs.get("Set-Cookie", "") or "") + "\n" + (hdrs.get("Authorization", "") or "") + "\n" + body
            for m in _JWT.findall(blob):
                tokens.setdefault(m, urlparse(u).path or "/")
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
    return tokens


def main():
    cookie = ""
    tokens = harvest(cookie)
    findings = []
    print(f"target: {BASE} | JWTs harvested: {len(tokens)}")
    for tok, where in tokens.items():
        hit = crack(tok)
        if hit:
            secret, alg = hit
            findings.append({"class": "auth", "severity": "high",
                             "endpoint": BASE + (where if where.startswith("/") else "/"),
                             "param": where,
                             "proof": {"alg": alg, "secret": secret, "token_prefix": tok[:24] + "..."},
                             "proof_request": f"HMAC-{alg} verify of harvested token with secret '{secret}'",
                             "validated_by": f"JWT signed with guessable {alg} key '{secret}' - tokens are "
                                             f"forgeable (auth bypass / privilege escalation)",
                             "confirmed": True})
            print(f"[jwt] CONFIRMED weak key: {where}  alg={alg} secret='{secret}'")
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[jwt] confirmed weak-key findings: {len(findings)} -> {OUT}")
    return 0


def _mint(secret, alg, payload):
    fn = _ALG[alg]
    h = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), f"{h}.{p}".encode(), fn).digest()).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"


def selftest():
    ok = True
    weak = _mint("secret", "HS256", {"sub": "guest", "role": "user"})
    strong = _mint("f8e3c1a0-7b2d-4e9f-a6c5-9d1e2f3a4b5c-unguessable-512bit", "HS256", {"sub": "x"})
    rs512 = _mint("changeme", "HS512", {"sub": "a"})
    cases = [
        ("weak-HS256",   weak,   "secret"),
        ("weak-HS512",   rs512,  "changeme"),
        ("strong-key",   strong, None),
        ("alg-none",     "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", None),  # not HS* -> not cracked here
        ("garbage",      "not.a.jwt", None),
    ]
    for name, tok, want_secret in cases:
        hit = crack(tok)
        got = hit[0] if hit else None
        flag = "OK" if got == want_secret else "FAIL"
        if got != want_secret:
            ok = False
        print(f"  [{flag}] {name}: cracked={got!r} want={want_secret!r}")
    print(f"  (secret wordlist: {len(SECRETS)} entries)")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(selftest())
    raise SystemExit(main())
