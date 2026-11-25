"""Gentle end-to-end validation of idor.py against the REAL range IDOR
(/api/note?id=, no ownership check, anon=401). A dozen requests, no fuzzing.
Confirms the detector fires + confirms on the actual target, both directions."""
import http.cookiejar, urllib.request, urllib.parse, urllib.error
import idor

BASE = "http://127.0.0.1:8099"
CREDS = {"alice": "Sunflower#A1pha", "bob": "Mountain#B2eta"}


class Req:
    def request(self, method, url, headers=None, data=None):
        req = urllib.request.Request(url, data=data, headers=dict(headers or {}), method=method)
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                return {"status": int(r.status), "headers": dict(r.headers.items()),
                        "body": r.read(400000), "url": r.geturl(), "error": ""}
        except urllib.error.HTTPError as e:
            return {"status": int(e.code), "headers": dict(e.headers.items() if e.headers else []),
                    "body": (e.read() if e.fp else b""), "url": url, "error": ""}
        except Exception as e:
            return {"status": 0, "headers": {}, "body": b"", "url": url, "error": str(e)[:120]}


def login(u, p):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(BASE + "/login", data=urllib.parse.urlencode({"username": u, "password": p}).encode(), timeout=8)
    return "; ".join(f"{c.name}={c.value}" for c in cj)


ca = login("alice", CREDS["alice"])
cb = login("bob", CREDS["bob"])
jar = Req()
refs = [{"method": "GET", "url": f"{BASE}/api/note?id={i}", "where": "query:id", "id": str(i)}
        for i in (1, 2, 3)]

print("login alice:", "yes" if ca else "NO", "| login bob:", "yes" if cb else "NO")
confirmed = 0
for direction, selfck, crossck, ma, mb in (("bob->alice", ca, cb, "alice", "bob"),
                                           ("alice->bob", cb, ca, "bob", "alice")):
    det = idor.run_detailed("127.0.0.1:8099", selfck, crossck, ma, mb, [], [], jar, cap=10, refs=refs)
    for d in det:
        if d["verdict"] == "cross_user_idor":
            c = idor.confirm_idor2(d["ref"]["url"], d["ref"]["method"], selfck, crossck, ma, mb, jar)
            confirmed += int(c["confirmed"])
            print(f"  {direction} {d['ref']['where']}={d['ref']['id']}: verdict={d['verdict']} "
                  f"b_status={d['b_status']} confirmed={c['confirmed']} basis={c['basis']}")
print("TOTAL confirmed IDOR:", confirmed,
      "->", "PASS -- idor.py detects the real range IDOR" if confirmed else "FAIL")
