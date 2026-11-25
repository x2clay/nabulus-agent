"""Self-authored IDOR fixture + idor.py true-positive/true-negative validation.

This is NOT the sealed range -- I wrote it, so knowing its answer is fine. It
serves two endpoints over a throwaway localhost server:
  /note?id=N    login required, NO ownership check  -> real IDOR (must fire)
  /secure?id=N  login required, owner==caller check  -> safe (must stay silent)
Both objects print the OWNER's username (exercises the marker confirm) and both
require login (exercises the anon-baseline confirm). We log in alice+bob, hand
idor.py the object refs directly, and assert it confirms the IDOR and clears the
secured one. Prints a PASS/FAIL line per case. Server runs in a daemon thread and
dies with the process."""
import http.server, threading, time, urllib.request, urllib.parse, urllib.error, http.cookiejar
import idor

PORT = 8097
BASE = f"http://127.0.0.1:{PORT}"
CREDS = {"alice": "pw_alice", "bob": "pw_bob"}
SESS = {}  # token -> user
NOTES = {  # id -> (owner, long private text >64 bytes)
    "1": ("alice", "ALICE PRIVATE NOTE. Quarterly figures, vendor contacts, and the internal launch timeline are recorded in this document and must not leave the account."),
    "2": ("bob", "BOB PRIVATE NOTE. Offshore ledger references, the API secret rotation plan, and personal recovery phrases are stored here for bob and bob alone."),
}


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _user(self):
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            part = part.strip()
            if part.startswith("sid="):
                return SESS.get(part[4:])
        return None

    def _send(self, code, body=b"", ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/login":
            n = int(self.headers.get("Content-Length", 0) or 0)
            f = urllib.parse.parse_qs(self.rfile.read(n).decode())
            u = f.get("username", [""])[0]
            p = f.get("password", [""])[0]
            if CREDS.get(u) == p:
                tok = u + "-tok"
                SESS[tok] = u
                self.send_response(200)
                self.send_header("Set-Cookie", f"sid={tok}; Path=/")
                self.end_headers()
                self.wfile.write(b"ok")
                return
            return self._send(401, b"bad credentials")
        return self._send(404, b"no")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        nid = urllib.parse.parse_qs(parsed.query).get("id", [""])[0]
        if parsed.path in ("/note", "/secure"):
            u = self._user()
            if not u:
                return self._send(401, b"login required")  # anon denied -> access-controlled
            note = NOTES.get(nid)
            if not note:
                return self._send(404, b"no such note")
            owner, text = note
            if parsed.path == "/secure" and owner != u:
                return self._send(403, b"forbidden")  # proper ownership check
            page = f"<html><body><h1>Note {nid} (owner {owner})</h1><p>{text}</p></body></html>"
            return self._send(200, page.encode())
        if parsed.path == "/":
            return self._send(200, b"<html>home</html>")
        return self._send(404, b"no")


def serve():
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()


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


threading.Thread(target=serve, daemon=True).start()
time.sleep(0.4)

ca = login("alice", CREDS["alice"])
cb = login("bob", CREDS["bob"])
jar = Req()
print("login alice:", "yes" if ca else "NO", "| login bob:", "yes" if cb else "NO")

# sanity: does bob literally receive alice's note content on the vulnerable route?
raw = jar.request("GET", BASE + "/note?id=1", headers={"Cookie": cb})
leaked = b"ALICE PRIVATE" in (raw.get("body") or b"")
print(f"sanity: bob GET /note?id=1 -> status {raw['status']}, alice's content present: {leaked}")

def ref(url):
    return {"method": "GET", "url": url, "where": "query:id", "id": url.rsplit("=", 1)[-1]}

cases = [
    ("VULN  /note   (expect CONFIRM)", BASE + "/note?id=1", True),
    ("SAFE  /secure (expect SILENT)",  BASE + "/secure?id=1", False),
]
all_ok = True
for label, url, should_fire in cases:
    det = idor.run_detailed("127.0.0.1", ca, cb, "alice", "bob", [], [], jar, cap=4, refs=[ref(url)])
    fired = any(d["verdict"] == "cross_user_idor" for d in det)
    conf = idor.confirm_idor2(url, "GET", ca, cb, "alice", "bob", jar)
    confirmed = conf["confirmed"]
    ok = (confirmed == should_fire)
    all_ok = all_ok and ok
    print(f"{label}: detail_fired={fired} confirmed={confirmed} basis={conf['basis']} -> {'PASS' if ok else 'FAIL'}")

print("RESULT:", "ALL PASS -- idor.py detects true IDOR and clears the secured endpoint" if all_ok else "FAIL")
