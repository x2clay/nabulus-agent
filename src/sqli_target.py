#!/usr/bin/env python3
"""sqli_target.py - intentionally-vulnerable local control for validating sqli_probe.

/item?id=   -> builds SQL by STRING CONCATENATION (classic SQLi, vulnerable)
/safe?id=   -> parameterized query (clean, must NOT be flagged)

In-memory sqlite, localhost only. Lab control, never deployed.
"""
import sqlite3, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_local = threading.local()


def _db():
    if not hasattr(_local, "c"):
        c = sqlite3.connect(":memory:")
        c.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)")
        c.executemany("INSERT INTO items(id,name) VALUES(?,?)",
                      [(1, "alpha"), (2, "beta"), (3, "gamma")])
        c.commit()
        _local.c = c
    return _local.c


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        idv = (q.get("id") or [""])[0]
        c = _db()
        try:
            if u.path == "/item":
                # VULNERABLE: raw string concatenation
                rows = c.execute(f"SELECT id,name FROM items WHERE id = {idv}").fetchall()
            elif u.path == "/safe":
                rows = c.execute("SELECT id,name FROM items WHERE id = ?", (idv,)).fetchall()
            else:
                self.send_response(404); self.end_headers(); return
            body = str(rows).encode()
            self.send_response(200)
        except Exception as e:
            body = f"ERR: {e}".encode()          # error leak feeds error-based detection
            self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
