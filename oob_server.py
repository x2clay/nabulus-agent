#!/usr/bin/env python3
"""oob_server.py - out-of-band callback listener (the SSRF validator).

Logs every inbound request (path carries a unique token) to a JSONL file. If a target server
ever hits this with our token, that server made an outbound request on our behalf = proof.
Binds 127.0.0.1 by default (local validation). For internet targets you'd use a public OOB
endpoint (e.g. interactsh) instead - noted, not done here.
"""
import sys, json, datetime, pathlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9099
LOG  = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else pathlib.Path("oob_hits.jsonl")
BIND = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"

class H(BaseHTTPRequestHandler):
    def _hit(self):
        rec = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "path": self.path, "client": self.client_address[0],
               "ua": self.headers.get("User-Agent", ""), "method": self.command}
        with open(LOG, "a", encoding="utf-8") as f: f.write(json.dumps(rec) + "\n")
        self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"ok")
    do_GET = _hit; do_POST = _hit; do_PUT = _hit
    def log_message(self, *a): pass

if __name__ == "__main__":
    LOG.write_text("", encoding="utf-8")
    print(f"oob listener on {BIND}:{PORT} -> {LOG}", flush=True)
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()
