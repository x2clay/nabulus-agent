#!/usr/bin/env python3
"""ssrf_target.py - INTENTIONALLY VULNERABLE local control endpoint, ONLY to validate the SSRF
detector (a positive-control benchmark, like a canary). Local 127.0.0.1 only. Not a real service.

  GET /fetch?url=...   -> server fetches the URL (the SSRF bug: positive control)
  GET /safe?url=...    -> echoes, never fetches          (negative control - must NOT flag)
"""
import sys, urllib.request, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8188

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(q.query)
        if q.path == "/fetch":
            url = params.get("url", [None])[0]
            if url:
                try: urllib.request.urlopen(url, timeout=5).read(64)   # the vuln: fetch attacker URL
                except Exception: pass
            self.send_response(200); self.end_headers(); self.wfile.write(b"fetched")
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"safe-no-fetch")
    def log_message(self, *a): pass

if __name__ == "__main__":
    print(f"ssrf control target on 127.0.0.1:{PORT} (/fetch vuln, /safe clean)", flush=True)
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
