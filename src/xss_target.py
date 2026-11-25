#!/usr/bin/env python3
"""xss_target.py - INTENTIONALLY VULNERABLE local control for validating the XSS detector.
Local 127.0.0.1 only. Not a real service - a positive/negative control pair (a canary).

  GET /reflect?q=...  -> reflects q UNESCAPED into the HTML body (the bug: reflected XSS)
  GET /safe?q=...     -> reflects q HTML-ESCAPED                 (negative control - must NOT fire)
"""
import sys, html, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8199


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        val = urllib.parse.parse_qs(q.query).get("q", [""])[0]
        if q.path == "/reflect":
            inner = val                       # UNESCAPED = vulnerable
        else:
            inner = html.escape(val)          # escaped = safe
        body = (f"<!doctype html><html><head><title>search</title></head>"
                f"<body><h1>Results</h1><div id=out>{inner}</div></body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"xss control target on 127.0.0.1:{PORT} (/reflect vuln, /safe clean)", flush=True)
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
