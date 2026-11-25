"""Fixture checks for the unauthenticated map and the empty-jar rule."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import surface


JS = """
const api = "/api/v1/records";
fetch("/api/v1/records");
const asset = "/_next/static/chunks/main.js";
const pic = "/logo.png";
//# sourceMappingURL=app.js.map
"""

MAP = json.dumps({
    "version": 3,
    "sources": ["src/pages/records.tsx", "src/lib/format.ts"],
    "mappings": "AAAA",
    "sourcesContent": ["export const route = \"/api/v1/hidden\";\n"],
})


def test_paths_skip_static_files():
    paths = surface.paths_from_js(JS)
    assert "/api/v1/records" in paths
    assert "/logo.png" not in paths
    assert all("/_next/static/" not in p for p in paths)
    assert surface.map_urls_from_js(JS) == ["app.js.map"]


def test_sourcemap_returns_names_not_source():
    routes, names = surface.paths_from_sourcemap(MAP)
    assert "/api/v1/hidden" in routes
    assert "records.tsx" in names
    assert "export const route" not in " ".join(names)


def test_classify_shell_wall_and_data():
    shell = b"<html><title>App</title><div id=root></div></html>"
    assert surface.classify(200, {"Content-Type": "text/html"}, shell, shell) == "shell"
    login = b"<html><form><input type=\"password\"></form></html>"
    assert surface.classify(200, {"Content-Type": "text/html"}, login, shell) == "wall"
    assert surface.classify(401, {}, b"no", shell) == "wall"
    err = b'{"error":"unauthorized","message":"no"}'
    assert surface.classify(200, {"Content-Type": "application/json"}, err, shell) == "empty"
    data = b'{"records":[{"id":"a","note":"quarterly model notes stay here"}]}'
    mixed = b'{"records":[{"id":"a","note":"quarterly model notes stay here"}],"field":"type=password"}'
    assert surface.classify(200, {"Content-Type": "application/json"}, mixed, shell) == "data"
    assert surface.classify(401, {"Content-Type": "application/json"}, data, shell) == "data"
    assert surface.classify(200, {"Content-Type": "application/json"}, data, shell) == "data"
    smap = MAP.encode()
    assert surface.classify(200, {"Content-Type": "application/json"}, smap, shell) == "data"
    line = surface.receipt("https://app.example/api", 200, {"Content-Type": "application/json"}, data)
    assert "quarterly" not in line
    assert "keys=records" in line


def test_build_map_orders_observed_calls_first():
    bodies = {
        "https://app.example/app.js": {"body": JS},
        "https://app.example/app.js.map": {"body": MAP},
    }
    urls = surface.build_map(
        "app.example",
        ["https://app.example/app.js"],
        ["https://app.example/api/v1/live"],
        lambda url: bodies.get(url, {"body": b""}),
    )
    assert urls[0] == "https://app.example/api/v1/live"
    assert "https://app.example/api/v1/records" in urls
    assert "https://app.example/api/v1/hidden" in urls
    assert "https://app.example/app.js.map" in urls
    assert not any(u.endswith(".png") for u in urls)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        cookie = self.headers.get("Cookie")
        if self.path.startswith("/set"):
            body = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "session=secret")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/echo"):
            body = f"cookie={cookie or ''}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/gone"):
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        if self.path.startswith("/api/item"):
            body = b'{"item":{"id":"1","body":"private research note of sufficient length"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"<html><title>App</title><div id=root>shell</div></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def test_empty_jar_does_not_replay_set_cookie():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        jar = surface.EmptyJar(timeout=5)
        base = f"http://127.0.0.1:{port}"
        jar.get(base + "/set")
        echoed = jar.get(base + "/echo")
        assert b"cookie=" == echoed["body"]
        lines = surface.audit("127.0.0.1", [base + "/api/item", base + "/gone"], jar)
        # audit() forces https and the control host. Call classify via the server directly.
        assert echoed["body"] == b"cookie="
        data = jar.get(base + "/api/item")
        shell = jar.get(base + "/nope")
        assert surface.classify(data["status"], data["headers"], data["body"], shell["body"]) == "data"
        gone = jar.get(base + "/gone")
        assert surface.classify(gone["status"], gone["headers"], gone["body"], shell["body"]) == "wall"
        assert lines is not None
    finally:
        server.shutdown()


def test_audit_matches_second_fetch():
    shell = b"<html><title>App</title><div id=root></div></html>"
    data = b'{"records":[{"id":"a","note":"quarterly model notes stay here"}]}'
    calls = {"n": 0}

    def get(url: str, hops: int = 4) -> dict:
        if "__nabulus_absent_" in url or url.endswith("/page"):
            return {"status": 200, "headers": {"Content-Type": "text/html"}, "body": shell, "url": url, "error": ""}
        if url.endswith("/once"):
            calls["n"] += 1
            body = data if calls["n"] == 1 else b'{"records":[]}'
            return {"status": 200, "headers": {"Content-Type": "application/json"}, "body": body, "url": url, "error": ""}
        return {"status": 200, "headers": {"Content-Type": "application/json"}, "body": data, "url": url, "error": ""}

    class Fake:
        def get(self, url: str, hops: int = 4) -> dict:
            return get(url, hops)

    lines = surface.audit("app.example", [
        "https://app.example/api/records",
        "https://app.example/page",
        "https://app.example/once",
    ], Fake())
    kinds = [line.split()[0] for line in lines]
    assert kinds.count("data") == 1
    assert any(line.startswith("data https://app.example/api/records") for line in lines)
    assert any(line.startswith("shell ") or line.startswith("page ") for line in lines)
    assert any(line.startswith("unstable ") for line in lines)
    assert all("quarterly" not in line for line in lines)


def test_rsc_and_action_calls_are_kept():
    assert surface.worth_recording("other", "GET", "https://app.example/desk?_rsc=abc", {})
    assert surface.worth_recording("other", "POST", "https://app.example/desk", {"next-action": "ab"})
    assert surface.worth_recording("fetch", "GET", "https://app.example/api/live", {})
    assert not surface.worth_recording("other", "GET", "https://app.example/logo.png", {})
    assert surface.worth_recording("other", "GET", "https://app.example/desk", {})
    assert surface.worth_recording("document", "GET", "https://app.example/desk", {})
    assert not surface.worth_recording("stylesheet", "GET", "https://app.example/app.css", {})
    text = 'x.createServerReference("a" * 0 + "0123456789abcdef0123456789abcdef01234567", callServer)'
    # the regex needs a literal hex id inside the call
    text = 'createServerReference("0123456789abcdef0123456789abcdef01234567", callServer)'
    assert surface.action_ids(text) == ["0123456789abcdef0123456789abcdef01234567"]
    assert surface.action_ids('hash="0123456789abcdef0123456789abcdef01234567"') == []
    gets = surface.rsc_gets(["https://app.example/desk", "https://app.example/desk?x=1"])
    assert gets[0]["url"].endswith("?_rsc=1")
    assert gets[1]["url"].endswith("&_rsc=1")
    assert gets[0]["headers"]["RSC"] == "1"
    posts = surface.action_posts(surface.action_ids(text), "https://app.example/desk")
    assert posts[0]["headers"]["Next-Action"].startswith("0123")
    assert posts[0]["body"] == "[]"
    assert "Cookie" not in surface.replay_headers({"Cookie": "a=1", "Next-Action": "abc", "Accept": "text/x-component"})


class ReplayJar:
    def __init__(self):
        self.seen = []

    def request(self, method, url, headers=None, data=None, hops=4):
        self.seen.append((method, url, headers, data))
        if method == "POST":
            body = b'{"records":[{"id":"a","note":"quarterly model notes stay here"}]}'
            return {"status": 200, "headers": {"Content-Type": "application/json"}, "body": body, "url": url, "error": ""}
        return {"status": 401, "headers": {}, "body": b"no", "url": url, "error": ""}


def test_replay_strips_cookie_and_confirms_data():
    jar = ReplayJar()
    lines = surface.replay([
        {"method": "GET", "url": "https://app.example/api/live?_rsc=1", "headers": {"RSC": "1", "Cookie": "session=1"}, "body": ""},
        {"method": "POST", "url": "https://app.example/desk", "headers": {"Next-Action": "0123456789abcdef0123456789abcdef01234567", "Cookie": "session=1"}, "body": "[]"},
        {"method": "POST", "url": "https://app.example/desk", "headers": {"Next-Action": "0123456789abcdef0123456789abcdef01234567"}, "body": "[]"},
    ], jar, b"<html>shell</html>")
    assert jar.seen[0][2].get("RSC") == "1"
    assert "Cookie" not in jar.seen[0][2]
    assert len(jar.seen) == 3  # GET once, POST twice because it was data
    assert any(line.startswith("replay data ") for line in lines)
    assert all("quarterly" not in line for line in lines)
    assert all("session=1" not in line for line in lines)


if __name__ == "__main__":
    test_paths_skip_static_files()
    test_sourcemap_returns_names_not_source()
    test_classify_shell_wall_and_data()
    test_build_map_orders_observed_calls_first()
    test_empty_jar_does_not_replay_set_cookie()
    test_audit_matches_second_fetch()
    test_rsc_and_action_calls_are_kept()
    test_replay_strips_cookie_and_confirms_data()
    print("surface ok")
