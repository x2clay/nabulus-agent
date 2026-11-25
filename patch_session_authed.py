"""Keystone: let the capturing crawl run AUTHENTICATED. open_host gains an
optional state_path; when given and present, the browser context loads that
Playwright storage_state (saved by login_one -> SESSIONS/{host}.storage.json), so
the recorded calls are the logged-in user's. Default None = unchanged unauth
behavior (backward compatible). Keeps a .bak."""
import io, shutil, time
P = "session.py"
shutil.copyfile(P, P + f".bak-authed-{time.strftime('%Y%m%d-%H%M%S')}")
s = io.open(P, encoding="utf-8").read()

repls = [
    ("def open_host(host: str, max_pages: int = 12) -> dict:",
     "def open_host(host: str, max_pages: int = 12, state_path: str | None = None) -> dict:", 1),
    ("    from urllib.parse import urlparse\n",
     "    from urllib.parse import urlparse\n    import os\n", 1),
    ("            ua = device.get(\"user_agent\") or \"\"\n"
     "            context = browser.new_context(\n"
     "                **device,\n"
     "                locale=\"en-US\",\n",
     "            ua = device.get(\"user_agent\") or \"\"\n"
     "            _state = {\"storage_state\": state_path} if state_path and os.path.exists(state_path) else {}\n"
     "            context = browser.new_context(\n"
     "                **device,\n"
     "                **_state,\n"
     "                locale=\"en-US\",\n", 1),
]
for old, new, n in repls:
    c = s.count(old)
    assert c == n, f"expected {n}x, found {c}: {old[:60]!r}"
    s = s.replace(old, new)
io.open(P, "w", encoding="utf-8").write(s)
import session  # compile/import check
print("session authed patch OK; open_host has state_path:",
      "state_path" in session.open_host.__code__.co_varnames)
