"""Active authed crawler (full-active). Logs in as alice in a real browser,
BFS-follows same-site links, and SUBMITS each form with its existing default
values but the id-ish field swapped to a harvested id -- the move that reaches
action-gated object URLs a passive/href crawl can't. Records every resulting URL
(incl. form-navigation targets via the request hook), then runs the two-session
idor.py check over the discovered object URLs.

allow_write gates state-changing submits (POST / button clicks). TRUE here only
because the range is throwaway; real scopes keep it off. logout/signout links are
hard-skipped so the crawl never deauths itself. Prints counts only (blind-safe)."""
import re, collections, http.cookiejar, urllib.request, urllib.parse, urllib.error
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright
import idor

BASE = "http://127.0.0.1:8099"
CREDS = {"alice": "Sunflower#A1pha", "bob": "Mountain#B2eta"}
ALLOW_WRITE = True
MAX_DEPTH = 4
MAX_FORM_SUBMITS = 60

_INT = re.compile(r"(?<![\d.])(\d{1,6})(?![\d.])")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_IDNAME = re.compile(r"(id|uid|user|order|doc|file|key|ref|pid|invoice|ticket|msg|cart|customer|account|acct|num|no)", re.I)
_SKIP = re.compile(r"logout|signout|sign-out|/logoff", re.I)

discovered = set()
ids = []


def add_ids(text):
    for v in _UUID.findall(text) + [m for m in _INT.findall(text) if m != "0"]:
        if v not in ids:
            ids.append(v)
    del ids[20:]


def record(url):
    if not url or not url.startswith(BASE):
        return
    pr = urlparse(url)
    q = urllib.parse.parse_qs(pr.query)
    num_seg = any(s.isdigit() or _UUID.match(s) for s in pr.path.split("/"))
    id_q = any(_IDNAME.search(k) for k in q)
    own_q = any(vals and idor._looks_ownable(vals[0]) for vals in q.values())
    if num_seg or id_q or own_q:
        discovered.add(url.split("#")[0])


def logged_out(page):
    try:
        return bool(page.query_selector("input[name='password']")) and page.url.rstrip("/") == BASE
    except Exception:
        return False


def login(page):
    page.goto(BASE + "/", wait_until="domcontentloaded", timeout=30000)
    page.fill("input[name='username']", "alice")
    page.fill("input[name='password']", CREDS["alice"])
    page.click("button[type='submit'], input[type='submit'], button")
    page.wait_for_load_state("domcontentloaded")


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, channel="chrome",
                                args=["--disable-blink-features=AutomationControlled"])
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    page.on("request", lambda r: record(r.url))
    login(page)
    add_ids(page.content())

    visited, frontier, submits = set(), [page.url], 0
    for _ in range(MAX_DEPTH):
        nxt = []
        for u in list(frontier):
            if u in visited or _SKIP.search(u):
                continue
            visited.add(u)
            try:
                page.goto(u, wait_until="domcontentloaded", timeout=20000)
            except Exception:
                continue
            if logged_out(page):
                login(page)
                continue
            record(page.url)
            add_ids(page.content())
            try:
                hrefs = page.eval_on_selector_all("a[href]", "els=>els.map(e=>e.getAttribute('href'))")
            except Exception:
                hrefs = []
            for href in hrefs:
                link = urljoin(u, href or "").split("#")[0]
                if link.startswith(BASE) and not _SKIP.search(link) and link not in visited:
                    nxt.append(link); record(link)
            # submit each form: defaults + id-ish field swapped to a harvested id
            try:
                n_forms = len(page.query_selector_all("form"))
            except Exception:
                n_forms = 0
            for fi in range(n_forms):
                if submits >= MAX_FORM_SUBMITS:
                    break
                try:
                    page.goto(u, wait_until="domcontentloaded", timeout=20000)
                    forms = page.query_selector_all("form")
                    if fi >= len(forms):
                        break
                    f = forms[fi]
                    method = (f.get_attribute("method") or "get").lower()
                    if method == "post" and not ALLOW_WRITE:
                        continue
                    target = None
                    for inp in f.query_selector_all("input, select, textarea"):
                        nm = inp.get_attribute("name") or ""
                        if _IDNAME.search(nm):
                            target = inp; break
                    if target is None or not ids:
                        continue
                    try:
                        target.fill(str(ids[0]))
                    except Exception:
                        continue
                    btn = f.query_selector("button[type='submit'], input[type='submit'], button")
                    if not btn:
                        continue
                    submits += 1
                    btn.click()
                    page.wait_for_load_state("domcontentloaded", timeout=15000)
                    record(page.url)
                    add_ids(page.content())
                except Exception:
                    continue
        frontier = [x for x in nxt if x not in visited]
        if not frontier:
            break
    browser.close()


# ---- two-session idor check over discovered object URLs ----
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


def stdlib_login(u, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(BASE + "/login", data=urllib.parse.urlencode({"username": u, "password": pw}).encode(), timeout=8)
    return "; ".join(f"{c.name}={c.value}" for c in cj)


ca = stdlib_login("alice", CREDS["alice"])
cb = stdlib_login("bob", CREDS["bob"])
jar = Req()
refs = idor.harvest_object_refs([], sorted(discovered))
det_ab = idor.run_detailed("127.0.0.1:8099", ca, cb, "alice", "bob", [], [], jar, cap=200, refs=refs)
det_ba = idor.run_detailed("127.0.0.1:8099", cb, ca, "bob", "alice", [], [], jar, cap=200, refs=refs)
findings = []
for d in det_ab:
    if d["verdict"] == "cross_user_idor":
        c = idor.confirm_idor2(d["ref"]["url"], d["ref"]["method"], ca, cb, "alice", "bob", jar)
        findings.append(c)
for d in det_ba:
    if d["verdict"] == "cross_user_idor":
        c = idor.confirm_idor2(d["ref"]["url"], d["ref"]["method"], cb, ca, "bob", "alice", jar)
        findings.append(c)

print("ids harvested:", len(ids), "| discovered object URLs:", len(discovered), "| object refs:", len(refs))
print("suspects:", len(findings), "| confirmed:", sum(1 for c in findings if c["confirmed"]))
print("confirm basis:", dict(collections.Counter(c["basis"] for c in findings)))
