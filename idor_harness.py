"""Two-session IDOR validation, blind-safe. Logs in A/B, crawls each authed
surface, HARVESTS ownable object ids from response BODIES (JSON values under
id-ish keys, UUIDs, bounded bare ints) -- not just from links -- then SYNTHESIZES
candidate object URLs by grafting those ids onto the 200-returning path stems the
crawl saw (/stem/{id} and ?idname={id}). Those candidates plus the real crawled
URLs go through idor.run_detailed in BOTH directions. Real object routes return
A-owned content and get the cross-user test; synthesized misses 404 and drop out.

Nothing hardcodes the route or the ids -- both come from live data that
re-randomizes per run, so the range layout stays unknown to the operator. Prints
ONLY structure + counts; the suspect URLs are written to a findings file for the
grader, never to stdout."""
import json, re, time, urllib.request, urllib.parse, urllib.error, http.cookiejar
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode
from html.parser import HTMLParser
import idor

import os
BASE = os.environ.get("NABLUS_TARGET", "http://127.0.0.1:8099").rstrip("/")
CREDS = {"alice": "Sunflower#A1pha", "bob": "Mountain#B2eta"}
OUT = r"C:\Users\Laith\nabulus-agent\idor_findings.json"

# ---- bounds (loopback target, but stay polite + deterministic) ----
MAX_IDS = 14            # distinct ownable ids fed to synthesis
MAX_STEMS = 16          # distinct 200-returning path stems
QUERY_NAMES = ["id", "user_id", "order_id", "doc_id", "file_id", "account_id"]
MAX_CANDIDATES = 500    # hard cap on synthesized object URLs
RUN_CAP = 600           # per-direction cap inside idor.run_detailed


# Pacing + reset-retry live in Req itself so EVERY consumer is resilient: the
# synth sweep (via Session), AND the confirm phase (which uses a Req directly).
# A single-threaded target under a burst refuses/resets connections (surfacing as
# status 0); without a retry the anon-baseline probe in confirm_idor2 misses its
# clean 401 and every real private resource degrades to "public-or-distinct".
PACE = 0.02           # polite inter-request throttle (single-threaded target)
RETRY_RESET = 3       # retries on status 0 (connection reset/refused under load)


class Req:
    def __init__(self, timeout=10, limit=400000):
        self.timeout = timeout; self.limit = limit
    def _once(self, method, url, headers, data):
        req = urllib.request.Request(url, data=data, headers=dict(headers or {}), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {"status": int(r.status), "headers": dict(r.headers.items()),
                        "body": r.read(self.limit), "url": r.geturl(), "error": ""}
        except urllib.error.HTTPError as e:
            return {"status": int(e.code), "headers": dict(e.headers.items() if e.headers else []),
                    "body": (e.read(self.limit) if e.fp else b""), "url": url, "error": ""}
        except Exception as e:
            return {"status": 0, "headers": {}, "body": b"", "url": url, "error": str(e)[:120]}
    def request(self, method, url, headers=None, data=None):
        if PACE:
            time.sleep(PACE)
        r = self._once(method, url, headers, data)
        for attempt in range(RETRY_RESET):
            if r.get("status") != 0:
                return r
            time.sleep(0.2 * (attempt + 1))        # back off, let the app recover
            r = self._once(method, url, headers, data)
        return r


def login(user, pw):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    body = urllib.parse.urlencode({"username": user, "password": pw}).encode()
    try:
        op.open(BASE + "/login", data=body, timeout=10)
    except Exception:
        pass
    return "; ".join(f"{c.name}={c.value}" for c in cj)


# ---- self-healing authed session -----------------------------------------
# Req already paces + retries transient resets; Session adds the auth layer:
# a bounded re-login when a genuine 401 drop happens after auth has been working
# (an evicted cookie mid-sweep), so one dropped session can't poison the rest.
MAX_RELOGIN = 3       # bounded self-heal so a truly-401 route can't loop


class Session:
    def __init__(self, user, pw, req):
        self.user, self.pw, self.req = user, pw, req
        self.cookie = login(user, pw)
        self.relogins = 0
        self.seen_ok = False

    def get(self, method, url, data=None, ctype=None):
        hdrs = {"Cookie": self.cookie}
        if ctype:
            hdrs["Content-Type"] = ctype
        r = self.req.request(method, url, headers=hdrs, data=data)
        st = r.get("status")
        if st == 200:
            self.seen_ok = True
        if st == 401 and self.seen_ok and self.relogins < MAX_RELOGIN:
            self.cookie = login(self.user, self.pw)
            self.relogins += 1
            self.seen_ok = False
            hdrs["Cookie"] = self.cookie
            r = self.req.request(method, url, headers=hdrs, data=data)
            if r.get("status") == 200:
                self.seen_ok = True
        return r


HREF = re.compile(rb'(?:href|action)=["\']([^"\'<>]+)["\']', re.I)
QPATH = re.compile(rb'["\'](/[A-Za-z0-9_./-]*\d[A-Za-z0-9_./-]*)["\']')


def crawl(cookie, req, depth=6):
    """BFS A's/B's authed surface. Returns (urls_seen, fetched) where fetched is
    a list of (url, status, body) for pages that answered."""
    urls, seen, fetched = set(), set(), []
    frontier = [BASE + "/"]
    for _ in range(depth):
        nxt = []
        for u in frontier:
            if u in seen:
                continue
            seen.add(u); urls.add(u)
            r = req.request("GET", u, headers={"Cookie": cookie})
            body = r.get("body") or b""
            fetched.append((u, r.get("status") or 0, body))
            for rx in (HREF.findall(body), QPATH.findall(body)):
                for m in rx:
                    link = urljoin(u, m.decode("utf-8", "replace")).split("#")[0]
                    if link.startswith(BASE) and link not in seen:
                        nxt.append(link); urls.add(link)
        frontier = nxt
        if not frontier:
            break
    return urls, fetched


# ---- id harvesting from bodies -------------------------------------------
_IDKEY = re.compile(r"(id|uid|user|account|acct|order|doc|file|key|ref|pid|invoice|ticket|msg|message|cart|customer)", re.I)
_UUID_B = re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_INT_B = re.compile(rb"(?<![\d.])(\d{1,6})(?![\d.])")  # avoid versions/decimals


def _walk_json(obj, hi, keynames):
    """Collect values of id-ish keys (high-precision tier) and record the key
    NAMES that carried an ownable value -- those names point at the object route."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (str, int)) and _IDKEY.search(str(k)) and idor._looks_ownable(str(v)):
                hi.append(str(v)); keynames.add(str(k).lower())
            _walk_json(v, hi, keynames)
    elif isinstance(obj, list):
        for v in obj:
            _walk_json(v, hi, keynames)


def harvest_ids(fetched):
    """Ordered, deduped ownable ids + the id-key NAMES that carried them.
    JSON id-keys + UUIDs first (precise), then bounded bare ints (noisy)."""
    hi, uu, lo, keynames = [], [], [], set()
    for _u, _s, body in fetched:
        try:
            _walk_json(json.loads(body.decode("utf-8", "replace")), hi, keynames)
        except Exception:
            pass
        uu += [m.decode() for m in _UUID_B.findall(body)]
        lo += [m.decode() for m in _INT_B.findall(body) if m != b"0"]
    out, seen = [], set()
    for v in hi + uu + lo:
        if v not in seen:
            seen.add(v); out.append(v)
        if len(out) >= MAX_IDS:
            break
    return out, keynames


class _FormGrab(HTMLParser):
    """Collect each form's action, method, and input NAMES -- the field names are
    the object's real query/body parameter, which generic guesses miss."""
    def __init__(self):
        super().__init__(convert_charrefs=True); self.forms = []; self._cur = None
    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "names": [], "defaults": {}}
        elif tag in ("input", "select", "textarea") and self._cur is not None and a.get("name"):
            self._cur["names"].append(a["name"])
            self._cur["defaults"][a["name"]] = a.get("value", "")
    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur); self._cur = None


def grab_forms(fetched):
    """Resolved same-host forms: list of {path, method, names[]}."""
    out = []
    for u, _s, body in fetched:
        p = _FormGrab()
        try:
            p.feed(body.decode("utf-8", "replace"))
        except Exception:
            continue
        if p._cur is not None:
            p.forms.append(p._cur)
        for f in p.forms:
            full = urljoin(u, f["action"] or u)
            if full.startswith(BASE):
                pr = urlparse(full).path or "/"
                out.append({"path": pr, "method": f["method"], "names": f["names"],
                            "defaults": f.get("defaults", {})})
    return out


# singular/plural + /api prefixes, derived from live id-key names and known stems
_ROUTE_TMPL = ["/{n}", "/{n}s", "/api/{n}", "/api/{n}s", "/{n}/view", "/view/{n}"]


def _noun(keyname):
    n = keyname.lower()
    for suf in ("_id", "id", "_uuid", "uuid", "_ref", "ref", "_no", "no"):
        if n.endswith(suf) and len(n) > len(suf):
            n = n[: -len(suf)]
    return n.strip("_-")


def derive_stems(path_stems, keynames, form_paths):
    """Union of: crawled 200 stems, form action paths, and routes derived from the
    id-key names found in JSON. All programmatic -- no route is hand-named."""
    stems_out = list(path_stems) + list(form_paths)
    nouns = {_noun(k) for k in keynames if _noun(k)}
    # also the last path segment of each crawled stem (collection noun)
    for p in path_stems:
        seg = [s for s in p.split("/") if s]
        if seg:
            nouns.add(seg[-1].lower())
    for n in nouns:
        for t in _ROUTE_TMPL:
            stems_out.append(t.format(n=n))
    seen, uniq = set(), []
    for s in stems_out:
        if s not in seen:
            seen.add(s); uniq.append(s)
        if len(uniq) >= 40:
            break
    return uniq


def stems(fetched):
    """Distinct paths that answered 200 (the real route shapes)."""
    s, seen = [], set()
    for u, st, _b in fetched:
        if st == 200:
            p = urlparse(u).path or "/"
            if p not in seen:
                seen.add(p); s.append(p)
        if len(s) >= MAX_STEMS:
            break
    return s


import hashlib
SENTINELS = ["90000071", "00000000-0000-4000-8000-000000000000"]  # improbable ids


def _shape_url(base, mode, i):
    return base + "/" + i if mode == "path" else base + "?" + urlencode({mode[2:]: i})


def _sig(resp):
    return (resp.get("status") or 0, hashlib.sha1((resp.get("body") or b"")[:200000]).hexdigest()[:12])


def build_shapes(all_stems, forms):
    """(base, mode) pairs to probe. Generic path + generic query names off every
    stem, PLUS each GET form's own field names as query params off its action
    (the real object parameter)."""
    shapes, seen = [], set()
    def add(base, mode):
        k = base + "||" + mode
        if k not in seen:
            seen.add(k); shapes.append((base, mode))
    for p in all_stems:
        base = BASE + (p.rstrip("/") or "")
        add(base, "path")
        for n in QUERY_NAMES:
            add(base, "q:" + n)
    for f in forms:
        if f["method"] == "get" and f["path"] != "/":
            base = BASE + (f["path"].rstrip("/") or "")
            for n in f["names"]:
                add(base, "q:" + n)
    return shapes


def synthesize(shapes, ids, sess):
    """Two-phase, so the expensive selectivity gate only runs on shapes that are
    actually alive. Phase A (liveness): one cheap probe per shape -- keep it only
    if it 200s, or if it 401/403s (protected: a real id may still 200) and a
    second id 200s. Dead 404 shapes cost exactly one request. Phase B
    (selectivity): the full id-sample gate on survivors only -- keep a shape where
    the id selects content (response varies by id); drop query-ignored aliases and
    shared pages (same response for every id) that caused the shared-page FPs."""
    out, seen, kept = [], set(), 0
    sample = list(dict.fromkeys((ids[:2] + ["1", "2", "3", "4"])))[:6] + SENTINELS
    # Liveness sweep over the classic low object ids: a real object route 200s for
    # a present id but 404s for a missing one, so probing a harvested (often large/
    # invalid) id alone would drop it. Lead with 1/2/3; stop early on a 200.
    probe_ids = ["1", "2", "3"]

    live = []
    for base, mode in shapes:
        statuses = []
        for pid in probe_ids:
            st = sess.get("GET", _shape_url(base, mode, pid)).get("status")
            statuses.append(st)
            if st == 200:
                break                               # clearly alive, no need to probe more
        # keep if any low id hit 200, OR the route is protected (401/403): a real id
        # may still select content -- let the selectivity gate decide.
        if any(s == 200 for s in statuses) or any(s in (401, 403) for s in statuses):
            live.append((base, mode))

    def add(url, mode, i):
        if url.startswith(BASE) and url not in seen:
            seen.add(url)
            out.append({"method": "GET", "url": url, "where": "synth:" + mode, "id": i})
    for base, mode in live:
        sigs = {_sig(sess.get("GET", _shape_url(base, mode, i))) for i in sample}
        if len(sigs) > 1 and any(s == 200 for s, _h in sigs):
            kept += 1
            for i in ids:
                if len(out) >= MAX_CANDIDATES:
                    return out, kept, len(live)
                add(_shape_url(base, mode, i), mode, i)
    return out, kept, len(live)


# ---- POST-form replay -----------------------------------------------------
FORM_CTYPE = "application/x-www-form-urlencoded"
MAX_POST_FIELDS = 6  # fields per form worth varying


def build_post_shapes(forms):
    """For each POST form: (action_url, defaults_dict, target_field). We vary one
    field (id-ish first, then others) and hold the rest at the form's REAL default
    values (what a browser sends) -- blanking co-fields made every POST fail
    validation identically, hiding the selector."""
    shapes = []
    for f in forms:
        if f["method"] != "post" or f["path"] == "/" or not f["names"]:
            continue
        base = BASE + (f["path"].rstrip("/") or "")
        defaults = dict(f.get("defaults", {}))
        ordered = [n for n in f["names"] if _IDKEY.search(n)] + \
                  [n for n in f["names"] if not _IDKEY.search(n)]
        for tgt in ordered[:MAX_POST_FIELDS]:
            shapes.append((base, defaults, tgt))
    return shapes


def _post_body(defaults, tgt, i):
    data = dict(defaults)
    data[tgt] = i
    return urlencode(data).encode()


def synthesize_post(post_shapes, ids, sess):
    """Same selectivity gate as GET: keep a (form,field) only if varying the id in
    that field varies the response. Emits POST refs carrying the encoded body.
    Post shapes are few (one per form field), so single-phase is fine -- but they
    still route through the self-healing session for pacing + relogin."""
    out, seen, kept = [], set(), 0
    sample = list(dict.fromkeys((ids[:2] + ["1", "2", "3", "4"])))[:6] + SENTINELS
    for base, defaults, tgt in post_shapes:
        sigs = {_sig(sess.get("POST", base, data=_post_body(defaults, tgt, i),
                              ctype=FORM_CTYPE)) for i in sample}
        if len(sigs) > 1 and any(s == 200 for s, _h in sigs):
            kept += 1
            for i in ids:
                key = base + "|" + tgt + "|" + i
                if key in seen or len(out) >= MAX_CANDIDATES:
                    continue
                seen.add(key)
                out.append({"method": "POST", "url": base, "where": "postform:" + tgt,
                            "id": i, "data": _post_body(defaults, tgt, i), "ctype": FORM_CTYPE})
    return out, kept


# ---- API endpoint enumeration --------------------------------------------
# Unlinked JSON API routes (no href, no XHR in the HTML) are invisible to a
# link/form crawler. Fuzz /api/{noun} from a curated object-noun wordlist plus
# the app's own page vocabulary; the selectivity gate downstream keeps only the
# ones where an id selects content.
API_NOUNS = ["note", "notes", "user", "users", "profile", "account", "accounts",
             "order", "orders", "invoice", "invoices", "doc", "docs", "document",
             "file", "files", "message", "messages", "item", "items", "product",
             "products", "ticket", "tickets", "comment", "comments", "report",
             "record", "records", "status", "search", "me", "flag", "admin",
             "export", "card", "payment", "transaction", "customer", "cart"]


def _vocab_nouns(fetched, cap=24):
    from collections import Counter
    c = Counter()
    for _u, _s, body in fetched:
        text = re.sub(rb"<[^>]+>", b" ", body).decode("utf-8", "replace").lower()
        for w in re.findall(r"[a-z]{3,12}", text):
            c[w] += 1
    out = []
    for w, _n in c.most_common(60):
        out.append(w)
        out.append(w[:-1] if w.endswith("s") else w + "s")
        if len(out) >= cap:
            break
    return out


def api_candidates(fetched):
    nouns = list(dict.fromkeys(API_NOUNS + _vocab_nouns(fetched)))
    paths = []
    for n in nouns:
        paths.append("/api/" + n)
        paths.append("/" + n)
    return paths


# ---- run ------------------------------------------------------------------
jar = Req()
sess_a = Session("alice", CREDS["alice"], jar)   # self-healing session for synthesis
cookie_a = sess_a.cookie
cookie_b = login("bob", CREDS["bob"])

urls_a, fetched_a = crawl(cookie_a, jar)
urls_b, fetched_b = crawl(cookie_b, jar)
fetched = fetched_a + fetched_b

ids, keynames = harvest_ids(fetched)
# sequential id enumeration: object ids often aren't rendered anywhere (esp. other
# users' objects), so try 1..N alongside harvested ids -- the classic IDOR sweep.
ids = list(dict.fromkeys(ids + [str(i) for i in range(1, 30)]))
crawled_stems = stems(fetched)
forms = grab_forms(fetched)
form_paths = {f["path"] for f in forms if f["path"] != "/"}
all_stems = list(dict.fromkeys(derive_stems(crawled_stems, keynames, form_paths)
                               + api_candidates(fetched)))[:140]
shapes = build_shapes(all_stems, forms)
synth_refs, kept_shapes, live_shapes = synthesize(shapes, ids, sess_a)
post_shapes = build_post_shapes(forms)
post_refs, kept_post = synthesize_post(post_shapes, ids, sess_a)
# refs = pre-vetted GET + POST object candidates + id-named refs from crawled URLs
crawled_refs = idor.harvest_object_refs([], sorted(urls_a))
seen_ref, refs = set(), []
for r in synth_refs + post_refs + crawled_refs:
    k = r["method"] + " " + r["url"] + " " + (r.get("data") or b"").decode("latin1")
    if k not in seen_ref:
        seen_ref.add(k); refs.append(r)

# Synthesis is the long, heavy phase; by the time it finishes the initial cookies
# may be stale (and sess_a may have self-healed to a new cookie internally).
# Let the single-threaded target drain the synth backlog, then refresh BOTH
# sessions so the cross-user confirm runs on live auth against a calm server --
# otherwise a stale cookie or a reset anon-baseline probe makes every real IDOR
# read as unconfirmable "public-or-distinct".
time.sleep(1.5)
cookie_a = login("alice", CREDS["alice"])
cookie_b = login("bob", CREDS["bob"])

# Both directions: ids live on both surfaces; the vuln may be either way.
det_ab = idor.run_detailed("127.0.0.1:8099", cookie_a, cookie_b, "alice", "bob",
                           [], [], jar, cap=RUN_CAP, refs=refs)
det_ba = idor.run_detailed("127.0.0.1:8099", cookie_b, cookie_a, "bob", "alice",
                           [], [], jar, cap=RUN_CAP, refs=refs)

findings = []
for d in det_ab:
    if d["verdict"] == "cross_user_idor":
        c = idor.confirm_idor2(d["ref"]["url"], d["ref"]["method"], cookie_a, cookie_b, "alice", "bob", jar,
                               data=d["ref"].get("data"), ctype=d["ref"].get("ctype"))
        findings.append({"dir": "bob->alice", "confirmed": c["confirmed"], "basis": c["basis"],
                         "b_status": d["b_status"], **d["ref"]})
for d in det_ba:
    if d["verdict"] == "cross_user_idor":
        c = idor.confirm_idor2(d["ref"]["url"], d["ref"]["method"], cookie_b, cookie_a, "bob", "alice", jar,
                               data=d["ref"].get("data"), ctype=d["ref"].get("ctype"))
        findings.append({"dir": "alice->bob", "confirmed": c["confirmed"], "basis": c["basis"],
                         "b_status": d["b_status"], **d["ref"]})

def _jsafe(o):
    return o.decode("latin1") if isinstance(o, bytes) else str(o)
open(OUT, "w", encoding="utf-8").write(json.dumps(findings, ensure_ascii=False, indent=2, default=_jsafe))

# ---- blind-safe counts only (no URLs, no id values) ----
owned_ab = len(det_ab)
owned_ba = len(det_ba)
confirmed = sum(1 for f in findings if f["confirmed"])
import collections
bases = collections.Counter(f["basis"] for f in findings)
print("login alice:", "yes" if cookie_a else "NO", "| login bob:", "yes" if cookie_b else "NO")
print("authed urls crawled (A):", len(urls_a), "| (B):", len(urls_b))
getname_ct = sum(len(f["names"]) for f in forms if f["method"] == "get")
print("ids harvested:", len(ids), "| id-key names:", len(keynames),
      "| crawled stems:", len(crawled_stems), "| forms:", len(forms),
      "| GET-form field names:", getname_ct, "| derived stems:", len(all_stems))
print("GET shapes probed:", len(shapes), "| live (phase A):", live_shapes,
      "| id-selective kept:", kept_shapes, "| GET refs:", len(synth_refs),
      "| session relogins:", sess_a.relogins)
print("POST shapes probed:", len(post_shapes), "| id-selective kept:", kept_post, "| POST refs:", len(post_refs),
      "| total refs tested:", len(refs))
print("refs A legitimately owns (A->B dir):", owned_ab, "| (B->A dir):", owned_ba)
print("idor suspect findings:", len(findings), "| confirmed:", confirmed)
print("confirm basis:", dict(bases))
