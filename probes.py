"""Deterministic injection probes: free, local, no model, no scanner.

Mutates one parameter at a time on a parameterized route and reads the reply
the way surface.classify does. Two high-signal, low-false-positive tells:

  error-based SQLi -- value + "'" makes the app throw a 500 or emit a DB error
    string the clean baseline did not. -> suspect (injection).
  reflected XSS    -- a unique canary carrying HTML-breaking chars comes back
    verbatim and UNescaped inside an HTML response. -> suspect (xss).

Covers GET query parameters AND discovered <form> POST inputs, so a login-form
SQLi (POST body) is caught, not just GET params. The generic (model-driven)
skill stays as-is; this runs regardless of whether any model is up, which is
the point -- detection no longer depends on the LLM or on dalfox.

Output lines match what the engine already consumes:
  suspect <url> status=<n>            -- injection (error-based), confirm->sqlmap
  suspect-xss <url> status=<n>        -- reflected xss, confirm->re-send canary
interesting()/confirm treat both as leads; a suspect-xss is confirmed locally
by re-sending the canary and checking the unescaped reflection survives.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import surface

# A DB fault string the clean baseline would not contain.
SQL_ERRORS = (
    b"sql syntax", b"mysql_fetch", b"mysql_num_rows", b"you have an error in your sql",
    b"warning: mysql", b"unclosed quotation mark", b"quoted string not properly terminated",
    b"microsoft ole db", b"odbc sql", b"odbc drivers error", b"sqlstate",
    b"ora-01756", b"ora-00933", b"ora-00921", b"postgresql query failed",
    b"pg_query", b"sqlite_error", b"sqlite3::", b"native client", b"incorrect syntax near",
)

# A numeric id value → use arithmetic boolean payloads rather than quoted ones.
_NUMERIC = re.compile(r"^\d{1,12}$")

# A unique token plus a break-out that only renders if the app does not escape.
XSS_CANARY = "nqx9k3zz"
XSS_PAYLOAD = XSS_CANARY + '"><svg/onload=alert(1)>'
# Raw (unescaped) reflection fingerprint. If the app escaped it the body holds
# nqx9k3zz&quot;&gt;&lt;svg..., which does NOT contain this needle.
_XSS_RAW = (XSS_CANARY + '"><svg').lower().encode()


def _ctype(headers: dict) -> str:
    for key, value in (headers or {}).items():
        if key.lower() == "content-type":
            return value.lower()
    return ""


def _sql_error(body: bytes) -> bool:
    low = (body or b"")[:20000].lower()
    return any(n in low for n in SQL_ERRORS)


def _xss_reflected(body: bytes, headers: dict) -> bool:
    ctype = _ctype(headers)
    if ctype and "html" not in ctype:
        return False
    return _XSS_RAW in (body or b"").lower()


def _status(resp: dict) -> int:
    try:
        return int(resp.get("status") or 0)
    except (TypeError, ValueError):
        return 0


def _len_ratio(a: bytes, b: bytes) -> float:
    """0.0 = same length, 1.0 = maximally different."""
    la, lb = len(a or b""), len(b or b"")
    hi = max(la, lb)
    return abs(la - lb) / hi if hi else 0.0


def _boolean_tell(base: dict, rt: dict, rf: dict) -> bool:
    """Boolean-based SQLi: a TRUE condition reproduces the baseline page while a
    FALSE condition changes it. Catches injections that return 200 (custom error
    pages, ASP.NET) where the error-based 500/DB-string tell never fires.

    Low false positive: requires the true page to closely match the baseline AND
    the false page to differ from it by a clear margin. A static or always-equal
    endpoint fails both; an always-erroring endpoint fails the true match.
    """
    sb, st, sf = _status(base), _status(rt), _status(rf)
    if st == 0 or sf == 0 or sb == 0:
        return False
    bb = base.get("body") or b""
    bt = rt.get("body") or b""
    bf = rf.get("body") or b""
    if not bb.strip() or not bt.strip():
        return False
    norm_base = surface._norm(bb)
    true_like_base = (surface._norm(bt) == norm_base) or _len_ratio(bt, bb) <= 0.05
    false_differs = (surface._norm(bf) != surface._norm(bt)) and _len_ratio(bf, bt) >= 0.20
    return true_like_base and false_differs


def _bool_payloads(seed: str):
    """(true_value, false_value) pairs to append to the seed."""
    if _NUMERIC.match(seed):
        return (seed + " AND 1=1", seed + " AND 1=2")
    return (seed + "' AND '1'='1", seed + "' AND '1'='2")


def _set_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    out = [(k, value if k == param else v) for k, v in pairs]
    return urlunparse(parsed._replace(query=urlencode(out)))


class _FormScan(HTMLParser):
    """Collects <form> action/method and the names of its inputs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "get").upper(), "fields": {}}
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            if name:
                self._cur["fields"][name] = a.get("value", "1")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def forms_in(html: str, base_url: str) -> list[dict]:
    parser = _FormScan()
    try:
        parser.feed(html or "")
    except Exception:
        return []
    if parser._cur is not None:  # unterminated <form>
        parser.forms.append(parser._cur)
    out = []
    for form in parser.forms:
        if not form["fields"]:
            continue
        form["url"] = urljoin(base_url, form["action"] or base_url)
        out.append(form)
    return out


def _clean_value(value: str) -> str:
    """A benign seed value: keep a short existing one, else '1'."""
    value = (value or "").strip()
    return value if value and len(value) <= 24 else "1"


def probe_query(url: str, jar, max_params: int = 4) -> list[str]:
    """Mutate each GET query parameter with the two canaries."""
    parsed = urlparse(url)
    params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    if not params:
        return []
    base = jar.request("GET", url)
    base_sql_err = _sql_error(base.get("body") or b"")
    base_status = _status(base)
    lines: list[str] = []
    for param in params[:max_params]:
        seed = dict(parse_qsl(parsed.query, keep_blank_values=True)).get(param, "1")
        seed = _clean_value(seed)
        # error-based SQLi
        sqli_url = _set_query_param(url, param, seed + "'")
        r = jar.request("GET", sqli_url)
        st = _status(r)
        if (st >= 500 and base_status < 500) or (_sql_error(r.get("body") or b"") and not base_sql_err):
            lines.append(f"suspect {sqli_url} status={st}")
        else:
            # boolean-based SQLi (for 200-style injections that never 500)
            tv, fv = _bool_payloads(seed)
            rt = jar.request("GET", _set_query_param(url, param, tv))
            rf = jar.request("GET", _set_query_param(url, param, fv))
            if _boolean_tell(base, rt, rf):
                lines.append(f"suspect {_set_query_param(url, param, tv)} status={_status(rt)}")
        # reflected XSS
        xss_url = _set_query_param(url, param, XSS_PAYLOAD)
        r = jar.request("GET", xss_url)
        if _xss_reflected(r.get("body") or b"", r.get("headers") or {}):
            lines.append(f"suspect-xss {xss_url} status={_status(r)}")
    return lines


def probe_forms(html: str, base_url: str, jar, max_forms: int = 4) -> list[str]:
    """Mutate each discovered <form> input with the two canaries (POST or GET)."""
    lines: list[str] = []
    for form in forms_in(html, base_url)[:max_forms]:
        method = form["method"] if form["method"] in ("GET", "POST") else "POST"
        url = form["url"]
        base_fields = {k: _clean_value(v) for k, v in form["fields"].items()}
        base = _send_form(jar, method, url, base_fields)
        base_sql_err = _sql_error(base.get("body") or b"")
        base_status = _status(base)
        for name in list(form["fields"])[:6]:
            # error-based SQLi
            fields = dict(base_fields); fields[name] = base_fields.get(name, "1") + "'"
            r = _send_form(jar, method, url, fields)
            st = _status(r)
            if (st >= 500 and base_status < 500) or (_sql_error(r.get("body") or b"") and not base_sql_err):
                lines.append(f"suspect {url}?__form={name} status={st}")
            # reflected XSS
            fields = dict(base_fields); fields[name] = XSS_PAYLOAD
            r = _send_form(jar, method, url, fields)
            if _xss_reflected(r.get("body") or b"", r.get("headers") or {}):
                lines.append(f"suspect-xss {url}?__form={name} status={_status(r)}")
    return lines


def _send_form(jar, method: str, url: str, fields: dict) -> dict:
    body = urlencode(fields)
    if method == "GET":
        parsed = urlparse(url)
        full = urlunparse(parsed._replace(query=body))
        return jar.request("GET", full)
    return jar.request("POST", url, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=body.encode())


def confirm_xss(url: str, jar) -> bool:
    """Deterministic reflected-XSS confirm: re-send the canary, require the
    unescaped break-out to survive on an independent request. No dalfox."""
    parsed = urlparse(url)
    params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    # Prefer the param that already carried the canary; else try all.
    targets = [p for p in params if XSS_CANARY in dict(parse_qsl(parsed.query)).get(p, "")] or params
    for param in targets[:4]:
        probe = _set_query_param(url, param, XSS_PAYLOAD)
        r = jar.request("GET", probe)
        if _xss_reflected(r.get("body") or b"", r.get("headers") or {}):
            return True
    return False
