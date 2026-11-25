"""Policy-gated HTTP. Every request passes Policy.check_action + the shared RateLimiter, so a
worker physically cannot hit an out-of-scope asset, exceed the rate limit, or send a
state-changing method unless the scope file opted in. Governance enforced at the request layer,
not in prompts."""
from __future__ import annotations
import ssl
import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from urllib.parse import urlsplit

from .policy import Policy, RateLimiter

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE     # labs/self-signed; scope is the boundary, not TLS


@dataclass(frozen=True)
class Response:
    status: int
    ctype: str
    body: str


class GatedHttp:
    def __init__(self, policy: Policy, asset: str, limiter: RateLimiter, token: str | None = None):
        self._policy = policy
        self._asset = asset
        self._limiter = limiter
        self._token = token

    def request(self, method: str, url: str, body: dict | None = None) -> Response:
        path = urlsplit(url).path or "/"
        self._policy.check_action(self._asset, method, path)   # raises ScopeError => fail closed
        self._limiter.wait()
        data = json.dumps(body).encode() if body is not None else None
        headers = {"User-Agent": "nabulus-agent"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            r = urllib.request.urlopen(req, timeout=20, context=_CTX)
            return Response(r.status, r.headers.get("Content-Type", ""),
                            r.read(20000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return Response(e.code, e.headers.get("Content-Type", ""),
                            e.read(8000).decode("utf-8", "replace"))
        except Exception as e:  # network/DNS/timeout surfaced as status 0, never swallowed
            return Response(0, "", str(e))

    def get(self, url: str) -> Response:
        return self.request("GET", url)
