"""Scope / authorization enforcement. This is the mechanical gate - NOT a judgment call.

The coordinator cannot act on a target or run an action this module doesn't allow, period.
A scope policy + a destructive-action blocker sit UNDER the autonomy, so the reasoning layer
never decides whether something is authorized. Everything refuses by default (fail closed).
"""
from __future__ import annotations
import json
import pathlib
import time
import threading
from dataclasses import dataclass

from .contracts import Target

# Methods that can change server state. Proof-of-exploit is demonstrated WITHOUT these unless
# the scope file explicitly raises the impact level (default: never).
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class ScopeError(Exception):
    """Any attempt to act outside authorized scope. Fail closed."""


@dataclass(frozen=True)
class Policy:
    authorized_assets: frozenset[str]
    rate_limit_rps: float               # <= 0 means unlimited (default while testing owned targets)
    authorization_ref: str
    allow_state_changing: bool          # impact level: False => non-destructive proof only
    exclusions: frozenset[str]

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "Policy":
        d = json.loads(pathlib.Path(path).read_text())
        assets = d.get("authorized_assets") or []
        if not assets:
            raise ScopeError("scope file lists no authorized_assets; refusing to run")
        return cls(
            authorized_assets=frozenset(assets),
            rate_limit_rps=float(d.get("rate_limit_rps", 0)),   # absent => unlimited for now
            authorization_ref=d.get("authorization_ref", ""),
            allow_state_changing=bool(d.get("allow_state_changing", False)),
            exclusions=frozenset(d.get("exclusions") or []),
        )

    def check_target(self, target: Target) -> None:
        if target.asset not in self.authorized_assets:
            raise ScopeError(f"target {target.asset!r} not in authorized scope")

    def check_action(self, asset: str, method: str, path: str) -> None:
        if asset not in self.authorized_assets:
            raise ScopeError(f"{asset!r} not in authorized scope")
        if path in self.exclusions:
            raise ScopeError(f"path {path!r} is explicitly excluded")
        if method.upper() in STATE_CHANGING_METHODS and not self.allow_state_changing:
            raise ScopeError(
                f"{method} {path} is state-changing; policy is non-destructive-proof only. "
                f"Set allow_state_changing=true in the scope file to opt in (owned targets only).")


class RateLimiter:
    """Thread-safe minimum-interval limiter shared across the worker fleet.
    rps <= 0 => unlimited (no throttle); set a positive rps per-scope to throttle later."""

    def __init__(self, rps: float):
        self._min_interval = (1.0 / rps) if (rps and rps > 0) else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0.0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = max(0.0, self._next - now)
            self._next = max(now, self._next) + self._min_interval
        if sleep_for:
            time.sleep(sleep_for)
