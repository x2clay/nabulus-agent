"""Core data contracts for the nabulus autonomous pentest platform.

Everything that moves between coordinator, workers and validators is one of these
immutable records. Workers are short-lived and single-objective: one Task in, one
WorkerResult out, then retired - so no worker ever accumulates broad context. That is
both the "fresh context to avoid bias" pattern AND why the autonomy never builds up an
escalating session: each unit of work is small, scoped and legible on its own.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"; LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"


class VulnClass(str, Enum):
    IDOR = "idor-enumeration"
    BULK_DISCLOSURE = "bulk-user-disclosure"
    PRIV_ESC = "privilege-escalation"
    XSS_STORED = "xss-stored"
    XSS_REFLECTED = "xss-reflected"
    RACE_TOCTOU = "race-toctou"
    AUTH_JWT = "auth-jwt"
    SSRF = "ssrf"
    CORS = "cors-misconfig"
    CSRF = "csrf"
    INJECTION = "injection"
    BUSINESS_LOGIC = "business-logic"
    UNAUTH_EXPOSURE = "unauth-exposure"
    OPEN_REDIRECT = "open-redirect"


@dataclass(frozen=True)
class Target:
    """One authorized asset. Only the scope policy may construct these."""
    asset: str              # "cortisol.gg", "localhost:3000"
    base_url: str
    authorization_ref: str  # human-readable proof-of-authorization, carried from the scope file


@dataclass(frozen=True)
class Task:
    """A single bounded objective for one short-lived worker. The worker sees only this."""
    task_id: str
    target: Target
    vuln_class: VulnClass
    objective: str                                   # "probe /api/users/{id} for cross-user reads"
    params: dict[str, Any] = field(default_factory=dict)
    max_requests: int = 50                           # hard per-task budget


@dataclass(frozen=True)
class Evidence:
    request: str
    response_excerpt: str
    note: str = ""


@dataclass(frozen=True)
class Finding:
    vuln_class: VulnClass
    severity: Severity
    endpoint: str
    summary: str
    evidence: tuple[Evidence, ...] = ()
    confirmed: bool = False      # only True after a Validator independently reproduces it
    cvss: float | None = None
    remediation: str = ""


@dataclass(frozen=True)
class WorkerResult:
    task_id: str
    candidate_findings: tuple[Finding, ...] = ()     # UNvalidated - coordinator routes to a validator
    requests_made: int = 0
    notes: str = ""


@dataclass(frozen=True)
class ValidatorResult:
    finding: Finding
    reproduced: bool
    proof: tuple[Evidence, ...] = ()
    false_positive_reason: str = ""
