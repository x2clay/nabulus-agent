"""Worker base + first concrete worker (IDOR/enumeration).

A worker is short-lived and single-objective: one Task in, candidate (UNvalidated) findings out,
then discarded. It never decides scope - that's the gate under GatedHttp."""
from __future__ import annotations
import re
from abc import ABC, abstractmethod

from .contracts import Task, WorkerResult, Finding, Evidence, Severity, VulnClass
from .http import GatedHttp


class Worker(ABC):
    vuln_class: VulnClass

    def __init__(self, http: GatedHttp):
        self._http = http
        self._requests = 0

    @abstractmethod
    def probe(self, task: Task) -> list[Finding]:
        ...

    def run(self, task: Task) -> WorkerResult:
        findings = self.probe(task)
        return WorkerResult(task_id=task.task_id, candidate_findings=tuple(findings),
                            requests_made=self._requests)


_ID_RE = re.compile(r"\b(4000000000000\d{3}|80\d{14})\b")


class IdorWorker(Worker):
    """Sequential-id cross-user read probe. Candidate only if a response carries a user id that
    isn't the requester's. Read-only GET."""
    vuln_class = VulnClass.IDOR

    def probe(self, task: Task) -> list[Finding]:
        base = task.target.base_url.rstrip("/")
        tmpl = task.params.get("endpoint", "/api/users/{id}")
        my_id = int(task.params.get("requester_id", 0))
        start = int(task.params.get("start_id", 4000000000000001))
        sweep = min(int(task.params.get("sweep", 8)), task.max_requests)
        hits: list[Evidence] = []
        for i in range(sweep):
            tid = start + i
            if tid == my_id:
                continue
            r = self._http.get(base + tmpl.format(id=tid))
            self._requests += 1
            if r.status == 200 and ("json" in r.ctype or r.body.strip().startswith("{")):
                ids = {int(x) for x in _ID_RE.findall(r.body)}
                if (ids - {my_id}) or ('"username"' in r.body and str(my_id) not in r.body):
                    hits.append(Evidence(request=f"GET {tmpl.format(id=tid)}",
                                         response_excerpt=r.body[:180],
                                         note=f"ids={sorted(ids)[:6]}"))
        if not hits:
            return []
        return [Finding(
            vuln_class=VulnClass.IDOR, severity=Severity.HIGH, endpoint=tmpl,
            summary="Cross-user read via sequential id enumeration", evidence=tuple(hits),
            remediation="Enforce per-object authorization; return only public fields to "
                        "non-owners; use non-sequential ids.")]
