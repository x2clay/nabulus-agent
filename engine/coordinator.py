"""Coordinator: loads the scope policy, builds the authorized Target, dispatches a bounded fleet
of short-lived workers, collects candidates, and (next) routes them to validators. Concurrency is
capped and the whole fleet shares one RateLimiter, so it stays within the target's rate limit no
matter how many workers run."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from .policy import Policy, RateLimiter
from .contracts import Task, Target, Finding, WorkerResult
from .http import GatedHttp
from .worker import Worker


@dataclass
class Coordinator:
    policy: Policy
    max_workers: int = 6
    token: str | None = None
    _limiter: RateLimiter = field(init=False)

    def __post_init__(self):
        self._limiter = RateLimiter(self.policy.rate_limit_rps)

    def _http_for(self, target: Target) -> GatedHttp:
        return GatedHttp(self.policy, target.asset, self._limiter, self.token)

    def dispatch(self, tasks: list[Task],
                 worker_factory: Callable[[Task, GatedHttp], Worker]) -> list[WorkerResult]:
        """Each task gets a fresh, short-lived worker. Target is scope-checked before anything runs."""
        results: list[WorkerResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futs = {}
            for t in tasks:
                self.policy.check_target(t.target)      # fail closed before dispatch
                w = worker_factory(t, self._http_for(t.target))
                futs[pool.submit(w.run, t)] = t
            for fut in as_completed(futs):
                results.append(fut.result())
        return results

    @staticmethod
    def candidates(results: list[WorkerResult]) -> list[Finding]:
        return [f for r in results for f in r.candidate_findings]
