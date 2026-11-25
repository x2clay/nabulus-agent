"""Runners the harness can grade. A Runner returns Findings for a Target. RecordedRunner replays a
saved findings file (scores without a live target); EngineRunner drives our coordinator + workers.
Any external scanner wraps the same way."""
from __future__ import annotations
import json
import pathlib
from typing import Callable

from ..contracts import Finding, Target, VulnClass, Severity, Evidence


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        vuln_class=VulnClass(d["vuln_class"]),
        severity=Severity(d.get("severity", "info")),
        endpoint=str(d.get("endpoint", "")),
        summary=str(d.get("summary", "")),
        evidence=tuple(
            Evidence(request=e.get("request", ""), response_excerpt=e.get("response_excerpt", ""), note=e.get("note", ""))
            for e in d.get("evidence", [])
        ),
        confirmed=bool(d.get("confirmed", False)),
    )


class RecordedRunner:
    """Replays findings from JSON: {"<target>": [finding, ...]} or a bare [finding, ...]."""
    name = "recorded"

    def __init__(self, path: str | pathlib.Path):
        self._data = json.loads(pathlib.Path(path).read_text())

    def run(self, target: Target, web_search: bool) -> list[Finding]:
        rows = self._data.get(target.asset, []) if isinstance(self._data, dict) else self._data
        return [_finding_from_dict(d) for d in rows]


class EngineRunner:
    """Drives our coordinator. task_builder(target, web_search) -> (tasks, worker_factory)."""
    name = "nabulus-engine"

    def __init__(self, coordinator, task_builder: Callable):
        self._coord = coordinator
        self._build = task_builder

    def run(self, target: Target, web_search: bool) -> list[Finding]:
        tasks, factory = self._build(target, web_search)
        return self._coord.candidates(self._coord.dispatch(tasks, factory))
