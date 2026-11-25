"""Benchmark harness: run a scanner against a target with a known answer key, score it, and report
recall + false-positive rate split by contamination and web-search mode. Target-agnostic - a Runner
is anything that returns Findings for a Target, so the same harness grades our engine, an external
tool, or a recorded run."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol

from ..contracts import Finding, Target
from .answerkey import AnswerKey
from .scoring import Scorecard, score


class Runner(Protocol):
    name: str

    def run(self, target: Target, web_search: bool) -> list[Finding]:
        ...


@dataclass(frozen=True)
class BenchResult:
    runner: str
    target: str
    scorecards: tuple[Scorecard, ...]

    @property
    def web_search_gap(self) -> float | None:
        by_mode = {s.mode: s.recall for s in self.scorecards}
        if "web_search" in by_mode and "no_web_search" in by_mode:
            return round(by_mode["web_search"] - by_mode["no_web_search"], 3)
        return None


def run_benchmark(key: AnswerKey, runner: Runner, web_search_modes: tuple[bool, ...] = (False,)) -> BenchResult:
    target = Target(asset=key.target, base_url=key.base_url, authorization_ref="benchmark answer-key target")
    cards = [
        score(key, runner.run(target, ws), mode="web_search" if ws else "no_web_search")
        for ws in web_search_modes
    ]
    return BenchResult(runner=runner.name, target=key.target, scorecards=tuple(cards))


def format_result(result: BenchResult) -> str:
    lines = [f"== {result.runner} vs {result.target} =="]
    for s in result.scorecards:
        lines.append(
            f"[{s.mode}] recall={s.recall} precision={s.precision} fp_rate={s.fp_rate} "
            f"(TP={s.true_positives} FN={s.false_negatives} FP={s.false_positives})"
        )
        lines.append(f"   contamination: known={s.recall_contaminated} clean={s.recall_clean} gap={s.contamination_gap}")
        if s.missed:
            lines.append(f"   missed:      {', '.join(s.missed)}")
        if s.spurious:
            lines.append(f"   false alarms: {', '.join(s.spurious)}")
    if result.web_search_gap is not None:
        lines.append(f"web-search recall gap: {result.web_search_gap}  (high => leaning on published writeups)")
    return "\n".join(lines)
