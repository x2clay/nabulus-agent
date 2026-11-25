"""Match reported findings against an answer key and compute recall, precision, false-positive
rate, and the contamination gap (recall on known/published vulns vs clean/unpublished ones)."""
from __future__ import annotations
from dataclasses import dataclass

from ..contracts import Finding
from .answerkey import AnswerKey, ExpectedVuln


def _norm(s: str) -> str:
    return s.strip().lower().rstrip("/")


def _matches(expected: ExpectedVuln, finding: Finding) -> bool:
    if _norm(finding.vuln_class.value) != _norm(expected.vuln_class):
        return False
    if not expected.locator:
        return True
    e, f = _norm(expected.locator), _norm(finding.endpoint)
    return e in f or f in e


def _rate(num: int, den: int) -> float:
    return round(num / den, 3) if den else 0.0


@dataclass(frozen=True)
class Scorecard:
    target: str
    mode: str                         # "web_search" | "no_web_search"
    true_positives: int
    false_negatives: int
    false_positives: int
    recall: float
    precision: float
    fp_rate: float
    recall_contaminated: float
    recall_clean: float
    found: tuple[str, ...]
    missed: tuple[str, ...]
    spurious: tuple[str, ...]

    @property
    def contamination_gap(self) -> float:
        """Recall drop from known -> clean. A big gap means recall, not discovery."""
        return round(self.recall_contaminated - self.recall_clean, 3)


def score(key: AnswerKey, findings: list[Finding], mode: str) -> Scorecard:
    expected = list(key.expected)
    matched_expected: set[int] = set()
    matched_reported: set[int] = set()
    for i, exp in enumerate(expected):
        for j, found in enumerate(findings):
            if _matches(exp, found):
                matched_expected.add(i)
                matched_reported.add(j)
    tp = len(matched_expected)
    contaminated = [i for i, e in enumerate(expected) if e.contaminated]
    clean = [i for i, e in enumerate(expected) if not e.contaminated]
    return Scorecard(
        target=key.target,
        mode=mode,
        true_positives=tp,
        false_negatives=len(expected) - tp,
        false_positives=len(findings) - len(matched_reported),
        recall=_rate(tp, len(expected)),
        precision=_rate(len(matched_reported), len(findings)),
        fp_rate=_rate(len(findings) - len(matched_reported), len(findings)),
        recall_contaminated=_rate(sum(1 for i in contaminated if i in matched_expected), len(contaminated)),
        recall_clean=_rate(sum(1 for i in clean if i in matched_expected), len(clean)),
        found=tuple(expected[i].locator for i in sorted(matched_expected)),
        missed=tuple(e.locator for i, e in enumerate(expected) if i not in matched_expected),
        spurious=tuple(f.endpoint for j, f in enumerate(findings) if j not in matched_reported),
    )
