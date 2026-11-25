"""Ground-truth answer keys for benchmark targets. Each expected vuln is tagged contaminated
(the model likely saw a writeup) or clean (post-cutoff / unpublished), so the harness can report
discovery vs recall separately."""
from __future__ import annotations
import json
import pathlib
from dataclasses import dataclass


@dataclass(frozen=True)
class ExpectedVuln:
    vuln_class: str          # matches contracts.VulnClass value, e.g. "idor-enumeration"
    locator: str             # endpoint template or param, e.g. "/api/users/{id}"
    contaminated: bool = True
    note: str = ""


@dataclass(frozen=True)
class AnswerKey:
    target: str
    base_url: str
    contaminated: bool               # is the whole target a known/published benchmark?
    expected: tuple[ExpectedVuln, ...]

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "AnswerKey":
        d = json.loads(pathlib.Path(path).read_text())
        default_contam = bool(d.get("contaminated", True))
        expected = tuple(
            ExpectedVuln(
                vuln_class=str(e["vuln_class"]),
                locator=str(e.get("locator", "")),
                contaminated=bool(e.get("contaminated", default_contam)),
                note=str(e.get("note", "")),
            )
            for e in d.get("expected", [])
        )
        return cls(
            target=str(d["target"]),
            base_url=str(d.get("base_url", "")),
            contaminated=default_contam,
            expected=expected,
        )
