import pathlib
import pytest

from engine.bench.answerkey import AnswerKey
from engine.bench.runners import RecordedRunner
from engine.bench.harness import run_benchmark

HERE = pathlib.Path(__file__).parent


@pytest.mark.unit
def test_recall_precision_and_contamination_gap():
    # Arrange: 3 expected (2 contaminated, 1 clean); runner finds both contaminated + 1 false alarm
    key = AnswerKey.load(HERE / "fixtures" / "demo_key.json")
    runner = RecordedRunner(HERE / "fixtures" / "demo_findings.json")

    # Act
    card = run_benchmark(key, runner).scorecards[0]

    # Assert
    assert (card.true_positives, card.false_negatives, card.false_positives) == (2, 1, 1)
    assert card.recall == pytest.approx(0.667, abs=0.01)
    assert card.fp_rate == pytest.approx(0.333, abs=0.01)
    assert card.recall_contaminated == 1.0
    assert card.recall_clean == 0.0
    assert card.contamination_gap == 1.0   # all success was on memorized targets
