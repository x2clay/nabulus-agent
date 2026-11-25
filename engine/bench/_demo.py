import sys
import pathlib

sys.path.insert(0, r"C:\Users\Laith\nabulus-agent")
from engine.bench.answerkey import AnswerKey
from engine.bench.runners import RecordedRunner
from engine.bench.harness import run_benchmark, format_result

HERE = pathlib.Path(__file__).parent
key = AnswerKey.load(HERE / "fixtures" / "demo_key.json")
runner = RecordedRunner(HERE / "fixtures" / "demo_findings.json")
result = run_benchmark(key, runner)
print(format_result(result))
c = result.scorecards[0]
assert (c.true_positives, c.false_negatives, c.false_positives) == (2, 1, 1), c
assert c.recall_contaminated == 1.0 and c.recall_clean == 0.0 and c.contamination_gap == 1.0
print("\nDEMO OK")
