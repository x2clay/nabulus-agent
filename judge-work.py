"""Quality counts from the agent notebook and raw files. No response bodies."""
import json
import pathlib
from collections import Counter

agent = pathlib.Path(r"C:\Users\Laith\nabulus-agent")
nb = json.loads((agent / "notebook.json").read_text(encoding="utf-8"))
tests = nb.get("tests") or []
print("tests", len(tests), "blind", nb.get("blind"), "proofs", len(nb.get("proofs") or []))
by = Counter((t.get("tool"), (t.get("target") or "").split(".")[0]) for t in tests)
# tool -> result prefix
tools = Counter(t.get("tool") for t in tests)
print("tools", dict(tools))
print("RECENT")
for t in tests[-25:]:
    result = " ".join(str(t.get("result") or "").split())[:140]
    print(f"{t.get('tool')} {t.get('target')} {result}")

print("LEADS")
for item in nb.get("leads") or []:
    lead = item.get("lead") or {}
    ev = " ".join(str(lead.get("evidence") or "").split())[:80]
    matched = str(lead.get("matched") or "")
    path = matched.split("?", 1)[0]
    if "://" in path:
        path = "/" + path.split("/", 3)[-1]
    print(item.get("status"), lead.get("tool"), lead.get("severity"), path[:80], ev)
