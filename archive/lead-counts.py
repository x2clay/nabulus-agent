import json
import pathlib
nb = json.loads(pathlib.Path(r"C:\Users\Laith\nabulus-agent\notebook.json").read_text(encoding="utf-8"))
leads = nb.get("leads") or []
counts = {}
for item in leads:
    lead = item.get("lead") or item
    tool = str(lead.get("tool") or "?")
    sev = str(lead.get("severity") or "?")
    status = str(item.get("status") or "")
    key = f"{tool}:{sev}:{status}"
    counts[key] = counts.get(key, 0) + 1
print("lead_rows", len(leads))
for key in sorted(counts):
    print(key, counts[key])
print("proofs", len(nb.get("proofs") or []))
print("blind", nb.get("blind"))
