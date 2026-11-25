"""Extract the range run's findings from notebook.json into a flat JSON list
for grade.py. Prints ONLY structure + counts (no finding values), so the
operator stays blind to the discovered vuln layout."""
import json, re, os

NB = r"C:\Users\Laith\nabulus-agent\notebook.json"
OUT = r"C:\Users\Laith\nabulus-agent\range_findings.json"
PAT = re.compile(r"127\.0\.0\.1:8099/\S")  # a range URL WITH a path (drops bookkeeping)

if not os.path.exists(NB):
    raise SystemExit("notebook.json not found at " + NB)

nb = json.load(open(NB, encoding="utf-8"))
findings = []
seen = set()

def add(obj):
    blob = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    if blob not in seen:
        seen.add(blob)
        findings.append(obj)

def dict_has_range(d):
    return any(isinstance(v, str) and PAT.search(v) for v in d.values())

def walk(x, parent_captured=False):
    if isinstance(x, dict):
        cap = dict_has_range(x)
        if cap:
            add(x)
        for v in x.values():
            walk(v, cap or parent_captured)
    elif isinstance(x, list):
        for v in x:
            walk(v, parent_captured)
    elif isinstance(x, str):
        if not parent_captured and PAT.search(x):
            add({"text": x})

walk(nb)
json.dump(findings, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)

print("notebook top keys:", list(nb.keys()) if isinstance(nb, dict) else type(nb).__name__)
if isinstance(nb, dict):
    for k, v in nb.items():
        if isinstance(v, list):
            fields = sorted(v[0].keys()) if v and isinstance(v[0], dict) else (type(v[0]).__name__ if v else "empty")
            print(f"  {k}: list[{len(v)}] fields={fields}")
print("range findings extracted:", len(findings))
