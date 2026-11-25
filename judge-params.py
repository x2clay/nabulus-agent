import pathlib
import re

raw = pathlib.Path(r"C:\Users\Laith\nabulus-agent\raw")
text = (raw / "params.out").read_text(encoding="utf-8", errors="replace") if (raw / "params.out").exists() else ""
pairs = []
for line in text.splitlines():
    m = re.search(r"https?://([^/\s]+).*[?&]([A-Za-z0-9_]+)=1 base=(\S+) got=(\S+)", line)
    if m:
        pairs.append((m.group(1), m.group(2), m.group(3), m.group(4)))
print("param_changes", len(pairs))
print("param_lines", len(text.splitlines()))
for line in text.splitlines()[:12]:
    tail = line[line.find("base="):][:48] if "base=" in line else "no-base"
    name = ""
    if "?" in line:
        name = line.split("?", 1)[1].split("=", 1)[0][:24]
    print(name, tail)

verdicts = {"vulnerable": 0, "not_injectable": 0, "other": 0}
for path in raw.glob("sqlmap*.out"):
    body = path.read_text(encoding="utf-8", errors="replace").lower()
    if "is vulnerable" in body or "identified the following injection" in body:
        verdicts["vulnerable"] += 1
    elif "not injectable" in body or "does not seem to be injectable" in body:
        verdicts["not_injectable"] += 1
    else:
        verdicts["other"] += 1
print("sqlmap_files", verdicts)
keys = ("timeout", "connection refused", "fetched", "heuristic", "all tested parameters", "unable to connect")
for path in sorted(raw.glob("sqlmap*.out")):
    body = path.read_text(encoding="utf-8", errors="replace").lower()
    hits = [k for k in keys if k in body]
    print(path.name, "bytes", path.stat().st_size, "marks", ",".join(hits) or "-")
print("param_file_bytes", (raw / "params.out").stat().st_size if (raw / "params.out").exists() else 0)
