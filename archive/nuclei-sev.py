import json
import pathlib
import re
from collections import Counter

raw = pathlib.Path(r"C:\Users\Laith\nabulus-agent\raw")
files = sorted(raw.glob("follow_nuclei*.out"), key=lambda p: p.stat().st_mtime, reverse=True)[:3]
for path in files:
    counts = Counter()
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith("{"):
            try:
                info = json.loads(line).get("info") or {}
            except json.JSONDecodeError:
                continue
            counts[str(info.get("severity") or "?")] += 1
            continue
        hit = re.search(r"\[(info|low|medium|high|critical|unknown)\]", line, re.I)
        if hit:
            counts[hit.group(1).lower()] += 1
    print(path.name, "bytes", path.stat().st_size, "lines", len(text.splitlines()), dict(counts))
    shown = 0
    for line in text.splitlines():
        clean = re.sub(r"https?://\S+", "[url]", line).strip()
        if not clean:
            continue
        print(" ", clean[:110])
        shown += 1
        if shown >= 4:
            break
