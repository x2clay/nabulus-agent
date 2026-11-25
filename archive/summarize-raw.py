"""Counts only. No URLs, bodies, or headers."""
import json
import pathlib

raw = pathlib.Path(r"C:\Users\Laith\nabulus-agent\raw")
for path in sorted(raw.glob("ffuf*.json")) + sorted(raw.glob("ffuf*.out")):
    text = path.read_text(encoding="utf-8", errors="replace")
    blob = text[text.find("{") : text.rfind("}") + 1] if "{" in text else ""
    try:
        data = json.loads(blob) if blob else {}
    except json.JSONDecodeError:
        data = {}
    rows = data.get("results") or []
    counts: dict[str, int] = {}
    sizes: dict[str, int] = {}
    for row in rows:
        key = str(row.get("status"))
        counts[key] = counts.get(key, 0) + 1
        size = str(row.get("length"))
        sizes[size] = sizes.get(size, 0) + 1
    top = sorted(sizes.items(), key=lambda item: item[1], reverse=True)[:3]
    print(f"{path.name} rows={len(rows)} status={counts} top_sizes={top}")
