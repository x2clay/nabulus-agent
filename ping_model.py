import json, os, time, traceback, urllib.request
from pathlib import Path

for line in Path(r"C:\Users\Laith\nabulus-agent\local.env").read_text().splitlines():
    if "=" in line and not line.strip().startswith("#"):
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

base = os.environ["LLAMA_BASE"]
key = os.environ["LLAMA_API_KEY"]
print("base", base, "keylen", len(key), flush=True)
payload = {
    "model": os.environ.get("LLAMA_MODEL", "qwen2.5-coder-14b-instruct"),
    "messages": [{"role": "user", "content": "Reply with the single word ok."}],
    "max_tokens": 16,
    "temperature": 0,
}
req = urllib.request.Request(
    base.rstrip("/") + "/chat/completions",
    data=json.dumps(payload).encode(),
    headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
)
t0 = time.time()
try:
    with urllib.request.urlopen(req, timeout=180) as resp:
        raw = resp.read().decode()
    body = json.loads(raw)
    msg = body["choices"][0]["message"]
    print("content", repr(msg.get("content"))[:300], flush=True)
    print("usage", body.get("usage"), flush=True)
    print("timings", body.get("timings"), flush=True)
    print("seconds", round(time.time() - t0, 2), flush=True)
except Exception:
    traceback.print_exc()
    print("seconds", round(time.time() - t0, 2), flush=True)
