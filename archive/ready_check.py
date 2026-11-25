import os
import pathlib
import shutil
import sys

agent = pathlib.Path(r"C:\Users\Laith\nabulus-agent")
sys.path.insert(0, str(agent))
os.chdir(agent)
src = agent / "sensitive.txt"
dst = pathlib.Path(r"C:\Users\Laith\nabulus-tools\wordlists\sensitive.txt")
dst.parent.mkdir(parents=True, exist_ok=True)
if src.exists():
    shutil.copyfile(src, dst)
keys = {}
for line in (agent / "local.env").read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        keys[k] = v
import extractor
print("deepseek_set", bool(keys.get("DEEPSEEK_API_KEY")))
print("deepseek_model", keys.get("DEEPSEEK_MODEL"))
print("llama_base", keys.get("LLAMA_BASE"))
print("sensitive", dst.exists(), dst.stat().st_size if dst.exists() else 0)
print("prove", hasattr(extractor, "prove"))
print("session", (agent / "session.py").exists())
print("scope_empty", '"authorized_assets": []' in (agent / "scope.json").read_text(encoding="utf-8").replace(" ", ""))
