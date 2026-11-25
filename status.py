import json, pathlib, time, os
a = pathlib.Path(r"C:\Users\Laith\nabulus-agent")
def mtime(p):
    try: return f"{time.time()-os.path.getmtime(p):.0f}s"
    except OSError: return "n/a"
st = json.loads((a/"status.json").read_text(encoding="utf-8")) if (a/"status.json").exists() else {}
print("STATUS mtime", mtime(a/"status.json"), "phase=", st.get("phase"), "cycle=", st.get("cycle"), "leads=", st.get("leads_this_cycle"), "proved=", st.get("proved_this_cycle"), "hrs_left=", st.get("hours_left"))
o = (a/"run.out").read_text(encoding="utf-8", errors="replace") if (a/"run.out").exists() else ""
print("run.out", len(o), "B mtime", mtime(a/"run.out"), "tail:")
print("\n".join(o.splitlines()[-14:]))
nb = json.loads((a/"notebook.json").read_text(encoding="utf-8")) if (a/"notebook.json").exists() else {}
print("NB mtime", mtime(a/"notebook.json"), "tests", len(nb.get("tests",[])), "leads", len(nb.get("leads",[])), "proofs", len(nb.get("proofs",[])))
for l in nb.get("leads", [])[-8:]:
    ld = l.get("lead") or {}
    print("  lead", l.get("status"), ld.get("tool"), ld.get("matched"))
for p in nb.get("proofs", [])[-6:]:
    print("  PROOF", p.get("method"), (p.get("lead") or {}).get("matched"), "::", str(p.get("extracted"))[:70])
