import json, pathlib, sys, time
AGENT = pathlib.Path(r"C:\Users\Laith\nabulus-agent")
host = sys.argv[1]
scope = json.loads((AGENT/"scope.json").read_text(encoding="utf-8"))
scope["authorized_assets"] = [host]
(AGENT/"scope.json").write_text(json.dumps(scope, indent=2), encoding="utf-8")
(AGENT/"_run.json").write_text(json.dumps({"runid": f"{host}_{time.strftime('%Y%m%d-%H%M%S')}", "target": host}), encoding="utf-8")
print("scope set:", host, "| program:", scope.get("program"), "| auth_ref:", scope.get("authorization_ref"))
