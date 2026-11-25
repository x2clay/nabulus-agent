$agent = 'C:\Users\Laith\nabulus-agent'
Write-Output '=== status ==='
Get-Content (Join-Path $agent 'status.json') -ErrorAction SilentlyContinue
Write-Output '=== log tail ==='
Get-Content -Tail 25 (Join-Path $agent 'run.out')
Write-Output '=== notebook summary ==='
py -3 -c @"
import json, pathlib, collections
p = pathlib.Path(r'C:\Users\Laith\nabulus-agent\notebook.json')
print('notebook', p.exists(), p.stat().st_size if p.exists() else 0)
if not p.exists():
    raise SystemExit
nb = json.loads(p.read_text(encoding='utf-8'))
tests = nb.get('tests') or []
leads = nb.get('leads') or []
proofs = nb.get('proofs') or []
print('tests', len(tests), 'leads', len(leads), 'proofs', len(proofs))
c = collections.Counter((t.get('tool'), t.get('result')) for t in tests)
print('--- results ---')
for (tool, result), n in sorted(c.items(), key=lambda kv: (-kv[1], str(kv[0]))):
    print(f'{n:3} {tool}: {result}')
print('--- leads ---')
for item in leads[-15:]:
    lead = item.get('lead') or item
    print(item.get('status'), lead.get('tool'), lead.get('severity'), (lead.get('matched') or '')[:120], (lead.get('evidence') or '')[:80])
print('--- proofs ---')
for pr in proofs:
    print((pr.get('extracted') or '')[:200])
"@
