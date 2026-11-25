$raw = 'C:\Users\Laith\nabulus-agent\raw'
$names = @(
  'naabu_quantnq.com_1.out',
  'katana_quantnq.com_4.out',
  'katana_quantnq.com_5.out',
  'subfinder_quantnq.com_0.out',
  'feroxbuster_quantnq.com_10.out',
  'dalfox_quantnq.com_11.out',
  'httpx_quantnq.com_3.out',
  'rustscan_quantnq.com_2.out'
)
foreach ($n in $names) {
  Write-Output "===== $n ====="
  Get-Content -Raw (Join-Path $raw $n) -ErrorAction SilentlyContinue
}
Write-Output '===== ffuf shape ====='
py -3 -c @"
import json, pathlib
p = pathlib.Path(r'C:\Users\Laith\nabulus-agent\raw')
for f in sorted(p.glob('ffuf_quantnq.com_*.out')):
    t = f.read_text(encoding='utf-8', errors='replace')
    i, j = t.find('{'), t.rfind('}')
    print(f.name, 'bytes', f.stat().st_size, 'has_brace', i>=0)
    if i>=0:
        try:
            d = json.loads(t[i:j+1])
            rows = d.get('results') or []
            print('  results', len(rows), 'keys', list(d)[:8])
            codes = {}
            for r in rows:
                codes[str(r.get('status'))] = codes.get(str(r.get('status')), 0) + 1
            print('  status_counts', codes)
        except Exception as e:
            print('  json_err', type(e).__name__, str(e)[:160])
            print('  head', t[:180].replace('\n',' '))
"@
Write-Output '===== nuclei proc ===='
Get-Process -Id 42928 -ErrorAction SilentlyContinue | Select-Object Id,CPU,WorkingSet,StartTime | Format-List
