py -3 -c @"
import json, pathlib, collections, re
raw = pathlib.Path(r'C:\Users\Laith\nabulus-agent\raw')
nb = json.loads(pathlib.Path(r'C:\Users\Laith\nabulus-agent\notebook.json').read_text(encoding='utf-8'))

def ffuf_rows(text):
    rows=[]
    i=text.find('{'); j=text.rfind('}')
    if i>=0:
        try:
            data=json.loads(text[i:j+1])
            for row in data.get('results') or []:
                rows.append((row.get('status'), row.get('length'), row.get('url') or ''))
        except Exception:
            pass
    if not rows:
        for line in text.splitlines():
            m=re.match(r'(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)', line)
            if m:
                rows.append((int(m.group(2)), int(m.group(3)), m.group(1)))
    return rows

print('FFUF')
for f in sorted(raw.glob('ffuf_*.out'))+sorted(raw.glob('ffuf_*.json')):
    if 'quantnq' not in f.name: continue
    text=f.read_text(encoding='utf-8', errors='replace')
    rows=ffuf_rows(text)
    sizes=collections.Counter(r[1] for r in rows)
    codes=collections.Counter(r[0] for r in rows)
    print(f.name, 'rows', len(rows), 'codes', dict(codes), 'top_sizes', sizes.most_common(3))

print('FEROX')
for f in sorted(raw.glob('feroxbuster_quantnq.com_*.out')):
    codes=collections.Counter(); n=0
    for line in f.read_text(encoding='utf-8', errors='replace').splitlines():
        if not line.startswith('{'): continue
        try: row=json.loads(line)
        except Exception: continue
        if row.get('type') not in (None,'response') and 'status' not in row: continue
        if 'status' in row:
            codes[row.get('status')] += 1; n += 1
    print(f.name, 'bytes', f.stat().st_size, 'json_status', dict(codes), 'n', n)

print('SQLMAP')
for f in sorted(raw.glob('sqlmap_*.out'))[-6:]:
    t=f.read_text(encoding='utf-8', errors='replace')
    flag='other'
    low=t.lower()
    if 'not injectable' in low or 'do not appear to be injectable' in low: flag='not injectable'
    elif 'injectable' in low or 'vulnerable' in low: flag='injectable'
    elif 'connection timed out' in low or 'unable to connect' in low: flag='no connect'
    print(f.name, 'bytes', f.stat().st_size, flag)

print('BROWSER')
for f in pathlib.Path(r'C:\Users\Laith\nabulus-agent\sessions').glob('*.urls.json'):
    urls=json.loads(f.read_text(encoding='utf-8'))
    print(f.name, 'count', len(urls))
"@
Write-Output '=== children ==='
Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq 38632 } | ForEach-Object { $_.Name }
