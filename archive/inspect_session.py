import re, io
s = io.open('session.py', encoding='utf-8').read()
print('open_host sig present :', 'def open_host(host: str, max_pages: int = 12) -> dict:' in s)
print('netloc fix present    :', 'netloc = host.strip().lower()' in s)
m = re.search(r'            context = browser\.new_context\(\n(.*?)\n            \)', s, re.S)
print('--- new_context block ---')
print(m.group(0) if m else 'NOT FOUND')
print('--- login_one / state / calls_for lines ---')
for i, ln in enumerate(s.splitlines(), 1):
    t = ln.strip()
    if any(k in t for k in ('account.get', 'account[', 'state_path', 'def login_one',
                            'storage_state(path', 'def calls_for', 'def login(', 'STATE')):
        print(f'{i}: {t[:130]}')
