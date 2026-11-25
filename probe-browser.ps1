$ErrorActionPreference = "Stop"
$env:PYTHONUNBUFFERED = "1"
Set-Location "C:\Users\Laith\nabulus-agent"
py -3 -c @"
import session
from urllib.parse import urlsplit
r = session.open_host('quantnq.com')
part = urlsplit(r.get('landed') or '')
landed = (part.scheme + '://' + part.netloc + part.path)[:180]
print('profile=' + str(r.get('profile') or '-'))
print('blocked=' + str(bool(r.get('blocked'))))
print('urls=' + str(r.get('urls')))
print('cookies=' + str(r.get('cookies')))
print('error=' + str(r.get('error') or '-'))
print('title_len=' + str(len(r.get('title') or '')))
print('landed=' + (landed or '-'))
"@
