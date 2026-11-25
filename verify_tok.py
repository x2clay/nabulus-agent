import urllib.request, ssl, json, sys
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
BASE='https://cortisol.gg'; TOK=sys.argv[1]
def req(p):
    rq=urllib.request.Request(BASE+p, headers={'Authorization':'Bearer '+TOK,'User-Agent':'Mozilla/5.0'})
    try:
        r=urllib.request.urlopen(rq,timeout=20,context=ctx); return r.status, r.read().decode('utf-8','replace')
    except urllib.error.HTTPError as e: return e.code, e.read().decode('utf-8','replace')
    except Exception as e: return 0, str(e)
for p in ['/api/me','/api/wallet/address','/api/wallet/history','/api/bets/mine']:
    s,b=req(p); print(s, p, '::', b[:260].replace('\n',' '))
