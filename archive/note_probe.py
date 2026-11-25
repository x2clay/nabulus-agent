import urllib.request, urllib.parse, urllib.error, http.cookiejar, hashlib
BASE="http://127.0.0.1:8099"
def login(u,p):
    cj=http.cookiejar.CookieJar(); op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try: op.open(BASE+"/login",data=urllib.parse.urlencode({"username":u,"password":p}).encode(),timeout=8)
    except Exception as e: print("login err",e)
    return "; ".join(f"{c.name}={c.value}" for c in cj)
ca=login("alice","Sunflower#A1pha"); cb=login("bob","Mountain#B2eta")
print("alice cookie:",ca[:30],"| bob cookie:",cb[:30])
def get(url,ck):
    r=urllib.request.Request(url,headers=({"Cookie":ck} if ck else {}))
    try:
        with urllib.request.urlopen(r,timeout=8) as x: b=x.read(); return x.status,b
    except urllib.error.HTTPError as e: return e.code,(e.read() if e.fp else b"")
    except Exception as e: return 0,str(e).encode()
for i in [1,2,3,4]:
    sa,ba=get(BASE+f"/api/note?id={i}",ca)
    sb,bb=get(BASE+f"/api/note?id={i}",cb)
    san,ban=get(BASE+f"/api/note?id={i}",None)
    print(f"id={i}: alice[{sa} {len(ba)}b {hashlib.sha1(ba).hexdigest()[:8]}] bob[{sb} {len(bb)}b {hashlib.sha1(bb).hexdigest()[:8]}] anon[{san} {len(ban)}b]")
