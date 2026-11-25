"""Blind-safe: does the app serve a catch-all 200 for junk paths? Prints status +
body length + a short hash only -- never body content."""
import urllib.request, urllib.parse, urllib.error, http.cookiejar, hashlib
BASE="http://127.0.0.1:8099"
def login(u,p):
    cj=http.cookiejar.CookieJar()
    op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try: op.open(BASE+"/login",data=urllib.parse.urlencode({"username":u,"password":p}).encode(),timeout=10)
    except Exception: pass
    return "; ".join(f"{c.name}={c.value}" for c in cj)
ca=login("alice","Sunflower#A1pha"); cb=login("bob","Mountain#B2eta")
def get(url,ck):
    r=urllib.request.Request(url,headers={"Cookie":ck},method="GET")
    try:
        with urllib.request.urlopen(r,timeout=8) as x: b=x.read(400000); return x.status,b
    except urllib.error.HTTPError as e: return e.code,(e.read() if e.fp else b"")
    except Exception as ex: return 0,str(ex).encode()
def sig(b): return hashlib.sha1(b).hexdigest()[:10]
for label,url in [("absent-path",BASE+"/__nope_12345/999"),
                  ("absent-query",BASE+"/?id=99999"),
                  ("root",BASE+"/"),
                  ("absent-deep",BASE+"/zzz/qqq/777")]:
    sa,ba=get(url,ca); sb,bb=get(url,cb)
    print(f"{label:14} A[st={sa} len={len(ba):6} sig={sig(ba)}]  B[st={sb} len={len(bb):6} sig={sig(bb)}]")
