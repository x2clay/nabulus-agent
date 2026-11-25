"""Blind-safe: is the authed app JS/XHR-driven? Per crawled page print only
content-type + booleans (has fetch/XHR/api-literal/script). No paths, no bodies."""
import urllib.request, urllib.parse, urllib.error, http.cookiejar
from urllib.parse import urljoin
import re
BASE="http://127.0.0.1:8099"
def login(u,p):
    cj=http.cookiejar.CookieJar()
    op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try: op.open(BASE+"/login",data=urllib.parse.urlencode({"username":u,"password":p}).encode(),timeout=10)
    except Exception: pass
    return "; ".join(f"{c.name}={c.value}" for c in cj), op
ck,op=login("alice","Sunflower#A1pha")
def get(url):
    r=urllib.request.Request(url,headers={"Cookie":ck})
    try:
        with urllib.request.urlopen(r,timeout=8) as x: return x.status,x.headers.get("content-type",""),x.read(400000)
    except urllib.error.HTTPError as e: return e.code,"",b""
    except Exception as ex: return 0,"",b""
HREF=re.compile(rb'href=["\']([^"\'<>]+)["\']',re.I)
seen=set(); frontier=[BASE+"/"]; pages=[]
for _ in range(6):
    nxt=[]
    for u in frontier:
        if u in seen: continue
        seen.add(u); st,ct,body=get(u); pages.append((u,st,ct,body))
        for m in HREF.findall(body):
            l=urljoin(u,m.decode("utf-8","replace")).split("#")[0]
            if l.startswith(BASE) and l not in seen: nxt.append(l)
    frontier=nxt
    if not frontier: break
print("pages:",len(pages))
total_fetch=total_xhr=total_api=total_json=0
for u,st,ct,b in pages:
    low=b.lower()
    f=b"fetch(" in low; x=b"xmlhttprequest" in low or b".ajax" in low; a=b"/api/" in low
    j="json" in ct.lower()
    total_fetch+=f; total_xhr+=x; total_api+=a; total_json+=j
    print(f"  st={st} json_ct={j} fetch={int(f)} xhr={int(x)} api_literal={int(a)} bytes={len(b)}")
print(f"TOTAL pages with: fetch={total_fetch} xhr={total_xhr} api_literal={total_api} json_ct={total_json}")
