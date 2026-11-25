import urllib.request, urllib.error, re
def grab(path):
    try:
        b = urllib.request.urlopen("http://127.0.0.1:8099"+path, timeout=8).read()
        st = 200
    except urllib.error.HTTPError as e:
        b = e.read() if e.fp else b""; st = e.code
    except Exception as e:
        return path, "ERR "+str(e)[:60], []
    forms = re.findall(rb'<form[^>]*>', b, re.I)
    fields = []
    for m in re.finditer(rb'<(input|button|select)([^>]*)>', b, re.I):
        attrs = m.group(2).decode("latin1")
        name = re.search(r'name=["\']?([^"\'\s>]+)', attrs)
        typ = re.search(r'type=["\']?([^"\'\s>]+)', attrs)
        fields.append(f"{m.group(1).decode()}[name={name.group(1) if name else '-'},type={typ.group(1) if typ else '-'}]")
    return path, f"st={st} forms={len(forms)}", fields
for p in ["/", "/login"]:
    path, meta, fields = grab(p)
    print(path, meta)
    for f in fields: print("   ", f)
