#!/usr/bin/env python3
r"""Idempotent patcher for arjun 2.2.7 crash: `'dict' object has no attribute 'status_code'`.

Bug (arjun/__main__.py, initialize()): when the stability probe returns an "unhealthy" status
(400/413/418/429/503), the diagnostic print reads `request.status_code` -- but `request` is the
dict passed in, not the response. It should be `response_1.status_code`. Also, if the probe hits
a network error it returns a str, and `response_1.status_code` is accessed before arjun's own
`type(...)==str` guard, so a string probe result crashes too.

Fix: return 'skipped' early when the probe is a str, and read `response_1.status_code` (not
`request.status_code`). This is arjun's own later convention, applied one step earlier.

NOTE: patches the INSTALLED arjun package (found via its import path). A `pip install -U arjun`
reverts it -> re-run this patcher after any arjun reinstall/upgrade."""
import io, os
import arjun

MAIN = os.path.join(os.path.dirname(os.path.abspath(arjun.__file__)), "__main__.py")

OLD = (
    "        response_1 = requester(request, {fuzz[:-1]: fuzz[::-1][:-1]})\n"
    "        mem.var['healthy_url'] = response_1.status_code not in (400, 413, 418, 429, 503)\n"
    "        if not mem.var['healthy_url']:\n"
    "            print('%s Target returned HTTP %i, this may cause problems.' % (bad, request.status_code))"
)
NEW = (
    "        response_1 = requester(request, {fuzz[:-1]: fuzz[::-1][:-1]})\n"
    "        if type(response_1) == str:\n"
    "            return 'skipped'\n"
    "        mem.var['healthy_url'] = response_1.status_code not in (400, 413, 418, 429, 503)\n"
    "        if not mem.var['healthy_url']:\n"
    "            print('%s Target returned HTTP %i, this may cause problems.' % (bad, response_1.status_code))"
)

with io.open(MAIN, "r", encoding="utf-8") as fh:
    src = fh.read()

if "request.status_code" not in src:
    print(f"arjun __main__.py: already patched ({MAIN})")
else:
    assert OLD in src, "arjun: anchor not found (version differs from 2.2.7?) -- inspect manually"
    src = src.replace(OLD, NEW, 1)
    with io.open(MAIN, "w", encoding="utf-8") as fh:
        fh.write(src)
    print(f"arjun __main__.py: patched ({MAIN})")
