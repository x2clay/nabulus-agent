$ErrorActionPreference="Continue"
$A="C:\Users\Laith\nabulus-agent"
$py="C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$env:PYTHONIOENCODING='utf-8'
Set-Location $A

# start OOB listener (127.0.0.1:9099) and the vulnerable control target (127.0.0.1:8188)
$oob=Start-Process $py -ArgumentList "`"$A\oob_server.py`" 9099 `"$A\oob_hits.jsonl`" 127.0.0.1" -PassThru -RedirectStandardOutput "$A\oob.out" -RedirectStandardError "$A\oob.err" -WindowStyle Hidden
$tgt=Start-Process $py -ArgumentList "`"$A\ssrf_target.py`" 8188" -PassThru -RedirectStandardOutput "$A\tgt.out" -RedirectStandardError "$A\tgt.err" -WindowStyle Hidden
Start-Sleep 3
"oob pid $($oob.Id); target pid $($tgt.Id)"

"==== POSITIVE control: /fetch?url= (should CONFIRM ssrf) ===="
& $py "$A\ssrf_probe.py" --target "http://127.0.0.1:8188/fetch" --oob "http://127.0.0.1:9099" --scope "$A\benchmark\scope_bench.json" --oob-log "$A\oob_hits.jsonl" --out "$A\ssrf_pos.json" 2>&1

"==== NEGATIVE control: /safe?url= (should find NOTHING) ===="
& $py "$A\ssrf_probe.py" --target "http://127.0.0.1:8188/safe" --oob "http://127.0.0.1:9099" --scope "$A\benchmark\scope_bench.json" --oob-log "$A\oob_hits.jsonl" --out "$A\ssrf_neg.json" 2>&1

"==== scope gate check: out-of-scope target (should REFUSE) ===="
& $py "$A\ssrf_probe.py" --target "http://example.com/fetch" --oob "http://127.0.0.1:9099" --scope "$A\benchmark\scope_bench.json" --oob-log "$A\oob_hits.jsonl" --out "$A\ssrf_oos.json" 2>&1

Stop-Process -Id $oob.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $tgt.Id -Force -ErrorAction SilentlyContinue
"stopped. DONE"