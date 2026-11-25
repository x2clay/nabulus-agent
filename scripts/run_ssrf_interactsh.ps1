# run_ssrf_interactsh.ps1 - validate the interactsh (public OOB) SSRF path with 3 controls.
# POSITIVE /fetch -> target fetches our interactsh payload -> CONFIRM. NEGATIVE /safe -> nothing.
# SCOPE example.com -> REFUSE. Logs to ssrf_itsh_run.log, writes DONE at end.
$A = "C:\Users\Laith\nabulus-agent"
$py = "C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$log = "$A\ssrf_itsh_run.log"
$scope = "$A\benchmark\scope_bench.json"
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $A
"=== run $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8

$tgt = Start-Process $py -ArgumentList "`"$A\ssrf_target.py`" 8188" -PassThru -RedirectStandardOutput "$A\tgt.out" -RedirectStandardError "$A\tgt.err" -WindowStyle Hidden
Start-Sleep 3
"target pid $($tgt.Id)" | Out-File $log -Append -Encoding utf8

"==== POSITIVE control: /fetch (should CONFIRM ssrf) ====" | Out-File $log -Append -Encoding utf8
& $py "$A\ssrf_probe.py" --target "http://127.0.0.1:8188/fetch" --oob-provider interactsh --scope $scope --out "$A\ssrf_itsh_pos.json" 2>&1 | Out-File $log -Append -Encoding utf8

"==== NEGATIVE control: /safe (should find NOTHING) ====" | Out-File $log -Append -Encoding utf8
& $py "$A\ssrf_probe.py" --target "http://127.0.0.1:8188/safe" --oob-provider interactsh --scope $scope --out "$A\ssrf_itsh_neg.json" 2>&1 | Out-File $log -Append -Encoding utf8

"==== SCOPE gate: example.com (should REFUSE) ====" | Out-File $log -Append -Encoding utf8
& $py "$A\ssrf_probe.py" --target "http://example.com/fetch" --oob-provider interactsh --scope $scope --out "$A\ssrf_itsh_oos.json" 2>&1 | Out-File $log -Append -Encoding utf8

Stop-Process -Id $tgt.Id -Force -ErrorAction SilentlyContinue
"DONE" | Out-File $log -Append -Encoding utf8
