# run_xss.ps1 - validate the XSS detector+headless-execution validator with 3 controls.
# POSITIVE /reflect -> injected JS executes in headless Chrome -> OOB fires -> CONFIRM.
# NEGATIVE /safe (escaped) -> no execution -> nothing. SCOPE example.com -> REFUSE.
$A = "C:\Users\Laith\nabulus-agent"
$py = "C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$log = "$A\xss_run.log"
$scope = "$A\benchmark\scope_bench.json"
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $A
"=== run $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8

$tgt = Start-Process $py -ArgumentList "`"$A\xss_target.py`" 8199" -PassThru -RedirectStandardOutput "$A\xtgt.out" -RedirectStandardError "$A\xtgt.err" -WindowStyle Hidden
Start-Sleep 3
"target pid $($tgt.Id)" | Out-File $log -Append -Encoding utf8

"==== POSITIVE control: /reflect (should CONFIRM xss) ====" | Out-File $log -Append -Encoding utf8
& $py "$A\xss_probe.py" --target "http://127.0.0.1:8199/reflect" --scope $scope --out "$A\xss_pos.json" 2>&1 | Out-File $log -Append -Encoding utf8

"==== NEGATIVE control: /safe (should find NOTHING) ====" | Out-File $log -Append -Encoding utf8
& $py "$A\xss_probe.py" --target "http://127.0.0.1:8199/safe" --scope $scope --out "$A\xss_neg.json" 2>&1 | Out-File $log -Append -Encoding utf8

"==== SCOPE gate: example.com (should REFUSE) ====" | Out-File $log -Append -Encoding utf8
& $py "$A\xss_probe.py" --target "http://example.com/search" --scope $scope --out "$A\xss_oos.json" 2>&1 | Out-File $log -Append -Encoding utf8

Stop-Process -Id $tgt.Id -Force -ErrorAction SilentlyContinue
"DONE" | Out-File $log -Append -Encoding utf8
