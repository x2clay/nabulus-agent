# run_sqli.ps1 - validate the SQLi module (sqlmap-backed) against a local vuln control,
# plus a sanity import of the refactored SSRF probe + shared injection engine.
$A = "C:\Users\Laith\nabulus-agent"
$py = "C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$log = "$A\sqli_run.log"
$scope = "$A\benchmark\scope_bench.json"
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $A
"=== sqli run $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8

# 0) import sanity for Layer-1 refactor (must not have broken SSRF)
"==== IMPORT CHECK: inject + ssrf_probe ====" | Out-File $log -Append -Encoding utf8
& $py -c "import inject, ssrf_probe; print('IMPORT_OK', inject.ALL_SURFACES)" 2>&1 | Out-File $log -Append -Encoding utf8

# 1) stand up the local vulnerable target on :8099
$t = Start-Process $py -ArgumentList "$A\sqli_target.py 8099" -PassThru -WindowStyle Hidden
$up = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep 1
    try { $c = New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1", 8099); if ($c.Connected) { $up = $true; $c.Close(); break } } catch {}
}
"sqli_target up=$up pid=$($t.Id)" | Out-File $log -Append -Encoding utf8

if ($up) {
    "==== SQLi POSITIVE: /item?id=1 (should CONFIRM) ====" | Out-File $log -Append -Encoding utf8
    & $py "$A\sqli_probe.py" --target "http://127.0.0.1:8099/item?id=1" --scope $scope --out "$A\sqli_pos.json" --python $py 2>&1 | Out-File $log -Append -Encoding utf8
    "==== SQLi NEGATIVE: /safe?id=1 (should be CLEAN) ====" | Out-File $log -Append -Encoding utf8
    & $py "$A\sqli_probe.py" --target "http://127.0.0.1:8099/safe?id=1" --scope $scope --out "$A\sqli_neg.json" --python $py 2>&1 | Out-File $log -Append -Encoding utf8
    "==== SCOPE gate: example.com (should REFUSE) ====" | Out-File $log -Append -Encoding utf8
    & $py "$A\sqli_probe.py" --target "http://example.com/item?id=1" --scope $scope --out "$A\sqli_oos.json" --python $py 2>&1 | Out-File $log -Append -Encoding utf8
}

Stop-Process -Id $t.Id -Force -ErrorAction SilentlyContinue
"==== RESULTS ====" | Out-File $log -Append -Encoding utf8
"POS=$(Get-Content "$A\sqli_pos.json" -Raw -ErrorAction SilentlyContinue)" | Out-File $log -Append -Encoding utf8
"NEG=$(Get-Content "$A\sqli_neg.json" -Raw -ErrorAction SilentlyContinue)" | Out-File $log -Append -Encoding utf8
"OOS=$(Get-Content "$A\sqli_oos.json" -Raw -ErrorAction SilentlyContinue)" | Out-File $log -Append -Encoding utf8
"DONE" | Out-File $log -Append -Encoding utf8
