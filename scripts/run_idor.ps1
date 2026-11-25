# run_idor.ps1 - validate the IDOR/BOLA cross-identity engine against OWASP Juice Shop
# (real, known BOLA). Stands Juice Shop up on :3000, runs the probe, tears it down.
$A = "C:\Users\Laith\nabulus-agent"
$py = "C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$node = "C:\Program Files\nodejs\node.exe"
$js = "C:\Users\Laith\benchlab\unzip\juice-shop_20.4.0-SNAPSHOT"
$log = "$A\idor_run.log"
$scope = "$A\benchmark\scope_bench.json"
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $A
"=== idor run $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8

$p = Start-Process $node -ArgumentList "build\app.js" -WorkingDirectory $js -PassThru -RedirectStandardOutput "$A\js.out" -RedirectStandardError "$A\js.err" -WindowStyle Hidden
$up = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep 2
    try { $c = New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1", 3000); if ($c.Connected) { $up = $true; $c.Close(); break } } catch {}
}
"juiceshop up=$up pid=$($p.Id)" | Out-File $log -Append -Encoding utf8

if ($up) {
    Start-Sleep 3
    "==== IDOR/BOLA: Juice Shop basket (should CONFIRM) ====" | Out-File $log -Append -Encoding utf8
    & $py "$A\idor_probe.py" --target "http://127.0.0.1:3000" --adapter juiceshop --scope $scope --out "$A\idor_juice.json" 2>&1 | Out-File $log -Append -Encoding utf8
    "==== SCOPE gate: example.com (should REFUSE) ====" | Out-File $log -Append -Encoding utf8
    & $py "$A\idor_probe.py" --target "http://example.com" --adapter juiceshop --scope $scope --out "$A\idor_oos.json" 2>&1 | Out-File $log -Append -Encoding utf8
}

Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Get-Process node -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $p.Id } | Stop-Process -Force -ErrorAction SilentlyContinue
"DONE" | Out-File $log -Append -Encoding utf8
