$ErrorActionPreference = 'Stop'
$agent = 'C:\Users\Laith\nabulus-agent'
$scope = Get-Content -Raw (Join-Path $agent 'scope.json')
if ($scope -notmatch 'quantnq\.com') { throw 'scope missing quantnq.com' }
if ($scope -match 'scanme') { throw 'scope still has scanme' }
$listen = Get-NetTCPConnection -LocalPort 8081 -State Listen -ErrorAction SilentlyContinue
if (-not $listen) { throw 'llama 8081 is not listening' }
$existing = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*autonomous.py*' }
if ($existing) {
  $existing | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; "stopped pid=$($_.ProcessId)" }
  Start-Sleep -Seconds 2
}
$out = Join-Path $agent 'run.out'
$err = Join-Path $agent 'run.err'
Set-Content -Path $out -Value '' -Encoding utf8
Set-Content -Path $err -Value '' -Encoding utf8
$cmd = "cmd.exe /c set PYTHONUNBUFFERED=1&& py -3 -u `"$agent\autonomous.py`" --hours 0.75 > `"$out`" 2> `"$err`""
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
"create_return=$($r.ReturnValue) pid=$($r.ProcessId)"
Start-Sleep -Seconds 25
$alive = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*autonomous.py*' }
if (-not $alive) {
  "FAILED process gone"
  "--- run.err ---"
  Get-Content -Tail 40 $err -ErrorAction SilentlyContinue
  "--- run.out ---"
  Get-Content -Tail 40 $out -ErrorAction SilentlyContinue
  exit 1
}
$alive | ForEach-Object { "alive pid=$($_.ProcessId) name=$($_.Name)" }
"--- run.out ---"
Get-Content -Tail 30 $out -ErrorAction SilentlyContinue
"--- run.err ---"
Get-Content -Tail 30 $err -ErrorAction SilentlyContinue
