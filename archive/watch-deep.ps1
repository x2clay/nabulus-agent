$agent = 'C:\Users\Laith\nabulus-agent'
Write-Output '=== python tree ==='
$py = Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -like '*autonomous.py*' }
$py | ForEach-Object { "pid=$($_.ProcessId) parent=$($_.ParentProcessId)" }
$kids = Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $py.ProcessId }
$kids | ForEach-Object { "child pid=$($_.ProcessId) name=$($_.Name) cmd=$($_.CommandLine.Substring(0, [Math]::Min(220, $_.CommandLine.Length)))" }
Write-Output '=== raw ==='
Get-ChildItem (Join-Path $agent 'raw') -File | Sort-Object LastWriteTime |
  ForEach-Object { "{0} bytes={1} mtime={2}" -f $_.Name, $_.Length, $_.LastWriteTime.ToString('HH:mm:ss') }
Write-Output '=== logs ==='
foreach ($n in @('run.out','run.err','status.json','notebook.json')) {
  $p = Join-Path $agent $n
  if (Test-Path $p) {
    $i = Get-Item $p
    "{0} bytes={1} mtime={2}" -f $n, $i.Length, $i.LastWriteTime.ToString('HH:mm:ss')
  } else { "$n missing" }
}
Write-Output '=== out tail ==='
Get-Content -Tail 40 (Join-Path $agent 'run.out') -ErrorAction SilentlyContinue
Write-Output '=== err tail ==='
Get-Content -Tail 40 (Join-Path $agent 'run.err') -ErrorAction SilentlyContinue
