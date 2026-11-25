$agent = 'C:\Users\Laith\nabulus-agent'
$jar = Join-Path $agent 'raw\emptyjar_quantnq.com.out'
$py = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*autonomous.py*' }
if ($py) { $py | ForEach-Object { "alive $($_.ProcessId) $($_.Name)" } } else { "DEAD" }
if (Test-Path $jar) {
  $lines = Get-Content $jar
  "emptyjar_lines=$($lines.Count)"
  $lines | ForEach-Object { ($_ -split ' ')[0] } | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }
  "--- paths ---"
  $lines | ForEach-Object {
    $p = ($_ -split ' ')[1]
    if ($p) { ($_ -split ' ')[0] + ' ' + $p }
  }
} else { "no emptyjar file" }
"--- tail ---"
Get-Content -Tail 15 (Join-Path $agent 'run.out')
