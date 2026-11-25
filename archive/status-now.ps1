$agent = 'C:\Users\Laith\nabulus-agent'
$py = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*autonomous.py*' }
if ($py) { $py | ForEach-Object { "alive $($_.ProcessId) $($_.Name)" } } else { "DEAD" }
$out = Join-Path $agent 'run.out'
$err = Join-Path $agent 'run.err'
"out_bytes=$((Get-Item $out).Length) err_bytes=$((Get-Item $err -ErrorAction SilentlyContinue).Length)"
"--- out ---"
Get-Content -Tail 40 $out
"--- err ---"
Get-Content -Tail 15 $err -ErrorAction SilentlyContinue
$jar = Join-Path $agent 'raw\emptyjar_quantnq.com.out'
if (Test-Path $jar) {
  $g = Get-Content $jar | ForEach-Object { ($_ -split ' ')[0] } | Group-Object
  "emptyjar " + (($g | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' ')
}
