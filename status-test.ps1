$agent = 'C:\Users\Laith\nabulus-agent'
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*autonomous.py*' -or $_.ParentProcessId -in @(31992,36520,36844) } |
  ForEach-Object { "pid=$($_.ProcessId) parent=$($_.ParentProcessId) name=$($_.Name)" }
"--- files ---"
Get-ChildItem $agent -File | Where-Object { $_.Name -match 'status|notebook|run\.' } |
  ForEach-Object { "$($_.Name) bytes=$($_.Length) mtime=$($_.LastWriteTime.ToString('HH:mm:ss'))" }
$raw = Join-Path $agent 'raw'
if (Test-Path $raw) {
  $files = Get-ChildItem $raw -File | Sort-Object LastWriteTime -Descending
  "raw_count=$($files.Count)"
  $files | Select-Object -First 8 | ForEach-Object { "$($_.Name) bytes=$($_.Length) mtime=$($_.LastWriteTime.ToString('HH:mm:ss'))" }
} else { 'raw missing' }
"--- out bytes ---"
(Get-Item (Join-Path $agent 'run.out')).Length
"--- err bytes ---"
(Get-Item (Join-Path $agent 'run.err')).Length
"--- err tail ---"
Get-Content -Tail 20 (Join-Path $agent 'run.err') -ErrorAction SilentlyContinue
"--- out tail ---"
Get-Content -Tail 20 (Join-Path $agent 'run.out') -ErrorAction SilentlyContinue
