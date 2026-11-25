$agent = 'C:\Users\Laith\nabulus-agent'
$py = Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -like '*autonomous.py*' }
$cycle = '-'
$phase = '-'
$proved = '-'
$leads = '-'
$st = Join-Path $agent 'status.json'
if (Test-Path $st) {
  try {
    $j = Get-Content -Raw $st | ConvertFrom-Json
    if ($null -ne $j.cycle) { $cycle = $j.cycle }
    if ($null -ne $j.phase) { $phase = $j.phase }
    if ($null -ne $j.proved_this_cycle) { $proved = $j.proved_this_cycle }
    elseif ($null -ne $j.proved) { $proved = $j.proved }
    if ($null -ne $j.leads_this_cycle) { $leads = $j.leads_this_cycle }
    elseif ($null -ne $j.leads) { $leads = $j.leads }
  } catch { }
}
$errPath = Join-Path $agent 'run.err'
$errHit = $false
if (Test-Path $errPath) {
  $tail = Get-Content -Tail 30 $errPath -ErrorAction SilentlyContinue
  if ($tail -match 'Traceback') { $errHit = $true }
}
$rawN = 0
$raw = Join-Path $agent 'raw'
if (Test-Path $raw) { $rawN = (Get-ChildItem $raw -File -ErrorAction SilentlyContinue | Measure-Object).Count }
$tail = "-"
$mapdata = "-"
$outp = Join-Path $agent "run.out"
if (Test-Path $outp) {
  $last = (Get-Content -Tail 1 $outp -ErrorAction SilentlyContinue | Select-Object -Last 1)
  if ($last) { $tail = (($last -replace "\s+", " ").Trim()) }
  if ($tail.Length -gt 90) { $tail = $tail.Substring(0, 90) }
  $maps = Select-String -Path $outp -Pattern 'map \S+ endpoints=\d+ .*data=\d+' -ErrorAction SilentlyContinue
  if ($maps) {
    $hit = [regex]::Match($maps[-1].Line, 'data=(\d+)')
    if ($hit.Success) { $mapdata = $hit.Groups[1].Value }
  }
}
$kids = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match "^(ffuf|feroxbuster|nuclei|sqlmap|naabu|katana|amass|dalfox|httpx|rustscan)\.exe$" } | ForEach-Object { $_.Name -replace "\.exe$","" } | Sort-Object -Unique)
$tools = $(if ($kids.Count) { $kids -join "," } else { "-" })
if ($errHit -and -not $py) { Write-Output "DEAD err cycle=$cycle phase=$phase leads=$leads proved=$proved mapdata=$mapdata tools=$tools tail=$tail"; exit }
if ($errHit) { Write-Output "ERR cycle=$cycle phase=$phase leads=$leads proved=$proved mapdata=$mapdata tools=$tools tail=$tail"; exit }
if (-not $py) { Write-Output "DEAD cycle=$cycle phase=$phase leads=$leads proved=$proved mapdata=$mapdata tools=$tools tail=$tail"; exit }
Write-Output "ALIVE cycle=$cycle phase=$phase leads=$leads proved=$proved mapdata=$mapdata tools=$tools tail=$tail"
