$ErrorActionPreference = "Continue"
Write-Output "PROC"
$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*autonomous.py*" -or $_.Name -match "ffuf|nuclei|ferox|naabu|katana|sqlmap|httpx|rustscan|dalfox|amass|gau" }
if (-not $procs) { Write-Output "none" }
$procs | ForEach-Object { Write-Output ($_.ProcessId.ToString() + " " + $_.Name) }
Write-Output "OUT"
Get-Content "C:\Users\Laith\nabulus-agent\run.out" -Tail 40
Write-Output "ERR"
$err = "C:\Users\Laith\nabulus-agent\run.err"
if (Test-Path $err) { Get-Content $err -Tail 15 }
Write-Output "STATUS"
Get-Content "C:\Users\Laith\nabulus-agent\status.json" -Raw
Write-Output "RAW"
Get-ChildItem "C:\Users\Laith\nabulus-agent\raw" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 12 | ForEach-Object { Write-Output ($_.LastWriteTime.ToString("HH:mm:ss") + " " + $_.Length + " " + $_.Name) }
