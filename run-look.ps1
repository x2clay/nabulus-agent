$ErrorActionPreference = "Continue"
Write-Output "PROC"
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -like "*autonomous.py*" -or $_.Name -match "^(ffuf|feroxbuster|nuclei|sqlmap|naabu|katana|amass|dalfox|httpx|rustscan)\.exe$"
} | ForEach-Object { Write-Output ($_.ProcessId.ToString() + " " + $_.Name) }
Write-Output "LINE"
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Laith\nabulus-agent\watch-line.ps1
Write-Output "TAIL"
Get-Content -Tail 35 C:\Users\Laith\nabulus-agent\run.out
Write-Output "ERR"
$err = "C:\Users\Laith\nabulus-agent\run.err"
if ((Test-Path $err) -and ((Get-Item $err).Length -gt 0)) { Get-Content -Tail 15 $err } else { Write-Output "empty" }
