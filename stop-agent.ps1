$ErrorActionPreference = "Continue"
$names = @("nuclei.exe", "ffuf.exe", "feroxbuster.exe", "dalfox.exe", "amass.exe", "naabu.exe", "katana.exe", "httpx.exe", "rustscan.exe", "sqlmap.exe")
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -like "*autonomous.py*" -or
  $_.CommandLine -like "*sqlmap.py*" -or
  $_.CommandLine -like "*commix.py*" -or
  ($names -contains $_.Name)
} | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
  Write-Output ("killed " + $_.ProcessId + " " + $_.Name)
}
Start-Sleep -Seconds 1
Write-Output "LEFT"
$left = Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -like "*autonomous.py*" -or
  $_.CommandLine -like "*sqlmap.py*" -or
  ($names -contains $_.Name)
}
if (-not $left) { Write-Output "none" }
$left | ForEach-Object { Write-Output ($_.ProcessId.ToString() + " " + $_.Name) }
