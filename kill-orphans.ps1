$ErrorActionPreference = "Continue"
Get-CimInstance Win32_Process | Where-Object { $_.Name -in @("dalfox.exe", "amass.exe") } | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
  Write-Output ("killed " + $_.ProcessId + " " + $_.Name)
}
Write-Output "LEFT"
Get-CimInstance Win32_Process | Where-Object {
  $_.Name -match "^(ffuf|feroxbuster|nuclei|sqlmap|naabu|katana|amass|dalfox|httpx|rustscan|python)\.exe$" -or $_.CommandLine -like "*autonomous.py*"
} | ForEach-Object { Write-Output ($_.ProcessId.ToString() + " " + $_.Name) }
