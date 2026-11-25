$names = @("nuclei.exe", "ffuf.exe", "feroxbuster.exe", "dalfox.exe", "amass.exe", "naabu.exe", "katana.exe", "httpx.exe", "rustscan.exe")
Get-CimInstance Win32_Process | Where-Object { $names -contains $_.Name -or $_.CommandLine -like "*sqlmap.py*" } | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
  Write-Output ("killed " + $_.ProcessId + " " + $_.Name)
}
Write-Output "done"
