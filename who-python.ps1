Get-CimInstance Win32_Process -Filter "Name = 'python.exe' OR Name = 'py.exe'" | ForEach-Object {
  Write-Output ($_.ProcessId.ToString() + ' ' + $_.Name + ' ' + $_.CommandLine)
}
