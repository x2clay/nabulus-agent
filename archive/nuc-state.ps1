Get-Process -Id 42928 -ErrorAction SilentlyContinue | Format-List Id,CPU,StartTime,Responding
Get-NetTCPConnection -OwningProcess 42928 -ErrorAction SilentlyContinue | Select-Object State,RemoteAddress,RemotePort | Format-Table -AutoSize
Write-Output '--- children of nuclei ---'
Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq 42928 } | ForEach-Object { $_.Name + ' ' + $_.ProcessId }
