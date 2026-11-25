$py = 'C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe'
$wd = 'C:\Users\Laith\nabulus-agent'
$arg = 'login_persist.py --creds creds.json --headful --watch 150'
$a = New-ScheduledTaskAction -Execute $py -Argument $arg -WorkingDirectory $wd
$p = New-ScheduledTaskPrincipal -UserId 'NABLUS\Laith' -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName 'cort_login' -Action $a -Principal $p -Force | Out-Null
Start-ScheduledTask -TaskName 'cort_login'
Start-Sleep -Seconds 3
(Get-ScheduledTask -TaskName 'cort_login').State
