param([double]$Hours = 1)
$agent = "C:\Users\Laith\nabulus-agent"
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*autonomous.py*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
$out = Join-Path $agent "run.out"
$err = Join-Path $agent "run.err"
Set-Content -Path $out -Value "" -Encoding utf8
Set-Content -Path $err -Value "" -Encoding utf8
$cmd = "cmd.exe /c set PYTHONUNBUFFERED=1&& py -3 -u `"$agent\autonomous.py`" --bench --hours $Hours > `"$out`" 2> `"$err`""
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
Write-Output $r.ProcessId
