$A = "C:\Users\Laith\nabulus-agent"
$py = "C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$log = "$A\login_run.log"
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $A
"=== login helper $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8
& $py "$A\login_helper.py" --creds "$A\cortisol_creds.json" --out "$A\login_tokens.json" 2>&1 | Out-File $log -Append -Encoding utf8
"DONE" | Out-File $log -Append -Encoding utf8
