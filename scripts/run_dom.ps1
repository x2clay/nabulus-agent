$A="C:\Users\Laith\nabulus-agent"; $py="C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$env:PYTHONIOENCODING='utf-8'; Set-Location $A
& $py "$A\login_dom.py" 2>&1 | Out-File "$A\dom_run.log" -Encoding utf8
