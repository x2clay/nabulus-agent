$ErrorActionPreference="Continue"
$root="C:\Users\Laith\benchlab"
$py="C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$entry=Get-ChildItem "$root\unzip" -Recurse -Filter app.js -ErrorAction SilentlyContinue | Where-Object {$_.FullName -like '*\build\app.js'} | Select-Object -First 1
if(-not $entry){ "no Juice Shop installed - run run_benchmark.ps1 first"; exit 1 }
$dest=(Get-Item $entry.FullName).Directory.Parent.FullName
$node=(Get-Command node).Source
$p=Start-Process $node -ArgumentList "`"$($entry.FullName)`"" -PassThru -WorkingDirectory $dest -RedirectStandardOutput "$root\h.out" -RedirectStandardError "$root\h.err" -WindowStyle Hidden
foreach($i in 1..40){ Start-Sleep 2; if(Test-NetConnection 127.0.0.1 -Port 3000 -InformationLevel Quiet){ break } }
$env:PYTHONIOENCODING='utf-8'
& $py "C:\Users\Laith\nabulus-agent\authz_probe.py" --base http://127.0.0.1:3000 --mode readonly `
   --scope "C:\Users\Laith\nabulus-agent\benchmark\scope_bench.json" `
   --seeds "C:\Users\Laith\nabulus-agent\benchmark\juiceshop_hard_seeds.txt" `
   --out "C:\Users\Laith\nabulus-agent\benchmark\hard_findings.json" `
   --report "C:\Users\Laith\nabulus-agent\benchmark\hard_report.md" `
   --proposals "C:\Users\Laith\nabulus-agent\benchmark\hard_prop.json" 2>&1
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
"stopped"