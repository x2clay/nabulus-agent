$ErrorActionPreference="Continue"
$A="C:\Users\Laith\nabulus-agent"; $B="$A\benchmark"; $root="C:\Users\Laith\benchlab"
$py="C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$env:PYTHONIOENCODING='utf-8'; $env:AUTHZ_RPS='4'
function Dump($f){ if(Test-Path $f){ (Get-Content $f -Raw | ConvertFrom-Json) | ForEach-Object { "  d"+$_.depth+" ["+$_.severity+"] "+$_.content_type+"  "+$_.endpoint } } else { "  (no findings file)" } }

"######## TARGET 1: quantnq.com (your site) - wordlist + harvest + branch, UNAUTH ########"
& $py "$A\authz_probe.py" --base https://www.quantnq.com --mode readonly --wordlist "$B\api_infra.txt" --budget 900 `
   --out "$A\quantnq_wl_findings.json" --report "$A\quantnq_wl_report.md" --proposals "$A\quantnq_wl_prop.json" 2>&1 | Select-String -Pattern '^\[authz\]'
"---- quantnq findings ----"; Dump "$A\quantnq_wl_findings.json"

"`n######## TARGET 2: OWASP Juice Shop (local) - same treatment ########"
$entry=Get-ChildItem "$root\unzip" -Recurse -Filter app.js -ErrorAction SilentlyContinue | Where-Object {$_.FullName -like '*\build\app.js'} | Select-Object -First 1
if($entry){
  $dest=(Get-Item $entry.FullName).Directory.Parent.FullName
  $node=(Get-Command node).Source
  $p=Start-Process $node -ArgumentList "`"$($entry.FullName)`"" -PassThru -WorkingDirectory $dest -RedirectStandardOutput "$root\h.out" -RedirectStandardError "$root\h.err" -WindowStyle Hidden
  foreach($i in 1..40){ Start-Sleep 2; if(Test-NetConnection 127.0.0.1 -Port 3000 -InformationLevel Quiet){ break } }
  & $py "$A\authz_probe.py" --base http://127.0.0.1:3000 --mode readonly --scope "$B\scope_bench.json" `
     --seeds "$B\juiceshop_hard_seeds.txt" --wordlist "$B\api_infra.txt" --budget 900 `
     --out "$B\hard2_findings.json" --report "$B\hard2_report.md" --proposals "$B\hard2_prop.json" 2>&1 | Select-String -Pattern '^\[authz\]'
  "---- juice shop findings ----"; Dump "$B\hard2_findings.json"
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
} else { "Juice Shop not installed - skipping target 2" }
"DONE"