$ErrorActionPreference="Continue"
$root="C:\Users\Laith\benchlab"
$entry=Get-ChildItem "$root\unzip" -Recurse -Filter app.js -ErrorAction SilentlyContinue | Where-Object {$_.FullName -like '*\build\app.js'} | Select-Object -First 1
if(-not $entry){ "no entry"; exit 1 }
$dest=(Get-Item $entry.FullName).Directory.Parent.FullName
$node=(Get-Command node).Source
$p=Start-Process $node -ArgumentList "`"$($entry.FullName)`"" -PassThru -WorkingDirectory $dest -RedirectStandardOutput "$root\v.out" -RedirectStandardError "$root\v.err" -WindowStyle Hidden
foreach($i in 1..40){ Start-Sleep 2; if(Test-NetConnection 127.0.0.1 -Port 3000 -InformationLevel Quiet){break} }
foreach($u in @(
  "http://127.0.0.1:3000/ftp/suspicious_errors.yml",
  "http://127.0.0.1:3000/encryptionkeys/premium.key",
  "http://127.0.0.1:3000/ftp/quarantine/",
  "http://127.0.0.1:3000/ftp/")){
  try { $r=Invoke-WebRequest $u -TimeoutSec 15 -UseBasicParsing; "$u -> HTTP $($r.StatusCode) ctype=$($r.Headers['Content-Type']) len=$($r.RawContentLength)" }
  catch { $sc=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{0}; "$u -> HTTP $sc" }
}
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
"stopped"