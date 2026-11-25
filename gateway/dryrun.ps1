$ErrorActionPreference="Continue"
$g="C:\Users\Laith\nabulus-agent\gateway"
$py="C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$env:GATEWAY_TOKEN = "dryrun-" + ([guid]::NewGuid().ToString("N").Substring(0,12))
$env:GATEWAY_BIND  = "100.93.154.108"   # Tailscale IP (also auto-detected if unset)
Remove-Item "$g\gateway.log","$g\gw.out","$g\gw.err" -ErrorAction SilentlyContinue

$p = Start-Process -FilePath $py -ArgumentList "`"$g\gateway.py`"" -PassThru `
      -RedirectStandardOutput "$g\gw.out" -RedirectStandardError "$g\gw.err" -WindowStyle Hidden
Start-Sleep -Seconds 3
"gateway pid: $($p.Id)"
"startup stdout: " + ((Get-Content "$g\gw.out" -ErrorAction SilentlyContinue) -join ' ')
"startup stderr: " + ((Get-Content "$g\gw.err" -ErrorAction SilentlyContinue) -join ' ')

$base="http://100.93.154.108:8090/run-tool"
$hdr=@{ Authorization = "Bearer $($env:GATEWAY_TOKEN)" }
function Post($body){
  try {
    $r=Invoke-WebRequest -Uri $base -Method POST -Headers $hdr -ContentType "application/json" `
        -Body ($body|ConvertTo-Json -Compress) -TimeoutSec 120 -UseBasicParsing
    $c=$r.Content; return "HTTP $($r.StatusCode) :: " + $c.Substring(0,[Math]::Min(400,$c.Length))
  } catch {
    $resp=$_.Exception.Response
    if($resp){ $sc=$resp.StatusCode.value__; $sr=(New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd(); return "HTTP $sc :: $sr" }
    return "ERR :: $($_.Exception.Message)"
  }
}

""
"=== OUT-OF-SCOPE request: httpx -u example.com (not in scope.json) ==="
Post @{ tool="httpx"; args=@("-u","example.com"); authorization_ref="dryrun" }
""
"=== IN-SCOPE request: subfinder -d scanme.nmap.org (authorized) ==="
$r = Post @{ tool="subfinder"; args=@("-d","scanme.nmap.org"); authorization_ref="scanme operator banner" }
$r.Substring(0,[Math]::Min(300,$r.Length))
""
"=== gateway.log ==="
Get-Content "$g\gateway.log"

Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
"gateway stopped (on-demand; no scheduled task registered)"
""
"=== triage.py --mock (against latest findings.json entry) ==="
& $py "$g\triage.py" --mock
