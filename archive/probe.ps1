$ErrorActionPreference="Continue"
$bin="C:\Users\Laith\nabulus-tools\bin"
$env:PATH="C:\Windows\System32;C:\Windows;$bin;$env:PATH"

"===== DNS ====="
foreach($h in @("quantnq.com","www.quantnq.com","pay.quantnq.com")){
  try { $r=[System.Net.Dns]::GetHostAddresses($h) | ForEach-Object { $_.IPAddressToString }
        "DNS $h -> $($r -join ', ')" }
  catch { "DNS $h -> NO RESOLVE" }
}

"===== raw HTTPS GET ====="
foreach($u in @("https://quantnq.com","https://www.quantnq.com","https://pay.quantnq.com")){
  try {
    $resp=Invoke-WebRequest $u -TimeoutSec 20 -UseBasicParsing
    "GET $u -> HTTP $($resp.StatusCode) | server=$($resp.Headers['Server']) | vercel=$($resp.Headers['x-vercel-id']) | len=$($resp.RawContentLength)"
  } catch {
    $sc=""; if($_.Exception.Response){ $sc=[int]$_.Exception.Response.StatusCode }
    "GET $u -> FAIL http=$sc :: $($_.Exception.Message)"
  }
}

"===== httpx (installed) on quantnq.com ====="
$tmp="$env:TEMP\hx_targets.txt"
"quantnq.com`r`nwww.quantnq.com`r`npay.quantnq.com" | Set-Content $tmp -Encoding ascii
& "$bin\httpx.exe" -l $tmp -status-code -title -tech-detect -silent -no-color 2>$null

"===== loop output sizes ====="
Get-ChildItem C:\Users\Laith\nabulus-agent\sessions,C:\Users\Laith\nabulus-agent\raw -File -ErrorAction SilentlyContinue |
  Select-Object @{n="bytes";e={$_.Length}}, Name | Format-Table -AutoSize | Out-String
"status.json:"; Get-Content C:\Users\Laith\nabulus-agent\status.json -Raw
"notebook.json:"; Get-Content C:\Users\Laith\nabulus-agent\notebook.json -Raw
