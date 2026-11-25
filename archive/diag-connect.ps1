$ErrorActionPreference = "Continue"
Write-Output "DNS_A"
Resolve-DnsName quantnq.com -Type A -ErrorAction Continue | ForEach-Object { if ($_.IPAddress) { Write-Output $_.IPAddress } }
Write-Output "DNS_AAAA"
Resolve-DnsName quantnq.com -Type AAAA -ErrorAction Continue | ForEach-Object { if ($_.IPAddress) { Write-Output $_.IPAddress } }
Write-Output "TCP443"
$r = Test-NetConnection quantnq.com -Port 443 -WarningAction SilentlyContinue
Write-Output ("tcp=" + $r.TcpTestSucceeded + " remote=" + $r.RemoteAddress)
Write-Output "PROXY"
netsh winhttp show proxy
$ie = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Write-Output ("proxy_enable=" + $ie.ProxyEnable + " proxy_server=" + $ie.ProxyServer)
Write-Output "CURL"
curl.exe -4 -sS -o NUL -D - --connect-timeout 15 --max-time 25 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" https://quantnq.com/ | Select-Object -First 12
Write-Output "CURL4_CODE"
curl.exe -4 -sS -o NUL -w "https4 code=%{http_code} ip=%{remote_ip} err=%{errormsg}`n" --http1.1 --connect-timeout 15 --max-time 25 https://quantnq.com/
Write-Output "CURL6_CODE"
curl.exe -6 -sS -o NUL -w "https6 code=%{http_code} ip=%{remote_ip} err=%{errormsg}`n" --connect-timeout 12 --max-time 20 https://quantnq.com/
Write-Output "CONTROL"
curl.exe -4 -sS -o NUL -w "example code=%{http_code} ip=%{remote_ip} err=%{errormsg}`n" --connect-timeout 12 --max-time 20 https://example.com/
