$ErrorActionPreference = "Continue"
Write-Output "WWW4"
curl.exe -4 -sS -o NUL -D - --http1.1 --connect-timeout 15 --max-time 25 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" https://www.quantnq.com/ | Select-Object -First 15
Write-Output "APEX_H2"
curl.exe -4 -sS -o NUL -w "h2 code=%{http_code} ip=%{remote_ip} ver=%{http_version} err=%{errormsg}`n" --http2 --connect-timeout 15 --max-time 25 https://quantnq.com/
Write-Output "WWW_H2"
curl.exe -4 -sS -o NUL -w "www_h2 code=%{http_code} ip=%{remote_ip} ver=%{http_version} err=%{errormsg}`n" --http2 --connect-timeout 15 --max-time 25 https://www.quantnq.com/
Write-Output "DNS_WWW"
Resolve-DnsName www.quantnq.com -Type A -ErrorAction Continue | ForEach-Object { if ($_.IPAddress) { Write-Output $_.IPAddress } }
