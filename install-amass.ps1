$dest = 'C:\Users\Laith\nabulus-tools\bin\amass.exe'
if (Test-Path $dest) { 'have amass'; exit 0 }
$tar = Join-Path $env:TEMP 'amass_windows_amd64.tar.gz'
$dir = Join-Path $env:TEMP 'amass-extract'
Invoke-WebRequest -Headers @{ 'User-Agent' = 'nabulus-agent' } -Uri 'https://github.com/owasp-amass/amass/releases/download/v5.1.3/amass_windows_amd64.tar.gz' -OutFile $tar
if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
tar -xf $tar -C $dir
$exe = Get-ChildItem $dir -Recurse -Filter amass.exe | Select-Object -First 1
if (-not $exe) { 'no amass exe'; exit 1 }
Copy-Item $exe.FullName $dest -Force
'installed amass'
