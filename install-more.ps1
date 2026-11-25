$ErrorActionPreference = 'Continue'
$bin = 'C:\Users\Laith\nabulus-tools\bin'
$lists = 'C:\Users\Laith\nabulus-tools\wordlists'
New-Item -ItemType Directory -Force -Path $bin, $lists | Out-Null
$headers = @{ 'User-Agent' = 'nabulus-agent' }

function Get-ReleaseExe($repo, $name) {
  $dest = Join-Path $bin "$name.exe"
  if (Test-Path $dest) { "have $name"; return }
  $rel = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$repo/releases/latest"
  $asset = $rel.assets | Where-Object { $_.name -match 'windows' -and $_.name -match 'amd64|x86_64' -and $_.name -match 'zip' } | Select-Object -First 1
  if (-not $asset) { "no asset $name"; return }
  $zip = Join-Path $env:TEMP $asset.name
  Invoke-WebRequest -Headers $headers -Uri $asset.browser_download_url -OutFile $zip
  $dir = Join-Path $env:TEMP "$name-extract"
  if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
  Expand-Archive -Path $zip -DestinationPath $dir -Force
  $exe = Get-ChildItem $dir -Recurse -Filter *.exe | Select-Object -First 1
  if (-not $exe) { "no exe in $name"; return }
  Copy-Item $exe.FullName $dest -Force
  "installed $name"
}

Get-ReleaseExe 'lc/gau' 'gau'
Get-ReleaseExe 'hakluke/hakrawler' 'hakrawler'
Get-ReleaseExe 'owasp-amass/amass' 'amass'

$raft = Join-Path $lists 'raft-medium-directories.txt'
if (-not (Test-Path $raft) -or (Get-Item $raft).Length -lt 10000) {
  Invoke-WebRequest -Headers $headers -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt' -OutFile $raft
}
"raft $((Get-Item $raft).Length)"

py -3 -m pip install --disable-pip-version-check arjun
"arjun_done"
