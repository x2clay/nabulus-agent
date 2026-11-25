$ErrorActionPreference="Continue"; $ProgressPreference="SilentlyContinue"
$root="C:\Users\Laith\benchlab"; New-Item -ItemType Directory -Force -Path $root | Out-Null
$unzip="$root\unzip"
$log="$root\bench.log"; ""|Set-Content $log
$py="C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$ua=@{'User-Agent'='nabulus-bench'}
function L($m){ (Get-Date).ToString("HH:mm:ss")+" "+$m | Tee-Object -FilePath $log -Append }

function Find-Entry {
  if(-not (Test-Path $unzip)){ return $null }
  $e = Get-ChildItem $unzip -Recurse -Filter app.js -ErrorAction SilentlyContinue |
       Where-Object { $_.FullName -like '*\build\app.js' } | Select-Object -First 1
  if(-not $e){ $e = Get-ChildItem $unzip -Recurse -Filter app.js -ErrorAction SilentlyContinue | Select-Object -First 1 }
  return $e
}

# ---- 1. install packaged Juice Shop if not already extracted ----
$entryItem = Find-Entry
if(-not $entryItem){
  $nodever = (node --version) 2>$null
  $major = if($nodever){ ($nodever -replace 'v','').Split('.')[0] } else { "22" }
  L "system node: $nodever (major $major)"
  try { $r=Invoke-RestMethod "https://api.github.com/repos/juice-shop/juice-shop/releases/latest" -Headers $ua }
  catch { L "github api fail: $($_.Exception.Message)"; exit 1 }
  L "release $($r.tag_name)"
  $asset = $r.assets | Where-Object { $_.name -match "node$($major)_win32_x64\.zip$" } | Select-Object -First 1
  if(-not $asset){ $asset = $r.assets | Where-Object { $_.name -match 'win32_x64\.zip$' -and $_.name -notmatch '\.md5$' } | Select-Object -First 1 }
  if(-not $asset){ L "ABORT: no win32_x64 asset in $($r.tag_name)"; exit 1 }
  L "asset $($asset.name) ($([math]::Round($asset.size/1MB,1))MB) - downloading"
  $zip="$root\juiceshop.zip"
  Invoke-WebRequest $asset.browser_download_url -OutFile $zip -Headers $ua
  Remove-Item $unzip -Recurse -Force -ErrorAction SilentlyContinue
  Expand-Archive $zip -DestinationPath $unzip -Force
  $entryItem = Find-Entry
}
if(-not $entryItem){ L "ABORT: no app.js entry after extract"; exit 1 }
$entry = $entryItem.FullName
$dest  = if($entry -like '*\build\app.js'){ (Get-Item $entry).Directory.Parent.FullName } else { (Get-Item $entry).Directory.FullName }
L "entry $entry"
L "workdir $dest"

# ---- 2. start Juice Shop as a child of THIS session ----
$node=(Get-Command node -ErrorAction SilentlyContinue).Source
if(-not $node){ L "ABORT: node not on PATH"; exit 1 }
$proc=Start-Process -FilePath $node -ArgumentList "`"$entry`"" -PassThru -WorkingDirectory $dest `
       -RedirectStandardOutput "$root\js.out" -RedirectStandardError "$root\js.err" -WindowStyle Hidden
L "node pid $($proc.Id); waiting for :3000"
$up=$false
foreach($i in 1..45){ Start-Sleep 2; if(Test-NetConnection 127.0.0.1 -Port 3000 -InformationLevel Quiet){ $up=$true; break } }
L "port 3000 up: $up"

# ---- 3. scored benchmark ----
if($up){
  L "running benchmark.py"
  & $py "C:\Users\Laith\nabulus-agent\benchmark\benchmark.py" --base "http://127.0.0.1:3000" 2>&1 | Tee-Object -FilePath $log -Append
} else {
  L "juice-shop did not come up; js.err tail:"
  Get-Content "$root\js.err" -Tail 12 -ErrorAction SilentlyContinue | ForEach-Object { L "  $_" }
}

# ---- 4. stop it (one-shot) ----
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
L "juice-shop stopped. DONE."
