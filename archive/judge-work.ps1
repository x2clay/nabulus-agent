$ErrorActionPreference = "Continue"
py -3 C:\Users\Laith\nabulus-agent\judge-work.py
Write-Output "LINE"
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Laith\nabulus-agent\watch-line.ps1
Write-Output "TAIL"
Get-Content -Tail 30 C:\Users\Laith\nabulus-agent\run.out
Write-Output "ERR"
$err = "C:\Users\Laith\nabulus-agent\run.err"
if (Test-Path $err) {
  $t = Get-Content -Tail 20 $err -ErrorAction SilentlyContinue
  if ($t) { $t } else { Write-Output "empty" }
}
