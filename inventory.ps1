Write-Output '=== bin ==='
Get-ChildItem 'C:\Users\Laith\nabulus-tools\bin' -File | ForEach-Object { $_.Name }
Write-Output '=== github ==='
Get-ChildItem 'C:\Users\Laith\nabulus-tools\github' -Directory | ForEach-Object { $_.Name }
Write-Output '=== wordlists ==='
Get-ChildItem 'C:\Users\Laith\nabulus-tools\wordlists' -File -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) $($_.Length)" }
$t = 'C:\Users\Laith\nuclei-templates'
if (Test-Path $t) {
  $yaml = (Get-ChildItem $t -Recurse -Filter *.yaml -File -ErrorAction SilentlyContinue | Measure-Object).Count
  "nuclei_yaml=$yaml"
} else { 'nuclei_templates missing' }
