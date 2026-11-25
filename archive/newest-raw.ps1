Get-ChildItem C:\Users\Laith\nabulus-agent\raw -File | Sort-Object LastWriteTime -Descending | Select-Object -First 8 | ForEach-Object {
  Write-Output ($_.LastWriteTime.ToString("HH:mm:ss") + " " + $_.Length + " " + $_.Name)
}
