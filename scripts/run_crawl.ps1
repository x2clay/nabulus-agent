# run_crawl.ps1 - browser-based endpoint discovery on the authorized quantnq surface.
$A = "C:\Users\Laith\nabulus-agent"
$py = "C:\Users\Laith\AppData\Local\Programs\Python\Python311\python.exe"
$log = "$A\crawl_run.log"
$scope = "$A\scope.json"
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $A
"=== crawl $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8
& $py "$A\crawl.py" --seeds "https://www.quantnq.com/" "https://quantnq.com/" "https://pay.quantnq.com/" --scope $scope --max-pages 50 --out "$A\quantnq_endpoints.json" 2>&1 | Out-File $log -Append -Encoding utf8
"DONE" | Out-File $log -Append -Encoding utf8
