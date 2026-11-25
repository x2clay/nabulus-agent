py -3 -c "import playwright_stealth,inspect,os; print(playwright_stealth.__file__); print([n for n in dir(playwright_stealth) if not n.startswith('_')])"
Write-Output '--- chrome ---'
@(
  'C:\Program Files\Google\Chrome\Application\chrome.exe',
  'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
) | ForEach-Object { if (Test-Path $_) { $_ } }
Get-ChildItem 'C:\Users\Laith\AppData\Local\Google\Chrome\Application\chrome.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
