py -3 -m pip install --disable-pip-version-check playwright-stealth
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\Laith\nabulus-agent\launch-test.ps1
