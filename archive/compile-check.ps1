tasklist /FI "IMAGENAME eq python.exe"
py -3 -m py_compile C:\Users\Laith\nabulus-agent\surface.py C:\Users\Laith\nabulus-agent\session.py C:\Users\Laith\nabulus-agent\battery.py C:\Users\Laith\nabulus-agent\playbook.py C:\Users\Laith\nabulus-agent\autonomous.py C:\Users\Laith\nabulus-agent\extractor.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
py -3 C:\Users\Laith\nabulus-agent\test_surface.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
py -3 C:\Users\Laith\nabulus-agent\test_battery.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
py -3 C:\Users\Laith\nabulus-agent\test_playbook.py
exit $LASTEXITCODE
