$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (!(Test-Path .venv\Scripts\python.exe)) { throw 'Run .\setup.ps1 first.' }
if (!(Test-Path frontend\dist\index.html)) { throw 'Build the interface with .\setup.ps1 -RebuildFrontend first.' }
Write-Host 'FirmGuard: http://127.0.0.1:8000 (Ctrl+C to stop)'
& .\.venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000 --workers 1
exit $LASTEXITCODE
