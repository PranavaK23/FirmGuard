param([switch]$RebuildFrontend)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 -m venv .venv } else { & python -m venv .venv }
if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment. Install Python 3.11 or newer.' }
& .\.venv\Scripts\python.exe -m pip install -r backend\requirements-lock.txt
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
if ($RebuildFrontend -or !(Test-Path frontend\dist\index.html)) {
    Push-Location frontend
    try {
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
        & npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    } finally { Pop-Location }
}
Write-Host 'Setup complete. Run .\start.ps1 and open http://127.0.0.1:8000.'
