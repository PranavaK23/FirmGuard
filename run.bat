@echo off
echo Starting FirmGuard on http://127.0.0.1:8000 ...
cd /d %~dp0
.\.venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000 --workers 1
pause
