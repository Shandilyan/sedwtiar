@echo off
cd /d "%~dp0"
echo ========================================================
echo   Starting SEDWTIAR Backend and Desktop Client
echo ========================================================

:: 1. Launch FastAPI Backend in a separate window
start "SEDWTIAR Backend (Port 8000)" cmd /k "cd /d "%~dp0backend" && .venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

:: 2. Wait 2 seconds for backend initialization
ping 127.0.0.1 -n 3 >nul

:: 3. Launch Native PySide6 Desktop App in a separate window
start "SEDWTIAR Desktop App" cmd /k "cd /d "%~dp0desktop-app" && .venv\Scripts\python.exe app.py"
