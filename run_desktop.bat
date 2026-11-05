@echo off
cd /d "%~dp0"

if exist "desktop-app\.venv\Scripts\pythonw.exe" (
    start "" "desktop-app\.venv\Scripts\pythonw.exe" desktop_app.py
) else if exist "desktop-app\.venv\Scripts\python.exe" (
    start "" "desktop-app\.venv\Scripts\python.exe" desktop_app.py
) else (
    start "" python desktop_app.py
)
