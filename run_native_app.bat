@echo off
rem Resolve the project root (the folder that contains both backend and desktop-app)
set "PROJECT_ROOT=%~dp0.."

rem === Start FastAPI backend ===
start "Backend" cmd /k "cd /d "%PROJECT_ROOT%\backend" && call .venv\Scripts\activate.bat && python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload || (echo *** BACKEND FAILED *** & pause)"

rem === Start Desktop (Tkinter) UI ===
start "Desktop UI" cmd /k "cd /d "%PROJECT_ROOT%\desktop-app" && call .venv\Scripts\activate.bat && python app.py || (echo *** DESKTOP UI FAILED *** & pause)"

rem Keep this batch window open so you can see any messages
pause
rem Resolve the project root (the folder that contains both backend and desktop-app)
set "PROJECT_ROOT=%~dp0.."

rem === Start FastAPI backend ===
start "Backend" cmd /c "cd /d "%PROJECT_ROOT%\backend" && call .venv\Scripts\activate.bat && python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload"

rem === Start Desktop (Tkinter) UI ===
start "Desktop UI" cmd /c "cd /d "%PROJECT_ROOT%\desktop-app" && call .venv\Scripts\activate.bat && python app.py"

cd /d "%~dp0\desktop-app"
if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" app.py
) else if exist ".venv\Scripts\python.exe" (
    start "" ".venv\Scripts\python.exe" app.py
) else (
    start "" python app.py
)
cd /d "%~dp0\desktop-app"
if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" app.py
) else if exist ".venv\Scripts\python.exe" (
    start "" ".venv\Scripts\python.exe" app.py
) else (
    start "" python app.py
)

