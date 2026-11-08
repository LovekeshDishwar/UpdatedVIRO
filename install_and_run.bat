@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python Launcher not found. Install Python 3.10+ and enable Add Python to PATH.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 (echo Could not create virtual environment.& pause & exit /b 1)
)
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 (echo pip upgrade failed.& pause & exit /b 1)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (echo Dependency installation failed.& pause & exit /b 1)
".venv\Scripts\python.exe" viro_app.py
if errorlevel 1 (echo VIRO exited with an error.& pause & exit /b 1)
endlocal
