@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" viro_app.py
) else (
  python viro_app.py
)
pause
