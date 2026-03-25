@echo off
title BugScanner Web GUI
color 0A
cd /d "%~dp0"

:: Activate venv if exists
if exist "%USERPROFILE%\.bugscanner\venv\Scripts\activate.bat" (
    call "%USERPROFILE%\.bugscanner\venv\Scripts\activate.bat"
) else if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
)

echo.
echo   BugScanner Web GUI starting...
echo   Open browser at: http://localhost:5000
echo   Press Ctrl+C to stop
echo.

python web_gui.py %*
pause
