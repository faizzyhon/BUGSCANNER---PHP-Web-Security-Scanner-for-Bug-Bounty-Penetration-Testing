@echo off
title BugScanner Installer — Muhammad Faizan
color 0A
cls

echo.
echo  ██████╗ ██╗   ██╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
echo  ██╔══██╗██║   ██║██╔════╝ ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
echo  ██████╔╝██║   ██║██║  ███╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
echo  ██╔══██╗██║   ██║██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
echo  ██████╔╝╚██████╔╝╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
echo  ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
echo.
echo   PHP Web Security Scanner ^| EC-Council Bug Bounty Edition
echo   Author: Muhammad Faizan ^| faizzyhon@gmail.com
echo.
echo ══════════════════════════════════════════════════════════
echo.

set INSTALL_DIR=%USERPROFILE%\.bugscanner
set SCRIPT_DIR=%~dp0

:: ── Check Python ──────────────────────────────────────────────────────────
echo [1/5] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo   [!] Python not found. Opening download page...
    start https://www.python.org/downloads/
    echo   [!] Please install Python 3.10+ then run this installer again.
    echo       IMPORTANT: Check "Add Python to PATH" during install!
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo   [+] Python %PY_VER% found

:: ── Create virtual environment ────────────────────────────────────────────
echo.
echo [2/5] Creating virtual environment...
if exist "%INSTALL_DIR%\venv" (
    echo   [*] Removing old venv...
    rmdir /s /q "%INSTALL_DIR%\venv"
)
mkdir "%INSTALL_DIR%" 2>nul
python -m venv "%INSTALL_DIR%\venv"
if errorlevel 1 (
    echo   [!] Failed to create venv. Trying without venv...
    set USE_VENV=0
) else (
    echo   [+] Virtual environment created
    set USE_VENV=1
)

:: ── Activate venv ─────────────────────────────────────────────────────────
if "%USE_VENV%"=="1" (
    call "%INSTALL_DIR%\venv\Scripts\activate.bat"
)

:: ── Install packages ──────────────────────────────────────────────────────
echo.
echo [3/5] Installing Python packages...
python -m pip install --quiet --upgrade pip wheel

python -m pip install --quiet ^
    requests beautifulsoup4 lxml ^
    click rich ^
    Jinja2 ^
    reportlab ^
    Flask Flask-WTF ^
    openai anthropic

if errorlevel 1 (
    echo   [!] Some packages failed. Trying one by one...
    python -m pip install requests
    python -m pip install beautifulsoup4 lxml
    python -m pip install click rich
    python -m pip install Jinja2 reportlab
    python -m pip install Flask
)
echo   [+] Python packages installed

:: Try WeasyPrint (optional)
python -m pip install --quiet weasyprint >nul 2>&1 && (
    echo   [+] WeasyPrint installed
) || (
    echo   [*] WeasyPrint skipped ^(using ReportLab for PDF^)
)

:: ── Copy files ────────────────────────────────────────────────────────────
echo.
echo [4/5] Installing BugScanner to %INSTALL_DIR%...
xcopy /E /I /Y "%SCRIPT_DIR%*" "%INSTALL_DIR%\app\" >nul 2>&1
mkdir "%INSTALL_DIR%\reports" 2>nul
echo   [+] Files copied

:: ── Create launchers ──────────────────────────────────────────────────────
echo.
echo [5/5] Creating launcher scripts...

:: CLI launcher
(
echo @echo off
echo title BugScanner CLI
echo color 0A
echo call "%INSTALL_DIR%\venv\Scripts\activate.bat" 2^>nul
echo cd /d "%INSTALL_DIR%\app"
echo python main.py %%*
) > "%INSTALL_DIR%\bugscanner.bat"

:: Web GUI launcher
(
echo @echo off
echo title BugScanner Web GUI
echo color 0A
echo call "%INSTALL_DIR%\venv\Scripts\activate.bat" 2^>nul
echo cd /d "%INSTALL_DIR%\app"
echo echo.
echo echo   BugScanner Web GUI starting...
echo echo   Open browser at: http://localhost:5000
echo echo   Press Ctrl+C to stop
echo echo.
echo python web_gui.py %%*
echo pause
) > "%INSTALL_DIR%\bugscanner-web.bat"

:: Add to PATH via registry (user-level, no admin needed)
setx PATH "%PATH%;%INSTALL_DIR%" >nul 2>&1

:: Also create desktop shortcuts
set DESKTOP=%USERPROFILE%\Desktop
set SHORTCUT_CLI=%DESKTOP%\BugScanner CLI.bat
set SHORTCUT_WEB=%DESKTOP%\BugScanner Web.bat

copy "%INSTALL_DIR%\bugscanner.bat" "%SHORTCUT_CLI%" >nul 2>&1
copy "%INSTALL_DIR%\bugscanner-web.bat" "%SHORTCUT_WEB%" >nul 2>&1
echo   [+] Desktop shortcuts created

:: ── Check Ollama ──────────────────────────────────────────────────────────
echo.
echo Checking Ollama (local AI)...
ollama --version >nul 2>&1
if errorlevel 1 (
    echo   [*] Ollama not found ^(optional — for free local AI^)
    echo   [*] Download: https://ollama.com/download/windows
    echo   [*] After install: ollama pull deepseek-r1
) else (
    echo   [+] Ollama is installed
    ollama list 2>nul
)

:: ── Done ──────────────────────────────────────────────════════════════════
echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║  [+] BugScanner installed successfully!                  ║
echo ╠══════════════════════════════════════════════════════════╣
echo ║                                                          ║
echo ║  CLI : Double-click "BugScanner CLI" on Desktop         ║
echo ║        or run: bugscanner scan --url https://target.com  ║
echo ║                                                          ║
echo ║  WEB : Double-click "BugScanner Web" on Desktop         ║
echo ║        then open http://localhost:5000 in browser        ║
echo ║                                                          ║
echo ╚══════════════════════════════════════════════════════════╝
echo.
echo   Author: Muhammad Faizan ^| faizzyhon@gmail.com
echo   Hack the Planet
echo.
pause
