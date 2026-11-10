@echo off
setlocal
title Traceglass
cd /d "%~dp0"

where node >nul 2>&1
if errorlevel 1 (
    echo Node.js is required. Install Node.js 22 or later, then run this file again.
    pause
    exit /b 1
)

if not exist "%~dp0node_modules\express\package.json" (
    echo Installing project dependencies...
    call npm ci
    if errorlevel 1 goto failed
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start.ps1"
if errorlevel 1 goto failed
exit /b 0

:failed
echo.
echo Traceglass could not start. Review the error above.
pause
exit /b 1
