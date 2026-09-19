@echo off
chcp 65001 >nul
echo PowerShell acilis taramasi basliyor...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Find-PowerShellStartup.ps1"
echo.
pause
