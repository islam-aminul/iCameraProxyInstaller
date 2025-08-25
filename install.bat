@echo off
setlocal

:: Change to script directory
cd /d "%~dp0"

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell.exe -Command "Start-Process cmd.exe -ArgumentList '/c \"%~f0\" %*' -Verb RunAs"
    exit /b 0
)

:: Check for uninstall argument
if "%1"=="--uninstall" (
    echo Starting iCamera Proxy Uninstaller...
    powershell.exe -ExecutionPolicy Bypass -File "iCameraProxyInstaller.ps1" -Uninstall
    
    :: Check exit code
    if %errorLevel% neq 0 (
        echo Uninstallation failed with error code %errorLevel%
        pause
        exit /b %errorLevel%
    )
    
    echo Uninstallation process completed.
) else (
    :: Run PowerShell installer
    echo Starting iCamera Proxy Installer...
    powershell.exe -ExecutionPolicy Bypass -File "iCameraProxyInstaller.ps1"
    
    :: Check exit code
    if %errorLevel% neq 0 (
        echo Installation failed with error code %errorLevel%
        pause
        exit /b %errorLevel%
    )
    
    echo Installation process completed.
)
pause