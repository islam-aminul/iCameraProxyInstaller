@echo off
setlocal

:: Change to installation directory
cd /d "%~dp0"

:: Find iCamera installation
for /d %%i in (C:\iCamera D:\iCamera E:\iCamera F:\iCamera) do (
    if exist "%%i\data\sqltool.rc" (
        set INSTALL_PATH=%%i
        goto :found
    )
)

echo iCamera installation not found!
pause
exit /b 1

:found
echo Found iCamera installation at: %INSTALL_PATH%

:: Set paths
set JAVA_PATH=%INSTALL_PATH%\jre\bin\java.exe
set HSQLDB_JAR=%INSTALL_PATH%\hsqldb\lib\hsqldb.jar
set RC_FILE=%INSTALL_PATH%\data\sqltool.rc

:: Check if files exist
if not exist "%JAVA_PATH%" (
    echo Java not found at: %JAVA_PATH%
    pause
    exit /b 1
)

if not exist "%HSQLDB_JAR%" (
    echo HSQLDB JAR not found at: %HSQLDB_JAR%
    pause
    exit /b 1
)

if not exist "%RC_FILE%" (
    echo sqltool.rc not found at: %RC_FILE%
    pause
    exit /b 1
)

:: Launch HSQLDB Swing Manager
echo Starting HSQLDB Database Manager...
"%JAVA_PATH%" -cp "%HSQLDB_JAR%" org.hsqldb.util.DatabaseManagerSwing --rcFile="%RC_FILE%"

pause