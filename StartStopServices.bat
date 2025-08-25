@echo off
setlocal

:: Find iCamera installation
for /d %%i in (C:\iCamera D:\iCamera E:\iCamera F:\iCamera) do (
    if exist "%%i\procrun\prunsrv.exe" (
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
set DATA_PATH=%INSTALL_PATH%\data
set APP_PATH=%INSTALL_PATH%\app

:menu
echo.
echo ================================
echo iCamera Service Management
echo ================================
echo 1. Start HSQLDB (Standalone)
echo 2. Stop HSQLDB (Standalone)
echo 3. Start iCamera Proxy (Standalone)
echo 4. Start HSQLDB Service
echo 5. Stop HSQLDB Service
echo 6. Start iCamera Proxy Service
echo 7. Stop iCamera Proxy Service
echo 8. Exit
echo ================================
set /p choice="Select option (1-8): "

if "%choice%"=="1" goto start_hsqldb_standalone
if "%choice%"=="2" goto stop_hsqldb_standalone
if "%choice%"=="3" goto start_proxy_standalone
if "%choice%"=="4" goto start_hsqldb_service
if "%choice%"=="5" goto stop_hsqldb_service
if "%choice%"=="6" goto start_proxy_service
if "%choice%"=="7" goto stop_proxy_service
if "%choice%"=="8" goto exit
goto menu

:start_hsqldb_standalone
echo Starting HSQLDB standalone...
cd /d "%DATA_PATH%"
start "HSQLDB Server" "%JAVA_PATH%" -cp "%HSQLDB_JAR%" org.hsqldb.server.Server --props server.properties
echo HSQLDB started in new window
goto menu

:stop_hsqldb_standalone
echo Stopping HSQLDB standalone...
taskkill /f /im java.exe /fi "WINDOWTITLE eq HSQLDB Server"
echo HSQLDB stopped
goto menu

:start_proxy_standalone
echo Starting iCamera Proxy standalone...
cd /d "%APP_PATH%"
set ICAMERA_PROXY_HOME=%APP_PATH%
set FFMPEG_HOME=%INSTALL_PATH%\ffmpeg\bin
start "iCamera Proxy" "%JAVA_PATH%" -Xms512m -Xmx1024m -Dlogback.configurationFile=logback.xml -Djava.awt.headless=true -jar CameraProxy.jar
echo iCamera Proxy started in new window
goto menu

:start_hsqldb_service
echo Starting HSQLDB service...
net start iCameraHSQLDB
goto menu

:stop_hsqldb_service
echo Stopping HSQLDB service...
net stop iCameraHSQLDB
goto menu

:start_proxy_service
echo Starting iCamera Proxy service...
net start iCameraProxy
goto menu

:stop_proxy_service
echo Stopping iCamera Proxy service...
net stop iCameraProxy
goto menu

:exit
echo Goodbye!
pause