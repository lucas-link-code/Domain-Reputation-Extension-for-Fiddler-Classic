@echo off
setlocal enabledelayedexpansion

echo.
echo ==============================================
echo  INSTALL DOMAIN REPUTATION INSPECTOR
echo  Installing from CURRENT DIRECTORY
echo ==============================================
echo.

rem PRIMARY LOCATION: Documents\Fiddler2\Scripts (recommended by Fiddler docs)
set "PRIMARY_PATH=%USERPROFILE%\Documents\Fiddler2\Scripts"

rem SECONDARY LOCATION: AppData\Local\Programs\Fiddler\Scripts (fallback)
set "SECONDARY_PATH=%LOCALAPPDATA%\Programs\Fiddler\Scripts"

rem OTHER POSSIBLE LOCATIONS for cleanup
set "APPDATA_PATH=%APPDATA%\Fiddler2\Scripts"
set "INSPECTORS_PATH=%USERPROFILE%\Documents\Fiddler2\Inspectors"

echo Checking for existing installations to clean up...

rem Clean up any existing installations in secondary locations
if exist "%SECONDARY_PATH%\DomainReputationInspector.dll" (
    echo Found old installation in: "%SECONDARY_PATH%"
    echo Removing old files...
    del /Q "%SECONDARY_PATH%\DomainReputationInspector.dll" 2>nul
    del /Q "%SECONDARY_PATH%\Newtonsoft.Json.dll" 2>nul
    del /Q "%SECONDARY_PATH%\System.Data.SQLite.dll" 2>nul
    del /Q "%SECONDARY_PATH%\SQLite.Interop.dll" 2>nul
    del /Q "%SECONDARY_PATH%\DomainReputationInspector.dll.config" 2>nul
    if exist "%SECONDARY_PATH%\x86\SQLite.Interop.dll" del /Q "%SECONDARY_PATH%\x86\SQLite.Interop.dll" 2>nul
    if exist "%SECONDARY_PATH%\x64\SQLite.Interop.dll" del /Q "%SECONDARY_PATH%\x64\SQLite.Interop.dll" 2>nul
    echo Old installation cleaned up from secondary location.
)

if exist "%APPDATA_PATH%\DomainReputationInspector.dll" (
    echo Found old installation in: "%APPDATA_PATH%"
    echo Removing old files...
    del /Q "%APPDATA_PATH%\DomainReputationInspector.dll" 2>nul
    del /Q "%APPDATA_PATH%\Newtonsoft.Json.dll" 2>nul
    del /Q "%APPDATA_PATH%\System.Data.SQLite.dll" 2>nul
    del /Q "%APPDATA_PATH%\SQLite.Interop.dll" 2>nul
    del /Q "%APPDATA_PATH%\DomainReputationInspector.dll.config" 2>nul
    echo Old installation cleaned up from AppData location.
)

if exist "%INSPECTORS_PATH%\DomainReputationInspector.dll" (
    echo Found old installation in: "%INSPECTORS_PATH%"
    echo Removing old files...
    del /Q "%INSPECTORS_PATH%\DomainReputationInspector.dll" 2>nul
    del /Q "%INSPECTORS_PATH%\Newtonsoft.Json.dll" 2>nul
    del /Q "%INSPECTORS_PATH%\System.Data.SQLite.dll" 2>nul
    del /Q "%INSPECTORS_PATH%\SQLite.Interop.dll" 2>nul
    del /Q "%INSPECTORS_PATH%\DomainReputationInspector.dll.config" 2>nul
    if exist "%INSPECTORS_PATH%\x86\SQLite.Interop.dll" del /Q "%INSPECTORS_PATH%\x86\SQLite.Interop.dll" 2>nul
    if exist "%INSPECTORS_PATH%\x64\SQLite.Interop.dll" del /Q "%INSPECTORS_PATH%\x64\SQLite.Interop.dll" 2>nul
    echo Old installation cleaned up from Inspectors location.
)

echo.
echo Installing to PRIMARY location: "%PRIMARY_PATH%"

rem Create primary Scripts folder if it doesn't exist
if not exist "%PRIMARY_PATH%" (
    echo Creating primary Scripts folder...
    mkdir "%PRIMARY_PATH%" 2>nul
    if not exist "%PRIMARY_PATH%" (
        echo ERROR: Could not create primary Scripts directory: "%PRIMARY_PATH%"
        echo Please manually create this folder and rerun the installer.
        echo NOTE: You may need to run Fiddler Classic once first to create the folder structure.
        pause
        exit /b 1
    )
)

echo Primary Scripts folder ready: "%PRIMARY_PATH%"
echo.

rem Check for Fiddler processes and terminate if needed
echo Checking for running Fiddler processes...

rem Single comprehensive check for any Fiddler-related processes
tasklist 2>nul | find /I "Fiddler" >nul
if %ERRORLEVEL% == 0 (
    echo   Fiddler processes detected - proceeding with termination
    goto :terminate_fiddler
) else (
    echo   No Fiddler processes detected - skipping termination
    goto :fiddler_terminated
)

:terminate_fiddler
echo   [1/2] Attempting graceful shutdown...
taskkill /IM Fiddler.exe 2>nul
taskkill /IM FiddlerClassic.exe 2>nul
taskkill /IM FiddlerSetup.exe 2>nul
timeout /t 2 /nobreak >nul

echo   [2/2] Attempting forced termination...
taskkill /F /IM Fiddler.exe 2>nul
taskkill /F /IM FiddlerClassic.exe 2>nul
taskkill /F /IM FiddlerSetup.exe 2>nul
powershell -Command "Get-Process -Name '*Fiddler*' -ErrorAction SilentlyContinue | Stop-Process -Force" 2>nul
wmic process where "name like '%fiddler%'" delete >nul 2>&1
timeout /t 2 /nobreak >nul

rem Check if we need nuclear methods
tasklist 2>nul | find /I "Fiddler" >nul
if %ERRORLEVEL% == 0 (
    echo   [3/3] Applying nuclear termination methods...
    
    rem PID-specific termination
    for /f "tokens=2 delims=," %%i in ('tasklist /FI "IMAGENAME eq Fiddler.exe" /FO CSV /NH 2^>nul ^| find "Fiddler.exe"') do (
        set PID=%%i
        set PID=!PID:"=!
        echo   Targeting PID !PID! specifically
        taskkill /F /PID !PID! 2>nul
        wmic process where "ProcessId=!PID!" delete >nul 2>&1
    )
    
    rem PowerShell .Kill() method
    powershell -Command "Get-Process -Name Fiddler -ErrorAction SilentlyContinue | ForEach-Object { Write-Host '  PowerShell killing PID:' $_.Id; $_.Kill(); Start-Sleep -Milliseconds 500 }" 2>nul
    
    rem Process tree termination
    wmic process where "name='Fiddler.exe'" call terminate >nul 2>&1
    
    timeout /t 3 /nobreak >nul
)

echo   Verifying termination results...
tasklist 2>nul | find /I "Fiddler" >nul
if %ERRORLEVEL% == 0 (
    echo   WARNING: Fiddler processes still detected in system
    goto :fiddler_still_running
) else (
    echo   [SUCCESS] All Fiddler processes terminated successfully.
    goto :fiddler_terminated
)

:fiddler_still_running
echo.
echo [WARNING] Fiddler is still running despite termination attempts.
echo.
echo MANUAL STEPS REQUIRED:
echo   1. Open Task Manager (Ctrl+Shift+Esc)
echo   2. Find and end all Fiddler processes
echo   3. Or restart your computer if Fiddler won't close
echo.
echo Press any key ONLY AFTER closing all Fiddler processes...
pause

rem One final check after manual intervention
tasklist 2>nul | find /I "Fiddler" >nul
if %ERRORLEVEL% == 0 (
    echo [ERROR] Fiddler is still running. Installation cannot continue safely.
    echo Please restart your computer and run this installer again.
    pause
    exit /b 1
)
echo   Proceeding with installation after manual termination...

:fiddler_terminated

rem Copy files from CURRENT directory to PRIMARY location
set COPIED=0
echo Installing core extension files...

echo Copying DomainReputationInspector.dll...
if exist "DomainReputationInspector.dll" (
    copy /Y "DomainReputationInspector.dll" "%PRIMARY_PATH%\" >nul 2>&1
    if exist "%PRIMARY_PATH%\DomainReputationInspector.dll" (
        set /a COPIED+=1
        echo   SUCCESS: Main extension DLL installed
    ) else (
        echo   ERROR: Failed to copy main extension DLL
    )
) else (
    echo   ERROR: DomainReputationInspector.dll not found in current directory
)

echo Copying Newtonsoft.Json.dll...
if exist "Newtonsoft.Json.dll" (
    copy /Y "Newtonsoft.Json.dll" "%PRIMARY_PATH%\" >nul 2>&1
    if exist "%PRIMARY_PATH%\Newtonsoft.Json.dll" (
        set /a COPIED+=1
        echo   SUCCESS: JSON library installed
    ) else (
        echo   ERROR: Failed to copy JSON library
    )
) else (
    echo   ERROR: Newtonsoft.Json.dll not found in current directory
)

echo Copying System.Data.SQLite.dll...
if exist "System.Data.SQLite.dll" (
    copy /Y "System.Data.SQLite.dll" "%PRIMARY_PATH%\" >nul 2>&1
    if exist "%PRIMARY_PATH%\System.Data.SQLite.dll" (
        set /a COPIED+=1
        echo   SUCCESS: SQLite library installed
    ) else (
        echo   WARNING: Failed to copy SQLite library
    )
) else (
    echo   WARNING: System.Data.SQLite.dll not found in current directory
)

echo Copying SQLite.Interop.dll (root folder)...
if exist "SQLite.Interop.dll" (
    copy /Y "SQLite.Interop.dll" "%PRIMARY_PATH%\" >nul 2>&1
    if exist "%PRIMARY_PATH%\SQLite.Interop.dll" (
        echo   SUCCESS: SQLite interop library installed to root Scripts folder
    ) else (
        echo   WARNING: Failed to copy SQLite interop library to root folder
    )
) else (
    echo   NOTE: SQLite.Interop.dll not found in current directory for root copy
)

echo Copying optional config...
if exist "DomainReputationInspector.dll.config" (
    copy /Y "DomainReputationInspector.dll.config" "%PRIMARY_PATH%\" >nul 2>&1
    if exist "%PRIMARY_PATH%\DomainReputationInspector.dll.config" (
        echo   SUCCESS: Configuration file installed
    )
)

rem Copy native SQLite libraries for both architectures
if not exist "%PRIMARY_PATH%\x86" mkdir "%PRIMARY_PATH%\x86" 2>nul
if not exist "%PRIMARY_PATH%\x64" mkdir "%PRIMARY_PATH%\x64" 2>nul

echo Copying SQLite.Interop.dll to architecture-specific folders...
if exist "SQLite.Interop.dll" (
    rem Copy the same DLL to both x86 and x64 folders (AnyCPU compatible)
    copy /Y "SQLite.Interop.dll" "%PRIMARY_PATH%\x86\" >nul 2>&1
    copy /Y "SQLite.Interop.dll" "%PRIMARY_PATH%\x64\" >nul 2>&1
    
    if exist "%PRIMARY_PATH%\x86\SQLite.Interop.dll" echo   SUCCESS: x86 SQLite native library installed
    if exist "%PRIMARY_PATH%\x64\SQLite.Interop.dll" echo   SUCCESS: x64 SQLite native library installed
    
    if not exist "%PRIMARY_PATH%\x86\SQLite.Interop.dll" echo   WARNING: Failed to copy x86 SQLite native library
    if not exist "%PRIMARY_PATH%\x64\SQLite.Interop.dll" echo   WARNING: Failed to copy x64 SQLite native library
) else (
    rem Fallback: Look for architecture-specific source folders
    set SQLITE_COPIED=0
    
    if exist "x86\SQLite.Interop.dll" (
        copy /Y "x86\SQLite.Interop.dll" "%PRIMARY_PATH%\x86\" >nul 2>&1
        if exist "%PRIMARY_PATH%\x86\SQLite.Interop.dll" (
            echo   SUCCESS: x86 SQLite native library installed (from x86 source)
            set SQLITE_COPIED=1
        )
    )
    
    if exist "x64\SQLite.Interop.dll" (
        copy /Y "x64\SQLite.Interop.dll" "%PRIMARY_PATH%\x64\" >nul 2>&1
        if exist "%PRIMARY_PATH%\x64\SQLite.Interop.dll" (
            echo   SUCCESS: x64 SQLite native library installed (from x64 source)
            set SQLITE_COPIED=1
        )
    )
    
    if "!SQLITE_COPIED!"=="0" (
        echo   WARNING: SQLite.Interop.dll not found in current directory or x86/x64 subfolders
        echo   NOTE: Extension may fail to load SQLite database without native libraries
    )
)

echo.
echo ==============================
echo INSTALLATION SUMMARY
echo ==============================

rem Check if both essential files exist
if exist "%PRIMARY_PATH%\DomainReputationInspector.dll" (
    if exist "%PRIMARY_PATH%\Newtonsoft.Json.dll" (
        goto :show_success
    )
)
goto :show_error

:show_success
    echo [SUCCESS] Core extension files installed successfully
    echo.
    echo INSTALLATION LOCATION:
    echo   %PRIMARY_PATH%
    echo.
    echo INSTALLED FILES:
    echo   [OK] DomainReputationInspector.dll (main extension)
    echo   [OK] Newtonsoft.Json.dll (JSON handling)
    if exist "%PRIMARY_PATH%\System.Data.SQLite.dll" echo   [OK] System.Data.SQLite.dll (database support)
    if exist "%PRIMARY_PATH%\SQLite.Interop.dll" echo   [OK] SQLite.Interop.dll (native SQLite)
    if exist "%PRIMARY_PATH%\DomainReputationInspector.dll.config" echo   [OK] DomainReputationInspector.dll.config (configuration)
    if exist "%PRIMARY_PATH%\x86\SQLite.Interop.dll" echo   [OK] x86\SQLite.Interop.dll (32-bit native SQLite)
    if exist "%PRIMARY_PATH%\x64\SQLite.Interop.dll" echo   [OK] x64\SQLite.Interop.dll (64-bit native SQLite)
    echo.
    echo [OK] OLD INSTALLATIONS: Cleaned up from secondary locations
    echo.
    echo NEXT STEPS:
    echo   1. Start Fiddler Classic
    echo   2. Look for "Domain Reputation" tab in the Inspectors panel
    echo   3. Start browsing websites to capture domain reputation data
    echo.
    echo NOTE: Extension will work with ET Open rules without an API key.
    echo       ET Pro requires an API key for enhanced threat intelligence.
goto :end_script

:show_error
echo [ERROR] Installation incomplete - missing core DLL files
echo.
echo TROUBLESHOOTING:
echo   1. Ensure you are running this script from the folder containing:
echo      - DomainReputationInspector.dll
echo      - Newtonsoft.Json.dll
echo   2. Run this script as Administrator if you get permission errors
echo   3. Make sure Fiddler Classic is completely closed before installation
echo.
echo Current directory files:
dir /B *.dll 2>nul

:end_script

echo.
echo ==============================
echo.
pause