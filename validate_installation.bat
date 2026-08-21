@echo off
setlocal enabledelayedexpansion

echo.
echo ==============================================
echo  VALIDATE DOMAIN REPUTATION INSPECTOR INSTALLATION
echo ==============================================
echo.

rem Define locations to check
set "PRIMARY_PATH=%USERPROFILE%\Documents\Fiddler2\Scripts"
set "SECONDARY_PATH=%LOCALAPPDATA%\Programs\Fiddler\Scripts"
set "APPDATA_PATH=%APPDATA%\Fiddler2\Scripts"

echo Checking installation locations...
echo.

rem Check primary location (should contain files)
echo PRIMARY LOCATION (should contain extension):
echo   %PRIMARY_PATH%
if exist "%PRIMARY_PATH%" (
    echo   [OK] Directory exists
    if exist "%PRIMARY_PATH%\DomainReputationInspector.dll" (
        echo   [OK] DomainReputationInspector.dll found
        for %%f in ("%PRIMARY_PATH%\DomainReputationInspector.dll") do echo     Size: %%~zf bytes, Modified: %%~tf
    ) else (
        echo   [MISSING] DomainReputationInspector.dll MISSING
    )
    
    if exist "%PRIMARY_PATH%\Newtonsoft.Json.dll" (
        echo   [OK] Newtonsoft.Json.dll found
    ) else (
        echo   [MISSING] Newtonsoft.Json.dll MISSING
    )
    
    if exist "%PRIMARY_PATH%\System.Data.SQLite.dll" (
        echo   [OK] System.Data.SQLite.dll found
    ) else (
        echo   [WARNING] System.Data.SQLite.dll missing (may cause issues)
    )
    
    if exist "%PRIMARY_PATH%\SQLite.Interop.dll" (
        echo   [OK] SQLite.Interop.dll found
    ) else (
        echo   [WARNING] SQLite.Interop.dll missing (may cause issues)
    )
    
    if exist "%PRIMARY_PATH%\x86\SQLite.Interop.dll" echo   [OK] x86\SQLite.Interop.dll found
    if exist "%PRIMARY_PATH%\x64\SQLite.Interop.dll" echo   [OK] x64\SQLite.Interop.dll found
) else (
    echo   [ERROR] Directory does not exist
)

echo.
echo SECONDARY LOCATION (should be empty):
echo   %SECONDARY_PATH%
if exist "%SECONDARY_PATH%" (
    echo   [OK] Directory exists
    if exist "%SECONDARY_PATH%\DomainReputationInspector.dll" (
        echo   [WARNING] WARNING: Old DomainReputationInspector.dll found (should be cleaned up)
        for %%f in ("%SECONDARY_PATH%\DomainReputationInspector.dll") do echo     Size: %%~zf bytes, Modified: %%~tf
    ) else (
        echo   [OK] No extension files found (good - cleaned up)
    )
) else (
    echo   [OK] Directory does not exist (good)
)

echo.
echo APPDATA LOCATION (should be empty):
echo   %APPDATA_PATH%
if exist "%APPDATA_PATH%" (
    echo   [OK] Directory exists
    if exist "%APPDATA_PATH%\DomainReputationInspector.dll" (
        echo   [WARNING] WARNING: Old DomainReputationInspector.dll found (should be cleaned up)
        for %%f in ("%APPDATA_PATH%\DomainReputationInspector.dll") do echo     Size: %%~zf bytes, Modified: %%~tf
    ) else (
        echo   [OK] No extension files found (good - cleaned up)
    )
) else (
    echo   [OK] Directory does not exist (good)
)

echo.
echo ==============================================
echo FIDDLER PROCESS CHECK
echo ==============================================
tasklist /FI "IMAGENAME eq Fiddler.exe" 2>nul | find /I "Fiddler.exe" >nul
if %ERRORLEVEL% EQU 0 (
    echo [WARNING] WARNING: Fiddler is currently running
    echo   Stop Fiddler and restart it to load the extension
) else (
    echo [OK] Fiddler is not running (good for loading new extension)
)

echo.
echo ==============================================
echo DATABASE LOCATION CHECK
echo ==============================================
set "DB_PATH=%APPDATA%\DomainReputationInspector"
echo Extension database location:
echo   %DB_PATH%
if exist "%DB_PATH%" (
    echo   [OK] Database directory exists
    if exist "%DB_PATH%\et_rules.db" (
        echo   [OK] ET Rules database found
        for %%f in ("%DB_PATH%\et_rules.db") do echo     Size: %%~zf bytes, Modified: %%~tf
    ) else (
        echo   [OK] No database yet (will be created on first run)
    )
    if exist "%DB_PATH%\settings.json" (
        echo   [OK] Settings file found
    ) else (
        echo   [OK] No settings yet (will be created on first run)
    )
) else (
    echo   [OK] Database directory doesn't exist yet (will be created on first run)
)

echo.
echo ==============================================
echo INSTALLATION VALIDATION SUMMARY
echo ==============================================

rem Check if installation is valid
set INSTALL_VALID=1
if not exist "%PRIMARY_PATH%\DomainReputationInspector.dll" set INSTALL_VALID=0
if not exist "%PRIMARY_PATH%\Newtonsoft.Json.dll" set INSTALL_VALID=0

if %INSTALL_VALID% EQU 1 (
    echo [SUCCESS] INSTALLATION STATUS: VALID
    echo   Core extension files are in the correct location
    echo   Ready to use with Fiddler Classic
    echo.
    echo NEXT STEPS:
    echo   1. Start Fiddler Classic
    echo   2. Look for "Domain Reputation" tab
    echo   3. Check Fiddler's Log tab for extension loading messages
    echo   4. If no tab appears, check Fiddler Rules → Customize Rules
    echo.
    echo TROUBLESHOOTING:
    echo   - If extension doesn't load, check Fiddler Log for error messages
    echo   - Ensure .NET Framework 4.6.1 or later is installed
) else (
    echo [FAILED] INSTALLATION STATUS: INVALID
    echo   Missing required files in primary location
    echo   Run install.bat from the correct directory
)

echo.
pause
