@echo off
setlocal

echo.
echo ==========================================
echo  DOMAIN REPUTATION INSPECTOR
echo ==========================================
echo.

set "NUGET=%~dp0nuget.exe"
if not exist "%NUGET%" set "NUGET=nuget"

echo Restoring NuGet packages...
"%NUGET%" install Newtonsoft.Json -Version 13.0.3 -OutputDirectory packages -NonInteractive
if errorlevel 1 goto :nugetfail
"%NUGET%" install System.Data.SQLite -Version 1.0.119 -OutputDirectory packages -NonInteractive
if errorlevel 1 goto :nugetfail
"%NUGET%" install System.Data.SQLite.Core -Version 1.0.119 -OutputDirectory packages -NonInteractive
if errorlevel 1 goto :nugetfail
"%NUGET%" install Stub.System.Data.SQLite.Core.NetFramework -Version 1.0.119 -OutputDirectory packages -NonInteractive
if errorlevel 1 goto :nugetfail

set "SQLITE_DIR="
if exist "packages\Stub.System.Data.SQLite.Core.NetFramework.1.0.119.0\lib\net46\System.Data.SQLite.dll" set "SQLITE_DIR=packages\Stub.System.Data.SQLite.Core.NetFramework.1.0.119.0"
if not defined SQLITE_DIR if exist "packages\Stub.System.Data.SQLite.Core.NetFramework.1.0.119\lib\net46\System.Data.SQLite.dll" set "SQLITE_DIR=packages\Stub.System.Data.SQLite.Core.NetFramework.1.0.119"

if not exist "packages\Newtonsoft.Json.13.0.3\lib\net45\Newtonsoft.Json.dll" (
    echo Missing Newtonsoft.Json.dll
    goto :nugetfail
)
if not defined SQLITE_DIR (
    echo Missing System.Data.SQLite.dll under packages\Stub.System.Data.SQLite.Core.NetFramework.*
    goto :nugetfail
)

if not exist "bin\PUBLIC" mkdir "bin\PUBLIC"

echo Compiling extension...
msbuild DomainReputationInspector.csproj /p:Configuration=Release /p:Platform=AnyCPU /verbosity:minimal
if errorlevel 1 goto :buildfail

echo.
echo BUILD SUCCESSFUL
echo.

echo Copying files to bin\PUBLIC...
copy "bin\Release\DomainReputationInspector.dll" "bin\PUBLIC\" > nul
if exist "bin\Release\DomainReputationInspector.dll.config" copy "bin\Release\DomainReputationInspector.dll.config" "bin\PUBLIC\" > nul
if exist "bin\Release\DomainReputationInspector.pdb" copy "bin\Release\DomainReputationInspector.pdb" "bin\PUBLIC\" > nul
copy "bin\Release\Newtonsoft.Json.dll" "bin\PUBLIC\" > nul
copy "bin\Release\System.Data.SQLite.dll" "bin\PUBLIC\" > nul

if not exist "bin\PUBLIC\x86" mkdir "bin\PUBLIC\x86"
if not exist "bin\PUBLIC\x64" mkdir "bin\PUBLIC\x64"
if exist "%SQLITE_DIR%\build\net46\x86\SQLite.Interop.dll" copy "%SQLITE_DIR%\build\net46\x86\SQLite.Interop.dll" "bin\PUBLIC\x86\" > nul
if exist "%SQLITE_DIR%\build\net46\x64\SQLite.Interop.dll" copy "%SQLITE_DIR%\build\net46\x64\SQLite.Interop.dll" "bin\PUBLIC\x64\" > nul

echo.
echo Files are in bin\PUBLIC\
echo Close Fiddler, copy that folder into the Fiddler Inspectors folder, then restart.
echo.
pause
exit /b 0

:nugetfail
echo.
echo NUGET RESTORE FAILED
echo Place nuget.exe in this folder or on PATH and retry.
pause
exit /b 1

:buildfail
echo.
echo BUILD FAILED
echo.
echo Troubleshooting:
echo    1. Install Visual Studio Build Tools
echo    2. Confirm .NET Framework 4.6.1 is installed
echo    3. Confirm Fiddler Classic is installed so Fiddler.exe can be referenced
echo    4. Confirm %SQLITE_DIR%\lib\net46\System.Data.SQLite.dll exists
echo.
pause
exit /b 1
