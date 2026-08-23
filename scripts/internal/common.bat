@echo off
rem Shared initialization for the exodus-mcp Windows batch entry points.
rem Batch callers set ROOT to the repository root (with a trailing backslash)
rem and then `call` this file once. Both steps are idempotent:
rem
rem   1. Import KEY=VALUE lines from %ROOT%.env without overriding variables
rem      already present in the environment, matching the shared precedence:
rem      flag ^> environment ^> .env ^> built-in default. '#' comments, rem
rem      lines, blank lines, and CRLF endings are tolerated.
rem   2. Resolve MSBUILD from Visual Studio 18 Community or vswhen where
rem      unavailable.

if not defined ROOT (
    echo ERROR: ROOT is not set; scripts must initialize it before calling common.bat.
    exit /b 1
)

if exist "%ROOT%.env" (
    for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%ROOT%.env") do (
        if /i not "%%a"=="rem" if not "%%a"=="" if not defined %%a set "%%a=%%b"
    )
)

if defined MSBUILD exit /b 0
set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
if exist "%MSBUILD%" exit /b 0
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "MSBUILD=%%i"
exit /b 0
