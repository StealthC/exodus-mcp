@echo off
setlocal
rem Builds the vendored Exodus emulator and installs the freshly generated
rem exe into the local test install configured through .env/environment, under
rem the emulator file name used there. This keeps manual fork experiments
rem pointed at the same binary the launcher starts.
rem
rem Usage: build-fork-windows.bat [--config Debug^|Release]
rem
rem Configuration comes from the environment or .env (see .env.example):
rem   EXODUS_MCP_EXODUS_DIR    required; Exodus install root used as target
rem   EXODUS_MCP_EXODUS_EXE    destination file name inside that root, or an
rem                            absolute path (default: Exodus.exe)

for /f %%i in ("%~dp0..\..") do set "ROOT=%%~fi\"
call "%ROOT%scripts\internal\common.bat"

set "CONFIG=Debug"
:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--config" (
    set "CONFIG=%~2"
    shift
    shift
    goto parse_args
)
echo ERROR: unknown argument '%~1'. Usage: build-fork-windows.bat [--config Debug^|Release]
goto fail
:args_done
if /i "%CONFIG%"=="Debug" goto config_ok
if /i "%CONFIG%"=="Release" goto config_ok
echo ERROR: invalid configuration '%CONFIG%'; use Debug or Release.
goto fail
:config_ok

if defined MSBUILD goto msbuild_ok
echo ERROR: MSBuild not found. Install Visual Studio with the C++ v143 toolset.
goto fail
:msbuild_ok

if not defined EXODUS_MCP_EXODUS_DIR (
    echo ERROR: EXODUS_MCP_EXODUS_DIR is not set. Copy .env.example to .env and adjust it.
    goto fail
)
if not exist "%EXODUS_MCP_EXODUS_DIR%\" (
    echo ERROR: EXODUS_MCP_EXODUS_DIR points to a missing directory:
    echo        %EXODUS_MCP_EXODUS_DIR%
    echo        Fix .env ^(see .env.example^).
    goto fail
)

rem Resolve the destination: an absolute EXODUS_MCP_EXODUS_EXE wins, otherwise
rem the value is a file name inside EXODUS_MCP_EXODUS_DIR; default Exodus.exe.
set "DEST_EXE="
set "EXE_IS_PATH="
if not defined EXODUS_MCP_EXODUS_EXE goto resolve_default
echo %EXODUS_MCP_EXODUS_EXE%| findstr /r "[\\:]" >nul && set "EXE_IS_PATH=1"
if defined EXE_IS_PATH (
    set "DEST_EXE=%EXODUS_MCP_EXODUS_EXE%"
    goto dest_ok
)
set "DEST_EXE=%EXODUS_MCP_EXODUS_DIR%\%EXODUS_MCP_EXODUS_EXE%"
goto dest_ok
:resolve_default
set "DEST_EXE=%EXODUS_MCP_EXODUS_DIR%\Exodus.exe"
:dest_ok

echo [1/2] Building Exodus (%CONFIG% x64)...
"%MSBUILD%" "%ROOT%vendor\exodus\Exodus.sln" -nologo -m -t:Build -p:Configuration=%CONFIG% -p:Platform=x64 -verbosity:minimal
if errorlevel 1 goto native_failed

echo [2/2] Installing generated exe into %DEST_EXE%
copy /y "%ROOT%vendor\exodus\Exodus.exe" "%DEST_EXE%" >nul
if errorlevel 1 goto copy_failed

rem The extension interface gains slots and fixes together with the device
rem DLLs; a fresh exe next to stale plugins mixes vtable layouts and marshal
rem instantiations, so the whole binary set moves as one unit.
copy /y "%ROOT%vendor\exodus\System.dll" "%EXODUS_MCP_EXODUS_DIR%\System.dll" >nul
if errorlevel 1 goto copy_failed
copy /y "%ROOT%vendor\exodus\Assemblies\*.dll" "%EXODUS_MCP_EXODUS_DIR%\Plugins\" >nul
if errorlevel 1 goto copy_failed

echo Done. Test install updated: %DEST_EXE% (%CONFIG% x64)
endlocal
exit /b 0

:native_failed
echo ERROR: Exodus build failed.
if /i "%CONFIG%"=="Release" echo        Release needs the fork's Release third-party libs; build ThirdPartyLibraries.sln in Release x64 first ^(see docs/BUILD.md^).
goto fail

:copy_failed
echo ERROR: could not replace %DEST_EXE%
echo        If the emulator is currently running, close it and run this script again.
goto fail

:fail
endlocal
exit /b 1
