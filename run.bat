@echo off
setlocal
rem Launches exodus-mcp together with Exodus. The launcher generates a fresh
rem authenticated pipe and capability for each child process.
rem Exodus install: EXODUS_MCP_EXODUS_DIR env wins; otherwise the hardcoded
rem nightly location below is used.

set "ROOT=%~dp0"
set "EXODUS_DIR=%EXODUS_MCP_EXODUS_DIR%"
if "%EXODUS_DIR%"=="" set "EXODUS_DIR=F:\projects\kid\emulators\Exodus_2.1"
set "EXODUS_EXE=%EXODUS_DIR%\Exodus.nightly.exe"

if not exist "%ROOT%bin\exodus-mcp.exe" echo ERROR: bin\exodus-mcp.exe not found. Run build.bat first. & exit /b 1

rem No arguments: launch the resolved nightly. Otherwise forward everything
rem (e.g. run.bat --exodus "D:\other\Exodus.exe" --listen 127.0.0.1:9000).
if not "%~1"=="" goto forward
"%ROOT%bin\exodus-mcp.exe" --exodus "%EXODUS_EXE%"
goto done

:forward
"%ROOT%bin\exodus-mcp.exe" %*

:done
endlocal
