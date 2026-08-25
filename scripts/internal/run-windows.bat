@echo off
setlocal
rem Launches exodus-mcp together with Exodus. The launcher generates a fresh
rem authenticated pipe and capability for each child process.
rem
rem Extra arguments are forwarded to exodus-mcp.exe, for example:
rem   run-windows.bat --listen 127.0.0.1:9000
rem
rem Configuration comes from the environment or .env (see .env.example):
rem   EXODUS_MCP_EXODUS_DIR     Exodus install root
rem   EXODUS_MCP_EXODUS_EXE     executable file name inside that root, or an
rem                             absolute path (default: Exodus.exe)

for /f %%i in ("%~dp0..\..") do set "ROOT=%%~fi\"
call "%ROOT%scripts\internal\common.bat"

rem Experiment scripts and fixtures live in the repo by default so the
rem launcher ships a usable allowlisted set; override with --scripts or
rem EXODUS_MCP_SCRIPTS_DIR (flag > environment > .env > default).
if not defined EXODUS_MCP_SCRIPTS_DIR set "EXODUS_MCP_SCRIPTS_DIR=%ROOT%scripts\experiments"

if not exist "%ROOT%bin\exodus-mcp.exe" (
    echo ERROR: bin\exodus-mcp.exe not found. Run scripts\build-windows.sh first.
    exit /b 1
)

set "EXODUS_EXE="
if defined EXODUS_MCP_EXODUS_EXE (
    if exist "%EXODUS_MCP_EXODUS_EXE%" (
        set "EXODUS_EXE=%EXODUS_MCP_EXODUS_EXE%"
    ) else if defined EXODUS_MCP_EXODUS_DIR (
        set "EXODUS_EXE=%EXODUS_MCP_EXODUS_DIR%\%EXODUS_MCP_EXODUS_EXE%"
    ) else (
        set "EXODUS_EXE=%EXODUS_MCP_EXODUS_EXE%"
    )
) else if defined EXODUS_MCP_EXODUS_DIR (
    set "EXODUS_EXE=%EXODUS_MCP_EXODUS_DIR%\Exodus.exe"
)
if not defined EXODUS_EXE (
    echo ERROR: EXODUS_MCP_EXODUS_DIR is not set. Copy .env.example to .env and adjust it.
    exit /b 1
)
if not exist "%EXODUS_EXE%" (
    echo ERROR: Exodus executable not found: %EXODUS_EXE%
    echo        Check EXODUS_MCP_EXODUS_DIR and EXODUS_MCP_EXODUS_EXE in .env.
    exit /b 1
)

"%ROOT%bin\exodus-mcp.exe" --exodus "%EXODUS_EXE%" %*
endlocal
