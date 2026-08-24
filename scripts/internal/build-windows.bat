@echo off
setlocal
rem Builds the native bridge DLL and the Go MCP server, then installs the DLL
rem into the Exodus Plugins folder so the next launch picks it up.
rem
rem Usage: build-windows.bat [--config Debug^|Release] [--plugins <dir>]
rem
rem Configuration comes from the environment or .env (see .env.example):
rem   EXODUS_MCP_EXODUS_DIR    required unless --plugins is passed; Exodus
rem                            install root used to locate Plugins\
rem   EXODUS_MCP_PLUGINS_DIR   optional plugin destination override

for /f %%i in ("%~dp0..\..") do set "ROOT=%%~fi\"
call "%ROOT%scripts\internal\common.bat"

set "CONFIG=Release"
set "PLUGINS_DIR="
:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--config" (
    set "CONFIG=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--plugins" (
    set "PLUGINS_DIR=%~2"
    shift
    shift
    goto parse_args
)
echo ERROR: unknown argument '%~1'. Usage: build-windows.bat [--config Debug^|Release] [--plugins ^<dir^>]
goto fail
:args_done
if /i "%CONFIG%"=="Debug" goto config_ok
if /i "%CONFIG%"=="Release" goto config_ok
echo ERROR: invalid configuration '%CONFIG%'; use Debug or Release.
goto fail
:config_ok

rem Resolve and validate the plugin destination before building anything so a
rem bad .env fails fast with an actionable message.
if defined PLUGINS_DIR goto plugins_resolved
if defined EXODUS_MCP_PLUGINS_DIR set "PLUGINS_DIR=%EXODUS_MCP_PLUGINS_DIR%"
if defined PLUGINS_DIR goto plugins_resolved
if not defined EXODUS_MCP_EXODUS_DIR (
    echo ERROR: EXODUS_MCP_EXODUS_DIR is not set. Copy .env.example to .env, or pass --plugins ^<dir^>.
    goto fail
)
if exist "%EXODUS_MCP_EXODUS_DIR%\" goto dir_ok
echo ERROR: EXODUS_MCP_EXODUS_DIR points to a missing directory:
echo        %EXODUS_MCP_EXODUS_DIR%
echo        Fix .env ^(see .env.example^) or pass --plugins ^<dir^>.
goto fail
:dir_ok
set "PLUGINS_DIR=%EXODUS_MCP_EXODUS_DIR%\Plugins"
:plugins_resolved

if defined MSBUILD goto msbuild_ok
echo ERROR: MSBuild not found. Install Visual Studio with the C++ v143 toolset.
goto fail
:msbuild_ok

echo [1/3] Building ExodusMcpPlugin.dll (%CONFIG% x64)...
"%MSBUILD%" "%ROOT%native-plugin\ExodusMcpPlugin.vcxproj" -nologo -m -t:Build -p:Configuration=%CONFIG% -p:Platform=x64 -p:SolutionDir="%ROOT%vendor\exodus\\" -verbosity:minimal
if errorlevel 1 goto native_failed

echo [2/3] Installing plugin into %PLUGINS_DIR%
if not exist "%PLUGINS_DIR%" mkdir "%PLUGINS_DIR%"
copy /y "%ROOT%vendor\exodus\Assemblies\ExodusMcpPlugin.dll" "%PLUGINS_DIR%" >nul
if errorlevel 1 goto copy_failed

echo [3/3] Building bin\exodus-mcp.exe...
set "VERSION=dev"
for /f "usebackq tokens=*" %%v in (`git -C "%ROOT%." describe --tags --always 2^>nul`) do set "VERSION=%%v"
pushd "%ROOT%"
go build -ldflags "-X main.version=%VERSION%" -o bin\exodus-mcp.exe .\cmd\exodus-mcp
if errorlevel 1 popd & goto go_failed
popd

echo Done. Plugin installed and server built at bin\exodus-mcp.exe (version %VERSION%)
endlocal
exit /b 0

:native_failed
echo ERROR: native plugin %CONFIG% build failed.
if /i "%CONFIG%"=="Release" echo        A Release plugin links Release third-party libs ^(zlibx64.lib etc.^); build vendor\exodus ThirdPartyLibraries.sln and Exodus.sln in Release x64 first ^(see docs/BUILD.md^).
goto fail

:copy_failed
echo ERROR: failed to copy the plugin DLL.
goto fail

:go_failed
echo ERROR: Go build failed.
goto fail

:fail
endlocal
exit /b 1
