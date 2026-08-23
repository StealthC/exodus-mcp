@echo off
setlocal
rem Builds the native bridge DLL and the Go MCP server, then installs the DLL
rem into the Exodus Plugins folder so the next launch picks it up.
rem Exodus install: EXODUS_MCP_EXODUS_DIR env wins; otherwise the hardcoded
rem nightly location below is used. An explicit argument overrides the Plugins
rem destination.

set "ROOT=%~dp0"
set "EXODUS_DIR=%EXODUS_MCP_EXODUS_DIR%"
if "%EXODUS_DIR%"=="" set "EXODUS_DIR=F:\projects\kid\emulators\Exodus_2.1"
set "PLUGINS_DIR=%EXODUS_DIR%\Plugins"
if not "%~1"=="" set "PLUGINS_DIR=%~1"

set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
if exist "%MSBUILD%" goto build_plugin
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "MSBUILD=%%i"
:build_plugin
if not exist "%MSBUILD%" echo ERROR: MSBuild not found. Install Visual Studio with the C++ v143 toolset. & exit /b 1

echo [1/3] Building ExodusMcpPlugin.dll (Debug x64)...
"%MSBUILD%" "%ROOT%native-plugin\ExodusMcpPlugin.vcxproj" -nologo -m -t:Build -p:Configuration=Debug -p:Platform=x64 -p:SolutionDir="%ROOT%vendor\exodus\\" -verbosity:minimal
if errorlevel 1 goto native_failed

echo [2/3] Installing plugin into %PLUGINS_DIR%
if not exist "%PLUGINS_DIR%" mkdir "%PLUGINS_DIR%"
copy /y "%ROOT%vendor\exodus\Assemblies\ExodusMcpPlugin.dll" "%PLUGINS_DIR%" >nul
if errorlevel 1 goto copy_failed

echo [3/3] Building bin\exodus-mcp.exe...
pushd "%ROOT%"
go build -o bin\exodus-mcp.exe .\cmd\exodus-mcp
if errorlevel 1 popd & goto go_failed
popd

echo Done. Plugin installed and server built at bin\exodus-mcp.exe
exit /b 0

:native_failed
echo ERROR: native plugin build failed.
exit /b 1

:copy_failed
echo ERROR: failed to copy the plugin DLL.
exit /b 1

:go_failed
echo ERROR: Go build failed.
exit /b 1
