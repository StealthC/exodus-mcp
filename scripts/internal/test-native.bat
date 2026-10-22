@echo off
setlocal
rem Builds and runs the standalone bridge-wire unit tests with cl.exe. The
rem tested translation unit (native-plugin\BridgeWire.cpp) has no Windows SDK
rem or Exodus SDK dependency, so this only needs the VS developer environment.
rem Used locally and by the Windows CI job.

for /f %%i in ("%~dp0..\..") do set "ROOT=%%~fi\"
call "%ROOT%scripts\internal\common.bat"

if defined VSROOT goto env_ok
set "VSROOT="
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath`) do set "VSROOT=%%i"
:env_ok
if not defined VSROOT (
    echo ERROR: Visual Studio installation not found via vswhere.
    goto fail
)
if exist "%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat" goto vcvars_ok
echo ERROR: vcvarsall.bat not found under %VSROOT%.
goto fail
:vcvars_ok
call "%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 goto fail

if not exist "%ROOT%bin" mkdir "%ROOT%bin"
pushd "%ROOT%bin"
cl /nologo /EHsc /W4 /std:c++17 /I "%ROOT%native-plugin" "%ROOT%native-plugin\BridgeWire.cpp" "%ROOT%native-plugin\tests\test_bridge_wire.cpp" /Fe:test-bridge-wire.exe
if errorlevel 1 popd & goto fail
"%ROOT%bin\test-bridge-wire.exe"
set "TEST_EXIT=%ERRORLEVEL%"
del test-bridge-wire.exe >nul 2>&1
popd
exit /b %TEST_EXIT%

:fail
exit /b 1
