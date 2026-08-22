# CI Plan

`exodus-mcp` can build Exodus and produce an MCP plugin DLL on GitHub Actions:
all Exodus C/C++ third-party source is in the submodule, so the only external
requirement is a Windows Visual Studio C++ toolchain.

## Dependency update policy

Keep `origin` in the submodule as `StealthC/Exodus` and retain
`RogerSanders/Exodus` as `upstream`. Update the fork first, validate its build,
then advance the submodule pin in a separate MCP pull request. Do not copy
Exodus into this repository or use a Git subtree.

## Runner policy

Use `windows-2022` as the required baseline because it targets Visual Studio
2022 and v143, the Exodus-declared toolset. Do not make `windows-latest` the
only target: it moved to newer Visual Studio 2026 images. Add it later as an
allowed-to-fail scheduled compatibility check. See the current
[runner image inventory](https://github.com/actions/runner-images) for changes.

## Initial workflow

Create `.github/workflows/build.yml`:

```yaml
name: build

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  build-windows:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Locate MSBuild
        id: msbuild
        shell: pwsh
        run: |
          $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
          $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
          if (-not $msbuild) { throw 'MSBuild was not found on the runner.' }
          "path=$msbuild" | Out-File -FilePath $env:GITHUB_OUTPUT -Append

      - name: Build third-party libraries
        shell: pwsh
        run: |
          & '${{ steps.msbuild.outputs.path }}' "$env:GITHUB_WORKSPACE\vendor\exodus\ThirdPartyLibraries.sln" /m /t:Build /p:Configuration=Release /p:Platform=x64 /nologo /verbosity:minimal
          if ($LASTEXITCODE) { exit $LASTEXITCODE }

      - name: Build Exodus
        shell: pwsh
        run: |
          & '${{ steps.msbuild.outputs.path }}' "$env:GITHUB_WORKSPACE\vendor\exodus\Exodus.sln" /m /t:Build /p:Configuration=Release /p:Platform=x64 /nologo /verbosity:minimal
          if ($LASTEXITCODE) { exit $LASTEXITCODE }

      # Later: build native-plugin/ExodusMcpPlugin.vcxproj here.
      - uses: actions/upload-artifact@v4
        with:
          name: exodus-release-x64
          if-no-files-found: error
          path: |
            vendor/exodus/Exodus.exe
            vendor/exodus/System.dll
            vendor/exodus/Assemblies/*.dll
```

## Plugin CI evolution

The native plugin should be an independent `native-plugin/` project. It must
consume `vendor/exodus` through an explicit `ExodusRoot` MSBuild property, not
developer-specific paths. Publish a separate plugin artifact containing only
the plugin DLL, required sidecars, `build-info.json`, and install instructions.

Required checks over time: Exodus Debug/Release x64 builds, plugin compilation,
HTTP/IPC unit tests without an emulator, and a legal-ROM or open-fixture smoke
test on a Windows runner.
