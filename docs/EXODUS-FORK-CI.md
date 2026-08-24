# Exodus Fork CI and Third-Party Sources

This document defines the `StealthC/Exodus` fork policy. It makes the emulator
build repeatable without adding MCP product code to the upstream repository.

## Why the bootstrap is required

The upstream Git repository contains the Visual Studio projects under `Third/`
but ignores their dependency source directories. The projects require these
exact directory names:

| Dependency | Required directory |
| --- | --- |
| zlib 1.2.8 | `Third/zlib/zlib-1.2.8/` |
| libjpeg 9a | `Third/libjpeg/jpeg-9a/` |
| libpng 1.6.12 | `Third/libpng/lpng1612/` |
| libtiff 4.0.9 | `Third/libtiff/tiff-4.0.9/` |
| expat 2.1.0 | `Third/expat/expat-2.1.0/` |

Those paths come from `Build/MSBuild/Exodus.Third.Paths.targets`. Catch and
HTML Help are not required for a Release x64 emulator build.

## Recommended distribution model

Version the exact source trees in the fork itself. The upstream `.gitignore`
excludes `Third/`, so use `git add -f` once for the five required source
directories and each dependency's licence files. This is the least surprising
and most reproducible choice: a normal checkout of `StealthC/Exodus` contains
everything needed by its CI.

The source dependencies have permissive but different licenses. Preserve their
license, copyright notices, original URL, downloaded-file hash, extraction
date, and any local configuration changes in a fork-only provenance document.
The `Third/` commit remains separate from functional Exodus changes, and an
upstream merge will not conflict merely because upstream ignores those paths.

An external release package or companion repository is an acceptable later
optimization if repository size becomes a problem. It must be versioned,
SHA-256 verified, and retain the same provenance; do not use an Actions cache
as a build-input registry.

## First-time import into the fork

From a clean local checkout of `StealthC/Exodus`, download the versions named
above, extract them into their exact required directories, retain their license
files, and verify the layout. Then create a standalone fork-only commit:

```powershell
git add -f `
  Third/zlib/zlib-1.2.8 `
  Third/libjpeg/jpeg-9a `
  Third/libpng/lpng1612 `
  Third/libtiff/tiff-4.0.9 `
  Third/expat/expat-2.1.0
git commit -m "build: vendor Exodus third-party source dependencies"
```

Before committing, add `Third/THIRD_PARTY_PROVENANCE.md` with the original
download URL and SHA-256 for every archive. Do not include `Third/catch` or
HTML Help unless tests or documentation builds specifically need them.

## Workflow for `StealthC/Exodus`

Create `.github/workflows/build.yml` in the fork:

```yaml
name: Build Exodus

on:
  pull_request:
  push:
    branches: [master]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  release-x64:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v5

      - name: Verify third-party source layout
        shell: pwsh
        run: |
          if (-not (Test-Path 'Third\zlib\zlib-1.2.8\adler32.c')) { throw 'Missing vendored third-party sources.' }

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
          & '${{ steps.msbuild.outputs.path }}' ThirdPartyLibraries.sln /m /t:Build /p:Configuration=Release /p:Platform=x64 /nologo /verbosity:minimal
          if ($LASTEXITCODE) { exit $LASTEXITCODE }

      - name: Build Exodus
        shell: pwsh
        run: |
          & '${{ steps.msbuild.outputs.path }}' Exodus.sln /m /t:Build /p:Configuration=Release /p:Platform=x64 /nologo /verbosity:minimal
          if ($LASTEXITCODE) { exit $LASTEXITCODE }

      - name: Assemble release layout
        shell: pwsh
        run: |
          $root = $env:GITHUB_WORKSPACE
          $stage = "$root\dist\Exodus"
          foreach ($d in 'Plugins','Modules','Workspaces','Captures','PersistentState','Savestates') {
            $null = New-Item -ItemType Directory -Force "$stage\$d"
          }
          Copy-Item "$root\Exodus.exe", "$root\System.dll", "$root\License.txt", "$root\ReleaseNotes.txt" $stage
          Copy-Item "$root\Packaging\ReleaseSettings.xml" "$stage\settings.xml"
          Copy-Item "$root\Assemblies\*.dll" "$stage\Plugins\"
          Copy-Item "$root\Data\Modules\*.xml" "$stage\Modules\"
          Copy-Item "$root\Data\Workspaces\*.xml" "$stage\Workspaces\"

      - uses: actions/upload-artifact@v6
        with:
          name: exodus-release-x64
          if-no-files-found: error
          path: dist/Exodus
```

The artifact replicates the original Exodus 2.1 distribution package: the
device/extension DLLs are assembled into `Plugins\` (never `Assemblies\`),
`settings.xml` is the release-mode file from `Packaging/ReleaseSettings.xml`
(root-relative `Modules`, `Workspaces`, `Savestates`, `PersistentState`,
`Captures`, and `AssembliesPath=Plugins`), and the default module and
workspace XMLs come from `Data\Modules` and `Data\Workspaces`. GitHub zips
`dist\Exodus` into a single downloadable artifact, so no separate archive is
produced.

`actions/checkout` and `actions/upload-artifact` are pinned at v5/v6
respectively, which run on the Node 24 runtime and avoid the Node 20
deprecation warning shown by the v4 actions.

Run it manually first and inspect the artifact before adding release publishing
for signed tags.
