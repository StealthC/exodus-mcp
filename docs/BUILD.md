# Building Exodus from Source

This is the reproducible build procedure for the Exodus fork used by
`exodus-mcp`. It does not rely on the incomplete upstream website guide.

## Layout

Exodus is a Git submodule at `vendor/exodus/`. Paths below are relative to that
directory.

```text
ThirdPartyLibraries.sln       builds libraries required by Exodus
Exodus.sln                    builds the emulator and bundled modules
Third/                        third-party source code and generated .lib files
Assemblies/                   generated Exodus extension/module DLLs
Exodus.exe                    generated emulator executable
System.dll                    generated system module
```

## Prerequisites

Build on Windows with Visual Studio Installer components:

- **Desktop development with C++**;
- MSVC C++ x64/x86 build tools with **v143**;
- Windows 10 or Windows 11 SDK.

The validated local setup is Visual Studio 18 Community, MSVC 14.37 (`v143`),
and Windows SDK 10.0.26100. Visual Studio 2022 is also suitable if it has
v143. Do not use an LLVM configuration: Exodus references obsolete
`LLVM-vs2014` profiles.

## Included third-party libraries

All requirements are committed under `Third/`; do not download or copy any
libraries manually. Build `ThirdPartyLibraries.sln` to generate them.

| Library | Source directory | Debug x64 output |
| --- | --- | --- |
| zlib 1.2.8 | `Third/zlib/zlib-1.2.8/` | `zlibx64d.lib` |
| libjpeg 9a | `Third/libjpeg/jpeg-9a/` | `libjpegx64d.lib` |
| libtiff 4.0.9 | `Third/libtiff/tiff-4.0.9/` | `libtiffx64d.lib` |
| expat 2.1.0 | `Third/expat/expat-2.1.0/` | `libexpatwx64d.lib` |
| libpng 1.6.12 | `Third/libpng/lpng1612/` | `libpngx64d.lib` |

The wrapper solution places outputs at the paths resolved by
`Build/MSBuild/Exodus.Third.Paths.targets`; no local include/library paths are
required.

## Build in Visual Studio

1. Open `ThirdPartyLibraries.sln`; build `Debug | x64` (or `Release | x64`).
2. Open `Exodus.sln`; build the **same** configuration and platform.
3. Run `Exodus.exe` from the Exodus source root, with that root as the working
   directory, so it can load `System.dll`, `Assemblies/`, `Data/`, and settings.

Start with `Debug | x64`. Use `Release | x64` after debug succeeds. Use
`Win32` only when a 32-bit binary is required.

## WSL driving Windows MSBuild

```bash
MSBUILD='/mnt/c/Program Files/Microsoft Visual Studio/18/Community/MSBuild/Current/Bin/MSBuild.exe'
cd /mnt/f/projects/kid/emulators/Exodus/vendor/exodus
"$MSBUILD" ThirdPartyLibraries.sln /m /t:Build /p:Configuration=Debug /p:Platform=x64 /nologo /verbosity:minimal
"$MSBUILD" Exodus.sln /m /t:Build /p:Configuration=Debug /p:Platform=x64 /nologo /verbosity:minimal
```

The first command generates third-party `.lib` files. The second generates
`Exodus.exe`, `System.dll`, module DLLs in `Assemblies/`, and `x64/`
intermediates.

## Known-good result and troubleshooting

Commit `08f388f77040af28d16d44fdfbddb73252953161` built as `Debug | x64` on
2026-08-22. Legacy expat, libjpeg, and libtiff warnings were non-fatal.

- Missing `v143`: add MSVC v143 x64/x86 build tools in Visual Studio Installer.
- Missing third-party headers/libraries: build `ThirdPartyLibraries.sln` first,
  with exactly the configuration and platform used by `Exodus.sln`.
- Missing `LLVM-vs2014`: select normal `Debug` or `Release`, not `* - LLVM`.
- Module load errors: launch from the Exodus source root and rebuild `System.dll`
  and `Assemblies/` together.
