# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial `exodus-mcp` repository structure.
- Pinned `StealthC/Exodus` as the `vendor/exodus` submodule.
- Reproducible Exodus build and CI documentation.
- Go command scaffold with a local development health endpoint and test.
- Architecture and MCP protocol compatibility plans.
- Artifact-first output policy for large emulator and analysis data.
- Phased tool roadmap and mandatory byte-order/address-space metadata policy.
- Initial `/mcp` HTTP transport shell with modern discovery, tool dispatch,
  header validation, Origin checks, and bounded legacy initialization support.
- Initial native `ExodusMcpPlugin` bridge: a persistent Exodus extension with
  an authenticated local named-pipe status endpoint and a read-only module
  snapshot.
- Windows named-pipe client for the Go server. `bridge_status` now returns the
  live native plugin status when matching pipe configuration is supplied.
- Optional Exodus launcher that generates one pipe name and capability per
  child process without logging the capability.
- Windows launcher now starts Exodus in its executable directory, preserving
  its relative settings and workspace paths.

### Changed

- Split CI ownership: `exodus-mcp` now tests the Go server only, while the
  Exodus fork owns its Windows build and binary artifacts.

### Fixed

- Removed the non-reproducible Exodus build job from the MCP CI. Its clean
  checkout did not contain the upstream-ignored third-party source trees.
- Pinned an Exodus fork revision that explicitly includes `<algorithm>` for
  `std::set_difference` under current MSVC toolchains.

### Security

- Nothing yet.

[Unreleased]: https://github.com/StealthC/exodus-mcp/compare/v0.0.0...HEAD
