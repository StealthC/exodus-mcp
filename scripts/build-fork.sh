#!/usr/bin/env bash
# Builds the vendored Exodus emulator and installs the generated exe into the
# local test install (EXODUS_MCP_EXODUS_DIR), under the emulator file name
# from EXODUS_MCP_EXODUS_EXE. Configuration comes from the environment or
# .env (see .env.example).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=lib/common.sh
source "$root/scripts/lib/common.sh"
load_dotenv "$root/.env"
export_windows_passthrough

exec cmd.exe /d /c "$(to_windows_path "$root/scripts/internal/build-fork-windows.bat")" "$@"
