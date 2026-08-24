#!/usr/bin/env bash
# Builds the Windows pair (native plugin + Go server) from WSL.
# Configuration comes from the environment or .env (see .env.example).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=lib/common.sh
source "$root/scripts/lib/common.sh"
load_dotenv "$root/.env"

export_windows_passthrough

exec cmd.exe /d /c "$(to_windows_path "$root/scripts/internal/build-windows.bat")" "$@"
