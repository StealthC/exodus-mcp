#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
root_windows=$(wslpath -w "$root")

exec cmd.exe /d /c "$root_windows\\run.bat" "$@"
