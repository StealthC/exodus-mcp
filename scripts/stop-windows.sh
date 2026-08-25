#!/usr/bin/env bash
# Stops the running Exodus/MCP pair gracefully.
#
# Exodus persists its configuration only on a clean shutdown (WM_CLOSE runs
# DestroySystemInterfaceThread, which writes settings.xml): a forced kill
# (taskkill /F) loses any in-session changes. This script therefore asks the
# emulator to close first — taskkill without /F posts WM_CLOSE to GUI windows
# — waits a grace period, and only then force-kills whatever remains. The MCP
# server exits on its own when its Exodus child terminates.
#
# Usage: ./scripts/stop-windows.sh [--grace-seconds N]
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=lib/common.sh
source "$root/scripts/lib/common.sh"
load_dotenv "$root/.env"

grace_seconds=10
while [ $# -gt 0 ]; do
	case "$1" in
		--grace-seconds) grace_seconds="$2"; shift 2 ;;
		*) echo "unknown option: $1"; exit 2 ;;
	esac
done

exodus_exe="${EXODUS_MCP_EXODUS_EXE:-Exodus.exe}"
server_exe="exodus-mcp.exe"

# Resolve the image name used by tasklist/taskkill: a bare file name works for
# both forms; an absolute path is normalized to its base name.
base_name=$(basename "$exodus_exe")

if ! tasklist.exe /FI "IMAGENAME eq $base_name" 2>/dev/null | grep -qiF "$base_name"; then
	echo "Exodus ($base_name) is not running; nothing to stop."
	exit 0
fi

echo "Requesting a graceful Exodus shutdown (WM_CLOSE, $grace_seconds s grace)..."
taskkill.exe /IM "$base_name" >/dev/null 2>&1 || true

for _ in $(seq 1 "$grace_seconds"); do
	if ! tasklist.exe /FI "IMAGENAME eq $base_name" 2>/dev/null | grep -qiF "$base_name"; then
		echo "Exodus exited cleanly; configuration was saved."
		exit 0
	fi
	sleep 1
done

echo "Grace period elapsed; force-killing Exodus and the MCP server."
taskkill.exe /F /IM "$base_name" >/dev/null 2>&1 || true
taskkill.exe /F /IM "$server_exe" >/dev/null 2>&1 || true
exit 0