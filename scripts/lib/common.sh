#!/usr/bin/env bash
# Shared helpers for the WSL wrapper scripts in scripts/.

# load_dotenv exports KEY=VALUE lines from the given file. Real environment
# variables win over .env values, matching the precedence used everywhere:
# flag > environment > .env > built-in default. Blank lines, '#'-comment
# lines, and CRLF endings are tolerated.
load_dotenv() {
	local file="$1"
	[ -f "$file" ] || return 0
	local line key value
	while IFS= read -r line || [ -n "$line" ]; do
		line="${line%$'\r'}"
		case "$line" in
			'' | '#'*) continue ;;
		esac
		key="${line%%=*}"
		value="${line#*=}"
		case "$key" in
			'' | *[!A-Za-z0-9_]*) continue ;;
		esac
		if [ -z "${!key+x}" ]; then
			export "$key=$value"
		fi
	done <"$file"
}

# to_windows_path converts a POSIX path into one cmd.exe accepts.
to_windows_path() {
	wslpath -w "$1"
}

# export_windows_passthrough publishes the canonical EXODUS_MCP_* variables
# to Windows child processes. WSL drops environment variables at the Windows
# boundary unless they are named in WSLENV, so wrappers must call this right
# before invoking cmd.exe.
export_windows_passthrough() {
	local passthrough=(
		EXODUS_MCP_EXODUS_DIR
		EXODUS_MCP_EXODUS_EXE
		EXODUS_MCP_PLUGINS_DIR
		EXODUS_MCP_LISTEN
		EXODUS_MCP_ARTIFACTS
		EXODUS_MCP_STATES_DIR
		EXODUS_MCP_SCRIPTS_DIR
		EXODUS_MCP_PYTHON
		EXODUS_MCP_PIPE_NAME
		EXODUS_MCP_CAPABILITY
	)
	local name names=()
	for name in "${passthrough[@]}"; do
		[ -n "${!name+x}" ] && names+=("$name")
	done
	if [ "${#names[@]}" -gt 0 ]; then
		export WSLENV="${WSLENV:+$WSLENV:}$(IFS=:; echo "${names[*]}")"
	fi
}
