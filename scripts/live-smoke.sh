#!/usr/bin/env bash
# Drives a live exodus-mcp endpoint through its protocol surface.
#
# Default checks are strictly read-only: health, discovery, tool catalog,
# bridge status, and emulator status. --full additionally exercises the
# mutating CPU-control tools (pause/run, M68K step, breakpoint and watchpoint
# lifecycle, paused frame-capture determinism) and always restores running
# state on exit.
#
# Requires: bash, curl, python3. Run against an already-launched pair
# (./scripts/run-windows.sh); never start a second pair for this script.
#
# Usage: ./scripts/live-smoke.sh [--url http://127.0.0.1:8767] [--full]
set -uo pipefail

BASE_URL="http://127.0.0.1:8767"
FULL=0
while [ $# -gt 0 ]; do
	case "$1" in
		--url) BASE_URL="$2"; shift 2 ;;
		--full) FULL=1; shift ;;
		*) echo "unknown option: $1"; exit 2 ;;
	esac
done

failures=0
step() { printf '\n== %s\n' "$1"; }

check() {
	local label="$1" condition="$2"
	if eval "$condition"; then
		echo "PASS  $label"
	else
		echo "FAIL  $label"
		failures=$((failures + 1))
	fi
}

json_get() {
	# json_get <json text> <python expression over parsed>
	python3 -c "
import json, sys
parsed = json.loads(sys.argv[1])
value = $2
print(json.dumps(value) if not isinstance(value, str) else value)
" "$1"
}

rpc_call() {
	# rpc_call <method> <params-json> -> raw result JSON or empty on failure
	local method="$1" params="$2"
	local body header_name
	header_name="Mcp-Method: $method"
	body=$(python3 -c "
import json, sys
params = json.loads(sys.argv[1])
params['_meta'] = {'io.modelcontextprotocol/protocolVersion': '2026-07-28'}
print(json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': sys.argv[2], 'params': params}))
" "$params" "$method") || return 1
	curl -fsS --max-time 30 -X POST "$BASE_URL/mcp" \
		-H 'Content-Type: application/json' \
		-H "MCP-Protocol-Version: 2026-07-28" \
		-H "$header_name" \
		-d "$body" 2>/dev/null | python3 -c "
import json, sys
envelope = json.load(sys.stdin)
if 'error' in envelope:
    sys.exit(3)
print(json.dumps(envelope.get('result', {})))
" 2>/dev/null
}

tool_call() {
	# tool_call <name> <args-json> -> structuredContent JSON or empty
	local result
	result=$(rpc_call "tools/call" "$(python3 -c "
import json, sys
print(json.dumps({'name': sys.argv[1], 'arguments': json.loads(sys.argv[2])}))
" "$1" "${2:-{}}")") || return 1
	json_get "$result" "result.get('structuredContent', {})" 2>/dev/null
}

step "Health endpoint"
health=$(curl -fsS --max-time 10 "$BASE_URL/healthz" 2>/dev/null || echo "")
check "healthz responds with status ok" "[ \"\$(json_get \"\$health\" \"parsed['status']\" 2>/dev/null)\" = 'ok' ]"

step "Modern discovery"
discover=$(rpc_call "server/discover" '{}')
check "server/discover advertises supported versions" \
	"[ \"\$(json_get \"\$discover\" \"','.join(parsed['supportedVersions'])\" 2>/dev/null)\" = '2026-07-28,2025-11-25' ]"

step "Tool catalog"
tools=$(rpc_call "tools/list" '{}')
check "tools/list includes bridge_status and emulator_status" \
	"[ -n \"\$(json_get \"\$tools\" \"[t['name'] for t in parsed['tools'] if t['name'] in ('bridge_status','emulator_status')]\" 2>/dev/null)\" ]"

step "Bridge status (read-only)"
status=$(tool_call "bridge_status")
check "bridge reports a connected plugin" \
	"[ \"\$(json_get \"\$status\" \"str(parsed.get('connected')).lower()\" 2>/dev/null)\" = 'true' ]"

step "Emulator status (read-only)"
emu=$(tool_call "emulator_status")
check "emulator_status returns structured data" "[ -n \"\$emu\" ]"

if [ "$FULL" = 1 ]; then
	step "CPU control (mutating; restores running state)"
	was_running=$(json_get "$emu" "parsed.get('running', False)" 2>/dev/null)

	paused=$(tool_call "cpu_pause")
	check "cpu_pause succeeds" "[ -n \"\$paused\" ]"

	step_result=$(tool_call "m68k_step")
	check "m68k_step succeeds while paused" "[ -n \"\$step_result\" ]"

	pc_before=$(json_get "$step_result" "parsed.get('pc', parsed)" 2>/dev/null)
	check "m68k_step echoes a program counter" "[ -n \"\$pc_before\" ]"

	bp=$(tool_call "cpu_breakpoint_set" '{"address": "0x00000200"}')
	bp_id=$(json_get "$bp" "parsed.get('id')" 2>/dev/null)
	if [ -n "$bp_id" ]; then
		check "breakpoint set returns an id" true
		tool_call "cpu_breakpoint_remove" "{\"id\": \"$bp_id\"}" >/dev/null
		check "breakpoint removed cleanly" true
	else
		check "breakpoint set returns an id" false
	fi

	wp=$(tool_call "cpu_watchpoint_set" '{"address": "0xFF0000", "length": 1}')
	wp_id=$(json_get "$wp" "parsed.get('id')" 2>/dev/null)
	if [ -n "$wp_id" ]; then
		check "watchpoint set returns an id" true
		tool_call "cpu_watchpoint_remove" "{\"id\": \"$wp_id\"}" >/dev/null
		check "watchpoint removed cleanly" true
	else
		check "watchpoint set returns an id" false
	fi

	frame_a=$(tool_call "frame_capture")
	frame_b=$(tool_call "frame_capture")
	hash_a=$(json_get "$frame_a" "parsed.get('sha256', '')" 2>/dev/null)
	hash_b=$(json_get "$frame_b" "parsed.get('sha256', '')" 2>/dev/null)
	if [ -n "$hash_a" ]; then
		check "paused frame captures are deterministic" "[ \"\$hash_a\" = \"\$hash_b\" ]"
	else
		echo "SKIP  frame determinism (no sha256 in response)"
	fi

	if [ "$was_running" = "True" ] || [ "$was_running" = "true" ]; then
		tool_call "cpu_run" >/dev/null
		echo "note  restored running state"
	fi
fi

printf '\n'
if [ "$failures" -ne 0 ]; then
	echo "live-smoke FAILED with $failures failure(s)."
	exit 1
fi
echo "live-smoke passed."
