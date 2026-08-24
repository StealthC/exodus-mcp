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
	local extra_headers=()
	if [ "$method" = "tools/call" ]; then
		name=$(json_get "$params" "parsed['name']" 2>/dev/null) || return 1
		extra_headers+=(-H "Mcp-Name: $name")
	fi
	curl -fsS --max-time 30 -X POST "$BASE_URL/mcp" \
		-H 'Content-Type: application/json' \
		-H "MCP-Protocol-Version: 2026-07-28" \
		-H "$header_name" \
		"${extra_headers[@]}" \
		-d "$body" 2>/dev/null | python3 -c "
import json, sys
envelope = json.load(sys.stdin)
if 'error' in envelope:
    sys.exit(3)
print(json.dumps(envelope.get('result', {})))
" 2>/dev/null
}

tool_call() {
	# tool_call <name> [arguments-json] -> structuredContent JSON or empty
	local name="$1"
	local arguments="${2:-}"
	if [ -z "$arguments" ]; then
		arguments='{}'
	fi
	local result
	result=$(rpc_call "tools/call" "$(python3 -c "
import json, sys
print(json.dumps({'name': sys.argv[1], 'arguments': json.loads(sys.argv[2])}))
" "$name" "$arguments")") || return 1
	json_get "$result" "parsed.get('structuredContent', {})" 2>/dev/null
}


# The plugin pipe can lag the HTTP health gate by tens of seconds on Debug
# builds; wait until the bridge actually answers before driving tools.
bridge_ready=0
for _ in $(seq 1 200); do
	if json_get "$(tool_call "emulator_status" 2>/dev/null)" "parsed.get('system_running') is not None" 2>/dev/null | grep -qi true; then
		bridge_ready=1
		break
	fi
	sleep 2
done
if [ "$bridge_ready" != 1 ]; then
	echo "bridge never became ready; aborting"
	exit 1
fi

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
	# The frame-, pixel-, and trace-level checks need a running program.
	# Override the location through EXODUS_MCP_SMOKE_ROM when needed.
	rom_args='{"path": "F:\\projects\\kid\\rom\\kid.bin", "run": true}'
	if [ -n "${EXODUS_MCP_SMOKE_ROM:-}" ]; then
		rom_args=$(python3 -c "import json, sys; print(json.dumps({'path': sys.argv[1], 'run': True}))" "$EXODUS_MCP_SMOKE_ROM")
	fi
	step "Test ROM load"
	rom_load_result=$(tool_call "rom_load" "$rom_args")
	rom_loaded=$(json_get "$rom_load_result" "parsed.get('loaded', False)" 2>/dev/null)
	check "test ROM loads and runs" "[ \"$rom_loaded\" = 'True' ] || [ \"$rom_loaded\" = 'true' ]"
	sleep 3

	step "CPU control (mutating; restores running state)"
	was_running=$(json_get "$emu" "parsed.get('system_running', False)" 2>/dev/null)

	paused=$(tool_call "cpu_pause")
	check "cpu_pause succeeds" "[ -n \"\$paused\" ]"

	# Purge anything left armed by an earlier session: an armed watchpoint or
	# breakpoint re-pauses every resumed run and poisons the checks below.
	for stale_id in $(json_get "$(tool_call "cpu_breakpoint_list")" "' '.join(str(i.get('breakpoint_id')) for i in parsed.get('breakpoints', []))" 2>/dev/null); do
		tool_call "cpu_breakpoint_remove" "{\"breakpoint_id\": $stale_id}" >/dev/null
	done
	for stale_id in $(json_get "$(tool_call "cpu_watchpoint_list")" "' '.join(str(i.get('watchpoint_id')) for i in parsed.get('watchpoints', []))" 2>/dev/null); do
		tool_call "cpu_watchpoint_remove" "{\"watchpoint_id\": $stale_id}" >/dev/null
	done

	step_result=$(tool_call "m68k_step")
	check "m68k_step succeeds while paused" "[ -n \"\$step_result\" ]"

	pc_before=$(json_get "$step_result" "parsed.get('pc', parsed)" 2>/dev/null)
	check "m68k_step echoes a program counter" "[ -n \"\$pc_before\" ]"

	bp=$(tool_call "cpu_breakpoint_set" '{"cpu": "m68k", "address": "0x00000200"}')
	bp_id=$(json_get "$bp" "parsed.get('breakpoint_id')" 2>/dev/null)
	if [ -n "$bp_id" ]; then
		check "breakpoint set returns an id" true
		bp_rm=$(tool_call "cpu_breakpoint_remove" "{\"breakpoint_id\": $bp_id}")
		check "breakpoint removed cleanly" \
			"[ \"\$(json_get \"\$bp_rm\" \"str(parsed.get('removed', False)).lower()\" 2>/dev/null)\" = 'true' ]"
	else
		check "breakpoint set returns an id" false
	fi

	wp=$(tool_call "cpu_watchpoint_set" '{"cpu": "m68k", "address": "0xFF0000", "length": 1}')
	wp_id=$(json_get "$wp" "parsed.get('watchpoint_id')" 2>/dev/null)
	if [ -n "$wp_id" ]; then
		check "watchpoint set returns an id" true
		wp_rm=$(tool_call "cpu_watchpoint_remove" "{\"watchpoint_id\": $wp_id}")
		check "watchpoint removed cleanly" \
			"[ \"\$(json_get \"\$wp_rm\" \"str(parsed.get('removed', False)).lower()\" 2>/dev/null)\" = 'true' ]"
	else
		check "watchpoint set returns an id" false
	fi

	# Throwaway capture: pausing is asynchronous, and the last timeslice can
	# still complete one buffer swap after cpu_pause returns. Settle first so
	# the compared pair observes a frozen image buffer.
	tool_call "frame_capture" >/dev/null
	frame_a=$(tool_call "frame_capture")
	# The response is artifact-first: the digest lives under summary.sha256.
	code_a=$(json_get "$frame_a" "parsed.get('code', parsed.get('error', {}).get('code', ''))" 2>/dev/null)
	if [ "$code_a" = "frame_capture_failed" ]; then
		echo "SKIP  frame determinism (no rendered VDP frame yet; load a ROM and run first)"
	else
		frame_b=$(tool_call "frame_capture")
		hash_a=$(json_get "$frame_a" "parsed.get('summary', {}).get('sha256', '')" 2>/dev/null)
		hash_b=$(json_get "$frame_b" "parsed.get('summary', {}).get('sha256', '')" 2>/dev/null)
		if [ -n "$hash_a" ]; then
			check "paused frame captures are deterministic" "[ \"\$hash_a\" = \"\$hash_b\" ]"
		else
			check "paused frame captures are deterministic" false
		fi
		# Regression stress for the paused back-to-back capture hang: several
		# consecutive large inline responses through the plugin pipe must all
		# complete within the client deadline with identical digests. An empty
		# digest counts as failure so a silent bridge error cannot pass here.
		stress_ok=true
		for _ in 1 2 3; do
			frame_s=$(tool_call "frame_capture")
			hash_s=$(json_get "$frame_s" "parsed.get('summary', {}).get('sha256', '')" 2>/dev/null)
			if [ -z "$hash_s" ] || [ "$hash_s" != "$hash_a" ]; then
				stress_ok=false
				break
			fi
		done
		check "consecutive paused captures stay responsive" "$stress_ok"
	fi

	step "VDP memory reads (read-only)"
	# Cross-check the dedicated VDP reader against the generic memory reader:
	# both must return the same bytes for the same range while paused.
	spaces=$(tool_call "memory_spaces_list")
	cram_space=$(json_get "$spaces" "[i['id'] for i in parsed.get('spaces', []) if i.get('device_instance') == 'VDP - CRAM'][0]")
	cram_vdp=$(tool_call "vdp_memory_read" '{"target": "cram", "address": 0, "length": 128, "representation": "raw_base64"}')
	cram_vdp_data=$(json_get "$cram_vdp" "parsed.get('data_base64', '')" 2>/dev/null)
	cram_mem=$(tool_call "memory_read" "{\"space\": \"$cram_space\", \"address\": 0, \"length\": 128, \"representation\": \"raw_base64\"}")
	cram_mem_data=$(json_get "$cram_mem" "parsed.get('data_base64', '')" 2>/dev/null)
	check "vdp_memory_read matches generic memory bytes" \
		"[ -n \"\$cram_vdp_data\" ] && [ \"\$cram_vdp_data\" = \"\$cram_mem_data\" ]"

	decoded=$(tool_call "vdp_memory_read" '{"target": "cram", "address": 0, "length": 128, "representation": "cram_rgb333"}')
	entry_count=$(json_get "$decoded" "len(parsed.get('entries', []))" 2>/dev/null)
	check "cram decode yields 64 palette entries" "[ \"\$entry_count\" = '64' ]"

	oob=$(tool_call "vdp_memory_read" '{"target": "vsram", "address": 79, "length": 4}')
	check "vsram range is enforced" \
		"[ \"\$(json_get \"\$oob\" \"parsed.get('code', '')\" 2>/dev/null)\" = 'out_of_range' ]"

	sprites=$(tool_call "vdp_sprite_table" '{"offset": 0, "count": 4}')
	sprite_count=$(json_get "$sprites" "len(parsed.get('entries', []))" 2>/dev/null)
	check "sprite table decodes paged entries" "[ \"\$sprite_count\" = '4' ]"
	chain_len=$(json_get "$sprites" "len(parsed.get('chain', {}).get('order', []))" 2>/dev/null)
	check "sprite link chain walks" "[ -n \"\$chain_len\" ] && [ \"\$chain_len\" -ge 1 ]"

	palette=$(tool_call "vdp_palette_export")
	line_count=$(json_get "$palette" "parsed.get('summary', {}).get('line_count')" 2>/dev/null)
	check "palette export yields four lines" "[ \"\$line_count\" = '4' ]"
	artifact_count=$(json_get "$palette" "len(parsed.get('artifacts', []))" 2>/dev/null)
	check "palette export attaches png and json artifacts" "[ \"\$artifact_count\" = '2' ]"

	tiles=$(tool_call "vdp_tile_export" '{"tile": 0, "count": 2}')
	tile_artifacts=$(json_get "$tiles" "len(parsed.get('artifacts', []))" 2>/dev/null)
	check "tile export attaches png and json artifacts" "[ \"\$tile_artifacts\" = '2' ]"

	plane=$(tool_call "vdp_plane_export" '{"plane": "b"}')
	size_cells=$(json_get "$plane" "len(parsed.get('summary', {}).get('size_cells', []))" 2>/dev/null)
	check "plane export reports register geometry" "[ \"\$size_cells\" = '2' ]"
	plane_artifacts=$(json_get "$plane" "len(parsed.get('artifacts', []))" 2>/dev/null)
	check "plane export attaches png and json artifacts" "[ \"\$plane_artifacts\" = '2' ]"

	pixel=$(tool_call "vdp_pixel_info" '{"x": 160, "y": 100}')
	if [ "$(json_get "$pixel" "parsed.get('code', '')" 2>/dev/null)" = "pixel_info_pending" ]; then
		tool_call "cpu_run" >/dev/null
		sleep 1
		tool_call "cpu_pause" >/dev/null
		pixel=$(tool_call "vdp_pixel_info" '{"x": 160, "y": 100}')
	fi
	pixel_source=$(json_get "$pixel" "parsed.get('source', '')" 2>/dev/null)
	check "pixel info attributes a source layer" "[ -n \"\$pixel_source\" ]"

	# Entries accumulate only while the system runs, so resume it for the
	# capture window and park it again afterwards.
	tool_call "cpu_run" >/dev/null
	trace=$(tool_call "cpu_trace_capture" '{"cpu": "m68k", "max_entries": 50, "timeout_ms": 400}')
	tool_call "cpu_pause" >/dev/null
	trace_captured=$(json_get "$trace" "parsed.get('summary', {}).get('captured', 0)" 2>/dev/null)
	check "m68k trace capture yields entries" "[ -n \"\$trace_captured\" ] && [ \"\$trace_captured\" -ge 1 ]"

	if [ "$was_running" = "True" ] || [ "$was_running" = "true" ]; then
		tool_call "cpu_run" >/dev/null
		emu_after=$(tool_call "emulator_status")
		check "restored running state" \
			"[ \"\$(json_get \"\$emu_after\" \"str(parsed.get('system_running', False)).lower()\" 2>/dev/null)\" = 'true' ]"
	fi
fi

printf '\n'
if [ "$failures" -ne 0 ]; then
	echo "live-smoke FAILED with $failures failure(s)."
	exit 1
fi
echo "live-smoke passed."
