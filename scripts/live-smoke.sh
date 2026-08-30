#!/usr/bin/env bash
# Drives a live exodus-mcp endpoint through its protocol surface.
#
# Default checks are strictly read-only: health, discovery, tool catalog,
# bridge status, and emulator status. --full additionally exercises the
# mutating CPU-control tools (pause/run, M68K step, breakpoint and watchpoint
# lifecycle, paused frame-capture determinism), the optimistic-concurrency
# surface (target generation read -> guarded mutation, conflict detection,
# the optional exclusive control lock with TTL expiry), memory write, the
# memory_freeze lifecycle, frame advance, input, the snapshot round trip, the
# snapshot comparison surface (memory_search, memory_diff around a rendered
# frame), the experiment fixture (experiment_run over smoke-input.json with
# manifest and internal-lock verification), and the global audit stream,
# always restoring running state on exit.
#
# Requires: bash, curl, python3. Run against an already-launched pair
# (./scripts/run-windows.sh); never start a second pair for this script.
#
# Usage: ./scripts/live-smoke.sh [--url http://127.0.0.1:8768] [--full]
set -uo pipefail

BASE_URL="http://127.0.0.1:8768"
FULL=0
while [ $# -gt 0 ]; do
	case "$1" in
	--url)
		BASE_URL="$2"
		shift 2
		;;
	--full)
		FULL=1
		shift
		;;
	*)
		echo "unknown option: $1"
		exit 2
		;;
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
		bp_counter=$(json_get "$bp" "parsed.get('break_counter')" 2>/dev/null)
		check "plain breakpoint defaults break_counter to 1" "[ \"\$bp_counter\" = '1' ]"
		bp_rm=$(tool_call "cpu_breakpoint_remove" "{\"breakpoint_id\": $bp_id}")
		check "breakpoint removed cleanly" \
			"[ \"\$(json_get \"\$bp_rm\" \"str(parsed.get('removed', False)).lower()\" 2>/dev/null)\" = 'true' ]"
	else
		check "breakpoint set returns an id" false
	fi

	bp_cond=$(tool_call "cpu_breakpoint_set" '{"cpu": "m68k", "address": "0x00000200", "condition": "range", "range_end": "0x00000220", "break_on_counter": true, "break_counter": 2}')
	bp_cond_id=$(json_get "$bp_cond" "parsed.get('breakpoint_id')" 2>/dev/null)
	if [ -n "$bp_cond_id" ]; then
		cond_name=$(json_get "$bp_cond" "parsed.get('condition')" 2>/dev/null)
		check "conditional breakpoint echoes condition" "[ \"\$cond_name\" = 'range' ]"
		bp_list=$(tool_call "cpu_breakpoint_list")
		list_cond=$(json_get "$bp_list" "' '.join(str(i.get('condition')) for i in parsed.get('breakpoints', []) if i.get('breakpoint_id') == $bp_cond_id)" 2>/dev/null)
		check "conditional breakpoint listed with condition" "[ \"\$list_cond\" = 'range' ]"
		bp_cond_rm=$(tool_call "cpu_breakpoint_remove" "{\"breakpoint_id\": $bp_cond_id}")
		check "conditional breakpoint removed cleanly" \
			"[ \"\$(json_get \"\$bp_cond_rm\" \"str(parsed.get('removed', False)).lower()\" 2>/dev/null)\" = 'true' ]"
	else
		check "conditional breakpoint set returns an id" false
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

	step "Phase 5 advanced analysis (read-only + event-driven)"
	# The system is paused here; rom_info and memory_search are read-only, and
	# the watchpoint trace + coverage restore the prior (paused) run state.
	rom_info=$(tool_call "rom_info")
	rom_identified=$(json_get "$rom_info" "parsed.get('identified', False)" 2>/dev/null)
	check "rom_info identifies the cartridge" "[ \"\$rom_identified\" = 'True' ] || [ \"\$rom_identified\" = 'true' ]"
	rom_title=$(json_get "$rom_info" "parsed.get('header', {}).get('overseas_name', '')" 2>/dev/null)
	check "rom_info reports a title" "[ -n \"\$rom_title\" ]"
	checksum_matches=$(json_get "$rom_info" "str(parsed.get('header', {}).get('checksum', {}).get('matches', False)).lower()" 2>/dev/null)
	check "rom_info validates the header checksum" "[ \"\$checksum_matches\" = 'true' ]"
	rom_computed=$(json_get "$rom_info" "parsed.get('header', {}).get('checksum', {}).get('computed', -1)" 2>/dev/null)
	rom_artifact=$(json_get "$rom_info" "parsed.get('artifact', {}).get('id', '')" 2>/dev/null)
	if [ -n "$rom_artifact" ]; then
		hd=$(tool_call "artifact_get" "{\"artifact_id\": \"$rom_artifact\"}")
		hd_artifact=$(json_get "$hd" "parsed.get('artifact', {}).get('id', '')" 2>/dev/null)
		check "rom_info attaches a header artifact" "[ -n \"\$hd_artifact\" ]"
	else
		check "rom_info attaches a header artifact" false
	fi

	# Independent Sega checksum over the ROM file, computed on this host. The
	# check is skipped when the Windows path is not reachable from WSL.
	rom_path=$(json_get "$rom_args" "parsed['path']" 2>/dev/null)
	rom_linux=$(python3 -c "
import sys, re
p = sys.argv[1].replace('\\\\', '/')
m = re.match(r'^([A-Za-z]):(.*)\$', p)
print('/mnt/' + m.group(1).lower() + m.group(2) if m and not p.startswith('/') else p)
" "$rom_path" 2>/dev/null)
	if [ -n "$rom_linux" ] && [ -f "$rom_linux" ]; then
		independent=$(python3 -c "
import sys
data = open(sys.argv[1], 'rb').read()
s = 0
for i in range(0x200, len(data) - 1, 2):
    s = (s + ((data[i] << 8) | data[i + 1])) & 0xFFFF
if (len(data) - 0x200) % 2 == 1:
    s = (s + (data[-1] << 8)) & 0xFFFF
print(s)
" "$rom_linux")
		check "rom_info checksum matches an independent computation" \
			"[ -n \"\$independent\" ] && [ \"\$independent\" = \"\$rom_computed\" ]"
	else
		echo "SKIP  rom_info independent checksum (ROM file not reachable from this host)"
	fi

	step "Memory search (consistent snapshot)"
	search=$(tool_call "memory_search" '{"space": "m68k-bus", "pattern": "53454741", "start_address": "0x100", "length": 512}')
	search_total=$(json_get "$search" "parsed.get('summary', {}).get('matches_total', 0)" 2>/dev/null)
	check "memory_search finds the header magic" "[ -n \"\$search_total\" ] && [ \"\$search_total\" -ge 1 ]"
	match_addr=$(json_get "$search" "parsed.get('matches', [{}])[0].get('address', -1)" 2>/dev/null)
	check "memory_search anchors the first match at 0x100" "[ \"\$match_addr\" = '256' ]"

	snap_dump=$(tool_call "memory_dump" '{"space": "m68k-bus", "address": "0x100", "length": 512}')
	snap_id=$(json_get "$snap_dump" "parsed.get('artifact', {}).get('id', '')" 2>/dev/null)
	if [ -n "$snap_id" ]; then
		snap_search=$(tool_call "memory_search" "{\"space\": \"m68k-bus\", \"pattern\": \"53454741\", \"snapshot_id\": \"$snap_id\"}")
		snap_total=$(json_get "$snap_search" "parsed.get('summary', {}).get('matches_total', 0)" 2>/dev/null)
		check "memory_search honors a snapshot artifact" "[ -n \"\$snap_total\" ] && [ \"\$snap_total\" -ge 1 ]"
	else
		check "memory_search honors a snapshot artifact" false
	fi

	# memory_diff against the same ROM snapshot: a fresh read of ROM cannot
	# differ from the dump, and the header byte 0x53 lives at 0x101.
	diff_rom=$(tool_call "memory_diff" "{\"snapshot_before_id\": \"$snap_id\", \"mode\": \"changed\", \"space\": \"m68k-bus\", \"start_address\": \"0x100\"}")
	diff_cells=$(json_get "$diff_rom" "parsed.get('summary', {}).get('range', {}).get('cells_scanned', 0)" 2>/dev/null)
	check "memory_diff scans the snapshot range" "[ \"\$diff_cells\" = '512' ]"
	diff_changed=$(json_get "$diff_rom" "parsed.get('summary', {}).get('matches_total', -1)" 2>/dev/null)
	check "memory_diff sees no change inside ROM" "[ \"\$diff_changed\" = '0' ]"
	diff_byte=$(tool_call "memory_diff" "{\"snapshot_before_id\": \"$snap_id\", \"mode\": \"equal_to\", \"value\": 83, \"space\": \"m68k-bus\", \"start_address\": \"0x100\"}")
	diff_equal=$(json_get "$diff_byte" "parsed.get('summary', {}).get('matches_total', 0)" 2>/dev/null)
	check "memory_diff equal_to finds the header byte" "[ -n \"\$diff_equal\" ] && [ \"\$diff_equal\" -ge 1 ]"

	step "Event-driven trace capture (watchpoint)"
	# A fresh cartridge state keeps the trigger deterministic: repeated
	# hit-and-rollback cycles can wedge the running game into a spin loop that
	# stops touching the watched address (observed live), so reload before the
	# capture. run:false parks the system at the entry point; the capture
	# resumes it during the window and restores the parked state.
	fresh_args=$(python3 -c "import json, sys; print(json.dumps({'path': sys.argv[1], 'run': False}))" "$rom_path" 2>/dev/null)
	if [ -z "$fresh_args" ]; then
		fresh_args='{"path": "F:\\projects\\kid\\rom\\kid.bin", "run": false}'
	fi
	tool_call "rom_load" "$fresh_args" >/dev/null
	wp_trace=$(tool_call "cpu_watchpoint_set" '{"cpu": "m68k", "address": "0xC00004", "length": 2, "access": "write"}')
	wp_trace_id=$(json_get "$wp_trace" "parsed.get('watchpoint_id')" 2>/dev/null)
	if [ -z "$wp_trace_id" ]; then
		check "watchpoint trace sets its trigger" false
	else
		check "watchpoint trace sets its trigger" true
		wptrace=$(tool_call "cpu_trace_capture_watchpoint" "{\"watchpoint_id\": $wp_trace_id, \"timeout_ms\": 3000}")
		wpt_captured=$(json_get "$wptrace" "parsed.get('summary', {}).get('captured', 0)" 2>/dev/null)
		wpt_hit=$(json_get "$wptrace" "str(parsed.get('summary', {}).get('stopped_on_watchpoint', False)).lower()" 2>/dev/null)
		check "watchpoint trace captures entries" "[ -n \"\$wpt_captured\" ] && [ \"\$wpt_captured\" -ge 1 ]"
		check "watchpoint trace stops on the hit" "[ \"\$wpt_hit\" = 'true' ]"
		wp_rm=$(tool_call "cpu_watchpoint_remove" "{\"watchpoint_id\": $wp_trace_id}")
		wp_rm_flag=$(json_get "$wp_rm" "str(parsed.get('removed', False)).lower()" 2>/dev/null)
		check "watchpoint trace trigger removed" "[ \"\$wp_rm_flag\" = 'true' ]"
	fi

	step "Execution coverage artifact"
	coverage=$(tool_call "cpu_coverage_capture" '{"cpu": "m68k", "duration_ms": 400}')
	coverage_entries=$(json_get "$coverage" "parsed.get('summary', {}).get('entries_total', 0)" 2>/dev/null)
	coverage_distinct=$(json_get "$coverage" "parsed.get('summary', {}).get('distinct_total', 0)" 2>/dev/null)
	check "coverage records executed entries" "[ -n \"\$coverage_entries\" ] && [ \"\$coverage_entries\" -ge 1 ]"
	check "coverage records distinct addresses" "[ -n \"\$coverage_distinct\" ] && [ \"\$coverage_distinct\" -ge 1 ]"

	step "Phase 4 controlled experimentation (generation + control lock)"
	# The system is paused here. Ordinary single-agent mutations need no
	# lease, no lock, and no generation precondition; stateful callers pass
	# the last observed target_generation. The smoke reads the generation
	# from a read-only observation, then exercises conflict detection, the
	# optional exclusive control lock, and its TTL expiry.

	# Read -> guarded mutation pattern: observe, then mutate with the
	# observed generation.
	gen_read=$(tool_call "emulator_status")
	gen=$(json_get "$gen_read" "parsed.get('target_generation', 0)" 2>/dev/null)
	check "observation reports a target generation" "[ -n \"\$gen\" ] && [ \"\$gen\" -ge 1 ]"

	# memory_write with read-back through the debugger path, unconditional.
	probe_byte=$(printf '\x5a' | base64)
	write_result=$(tool_call "memory_write" "{\"space\": \"m68k-bus\", \"address\": \"0xFF0000\", \"data\": \"$probe_byte\"}")
	write_code=$(json_get "$write_result" "parsed.get('code', '')" 2>/dev/null)
	if [ "$write_code" = "write_fault" ]; then
		echo "SKIP  memory_write echo (write fault on the probe address)"
	else
		written_len=$(json_get "$write_result" "parsed.get('length', 0)" 2>/dev/null)
		check "memory_write echoes written length" "[ \"\$written_len\" = '1' ]"
		before_gen=$(json_get "$write_result" "parsed.get('target_generation_before', 0)" 2>/dev/null)
		after_gen=$(json_get "$write_result" "parsed.get('target_generation_after', 0)" 2>/dev/null)
		check "mutation reports before/after generations" "[ -n \"\$before_gen\" ] && [ \"\$after_gen\" = \$((before_gen + 1)) ]"
		read_result=$(tool_call "memory_read" '{"space": "m68k-bus", "address": "0xFF0000", "length": 1}')
		read_hex=$(json_get "$read_result" "parsed.get('data_base64', '')" 2>/dev/null)
		check "memory_write read-back matches" "[ \"\$read_hex\" = \"\$probe_byte\" ]"

		# A guarded write with the current generation succeeds; the stale
		# generation fails with target_generation_conflict and no native
		# action (verified by the audit stream recording only the conflict).
		current_gen=$(json_get "$read_result" "parsed.get('target_generation', 0)" 2>/dev/null)
		guarded=$(tool_call "memory_write" "{\"space\": \"m68k-bus\", \"address\": \"0xFF0000\", \"data\": \"$probe_byte\", \"expected_target_generation\": $current_gen}")
		guarded_code=$(json_get "$guarded" "parsed.get('code', '')" 2>/dev/null)
		check "guarded write with the current generation succeeds" "[ -z \"\$guarded_code\" ] || [ \"\$guarded_code\" != 'target_generation_conflict' ]"
		guarded_after=$(json_get "$guarded" "parsed.get('target_generation_after', 0)" 2>/dev/null)
		stale_gen=$((current_gen - 1))
		conflict=$(tool_call "memory_write" "{\"space\": \"m68k-bus\", \"address\": \"0xFF0000\", \"data\": \"$probe_byte\", \"expected_target_generation\": $stale_gen}")
		conflict_code=$(json_get "$conflict" "parsed.get('code', '')" 2>/dev/null)
		check "stale generation yields target_generation_conflict" "[ \"\$conflict_code\" = 'target_generation_conflict' ]"
		conflict_expected=$(json_get "$conflict" "parsed.get('expected_target_generation', -1)" 2>/dev/null)
		conflict_current=$(json_get "$conflict" "parsed.get('target_generation', -1)" 2>/dev/null)
		check "conflict reports expected and current" "[ \"\$conflict_expected\" = \"\$stale_gen\" ] && [ \"\$conflict_current\" = \"\$guarded_after\" ]"

		# memory_freeze pins a cell while the system runs: the sweeper
		# must re-apply the bytes (write_count grows) and the value must
		# still hold after a running window; removing it stops the writes.
		freeze=$(tool_call "memory_freeze" "{\"space\": \"m68k-bus\", \"address\": \"0xFF0000\", \"data\": \"$probe_byte\"}")
		freeze_id=$(json_get "$freeze" "parsed.get('freeze_id', '')" 2>/dev/null)
		if [ -z "$freeze_id" ]; then
			check "memory_freeze registers a freeze entry" false
		else
			check "memory_freeze registers a freeze entry" true
			tool_call "cpu_run" >/dev/null
			sleep 1
			tool_call "cpu_pause" >/dev/null
			frozen_read=$(tool_call "memory_read" '{"space": "m68k-bus", "address": "0xFF0000", "length": 1}')
			frozen_hex=$(json_get "$frozen_read" "parsed.get('data_base64', '')" 2>/dev/null)
			freeze_listed=$(tool_call "memory_freeze_list")
			freeze_writes=$(json_get "$freeze_listed" "parsed.get('freezes', [{}])[0].get('write_count', 0)" 2>/dev/null)
			check "memory_freeze sweeper re-applied the cell" "[ -n \"\$freeze_writes\" ] && [ \"\$freeze_writes\" -ge 1 ]"
			check "memory_freeze keeps the cell pinned while running" "[ \"\$frozen_hex\" = \"\$probe_byte\" ]"
			freeze_rm=$(tool_call "memory_freeze_remove" "{\"freeze_id\": \"$freeze_id\"}")
			freeze_rm_flag=$(json_get "$freeze_rm" "str(parsed.get('removed', False)).lower()" 2>/dev/null)
			check "memory_freeze_remove deletes the entry" "[ \"\$freeze_rm_flag\" = 'true' ]"

			# memory_freeze_clear drops the whole set in one call.
			tool_call "memory_freeze" "{\"space\": \"m68k-bus\", \"address\": \"0xFF0002\", \"data\": \"$probe_byte\"}" >/dev/null
			tool_call "memory_freeze" "{\"space\": \"m68k-bus\", \"address\": \"0xFF0004\", \"data\": \"$probe_byte\"}" >/dev/null
			freeze_clear=$(tool_call "memory_freeze_clear" "{}")
			freeze_cleared=$(json_get "$freeze_clear" "parsed.get('removed', -1)" 2>/dev/null)
			check "memory_freeze_clear reports the removed count" "[ \"\$freeze_cleared\" = '2' ]"
			freeze_after=$(tool_call "memory_freeze_list")
			freeze_after_total=$(json_get "$freeze_after" "parsed.get('freezes_total', -1)" 2>/dev/null)
			check "memory_freeze_clear empties the set" "[ \"\$freeze_after_total\" = '0' ]"
		fi

		# Optional exclusive control lock: foreign mutations are rejected,
		# reads stay available, the holder passes, expiry releases the lock.
		lock=$(tool_call "target_control_acquire" '{"purpose": "live-smoke phase 4"}')
		control_id=$(json_get "$lock" "parsed.get('control_id', '')" 2>/dev/null)
		if [ -z "$control_id" ]; then
			check "target_control_acquire returns a control id" false
		else
			check "target_control_acquire returns a control id" true
			status=$(tool_call "target_control_status")
			status_active=$(json_get "$status" "str(parsed.get('active', False)).lower()" 2>/dev/null)
			check "target_control_status reports the active lock" "[ \"\$status_active\" = 'true' ]"
			status_leak=$(json_get "$status" "'control_id' in parsed" 2>/dev/null)
			check "control status never leaks the control id" "[ \"\$status_leak\" = 'false' ]"
			held=$(tool_call "memory_write" "{\"space\": \"m68k-bus\", \"address\": \"0xFF0000\", \"data\": \"$probe_byte\"}")
			held_code=$(json_get "$held" "parsed.get('code', '')" 2>/dev/null)
			check "foreign mutation is target_control_held" "[ \"\$held_code\" = 'target_control_held' ]"
			held_read=$(tool_call "memory_read" '{"space": "m68k-bus", "address": "0xFF0000", "length": 1}')
			check "reads stay available under the lock" "[ -n \"\$(json_get \"\$held_read\" \"parsed.get('data_base64', '')\" 2>/dev/null)\" ]"
			holder_write=$(tool_call "memory_write" "{\"space\": \"m68k-bus\", \"address\": \"0xFF0000\", \"data\": \"$probe_byte\", \"control_id\": \"$control_id\"}")
			holder_code=$(json_get "$holder_write" "parsed.get('code', '')" 2>/dev/null)
			check "holder mutation passes with its control_id" "[ -z \"\$holder_code\" ] || [ \"\$holder_code\" != 'target_control_held' ]"
			renewed=$(tool_call "target_control_renew" "{\"control_id\": \"$control_id\", \"ttl_ms\": 200}")
			renew_ok=$(json_get "$renewed" "parsed.get('control_id', '')" 2>/dev/null)
			check "target_control_renew extends the lock" "[ \"\$renew_ok\" = \"\$control_id\" ]"
			# Expiry releases only the lock; ordinary mutations resume.
			sleep 1
			expired_status=$(tool_call "target_control_status")
			expired_active=$(json_get "$expired_status" "str(parsed.get('active', False)).lower()" 2>/dev/null)
			check "lock expires by its TTL" "[ \"\$expired_active\" = 'false' ]"
			after_expiry=$(tool_call "memory_write" "{\"space\": \"m68k-bus\", \"address\": \"0xFF0000\", \"data\": \"$probe_byte\"}")
			after_expiry_code=$(json_get "$after_expiry" "parsed.get('code', '')" 2>/dev/null)
			check "mutation resumes after lock expiry" "[ -z \"\$after_expiry_code\" ] || [ \"\$after_expiry_code\" != 'target_control_held' ]"
		fi

		# frame_advance: one rendered frame while paused, parked again after.
		advance=$(tool_call "frame_advance" "{\"frames\": 1}")
		advance_code=$(json_get "$advance" "parsed.get('code', '')" 2>/dev/null)
		if [ "$advance_code" = "frame_timeout" ]; then
			echo "SKIP  frame_advance (display not rendering; game may be at a blank screen)"
		else
			completed=$(json_get "$advance" "parsed.get('frames_completed', 0)" 2>/dev/null)
			check "frame_advance completes one frame" "[ \"\$completed\" = '1' ]"

			# memory_diff around a rendered frame: dump all of 68K work RAM,
			# advance a frame, dump again; running game state must move cells
			# somewhere in the window (the first 0x100 bytes alone can be a
			# stable region at boot, e.g. the Sega splash counters).
			ram_before=$(tool_call "memory_dump" '{"space": "m68k-bus", "address": "0xFF0000", "length": 65536}')
			ram_before_id=$(json_get "$ram_before" "parsed.get('artifact', {}).get('id', '')" 2>/dev/null)
			tool_call "frame_advance" "{\"frames\": 1}" >/dev/null
			ram_after=$(tool_call "memory_dump" '{"space": "m68k-bus", "address": "0xFF0000", "length": 65536}')
			ram_after_id=$(json_get "$ram_after" "parsed.get('artifact', {}).get('id', '')" 2>/dev/null)
			if [ -z "$ram_before_id" ] || [ -z "$ram_after_id" ]; then
				check "memory_diff sees the frame update work RAM" false
			else
				ram_diff=$(tool_call "memory_diff" "{\"snapshot_before_id\": \"$ram_before_id\", \"snapshot_after_id\": \"$ram_after_id\", \"mode\": \"changed\", \"width\": \"word\", \"start_address\": \"0xFF0000\"}")
				ram_diff_total=$(json_get "$ram_diff" "parsed.get('summary', {}).get('matches_total', -1)" 2>/dev/null)
				check "memory_diff sees the frame update work RAM" "[ -n \"\$ram_diff_total\" ] && [ \"\$ram_diff_total\" -ge 1 ]"
			fi
		fi

		# input_set down/up; a workspace without a controller skips.
		input_result=$(tool_call "input_set" "{\"player\": 1, \"buttons\": [\"a\"], \"state\": \"down\"}")
		input_code=$(json_get "$input_result" "parsed.get('code', '')" 2>/dev/null)
		if [ "$input_code" = "controller_not_found" ]; then
			echo "SKIP  input_set (no controller device in the loaded workspace)"
		else
			check "input_set presses a button" "[ -n \"\$input_result\" ]"
			released=$(tool_call "input_set" "{\"player\": 1, \"buttons\": [\"a\"], \"state\": \"up\"}")
			check "input_set releases a button" "[ -n \"\$released\" ]"
		fi

		# state_save -> state_list -> state_load round trip.
		saved=$(tool_call "state_save" "{\"name\": \"smoke\"}")
		state_id=$(json_get "$saved" "parsed.get('state_id', '')" 2>/dev/null)
		if [ -z "$state_id" ]; then
			check "state_save returns a snapshot id" false
		else
			check "state_save returns a snapshot id" true
			state_sha=$(json_get "$saved" "parsed.get('sha256', '')" 2>/dev/null)
			check "state_save verifies the snapshot digest" "[ -n \"\$state_sha\" ]"
			snapshot_list=$(tool_call "state_list")
			listing_ids=$(json_get "$snapshot_list" "' '.join(str(s.get('state_id', '')) for s in parsed.get('snapshots', []))" 2>/dev/null)
			case " $listing_ids " in
			*" $state_id "*) check "state_list reports the snapshot" true ;;
			*) check "state_list reports the snapshot" false ;;
			esac
			loaded=$(tool_call "state_load" "{\"state_id\": \"$state_id\"}")
			loaded_flag=$(json_get "$loaded" "str(parsed.get('loaded', False)).lower()" 2>/dev/null)
			check "state_load restores the snapshot" "[ \"\$loaded_flag\" = 'true' ]"
		fi

		step "Experiment fixture (allowlisted scripted fixture)"
		# smoke-input.json lives in the configured scripts directory (the
		# launcher defaults it to <repo>\scripts\experiments). The fixture
		# presses start, advances three frames, releases, and captures a
		# frame; it ends with the system parked, matching the surrounding
		# checks, and the final restore block resumes it when needed. The
		# run acquires an internal control lock for its full duration and
		# releases it after the manifest is finalized; no lease is involved.
		if [ "$input_code" = "controller_not_found" ]; then
			echo "SKIP  experiment fixture (no controller device in the workspace)"
		else
			ctx_list=$(tool_call "context_list")
			ctx_id=$(json_get "$ctx_list" "[c['id'] for c in parsed.get('contexts', []) if c.get('default')][0]" 2>/dev/null)
			if [ -z "$ctx_id" ]; then
				check "experiment fixture resolves the default context" false
			else
				check "experiment fixture resolves the default context" true
				exp=$(tool_call "experiment_run" "{\"context\": \"$ctx_id\", \"script\": \"smoke-input.json\", \"timeout_ms\": 30000}")
				exp_code=$(json_get "$exp" "parsed.get('code', '')" 2>/dev/null)
				exp_status=$(json_get "$exp" "parsed.get('status', '')" 2>/dev/null)
				if [ "$exp_code" = "experiment_failed" ]; then
					check "experiment fixture completes" false
				else
					check "experiment fixture completes" "[ \"\$exp_status\" = 'completed' ]"
					exp_steps=$(json_get "$exp" "parsed.get('completed_steps', -1)" 2>/dev/null)
					check "experiment fixture ran all steps" "[ \"\$exp_steps\" = '5' ]"
					manifest_id=$(json_get "$exp" "[a['id'] for a in parsed.get('artifacts', []) if a.get('kind') == 'experiment-manifest'][0]" 2>/dev/null)
					if [ -n "$manifest_id" ]; then
						manifest_data=$(curl -fsS --max-time 10 "$BASE_URL/artifacts/$manifest_id?context=$ctx_id" 2>/dev/null || echo "")
						manifest_status=$(json_get "$manifest_data" "parsed.get('status', '')" 2>/dev/null)
						manifest_steps=$(json_get "$manifest_data" "len(parsed.get('steps', []))" 2>/dev/null)
						check "experiment manifest records completion" "[ \"\$manifest_status\" = 'completed' ]"
						check "experiment manifest lists every step" "[ \"\$manifest_steps\" = '5' ]"
						# The frame_capture step's PNG lives in the context artifact
						# store; its descriptor is echoed in the manifest step
						# value, so verify the artifact id and its bytes there.
						frame_id=$(json_get "$manifest_data" "[s['value']['artifact']['id'] for s in parsed.get('steps', []) if 'artifact' in s.get('value', {})][0]" 2>/dev/null)
						frame_bytes=0
						if [ -n "$frame_id" ]; then
							frame_bytes=$(curl -fsS --max-time 10 "$BASE_URL/artifacts/$frame_id?context=$ctx_id" 2>/dev/null | wc -c)
						fi
						check "experiment captured a frame artifact" "[ \"\$frame_bytes\" -gt 0 ]"
						# The run's internal control lock was released and the
						# audit stream records the reason.
						lock_audit=$(tool_call "target_audit_log" "{\"tool\": \"target_control\"}")
						lock_end_reason=$(json_get "$lock_audit" "' '.join(str(e.get('detail', {}).get('reason', '')) for e in parsed.get('entries', []))" 2>/dev/null)
						case " $lock_end_reason " in
						*" experiment_completed "*) check "experiment releases its internal lock" true ;;
						*) check "experiment releases its internal lock" false ;;
						esac
					else
						check "experiment manifest records completion" false
						check "experiment manifest lists every step" false
						check "experiment captured a frame artifact" false
					fi
				fi
			fi
		fi

		mutation_log=$(tool_call "context_mutation_log" '{"limit": 50}')
		log_count=$(json_get "$mutation_log" "len(parsed.get('entries', []))" 2>/dev/null)
		check "mutation log records the actions" "[ -n \"\$log_count\" ] && [ \"\$log_count\" -ge 3 ]"
		audit_log=$(tool_call "target_audit_log" "{\"limit\": 20}")
		audit_count=$(json_get "$audit_log" "len(parsed.get('entries', []))" 2>/dev/null)
		check "target audit stream is queryable" "[ -n \"\$audit_count\" ] && [ \"\$audit_count\" -ge 3 ]"

		step "Phase 9 quick-wins (input_sequence, vdp_memory_export, target_reset, state contract)"
		# input_sequence: two steps; ends paused with every button released.
		seq_result=$(tool_call "input_sequence" '{"player": 1, "steps": [{"buttons": ["a"], "frames": 1}, {"buttons": ["b"], "frames": 2}]}')
		seq_code=$(json_get "$seq_result" "parsed.get('code', '')" 2>/dev/null)
		if [ "$seq_code" = "controller_not_found" ]; then
			echo "SKIP  input_sequence (no controller device in the loaded workspace)"
		else
			seq_steps=$(json_get "$seq_result" "parsed.get('steps_completed', -1)" 2>/dev/null)
			check "input_sequence completes all steps" "[ \"\$seq_steps\" = '2' ]"
			seq_tokens=$(json_get "$seq_result" "len(parsed.get('frame_tokens', []))" 2>/dev/null)
			check "input_sequence reports per-step frame tokens" "[ \"\$seq_tokens\" = '2' ]"
		fi
		# Re-pause so the export samples a temporally stable buffer.
		tool_call "cpu_pause" >/dev/null

		# vdp_memory_export: full CRAM buffer as a provenanced artifact.
		exported=$(tool_call "vdp_memory_export" '{"target": "cram", "address": 0}')
		export_code=$(json_get "$exported" "parsed.get('code', '')" 2>/dev/null)
		if [ -n "$export_code" ]; then
			check "vdp_memory_export CRAM full buffer" false
		else
			export_len=$(json_get "$exported" "parsed.get('length', -1)" 2>/dev/null)
			check "vdp_memory_export CRAM full buffer" "[ \"\$export_len\" = '128' ]"
			export_kind=$(json_get "$exported" "parsed.get('artifact', {}).get('kind', '')" 2>/dev/null)
			check "vdp_memory_export artifact kind" "[ \"\$export_kind\" = 'vdp-memory-export' ]"
		fi

		# target_reset hard: uses the smoke-loaded ROM path and ends running;
		# re-pause afterwards so the state-contract check samples paused.
		reset_result=$(tool_call "target_reset" '{"kind": "hard"}')
		reset_code=$(json_get "$reset_result" "parsed.get('code', '')" 2>/dev/null)
		if [ -n "$reset_code" ]; then
			check "target_reset hard resets the loaded ROM" false
		else
			reset_source=$(json_get "$reset_result" "parsed.get('reset_source', '')" 2>/dev/null)
			check "target_reset reports reset_source hard" "[ \"\$reset_source\" = 'hard' ]"
			reset_running=$(json_get "$reset_result" "str(parsed.get('system_running', False)).lower()" 2>/dev/null)
			check "target_reset leaves the system running" "[ \"\$reset_running\" = 'true' ]"
			tool_call "cpu_pause" >/dev/null
		fi

		# target_reset soft: validate native vector and preservation proofs in
		# both paused and running states.
		soft_before=$(tool_call "bridge_status")
		soft_generation_before=$(json_get "$soft_before" "parsed.get('target_generation', -1)" 2>/dev/null)
		soft_paused=$(tool_call "target_reset" '{"kind": "soft"}')
		soft_code=$(json_get "$soft_paused" "parsed.get('code', '')" 2>/dev/null)
		if [ -n "$soft_code" ]; then
			check "target_reset soft succeeds while paused" false
		else
			soft_generation_after=$(json_get "$soft_paused" "parsed.get('target_generation_after', -1)" 2>/dev/null)
			soft_fetch_valid=$(json_get "$soft_paused" "str(parsed.get('vector_fetch', {}).get('valid', False)).lower()" 2>/dev/null)
			soft_ram=$(json_get "$soft_paused" "str(parsed.get('ram_preserved', {}).get('work_ram', False) and parsed.get('ram_preserved', {}).get('z80_ram', False)).lower()" 2>/dev/null)
			soft_vdp=$(json_get "$soft_paused" "str(parsed.get('vdp_preserved', False)).lower()" 2>/dev/null)
			soft_final=$(json_get "$soft_paused" "parsed.get('final_run_state', '')" 2>/dev/null)
			check "target_reset soft succeeds while paused" "[ \"$soft_final\" = 'paused' ] && [ \"$soft_fetch_valid\" = 'true' ] && [ \"$soft_ram\" = 'true' ] && [ \"$soft_vdp\" = 'true' ]"
			check "soft reset advances generation once" "[ \"$soft_generation_after\" -eq $((soft_generation_before + 1)) ]"
		fi
		tool_call "cpu_run" >/dev/null
		soft_running=$(tool_call "target_reset" '{"kind": "soft"}')
		soft_running_code=$(json_get "$soft_running" "parsed.get('code', '')" 2>/dev/null)
		soft_running_final=$(json_get "$soft_running" "parsed.get('final_run_state', '')" 2>/dev/null)
		check "target_reset soft preserves running state" "[ -z \"$soft_running_code\" ] && [ \"$soft_running_final\" = 'running' ]"
		tool_call "cpu_pause" >/dev/null

		# State run-state contract: saved_run_state recorded at save time and
		# echoed on load alongside final_run_state.
		contract_saved=$(tool_call "state_save" '{"name": "contract"}')
		contract_state=$(json_get "$contract_saved" "parsed.get('saved_run_state', '')" 2>/dev/null)
		check "state_save records saved_run_state" "[ -n \"\$contract_state\" ]"
		contract_id=$(json_get "$contract_saved" "parsed.get('state_id', '')" 2>/dev/null)
		if [ -z "$contract_id" ]; then
			check "state_load reports saved and final run state" false
		else
			contract_loaded=$(tool_call "state_load" "{\"state_id\": \"$contract_id\"}")
			contract_saved2=$(json_get "$contract_loaded" "parsed.get('saved_run_state', '')" 2>/dev/null)
			contract_final=$(json_get "$contract_loaded" "parsed.get('final_run_state', '')" 2>/dev/null)
			check "state_load reports saved and final run state" "[ -n \"\$contract_saved2\" ] && [ -n \"\$contract_final\" ]"
		fi

		step "Phase 9 instrumentation (one-shot, run_until, state_load override)"
		# run_until_breakpoint at the current PC: the next fetched instruction
		# hits the breakpoint, so the wrapper must fire deterministically.
		tool_call "cpu_pause" >/dev/null
		run_pc=$(json_get "$(tool_call "m68k_registers")" "int(parsed.get('registers', {}).get('pc', 0))" 2>/dev/null)
		if [ -z "$run_pc" ] || [ "$run_pc" = "0" ]; then
			check "run_until_breakpoint fires at the target PC" false
			check "run_until_breakpoint removes its instrument" false
		else
			run_result=$(tool_call "run_until_breakpoint" "{\"cpu\": \"m68k\", \"address\": $run_pc, \"timeout_ms\": 20000}")
			run_reason=$(json_get "$run_result" "parsed.get('stop_reason', '')" 2>/dev/null)
			check "run_until_breakpoint fires at the target PC" "[ \"\$run_reason\" = 'breakpoint_hit' ]"
			run_removed=$(json_get "$run_result" "str(parsed.get('instrument_removed', False)).lower()" 2>/dev/null)
			check "run_until_breakpoint removes its instrument" "[ \"\$run_removed\" = 'true' ]"
			run_hit=$(json_get "$run_result" "parsed.get('hit_count', 0) >= 1" 2>/dev/null)
			check "run_until_breakpoint reports the hit count" "[ \"\$run_hit\" = 'true' ]"
		fi
		bp_count=$(json_get "$(tool_call "cpu_breakpoint_list")" "len(parsed.get('breakpoints', []))" 2>/dev/null)
		check "run_until leaves no breakpoint residue" "[ \"\$bp_count\" = '0' ]"

		# run_until_watchpoint on work RAM: the running system writes it
		# within the window, so the wrapper must stop on the write access.
		wp_result=$(tool_call "run_until_watchpoint" '{"cpu": "m68k", "address": "0xFF0000", "length": 2, "access": "write", "timeout_ms": 20000}')
		wp_reason=$(json_get "$wp_result" "parsed.get('stop_reason', '')" 2>/dev/null)
		check "run_until_watchpoint fires on a RAM write" "[ \"\$wp_reason\" = 'watchpoint_hit' ]"
		wp_removed=$(json_get "$wp_result" "str(parsed.get('instrument_removed', False)).lower()" 2>/dev/null)
		check "run_until_watchpoint removes its instrument" "[ \"\$wp_removed\" = 'true' ]"
		wp_count=$(json_get "$(tool_call "cpu_watchpoint_list")" "len(parsed.get('watchpoints', []))" 2>/dev/null)
		check "run_until leaves no watchpoint residue" "[ \"\$wp_count\" = '0' ]"

		# The managed stop is attributed: emulator_status reports the source.
		pause_src=$(json_get "$(tool_call "emulator_status")" "parsed.get('pause_source', '')" 2>/dev/null)
		check "emulator_status attributes the managed stop" "[ \"\$pause_src\" = 'breakpoint_or_watchpoint' ]"

		# A run_until window that never fires times out and still removes the
		# armed instrument (address 1 is inside the vector table; it is never
		# executed as code).
		timeout_result=$(tool_call "run_until_breakpoint" '{"cpu": "m68k", "address": 1, "timeout_ms": 200}')
		timeout_code=$(json_get "$timeout_result" "parsed.get('code', '')" 2>/dev/null)
		check "run_until timeout reports run_until_timeout" "[ \"\$timeout_code\" = 'run_until_timeout' ]"
		timeout_removed=$(json_get "$timeout_result" "str(parsed.get('instrument_removed', False)).lower()" 2>/dev/null)
		check "run_until timeout removes its instrument" "[ \"\$timeout_removed\" = 'true' ]"

		# one_shot via cpu_breakpoint_set: the paused-state sweep removes the
		# fired instrument and emulator_status reports the removal.
		tool_call "cpu_pause" >/dev/null
		one_pc=$(json_get "$(tool_call "m68k_registers")" "int(parsed.get('registers', {}).get('pc', 0))" 2>/dev/null)
		one_set=$(tool_call "cpu_breakpoint_set" "{\"cpu\": \"m68k\", \"address\": $one_pc, \"one_shot\": true}")
		one_id=$(json_get "$one_set" "int(parsed.get('breakpoint_id', 0))" 2>/dev/null)
		if [ -z "$one_id" ] || [ "$one_id" = "0" ]; then
			check "one-shot breakpoint auto-removes on hit" false
			check "one-shot stop attributed to the instrument" false
		else
			tool_call "cpu_run" >/dev/null
			sleep 1
			one_status=$(tool_call "emulator_status")
			one_removals=$(json_get "$one_status" "len(parsed.get('one_shot_removals', []))" 2>/dev/null)
			check "one-shot breakpoint auto-removes on hit" "[ \"\$one_removals\" = '1' ]"
			one_src=$(json_get "$one_status" "parsed.get('pause_source', '')" 2>/dev/null)
			check "one-shot stop attributed to the instrument" "[ \"\$one_src\" = 'breakpoint_or_watchpoint' ]"
		fi

		# state_load run_state override: a post-load cpu_control inside the
		# control window forces the restored run state.
		tool_call "cpu_pause" >/dev/null
		override_saved=$(tool_call "state_save" '{"name": "override"}')
		override_id=$(json_get "$override_saved" "parsed.get('state_id', '')" 2>/dev/null)
		if [ -z "$override_id" ]; then
			check "state_load run_state override reports the forced state" false
			check "state_load run_state paused override" false
		else
			override_loaded=$(tool_call "state_load" "{\"state_id\": \"$override_id\", \"run_state\": \"running\"}")
			override_final=$(json_get "$override_loaded" "parsed.get('final_run_state', '')" 2>/dev/null)
			override_field=$(json_get "$override_loaded" "parsed.get('run_state_override', '')" 2>/dev/null)
			check "state_load run_state override reports the forced state" "[ \"\$override_final\" = 'running' ] && [ \"\$override_field\" = 'running' ]"
			override_paused=$(tool_call "state_load" "{\"state_id\": \"$override_id\", \"run_state\": \"paused\"}")
			override_paused_final=$(json_get "$override_paused" "parsed.get('final_run_state', '')" 2>/dev/null)
			check "state_load run_state paused override" "[ \"\$override_paused_final\" = 'paused' ]"
		fi
	fi

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
