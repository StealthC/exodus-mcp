package mcp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/bridge"
)

// ----------------------------------------------------------------------------------------------------------------------
// Catalog-consolidation registry (roadmap issue #17)
//
// The consolidation merges tools without losing capability. These tests are the
// enforcement half: every deprecated alias is registered, every alias names a
// canonical (non-alias) replacement, every alias response carries a well-formed
// `deprecated` block, and every merged tool is a single registered concept.
// ----------------------------------------------------------------------------------------------------------------------

// deprecatedBlock returns the published deprecation marker of one response.
func deprecatedBlock(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("result carries no structured content: %v", result)
	}
	block, ok := structured["deprecated"].(map[string]any)
	if !ok {
		t.Fatalf("result carries no deprecated block: %v", structured)
	}
	return block
}

// TestEveryRegisteredAliasDeclaresItsReplacement drives the alias declaration:
// a name in toolAliasRecords must be registered, must not itself be a
// canonical concept, and must resolve to a registered canonical tool.
func TestEveryRegisteredAliasDeclaresItsReplacement(t *testing.T) {
	if len(toolAliasRecords) == 0 {
		t.Fatal("no alias is declared")
	}
	seen := map[string]bool{}
	for _, record := range toolAliasRecords {
		if seen[record.Alias] {
			t.Fatalf("alias %q is declared twice", record.Alias)
		}
		seen[record.Alias] = true
		spec := lookupTool(record.Alias)
		if spec == nil {
			t.Fatalf("declared alias %q is not registered", record.Alias)
		}
		if record.Alias == record.Replacement {
			t.Fatalf("alias %q names itself as its replacement", record.Alias)
		}
		if record.Mapping == "" {
			t.Fatalf("alias %q declares no payload mapping", record.Alias)
		}
		if _, alias := toolAliasByName[record.Replacement]; alias {
			t.Fatalf("alias %q resolves to another alias %q", record.Alias, record.Replacement)
		}
		if lookupTool(record.Replacement) == nil {
			t.Fatalf("alias %q resolves to unregistered tool %q", record.Alias, record.Replacement)
		}
	}
}

// TestEveryAliasSpecIsWrapped proves the runtime half: a caller invoking any
// legacy name gets a `deprecated` block naming the declared replacement, on
// success and on failure alike.
func TestEveryAliasSpecIsWrapped(t *testing.T) {
	for _, record := range toolAliasRecords {
		spec := lookupTool(record.Alias)
		if spec == nil {
			t.Fatalf("declared alias %q is not registered", record.Alias)
		}
		server := contractServer(t)
		result := callSpecForTest(t, server, spec, record.Alias, `{}`)
		block, present := result["structuredContent"].(map[string]any)["deprecated"].(map[string]any)
		if !present {
			t.Fatalf("%s carries no deprecated block: %v", record.Alias, result["structuredContent"])
		}
		if block["code"] != aliasDeprecatedCode {
			t.Fatalf("%s deprecated.code = %v", record.Alias, block["code"])
		}
		if block["tool"] != record.Alias {
			t.Fatalf("%s deprecated.tool = %v", record.Alias, block["tool"])
		}
		if block["replacement"] != record.Replacement {
			t.Fatalf("%s deprecated.replacement = %v, want %s", record.Alias, block["replacement"], record.Replacement)
		}
		if block["removal"] == nil || block["message"] == nil {
			t.Fatalf("%s deprecated block is incomplete: %v", record.Alias, block)
		}
	}
}

// callSpecForTest dispatches one handler directly so the test controls the tool
// name and bypasses the published-argument guard.
func callSpecForTest(t *testing.T, server *Server, spec *toolSpec, tool, arguments string) map[string]any {
	t.Helper()
	var panicked any
	var result map[string]any
	func() {
		defer func() { panicked = recover() }()
		result = spec.run(toolContext{server: server, ctx: context.Background(), modern: true, invokedAs: tool}, json.RawMessage(arguments))
	}()
	if panicked != nil {
		t.Fatalf("%s panicked: %v", tool, panicked)
	}
	if result == nil {
		t.Fatalf("%s returned no result", tool)
	}
	return result
}

// TestConsolidatedCatalogHasNoDuplicateConcept pins the merged catalog: each
// canonical concept is registered exactly once, and no canonical name is
// declared as an alias.
func TestConsolidatedCatalogHasNoDuplicateConcept(t *testing.T) {
	canonical := map[string]bool{}
	for _, spec := range toolRegistry {
		if _, alias := toolAliasByName[spec.name]; alias {
			continue
		}
		canonical[spec.name] = true
	}
	for _, name := range consolidatedCanonicalTools {
		if !canonical[name] {
			t.Fatalf("merged tool %q is not registered as a canonical concept", name)
		}
	}
	// The consolidation lands the catalog on 72 concepts: the 100 tools that
	// existed before the merge, 39 of them now deprecated aliases, plus 11 merged
	// tools.
	if len(toolAliasRecords) != deprecatedAliasCount {
		t.Fatalf("declared aliases = %d, want %d", len(toolAliasRecords), deprecatedAliasCount)
	}
	if len(canonical) != canonicalConceptCount {
		t.Fatalf("canonical concepts = %d, want %d", len(canonical), canonicalConceptCount)
	}
	if len(toolRegistry) != deprecatedAliasCount+canonicalConceptCount {
		t.Fatalf("registry = %d tools, want %d", len(toolRegistry), deprecatedAliasCount+canonicalConceptCount)
	}
	if len(aliasToolNames()) != deprecatedAliasCount {
		t.Fatalf("published aliases = %d, want %d", len(aliasToolNames()), deprecatedAliasCount)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// target_status alias parity (group 1)
// ----------------------------------------------------------------------------------------------------------------------

// consolidatedCanonicalTools is the merged catalog. Each consolidation group
// appends its canonical concept here.
var consolidatedCanonicalTools = []string{"target_status", "memory_map", "memory_read", "disassemble", "cpu_step", "debug_instrument", "events_list", "vdp_memory_read", "vdp_render_export", "capture", "snapshot_diff", "trace_session_query", "trace", "sound_status"}

// payloadView strips the fields the dispatcher injects into every response and
// the alias' own deprecation marker, so two payloads can be compared field by
// field.
func payloadView(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	structured := structured(result)
	view := make(map[string]any, len(structured))
	for key, value := range structured {
		switch key {
		case "result_type", "schema_version", "target_generation", "deprecated":
			continue
		}
		view[key] = value
	}
	return view
}

// canonicalPayload calls one tool on a throwaway server so per-server
// observations (run-state timestamps, generation) never leak between the two
// sides of a parity comparison.
func canonicalPayload(t *testing.T, client bridge.Client, tool, arguments string) map[string]any {
	t.Helper()
	return payloadView(t, postToolCall(t, newTestServer(t, client), tool, arguments))
}

// TestTargetStatusAbsorbsTheStatusTools proves the aliases and the merged tool
// observe the same target: each legacy payload is the documented projection of
// target_status.
func TestTargetStatusAbsorbsTheStatusTools(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		switch method {
		case "status":
			return json.RawMessage(`{"plugin_version":"0.7.0","lifecycle":"ready"}`), nil
		case "emulator_status":
			return json.RawMessage(`{"system_running":true,"modules":[{"id":1,"display_name":"ROM","instance_name":"ROM"}],"devices":[{"instance_name":"M68000","display_name":"M68000","processor":true},{"instance_name":"Main RAM","display_name":"Main RAM","memory":true}],"rom":{"loaded":true,"size_bytes":768,"padded_size_bytes":1024,"path":"C:\\roms\\kid.bin","path_source":"loaded_module"}}`), nil
		case "mem_read":
			return json.RawMessage(`{"space_id":"m68k-bus","address":256,"effective_address":256,"length":256,"byte_order":"big-endian","encoding":"base64","data":""}`), nil
		default:
			return json.RawMessage(`{}`), nil
		}
	}

	canonical := canonicalPayload(t, client, "target_status", `{}`)
	bridge := canonicalPayload(t, client, "bridge_status", `{}`)
	emulator := canonicalPayload(t, client, "emulator_status", `{}`)
	info := canonicalPayload(t, client, "target_info", `{}`)

	bridgeSection, ok := canonical["bridge"].(map[string]any)
	if !ok {
		t.Fatalf("target_status has no bridge section: %v", canonical)
	}
	for key, value := range bridge {
		if !jsonEqual(t, bridgeSection[key], value) {
			t.Fatalf("bridge.%s = %v, bridge_status says %v", key, bridgeSection[key], value)
		}
	}
	if bridgeSection["connected"] != true {
		t.Fatalf("bridge.connected = %v", bridgeSection["connected"])
	}

	runState, _ := canonical["run_state"].(map[string]any)
	devices, _ := canonical["devices"].(map[string]any)
	rom, _ := canonical["rom"].(map[string]any)
	// last_run_state_change is a per-observation timestamp anchored at server
	// creation; the shape is compared, not the instant.
	if runState["last_run_state_change"] == nil || emulator["last_run_state_change"] == nil {
		t.Fatalf("run state transition timestamp missing: %v / %v", runState["last_run_state_change"], emulator["last_run_state_change"])
	}
	for _, key := range []string{
		"system_running", "run_state", "pause_source", "stop_source",
		"pause_source_note", "capture_consistency",
	} {
		if !jsonEqual(t, runState[key], emulator[key]) {
			t.Fatalf("run_state.%s = %v, emulator_status says %v", key, runState[key], emulator[key])
		}
	}
	if !jsonEqual(t, devices["modules"], emulator["modules"]) {
		t.Fatalf("devices.modules = %v, emulator_status modules = %v", devices["modules"], emulator["modules"])
	}
	if !jsonEqual(t, devices["entries"], emulator["devices"]) {
		t.Fatalf("devices.entries = %v, emulator_status devices = %v", devices["entries"], emulator["devices"])
	}
	for _, key := range []string{"loaded", "size_bytes", "padded_size_bytes", "path", "path_source"} {
		if !jsonEqual(t, rom[key], emulator["rom"].(map[string]any)[key]) {
			t.Fatalf("rom.%s = %v, emulator_status says %v", key, rom[key], emulator["rom"].(map[string]any)[key])
		}
	}

	if !jsonEqual(t, canonical["emulator"], info["emulator"]) {
		t.Fatalf("emulator = %v, target_info says %v", canonical["emulator"], info["emulator"])
	}
	if !jsonEqual(t, canonical["platform"], info["platform"]) {
		t.Fatalf("platform = %v, target_info says %v", canonical["platform"], info["platform"])
	}
	if !jsonEqual(t, canonical["rom"].(map[string]any)["summary"], info["rom"]) {
		t.Fatalf("rom.summary = %v, target_info says %v", canonical["rom"].(map[string]any)["summary"], info["rom"])
	}
	informationDevices, _ := info["devices"].(map[string]any)
	for _, key := range []string{"count", "processors", "memory_spaces"} {
		if !jsonEqual(t, devices[key], informationDevices[key]) {
			t.Fatalf("devices.%s = %v, target_info says %v", key, devices[key], informationDevices[key])
		}
	}
	if !jsonEqual(t, canonical["run_state"].(map[string]any)["system_running"], info["system_running"]) {
		t.Fatalf("run_state.system_running = %v, target_info says %v", canonical["run_state"].(map[string]any)["system_running"], info["system_running"])
	}
}

// TestTargetStatusReportsUnavailableSectionsHonestly covers the degraded bridge:
// the merged tool still answers, the aliases keep their strict failures.
func TestTargetStatusReportsUnavailableSectionsHonestly(t *testing.T) {
	// A plugin that advertises no operations answers nothing; the bridge itself
	// is still reachable, which is exactly the partial state target_status must
	// describe instead of hiding.
	client := &fakeBridgeClient{status: bridge.Status{ProtocolVersion: 2}}

	canonical := canonicalPayload(t, client, "target_status", `{}`)
	runState, _ := canonical["run_state"].(map[string]any)
	if runState["available"] != false {
		t.Fatalf("run_state.available = %v, want false", runState["available"])
	}
	unavailable, _ := runState["unavailable"].(map[string]any)
	if unavailable["code"] != "unsupported_plugin" {
		t.Fatalf("run_state.unavailable = %v", unavailable)
	}
	if canonical["emulator"] == nil {
		t.Fatalf("target_status lost the emulator identity: %v", canonical)
	}

	strict := postToolCall(t, newTestServer(t, client), "emulator_status", `{}`)
	if structured(strict)["code"] != "unsupported_plugin" {
		t.Fatalf("emulator_status no longer fails on an unavailable emulator status: %v", structured(strict))
	}
}

// TestAliasDeprecationAlsoAnnotatesFailures keeps the migration hint on error
// responses, where a caller needs it most.
func TestAliasDeprecationAlsoAnnotatesFailures(t *testing.T) {
	client := &fakeBridgeClient{status: bridge.Status{ProtocolVersion: 2}}
	result := postToolCall(t, newTestServer(t, client), "target_info", `{}`)
	block := deprecatedBlock(t, result)
	if block["replacement"] != "target_status" {
		t.Fatalf("replacement = %v", block["replacement"])
	}
}

// TestDeprecatedAliasesArePublishedAsDeprecated proves the catalog tells a
// client about the migration before it calls the alias.
func TestDeprecatedAliasesArePublishedAsDeprecated(t *testing.T) {
	schemas := toolSchemas()
	byName := map[string]map[string]any{}
	for _, schema := range schemas {
		byName[schema["name"].(string)] = schema
	}
	names := aliasToolNames()
	if len(names) == 0 {
		t.Fatal("no alias is published")
	}
	for _, name := range names {
		schema, present := byName[name]
		if !present {
			t.Fatalf("alias %q is not published", name)
		}
		annotation, ok := schema["x-deprecated-tool"].(map[string]any)
		if !ok {
			t.Fatalf("alias %q publishes no x-deprecated-tool annotation", name)
		}
		if annotation["replacement"] != toolAliasByName[name].Replacement {
			t.Fatalf("alias %q annotation replacement = %v", name, annotation["replacement"])
		}
		if !strings.HasPrefix(schema["description"].(string), "DEPRECATED: use ") {
			t.Fatalf("alias %q description does not announce the deprecation: %v", name, schema["description"])
		}
	}
	for _, canonical := range []string{"target_status", "artifact_get", "memory_read"} {
		if _, present := byName[canonical]["x-deprecated-tool"]; present {
			t.Fatalf("canonical tool %q publishes a deprecation annotation", canonical)
		}
	}
	sorted := append([]string{}, names...)
	sort.Strings(sorted)
	for index := range names {
		if names[index] != sorted[index] {
			t.Fatalf("alias names are not sorted")
		}
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_map alias parity (group 2)
// ----------------------------------------------------------------------------------------------------------------------

// TestMemoryMapAbsorbsTheMapTools proves the two legacy views are the two
// sections of the merged tool.
func TestMemoryMapAbsorbsTheMapTools(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "mem_spaces" {
			return json.RawMessage(memSpacesPayload()), nil
		}
		return json.RawMessage(`{}`), nil
	}

	canonical := canonicalPayload(t, client, "memory_map", `{}`)
	reference := canonicalPayload(t, client, "mega_drive_memory_map", `{}`)
	live := canonicalPayload(t, client, "memory_spaces_list", `{}`)

	if !jsonEqual(t, canonical["reference"], reference) {
		t.Fatalf("memory_map.reference = %v, mega_drive_memory_map says %v", canonical["reference"], reference)
	}
	if !jsonEqual(t, canonical["live"], live) {
		t.Fatalf("memory_map.live = %v, memory_spaces_list says %v", canonical["live"], live)
	}
	spaces, _ := canonical["live"].(map[string]any)["spaces"].([]any)
	if len(spaces) == 0 {
		t.Fatalf("memory_map.live carries no spaces: %v", canonical["live"])
	}
	regions, _ := canonical["reference"].(map[string]any)["regions"].([]any)
	if len(regions) == 0 {
		t.Fatalf("memory_map.reference carries no regions: %v", canonical["reference"])
	}
}

// TestMemoryMapValidatesTheContextKeepsTheInventory: the merged tool accepts the
// legacy context argument and rejects an unknown handle instead of silently
// ignoring it.
func TestMemoryMapValidatesTheContext(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, _ string, _ map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memSpacesPayload()), nil
	}
	result := postToolCall(t, newTestServer(t, client), "memory_map", `{"context":"ctx_missing"}`)
	if structured(result)["code"] != "unknown_context" {
		t.Fatalf("code = %v, want unknown_context", structured(result))
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_read alias parity (group 3)
// ----------------------------------------------------------------------------------------------------------------------

// busReadClient answers mem_read for the two processor bus spaces with the byte
// order each bus declares.
func busReadClient() *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	blob := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "mem_read" {
			return json.RawMessage(`{}`), nil
		}
		order := "big-endian"
		if params["space"] == "z80-bus" {
			order = "little-endian"
		}
		address, _ := strconv.ParseUint(params["address"], 10, 64)
		length, _ := strconv.ParseUint(params["length"], 10, 64)
		data := blob[:length]
		return json.RawMessage(fmt.Sprintf(`{"space_id":%q,"kind":"bus","address":%d,"effective_address":%d,"length":%d,"byte_order":%q,"encoding":"base64","data":%q}`,
			params["space"], address, address, length, order, base64.StdEncoding.EncodeToString(data))), nil
	}
	return client
}

// TestMemoryReadAbsorbsTheBusReaders proves each legacy bus reader is
// memory_read{cpu} for the same bus: every legacy field is reproduced, and the
// merged tool adds the cpu echo and the request echo.
func TestMemoryReadAbsorbsTheBusReaders(t *testing.T) {
	client := busReadClient()
	for _, tc := range []struct {
		cpu        string
		alias      string
		byteOrder  string
		addressArg string
		address    float64
	}{
		{"m68k", "m68k_read_memory", "big-endian", "0xFF0000", 0xFF0000},
		{"z80", "z80_read_memory", "little-endian", "0x2000", 0x2000},
	} {
		canonical := canonicalPayload(t, client, "memory_read", fmt.Sprintf(`{"cpu":%q,"address":%q,"length":4}`, tc.cpu, tc.addressArg))
		legacy := canonicalPayload(t, client, tc.alias, fmt.Sprintf(`{"address":%q,"length":4}`, tc.addressArg))

		for key, value := range legacy {
			if !jsonEqual(t, canonical[key], value) {
				t.Fatalf("%s: memory_read{cpu:%s}.%s = %v, alias says %v", tc.alias, tc.cpu, key, canonical[key], value)
			}
		}
		if canonical["cpu"] != tc.cpu {
			t.Fatalf("%s: memory_read.cpu = %v", tc.alias, canonical["cpu"])
		}
		if canonical["space_id"] != tc.cpu+"-bus" {
			t.Fatalf("%s: memory_read.space_id = %v", tc.alias, canonical["space_id"])
		}
		if canonical["byte_order"] != tc.byteOrder {
			t.Fatalf("%s: memory_read.byte_order = %v, want %s", tc.alias, canonical["byte_order"], tc.byteOrder)
		}
		if canonical["requested_address"] != tc.address {
			t.Fatalf("%s: memory_read.requested_address = %v, want %v", tc.alias, canonical["requested_address"], tc.address)
		}
	}
}

// TestMemoryReadRejectsAmbiguousBusSelection keeps the selector unambiguous.
func TestMemoryReadRejectsAmbiguousBusSelection(t *testing.T) {
	client := busReadClient()
	result := postToolCall(t, newTestServer(t, client), "memory_read", `{"cpu":"m68k","space":"mem-ram","address":0,"length":1}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", structured(result))
	}
	// Omitting both is also rejected: the handler must not guess a space.
	result = postToolCall(t, newTestServer(t, client), "memory_read", `{"address":0,"length":1}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", structured(result))
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// disassemble alias parity (group 4)
// ----------------------------------------------------------------------------------------------------------------------

// disasmClient answers the native disasm operation for both processors.
func disasmClient() *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "disasm" {
			return json.RawMessage(`{}`), nil
		}
		cpu := params["cpu"]
		start := uint64(0x2064)
		if value, err := strconv.ParseUint(params["address"], 10, 64); err == nil {
			start = value
		}
		if cpu == "z80" {
			return json.RawMessage(fmt.Sprintf(`{"cpu":"z80","start_address":%d,"requested_count":2,"disassembly_method":"linear sweep from the start address; not execution-verified","lines":[{"address":%d,"length":1,"bytes":"00","mnemonic":"nop","operands":""},{"address":%d,"length":3,"bytes":"C3 00 00","mnemonic":"jp","operands":"$0000"}]}`, start, start, start+1)), nil
		}
		return json.RawMessage(fmt.Sprintf(`{"cpu":"m68k","start_address":%d,"requested_count":2,"disassembly_method":"linear sweep from the start address; not execution-verified","lines":[{"address":%d,"length":2,"bytes":"60 FE","mnemonic":"bra.s","operands":"$%X"},{"address":%d,"length":2,"bytes":"4E71","mnemonic":"nop","operands":""}]}`, start, start, start, start+2)), nil
	}
	return client
}

// TestDisassembleAbsorbsThePerCPUDisassemblers proves each legacy disassembler
// is disassemble{cpu}: identical payload, with the processor as an argument.
func TestDisassembleAbsorbsThePerCPUDisassemblers(t *testing.T) {
	client := disasmClient()
	for _, tc := range []struct {
		cpu   string
		alias string
		args  string
	}{
		{"m68k", "m68k_disassemble", `{"count":2}`},
		{"z80", "z80_disassemble", `{"count":2}`},
		{"m68k", "m68k_disassemble", `{"addresses":["0x2064","0x3000"]}`},
	} {
		canonicalArgs := `{"cpu":"` + tc.cpu + `",` + strings.TrimPrefix(tc.args, "{")
		canonical := canonicalPayload(t, client, "disassemble", canonicalArgs)
		legacy := canonicalPayload(t, client, tc.alias, tc.args)
		if !jsonEqual(t, canonical, legacy) {
			t.Fatalf("%s parity failed:\ncanonical = %v\nlegacy     = %v", tc.alias, canonical, legacy)
		}
		if canonical["cpu"] != tc.cpu {
			t.Fatalf("%s: cpu = %v", tc.alias, canonical["cpu"])
		}
	}
}

// TestDisassembleRequiresAKnownProcessor keeps the selector closed: the merged
// tool cannot guess a processor.
func TestDisassembleRequiresAKnownProcessor(t *testing.T) {
	client := disasmClient()
	result := postToolCall(t, newTestServer(t, client), "disassemble", `{"cpu":"m68000"}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", structured(result))
	}
	result = postToolCall(t, newTestServer(t, client), "disassemble", `{}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params for a missing cpu", structured(result))
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// cpu_step alias parity (group 5)
// ----------------------------------------------------------------------------------------------------------------------

// stepClient answers the native cpu_control step actions and the run-state
// observation the optional completion wait polls.
func stepClient(runningPolls int) *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	statusPolls := 0
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "cpu_control":
			action := params["action"]
			cpu := params["cpu"]
			state := "false"
			if action == "run" {
				state = "true"
			}
			return json.RawMessage(fmt.Sprintf(`{"action":%q,"cpu":%q,"processor_pc":4660,"system_running":%s}`, action, cpu, state)), nil
		case "emulator_status":
			statusPolls++
			return json.RawMessage(fmt.Sprintf(`{"system_running":%t,"modules":[],"devices":[]}`, statusPolls <= runningPolls)), nil
		default:
			return json.RawMessage(`{}`), nil
		}
	}
	return client
}

// TestCPUStepAbsorbsTheStepTools proves each legacy stepping tool is cpu_step
// with the processor and the mode as arguments.
func TestCPUStepAbsorbsTheStepTools(t *testing.T) {
	for _, tc := range []struct {
		canonicalArgs string
		alias         string
		aliasArgs     string
		mode          string
	}{
		{`{"cpu":"m68k"}`, "m68k_step", `{}`, cpuStepModeInstruction},
		{`{"cpu":"z80"}`, "z80_step", `{}`, cpuStepModeInstruction},
		{`{"cpu":"m68k","mode":"over"}`, "cpu_step_over", `{"cpu":"m68k"}`, cpuStepModeOver},
		{`{"cpu":"z80","mode":"out"}`, "cpu_step_out", `{"cpu":"z80"}`, cpuStepModeOut},
	} {
		client := stepClient(0)
		canonical := canonicalPayload(t, client, "cpu_step", tc.canonicalArgs)
		legacy := canonicalPayload(t, client, tc.alias, tc.aliasArgs)
		if canonical["mode"] != tc.mode {
			t.Fatalf("%s: cpu_step.mode = %v, want %s", tc.alias, canonical["mode"], tc.mode)
		}
		delete(canonical, "mode")
		delete(canonical, "step_completion")
		if !jsonEqual(t, canonical, legacy) {
			t.Fatalf("%s parity failed:\ncanonical = %v\nlegacy     = %v", tc.alias, canonical, legacy)
		}
	}
}

// TestCPUStepWaitsForCompletionWhenAsked covers the only new behavior of the
// merged tool: an optional bounded wait for the pause that over/out produce.
func TestCPUStepWaitsForCompletionWhenAsked(t *testing.T) {
	client := stepClient(1)
	result := structured(postToolCall(t, newTestServer(t, client), "cpu_step", `{"cpu":"m68k","mode":"over","timeout_ms":2000}`))
	completion, ok := result["step_completion"].(map[string]any)
	if !ok {
		t.Fatalf("step_completion missing: %v", result)
	}
	if completion["completed"] != true {
		t.Fatalf("step did not complete: %v", completion)
	}
	if completion["system_running"] != false {
		t.Fatalf("system_running = %v", completion["system_running"])
	}

	// The same call without timeout_ms returns immediately, like the legacy
	// alias, and never polls the run state.
	client = stepClient(1)
	result = structured(postToolCall(t, newTestServer(t, client), "cpu_step", `{"cpu":"m68k","mode":"over"}`))
	if _, present := result["step_completion"]; present {
		t.Fatalf("step_completion must not appear without timeout_ms: %v", result)
	}
}

// TestCPUStepRejectsAMeaninglessTimeout keeps timeout_ms honest: an instruction
// step cannot outlive the call.
func TestCPUStepRejectsAMeaninglessTimeout(t *testing.T) {
	result := postToolCall(t, newTestServer(t, stepClient(0)), "cpu_step", `{"cpu":"m68k","timeout_ms":10}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", structured(result))
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// debug_instrument alias parity (group 6)
// ----------------------------------------------------------------------------------------------------------------------

// instrumentPayload returns one structured payload without volatile timing.
func instrumentPayload(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	view := payloadView(t, result)
	delete(view, "elapsed_ms")
	return view
}

// TestDebugInstrumentAbsorbsTheInstrumentTools proves every legacy instrument
// tool is one (action, kind) pair of debug_instrument with the same payload.
func TestDebugInstrumentAbsorbsTheInstrumentTools(t *testing.T) {
	cases := []struct {
		alias     string
		aliasArgs string
		canonical string
	}{
		{"cpu_breakpoint_set", `{"cpu":"m68k","address":4096}`, `{"action":"set","kind":"breakpoint","cpu":"m68k","address":4096}`},
		{"cpu_watchpoint_set", `{"cpu":"m68k","address":4096,"length":2,"access":"write"}`, `{"action":"set","kind":"watchpoint","cpu":"m68k","address":4096,"length":2,"access":"write"}`},
		{"cpu_breakpoint_list", `{}`, `{"action":"list","kind":"breakpoint"}`},
		{"cpu_watchpoint_list", `{}`, `{"action":"list","kind":"watchpoint"}`},
		{"cpu_breakpoint_remove", `{"breakpoint_id":1}`, `{"action":"remove","kind":"breakpoint","breakpoint_id":1}`},
		{"cpu_watchpoint_remove", `{"watchpoint_id":1}`, `{"action":"remove","kind":"watchpoint","watchpoint_id":1}`},
	}
	for _, tc := range cases {
		fake := newRunUntilFake(t)
		canonical := canonicalPayload(t, &fakeBridgeClient{status: newFakeStatus(), executeFunc: fake.execute()}, "debug_instrument", tc.canonical)
		legacy := canonicalPayload(t, &fakeBridgeClient{status: newFakeStatus(), executeFunc: newRunUntilFake(t).execute()}, tc.alias, tc.aliasArgs)

		result, _ := canonical["result"].(map[string]any)
		if result == nil {
			t.Fatalf("%s: debug_instrument produced no result object: %v", tc.alias, canonical)
		}
		if !jsonEqual(t, result, legacy) {
			t.Fatalf("%s parity failed:\ncanonical = %v\nlegacy     = %v", tc.alias, result, legacy)
		}
		for _, key := range []string{"action", "kind"} {
			if canonical[key] == nil {
				t.Fatalf("%s: debug_instrument lost %s", tc.alias, key)
			}
		}
	}
}

// TestDebugInstrumentAbsorbsRunUntil proves the run_until windows are the same
// call with run_until: true, including the stop evidence and the residue-free
// removal.
func TestDebugInstrumentAbsorbsRunUntil(t *testing.T) {
	canonicalFake := newRunUntilFake(t)
	canonicalFake.fireOnStatusCall = 2
	canonical := instrumentPayload(t, postToolCall(t, canonicalFake.server(t), "debug_instrument", `{"action":"set","kind":"breakpoint","run_until":true,"cpu":"m68k","address":4096}`))

	legacyFake := newRunUntilFake(t)
	legacyFake.fireOnStatusCall = 2
	legacy := instrumentPayload(t, postToolCall(t, legacyFake.server(t), "run_until_breakpoint", `{"cpu":"m68k","address":4096}`))

	result, _ := canonical["result"].(map[string]any)
	if result == nil {
		t.Fatalf("debug_instrument produced no result object: %v", canonical)
	}
	delete(result, "elapsed_ms")
	if !jsonEqual(t, result, legacy) {
		t.Fatalf("run_until parity failed:\ncanonical = %v\nlegacy     = %v", result, legacy)
	}
	if canonical["instrument_id"] != legacy["resource_id"] {
		t.Fatalf("instrument_id = %v, resource_id = %v", canonical["instrument_id"], legacy["resource_id"])
	}
	if canonical["run_until"] != true {
		t.Fatalf("run_until marker missing: %v", canonical)
	}
}

// TestDebugInstrumentUpdateReplacesTheInstrument documents the one action the
// legacy tools did not have: a replacement that reports both ids.
func TestDebugInstrumentUpdateReplacesTheInstrument(t *testing.T) {
	fake := newRunUntilFake(t)
	result := structured(postToolCall(t, fake.server(t), "debug_instrument", `{"action":"update","kind":"breakpoint","breakpoint_id":1,"cpu":"m68k","address":4096,"one_shot":true}`))
	if result["previous_instrument_id"] != float64(1) {
		t.Fatalf("previous_instrument_id = %v", result["previous_instrument_id"])
	}
	if result["instrument_id"] != float64(1) {
		t.Fatalf("instrument_id = %v", result["instrument_id"])
	}
	update, _ := result["result"].(map[string]any)
	if update["removed"] == nil || update["created"] == nil {
		t.Fatalf("update result is incomplete: %v", update)
	}
}

// TestDebugInstrumentRejectsArgumentsOutsideTheAction keeps the merged contract
// honest: an argument that does not apply is rejected, never dropped.
func TestDebugInstrumentRejectsArgumentsOutsideTheAction(t *testing.T) {
	fake := newRunUntilFake(t)
	for _, arguments := range []string{
		`{"action":"list","kind":"breakpoint","address":4096}`,
		`{"action":"set","kind":"breakpoint","cpu":"m68k","address":4096,"length":2}`,
		`{"action":"set","kind":"watchpoint","cpu":"m68k","address":4096,"condition":"equal"}`,
		`{"action":"set","kind":"breakpoint","run_until":true,"cpu":"m68k","address":4096,"one_shot":true}`,
		`{"action":"remove","kind":"breakpoint","breakpoint_id":1,"address":4096}`,
	} {
		result := postToolCall(t, fake.server(t), "debug_instrument", arguments)
		if structured(result)["code"] != "unsupported_parameter" {
			t.Fatalf("%s: code = %v, want unsupported_parameter", arguments, structured(result))
		}
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// events_list alias parity (group 7)
// ----------------------------------------------------------------------------------------------------------------------

// seededAuditServer returns a server whose audit stream holds five
// memory_write rows and one control-lock lifecycle row.
func seededAuditServer(t *testing.T) *Server {
	t.Helper()
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	contextID := defaultContextID(t, server)
	for index := 0; index < 5; index++ {
		server.audit.Record(analysis.AuditEntry{Tool: "memory_write", Outcome: analysis.OutcomeOK, ContextID: contextID, Detail: map[string]any{"index": index}})
	}
	server.audit.Record(analysis.AuditEntry{Tool: "run_state_change", Outcome: analysis.OutcomeOK, ContextID: contextID})
	server.audit.Record(analysis.AuditEntry{Tool: "target_control_acquire", Outcome: analysis.OutcomeLockEvent, ContextID: contextID})
	return server
}

// TestEventsListAbsorbsTheAuditTools proves both audit tools are kinds of one
// query with the same payload.
func TestEventsListAbsorbsTheAuditTools(t *testing.T) {
	cases := []struct {
		canonical string
		alias     string
		aliasArgs string
		section   string
	}{
		{`{"kinds":["audit"],"limit":2}`, "target_audit_log", `{"limit":2}`, "audit"},
		{`{"kinds":["audit"],"tool":"memory_write","limit":1}`, "target_audit_log", `{"tool":"memory_write","limit":1}`, "audit"},
		{`{"kinds":["mutation"],"limit":2}`, "context_mutation_log", `{"limit":2}`, "mutation"},
		{`{"kinds":["run_state"]}`, "target_audit_log", `{"tool":"run_state_change"}`, "run_state"},
	}
	for _, tc := range cases {
		canonical := canonicalPayloadWithServer(t, seededAuditServer(t), "events_list", tc.canonical)
		legacy := canonicalPayloadWithServer(t, seededAuditServer(t), tc.alias, tc.aliasArgs)
		sections, _ := canonical["sections"].(map[string]any)
		section, _ := sections[tc.section].(map[string]any)
		if section == nil {
			t.Fatalf("%s: events_list has no %s section: %v", tc.alias, tc.section, canonical)
		}
		if !jsonEqual(t, normalizeVolatile(section), normalizeVolatile(legacy)) {
			t.Fatalf("%s parity failed:\nsection = %v\nlegacy  = %v", tc.alias, section, legacy)
		}
		if canonicalCursor, _ := section["next_cursor"].(string); canonicalCursor != "" {
			legacyCursor, _ := legacy["next_cursor"].(string)
			if cursorPrefix(canonicalCursor) != cursorPrefix(legacyCursor) {
				t.Fatalf("%s cursor family = %q, want %q", tc.alias, cursorPrefix(canonicalCursor), cursorPrefix(legacyCursor))
			}
		}
	}
}

// canonicalPayloadWithServer renders one modern payload from an existing server.
func canonicalPayloadWithServer(t *testing.T, server *Server, tool, arguments string) map[string]any {
	t.Helper()
	return payloadView(t, postToolCall(t, server, tool, arguments))
}

// TestEventsListAbsorbsTheDebugEvents proves the debug stream is the same query
// with one extra id-based cursor.
func TestEventsListAbsorbsTheDebugEvents(t *testing.T) {
	canonicalFake := newRunUntilFake(t)
	canonicalFake.fireOnStatusCall = 2
	server := canonicalFake.server(t)
	if result := structured(postToolCall(t, server, "run_until_breakpoint", `{"cpu":"m68k","address":4096}`)); result["stop_reason"] != stopReasonBreakpointHit {
		t.Fatalf("fixture did not record a stop: %v", result)
	}
	canonical := payloadView(t, postToolCall(t, server, "events_list", `{"kinds":["debug"]}`))
	legacy := payloadView(t, postToolCall(t, server, "cpu_debug_events_list", `{}`))

	sections, _ := canonical["sections"].(map[string]any)
	section, _ := sections["debug"].(map[string]any)
	if section == nil {
		t.Fatalf("events_list has no debug section: %v", canonical)
	}
	if section["next_cursor"] != nil {
		t.Fatalf("a complete debug page must report a null next_cursor: %v", section["next_cursor"])
	}
	delete(section, "next_cursor")
	if !jsonEqual(t, section, legacy) {
		t.Fatalf("debug parity failed:\nsection = %v\nlegacy  = %v", section, legacy)
	}
}

// TestEventsListPagesAuditByCursorOnly proves #11 cursor paging survives the
// merge: a cursor carries the stream and its query.
func TestEventsListPagesAuditByCursorOnly(t *testing.T) {
	server := seededAuditServer(t)
	first := structured(postToolCall(t, server, "events_list", `{"kinds":["audit"],"tool":"memory_write","limit":2}`))
	cursor, _ := first["next_cursor"].(string)
	if cursor == "" {
		t.Fatalf("first page must be partial: %v", first)
	}
	seen := map[float64]bool{}
	collect := func(page map[string]any) {
		sections, _ := page["sections"].(map[string]any)
		section, _ := sections["audit"].(map[string]any)
		for _, raw := range section["entries"].([]any) {
			entry := raw.(map[string]any)
			if entry["tool"] != "memory_write" {
				t.Fatalf("cursor page lost the tool filter: %v", entry)
			}
			id := entry["operation_id"].(float64)
			if seen[id] {
				t.Fatalf("entry %v repeated across pages", id)
			}
			seen[id] = true
		}
	}
	collect(first)
	for cursor != "" {
		page := structured(postToolCall(t, server, "events_list", fmt.Sprintf(`{"kinds":["audit"],"cursor":%q}`, cursor)))
		collect(page)
		cursor, _ = page["next_cursor"].(string)
	}
	if len(seen) != 5 {
		t.Fatalf("paged %d audit rows, want 5", len(seen))
	}

	// A cursor is only meaningful for one stream.
	result := postToolCall(t, server, "events_list", `{"kinds":["audit","debug"],"cursor":"aud1.x"}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", structured(result))
	}
}

// TestEventsListRejectsFiltersNoKindConsumes keeps the merged filter surface
// honest for an explicit selection.
func TestEventsListRejectsFiltersNoKindConsumes(t *testing.T) {
	result := postToolCall(t, newTestServer(t, &fakeBridgeClient{status: newFakeStatus()}), "events_list", `{"kinds":["audit"],"cpu":"m68k"}`)
	payload := structured(result)
	if payload["code"] != "unsupported_parameter" || payload["field"] != "cpu" {
		t.Fatalf("payload = %v", payload)
	}
}

// volatileAuditFields are per-server values (context handles are generated per
// server, timestamps are wall clock) that two independently seeded servers can
// never share; the parity comparison normalizes them instead of ignoring the
// surrounding structure.
var volatileAuditFields = map[string]bool{
	"context_id":       true,
	"timestamp":        true,
	"oldest_timestamp": true,
	"newest_timestamp": true,
	"created_at":       true,
	"first_seen_at":    true,
	"last_seen_at":     true,
	// A cursor embeds the same per-server context handle, so its payload is
	// volatile; the parity assertion below still compares the cursor family.
	"next_cursor": true,
	"cursor":      true,
	// Artifact identity is per store instance: an id, its download URL, and the
	// capture timestamp cannot be equal across two servers.
	"id":          true,
	"url":         true,
	"captured_at": true,
	// A capture id is generated per export, so two runs never share one.
	"capture_id": true,
	// A manifest embeds the capture id and wall-clock timestamps, so its own
	// digest cannot match between two runs.
	"manifest_sha256": true,
	// The JSONL trace view embeds per-event capture timestamps.
	"jsonl_sha256":            true,
	"linked_trace_capture_id": true,
}

// cursorPrefix returns the family prefix of one cursor, the part that names the
// stream and therefore must match between the merged tool and its alias.
func cursorPrefix(cursor string) string {
	if index := strings.Index(cursor, "."); index >= 0 {
		return cursor[:index+1]
	}
	return cursor
}

// normalizeVolatile replaces per-server values with a placeholder so a parity
// comparison still checks that both payloads carry them.
func normalizeVolatile(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		normalized := make(map[string]any, len(typed))
		kind, _ := typed["kind"].(string)
		for key, entry := range typed {
			if volatileAuditFields[key] {
				normalized[key] = "<volatile>"
				continue
			}
			// A manifest artifact embeds capture ids and RFC3339Nano
			// timestamps, so both its digest and its byte size vary with the
			// run. The digest and size of a deterministic payload (PNG, tile
			// JSON, raw bytes) are still compared.
			if isPerRunReportKind(kind) && (key == "sha256" || key == "size_bytes") {
				normalized[key] = "<volatile>"
				continue
			}
			normalized[key] = normalizeVolatile(entry)
		}
		return normalized
	case []any:
		normalized := make([]any, 0, len(typed))
		for _, entry := range typed {
			normalized = append(normalized, normalizeVolatile(entry))
		}
		return normalized
	default:
		return value
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// vdp_memory_read alias parity (group 8)
// ----------------------------------------------------------------------------------------------------------------------

// vdpReadClient answers the timed-buffer VDP read for any target.
func vdpReadClient() *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "vdp_mem_read" {
			return json.RawMessage(`{}`), nil
		}
		length := 32
		if value, err := strconv.Atoi(params["length"]); err == nil && value > 0 {
			length = value
		}
		buffer := make([]byte, length)
		buffer[0] = 0x02
		return json.RawMessage(fmt.Sprintf(`{"target":%q,"address_space":"mem-vdp-%s","address":0,"effective_address":0,"length":%d,"buffer_size":65536,"entry_size":1,"byte_order":"big-endian","encoding":"base64","consistency":"live","system_paused_during_read":false,"data":%q}`,
			params["target"], params["target"], length, base64.StdEncoding.EncodeToString(buffer))), nil
	}
	return client
}

// TestVDPMemoryReadAbsorbsTheExport proves the binary export is the artifact
// output of the same read.
func TestVDPMemoryReadAbsorbsTheExport(t *testing.T) {
	arguments := `{"target":"vram","address":0,"length":32}`
	canonical := canonicalPayload(t, vdpReadClient(), "vdp_memory_read", `{"output":"artifact",`+strings.TrimPrefix(arguments, "{"))
	legacy := canonicalPayload(t, vdpReadClient(), "vdp_memory_export", arguments)

	if canonical["output"] != "artifact" {
		t.Fatalf("output = %v", canonical["output"])
	}
	delete(canonical, "output")
	if !jsonEqual(t, canonical["sha256"], legacy["sha256"]) {
		t.Fatalf("sha256 = %v, vdp_memory_export says %v", canonical["sha256"], legacy["sha256"])
	}
	// Artifact ids, URLs and capture timestamps are per-server; normalize them
	// and compare everything else, including the provenance envelope.
	if !jsonEqual(t, normalizeVolatile(canonical), normalizeVolatile(legacy)) {
		t.Fatalf("artifact parity failed:\ncanonical = %v\nlegacy     = %v", canonical, legacy)
	}
}

// TestVDPMemoryReadDefaultsToInline proves the pre-merge inline behavior is the
// default: omitting output publishes inline and returns the same decoded view.
func TestVDPMemoryReadDefaultsToInline(t *testing.T) {
	canonical := canonicalPayload(t, vdpReadClient(), "vdp_memory_read", `{"target":"cram","address":0,"length":32,"representation":"hexdump"}`)
	if canonical["output"] != "inline" {
		t.Fatalf("output = %v", canonical["output"])
	}
	if canonical["representation"] != "hexdump" || canonical["hex"] == nil {
		t.Fatalf("inline payload lost its decoded view: %v", canonical)
	}
}

// TestVDPMemoryReadRejectsAnInlineRepresentationOnArtifact keeps the two
// deliveries unambiguous.
func TestVDPMemoryReadRejectsAnInlineRepresentationOnArtifact(t *testing.T) {
	result := postToolCall(t, newTestServer(t, vdpReadClient()), "vdp_memory_read", `{"output":"artifact","target":"vram","address":0,"representation":"hexdump"}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", structured(result))
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// vdp_render_export alias parity (group 9)
// ----------------------------------------------------------------------------------------------------------------------

// renderClient builds a VDP fixture with a populated tile and plane table.
func renderClient() *fakeVDPMemoryClient {
	vram := make([]byte, 65536)
	copy(vram[5*32:], []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF})
	// Name table B at 8192: cell 0 maps to tile 5 with palette line 1.
	vram[8192] = 0x00
	vram[8193] = 0x25
	cram := make([]byte, 128)
	for entry := 1; entry < 16; entry++ {
		cram[entry*2] = 0x0E
		cram[entry*2+1] = 0xEE
	}
	return newFakeVDPMemoryClient(vram, cram)
}

// TestVDPRenderExportAbsorbsTheRenderTools proves each legacy render tool is the
// same call with a mode, including the artifact descriptors and summaries.
func TestVDPRenderExportAbsorbsTheRenderTools(t *testing.T) {
	cases := []struct {
		canonical string
		alias     string
		aliasArgs string
	}{
		{`{"mode":"tiles","tile":5,"scale":2}`, "vdp_tile_export", `{"tile":5,"scale":2}`},
		{`{"mode":"plane","plane":"b"}`, "vdp_plane_export", `{"plane":"b"}`},
	}
	for _, tc := range cases {
		canonical := canonicalPayload(t, renderClient(), "vdp_render_export", tc.canonical)
		legacy := canonicalPayload(t, renderClient(), tc.alias, tc.aliasArgs)
		if canonical["mode"] == nil {
			t.Fatalf("%s: vdp_render_export lost its mode echo", tc.alias)
		}
		delete(canonical, "mode")
		if !jsonEqual(t, normalizeVolatile(canonical), normalizeVolatile(legacy)) {
			t.Fatalf("%s parity failed:\ncanonical = %v\nlegacy     = %v", tc.alias, canonical, legacy)
		}
	}
}

// TestVDPRenderExportCropsTheRenderedImage covers the merged tool's one new
// argument: a source-pixel window applied before scaling.
func TestVDPRenderExportCropsTheRenderedImage(t *testing.T) {
	full := canonicalPayload(t, renderClient(), "vdp_render_export", `{"mode":"tiles","tile":5,"scale":2}`)
	cropped := canonicalPayload(t, renderClient(), "vdp_render_export", `{"mode":"tiles","tile":5,"scale":2,"crop":{"x":2,"y":0,"width":4,"height":8}}`)

	fullSummary, _ := full["summary"].(map[string]any)
	croppedSummary, _ := cropped["summary"].(map[string]any)
	if croppedSummary["png_width"] != float64(8) || croppedSummary["png_height"] != float64(16) {
		t.Fatalf("cropped png is %vx%v, want 8x16 (4x8 source pixels at scale 2)", croppedSummary["png_width"], croppedSummary["png_height"])
	}
	if fullSummary["png_width"] != nil {
		t.Fatalf("an uncropped export must not invent crop dimensions: %v", fullSummary)
	}
	crop, _ := croppedSummary["crop"].(map[string]any)
	if crop["width"] != float64(4) || crop["source_width"] != float64(8) || crop["scale"] != float64(2) {
		t.Fatalf("crop view = %v", crop)
	}
	// The tile JSON still describes the whole exported strip: crop is an image
	// window, not a decode change.
	if fullSummary["tile_count"] != croppedSummary["tile_count"] {
		t.Fatalf("crop changed the decoded tile count: %v vs %v", fullSummary["tile_count"], croppedSummary["tile_count"])
	}
}

// TestVDPRenderExportRejectsAnArgumentOutsideTheMode keeps the merged contract
// honest, and rejects a crop larger than the image instead of clipping silently.
func TestVDPRenderExportRejectsAnArgumentOutsideTheMode(t *testing.T) {
	for _, arguments := range []string{
		`{"mode":"tiles","plane":"b"}`,
		`{"mode":"plane","plane":"b","tile":1}`,
	} {
		result := postToolCall(t, newTestServer(t, renderClient()), "vdp_render_export", arguments)
		if structured(result)["code"] != "unsupported_parameter" {
			t.Fatalf("%s: code = %v, want unsupported_parameter", arguments, structured(result))
		}
	}
	result := postToolCall(t, newTestServer(t, renderClient()), "vdp_render_export", `{"mode":"tiles","tile":5,"crop":{"x":4,"y":0,"width":8,"height":8}}`)
	if structured(result)["code"] != "out_of_range" {
		t.Fatalf("code = %v, want out_of_range", structured(result))
	}
}

// isPerRunReportKind reports whether an artifact kind embeds run identity
// (capture ids, state ids, timestamps) in its own payload, which makes its digest
// and byte size vary even when the compared inputs are identical.
func isPerRunReportKind(kind string) bool {
	switch kind {
	case stateDiffKind, "memory-diff-results", "state-diff", "cpu-trace", "cpu-trace-jsonl", "cpu-coverage", "debug-event":
		return true
	}
	return strings.HasSuffix(kind, "manifest")
}

// jsonEqual compares two decoded JSON values structurally.
func jsonEqual(t *testing.T, left, right any) bool {
	t.Helper()
	return jsonText(left) == jsonText(right)
}

// ----------------------------------------------------------------------------------------------------------------------
// snapshot_diff alias parity (group 11)
// ----------------------------------------------------------------------------------------------------------------------

// stateDiffServer saves two distinct snapshots through a fake native writer, so
// a real byte-level state comparison is possible in a unit test.
func stateDiffServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	client := &fakeBridgeClient{status: newFakeStatus()}
	saves := 0
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "state_save":
			saves++
			content := []byte("state-before-bytes")
			if saves > 1 {
				content = []byte("state-after-bytes!")
			}
			if err := os.MkdirAll(filepath.Dir(params["path"]), 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(params["path"], content, 0o644); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"saved":true,"file_type":"zip","system_running":false}`), nil
		case "emulator_status":
			return json.RawMessage(`{"system_running":false,"modules":[],"devices":[]}`), nil
		}
		return json.RawMessage(`{}`), nil
	}
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())
	before := structured(postToolCall(t, server, "state_save", `{"name":"before"}`))["state_id"].(string)
	after := structured(postToolCall(t, server, "state_save", `{"name":"after"}`))["state_id"].(string)
	return server, before, after
}

// TestSnapshotDiffAbsorbsTheStateDiff compares both tools against the same
// snapshot pair, so only the envelope differs.
func TestSnapshotDiffAbsorbsTheStateDiff(t *testing.T) {
	server, before, after := stateDiffServer(t)
	arguments := fmt.Sprintf(`"snapshot_before_id":%q,"snapshot_after_id":%q`, before, after)
	canonical := payloadView(t, postToolCall(t, server, "snapshot_diff", `{"sections":["state"],`+arguments+`}`))
	legacy := payloadView(t, postToolCall(t, server, "state_diff", `{`+arguments+`}`))

	results, _ := canonical["results"].(map[string]any)
	section, _ := results["state"].(map[string]any)
	if section == nil {
		t.Fatalf("snapshot_diff has no state section: %v", canonical)
	}
	if !jsonEqual(t, normalizeVolatile(section), normalizeVolatile(legacy)) {
		t.Fatalf("state parity failed:\nsection = %v\nlegacy = %v", section, legacy)
	}
	if canonical["identical"] != legacy["identical"] {
		t.Fatalf("combined verdict = %v, state_diff says %v", canonical["identical"], legacy["identical"])
	}
}

// TestSnapshotDiffAbsorbsTheMemoryDiff compares both tools against the same
// memory snapshots and checks the shared cursor family.
func TestSnapshotDiffAbsorbsTheMemoryDiff(t *testing.T) {
	server := newTestServer(t, ramBlobClient([]byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}))
	before := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":8}`))["artifact"].(map[string]any)["id"].(string)
	after := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":8}`))["artifact"].(map[string]any)["id"].(string)
	arguments := fmt.Sprintf(`"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"unchanged","max_matches":2`, before, after)

	canonical := payloadView(t, postToolCall(t, server, "snapshot_diff", `{"sections":["memory"],`+arguments+`}`))
	legacy := payloadView(t, postToolCall(t, server, "memory_diff", `{`+arguments+`}`))

	results, _ := canonical["results"].(map[string]any)
	section, _ := results["memory"].(map[string]any)
	if section == nil {
		t.Fatalf("snapshot_diff has no memory section: %v", canonical)
	}
	if !jsonEqual(t, normalizeVolatile(section), normalizeVolatile(legacy)) {
		t.Fatalf("memory parity failed:\nsection = %v\nlegacy = %v", section, legacy)
	}
	canonicalCursor, _ := canonical["next_cursor"].(string)
	legacyCursor, _ := legacy["next_cursor"].(string)
	if cursorPrefix(canonicalCursor) != cursorPrefix(legacyCursor) || canonicalCursor == "" {
		t.Fatalf("cursor family = %q, memory_diff says %q", cursorPrefix(canonicalCursor), cursorPrefix(legacyCursor))
	}
	if canonical["returned"] != legacy["returned"] || canonical["total"] != legacy["total"] {
		t.Fatalf("paging envelope = %v/%v, memory_diff says %v/%v", canonical["returned"], canonical["total"], legacy["returned"], legacy["total"])
	}
}

// TestSnapshotDiffSelectsAndRejectsBySection covers the dispatcher contract.
func TestSnapshotDiffSelectsAndRejectsBySection(t *testing.T) {
	server := newTestServer(t, ramBlobClient([]byte{0x01, 0x02, 0x03, 0x04}))
	artifactID := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))["artifact"].(map[string]any)["id"].(string)

	// A memory-only argument selects the memory section without an explicit list.
	inferred := structured(postToolCall(t, server, "snapshot_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"mode":"changed"}`, artifactID)))
	sections, _ := inferred["sections"].([]any)
	if len(sections) != 1 || sections[0] != "memory" {
		t.Fatalf("inferred sections = %v, want [memory]", inferred["sections"])
	}

	rejected := structured(postToolCall(t, server, "snapshot_diff", `{"sections":["state"],"mode":"changed"}`))
	if rejected["code"] != "unsupported_parameter" || rejected["field"] != "mode" {
		t.Fatalf("expected an unsupported_parameter rejection for mode: %v", rejected)
	}
	empty := structured(postToolCall(t, server, "snapshot_diff", `{"sections":[]}`))
	if empty["code"] != "invalid_params" {
		t.Fatalf("empty sections must be rejected: %v", empty)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// trace_session_query / trace alias parity (group 12)
// ----------------------------------------------------------------------------------------------------------------------

// TestTraceSessionQueryAbsorbsTheSessionViews proves both session views are the
// same query with include selecting them.
func TestTraceSessionQueryAbsorbsTheSessionViews(t *testing.T) {
	fake := newTraceSessionFake(fakeTraceSegment(
		[3]string{"00FF0000", "NOP", ""},
		[3]string{"00FF0002", "NOP", ""},
		[3]string{"00FF0004", "NOP", ""},
	))
	server := newTestServer(t, fake.client())
	if start := structured(postToolCall(t, server, "trace_session_start", `{"cpu":"m68k"}`)); start["code"] != nil {
		t.Fatalf("trace_session_start failed: %v", start)
	}

	status := canonicalPayloadWithServer(t, server, "trace_session_status", `{"collect":false}`)
	queryStatus := canonicalPayloadWithServer(t, server, "trace_session_query", `{"include":["status"],"collect":false}`)
	assertSectionParity(t, "status", queryStatus, status)

	events := canonicalPayloadWithServer(t, server, "trace_session_events", `{"collect":false,"limit":2}`)
	queryEvents := canonicalPayloadWithServer(t, server, "trace_session_query", `{"include":["events"],"collect":false,"limit":2}`)
	assertSectionParity(t, "events", queryEvents, events)

	queryCursor, _ := queryEvents["next_cursor"].(string)
	legacyCursor, _ := events["next_cursor"].(string)
	if legacyCursor == "" {
		if queryCursor != "" {
			t.Fatalf("merged query invented a cursor the view did not publish: %q", queryCursor)
		}
	} else if cursorPrefix(queryCursor) != cursorPrefix(legacyCursor) {
		t.Fatalf("events cursor family = %q, trace_session_events says %q", cursorPrefix(queryCursor), cursorPrefix(legacyCursor))
	}

	// A view-specific argument is rejected when the other view is selected.
	rejected := structured(postToolCall(t, server, "trace_session_query", `{"include":["status"],"limit":2}`))
	if rejected["code"] != "unsupported_parameter" || rejected["field"] != "limit" {
		t.Fatalf("expected unsupported_parameter for limit: %v", rejected)
	}
}

// assertSectionParity compares one section of a merged query with the alias
// payload, normalizing per-run identity.
func assertSectionParity(t *testing.T, section string, merged, legacy map[string]any) {
	t.Helper()
	sections, _ := merged["sections"].(map[string]any)
	payload, _ := sections[section].(map[string]any)
	if payload == nil {
		t.Fatalf("merged query has no %s section: %v", section, merged)
	}
	if !jsonEqual(t, normalizeVolatile(payload), normalizeVolatile(legacy)) {
		t.Fatalf("%s parity failed:\nsection = %v\nlegacy  = %v", section, payload, legacy)
	}
}

// traceCaptureClient answers the native trace_capture operation for window,
// watchpoint, and coverage captures.
func traceCaptureClient() *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "vdp_status":
			return json.RawMessage(`{"image_buffer":{"last_rendered_frame_token":0}}`), nil
		case "regs_get":
			return json.RawMessage(`{"cpu":"m68k","registers":{"pc":8192}}`), nil
		case "disasm":
			return json.RawMessage(`{"cpu":"m68k","start_address":8192,"requested_count":1,"lines":[{"address":8192,"length":2,"bytes":"4E71","mnemonic":"nop","operands":""}]}`), nil
		case "trace_capture":
			watchpoint := params["watchpoint_id"] != ""
			payload := fmt.Sprintf(`{"cpu":"m68k","requested_entries":2,"captured":2,"timed_out":false,"duration_ms":40,`+
				`"watchpoint_mode":%t,"stopped_on_watchpoint":%t,"watchpoint_ids_hit":[3],`+
				`"sample":[{"address":2064,"cycle":10,"text":"2064 10 move.l"}],"trace_text":%q}`,
				watchpoint, watchpoint, "2064 10 move.l d0,-(sp)\n2066 22 rts")
			return json.RawMessage(payload), nil
		}
		return json.RawMessage(`{}`), nil
	}
	return client
}

// TestTraceAbsorbsTheCaptureTools proves each legacy capture is one
// analyze/until combination with the same payload under result.
func TestTraceAbsorbsTheCaptureTools(t *testing.T) {
	cases := []struct {
		canonical string
		alias     string
		aliasArgs string
	}{
		{`{"analyze":"trace","until":"window","cpu":"m68k","max_entries":2}`, "cpu_trace_capture", `{"cpu":"m68k","max_entries":2}`},
		{`{"analyze":"trace","until":"watchpoint","watchpoint_id":3,"max_entries":2,"timeout_ms":900}`, "cpu_trace_capture_watchpoint", `{"watchpoint_id":3,"max_entries":2,"timeout_ms":900}`},
		{`{"analyze":"coverage","until":"window","cpu":"m68k","max_entries":2}`, "cpu_coverage_capture", `{"cpu":"m68k","max_entries":2}`},
	}
	for _, tc := range cases {
		canonical := canonicalPayload(t, traceCaptureClient(), "trace", tc.canonical)
		legacy := canonicalPayload(t, traceCaptureClient(), tc.alias, tc.aliasArgs)
		result, _ := canonical["result"].(map[string]any)
		if result == nil {
			t.Fatalf("%s: trace produced no result: %v", tc.alias, canonical)
		}
		if !jsonEqual(t, normalizeVolatile(result), normalizeVolatile(legacy)) {
			t.Fatalf("%s parity failed:\nresult = %v\nlegacy = %v", tc.alias, result, legacy)
		}
	}
}

// TestTraceInferenceAndRejections covers the selector contract.
func TestTraceInferenceAndRejections(t *testing.T) {
	// watchpoint_id without cpu means until=watchpoint.
	inferred := canonicalPayload(t, traceCaptureClient(), "trace", `{"watchpoint_id":3,"max_entries":2,"timeout_ms":900}`)
	if inferred["until"] != traceUntilWatchpoint {
		t.Fatalf("until = %v, want watchpoint", inferred["until"])
	}
	// A window-only argument is rejected on a watchpoint capture.
	rejected := canonicalPayload(t, traceCaptureClient(), "trace", `{"until":"watchpoint","watchpoint_id":3,"cpu":"m68k"}`)
	sections, _ := rejected["sections"].(map[string]any)
	_ = sections
	server := newTestServer(t, traceCaptureClient())
	payload := structured(postToolCall(t, server, "trace", `{"until":"watchpoint","watchpoint_id":3,"cpu":"m68k"}`))
	if payload["code"] != "unsupported_parameter" || payload["field"] != "cpu" {
		t.Fatalf("expected unsupported_parameter for cpu: %v", payload)
	}
	// coverage has no watchpoint form.
	payload = structured(postToolCall(t, server, "trace", `{"analyze":"coverage","until":"watchpoint","watchpoint_id":3}`))
	if payload["code"] != "invalid_params" {
		t.Fatalf("coverage/watchpoint must be rejected: %v", payload)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// sound_status / audio_capture parity (group 13)
// ----------------------------------------------------------------------------------------------------------------------

// wavFixture renders one small valid 16-bit stereo RIFF/WAVE payload.
func wavFixture(frames int) []byte {
	dataSize := frames * 2 * 2
	buffer := make([]byte, 44+dataSize)
	copy(buffer[0:4], "RIFF")
	binary.LittleEndian.PutUint32(buffer[4:8], uint32(36+dataSize))
	copy(buffer[8:12], "WAVE")
	copy(buffer[12:16], "fmt ")
	binary.LittleEndian.PutUint32(buffer[16:20], 16)
	binary.LittleEndian.PutUint16(buffer[20:22], 1)
	binary.LittleEndian.PutUint16(buffer[22:24], 2)
	binary.LittleEndian.PutUint32(buffer[24:28], 44100)
	binary.LittleEndian.PutUint32(buffer[28:32], 44100*4)
	binary.LittleEndian.PutUint16(buffer[32:34], 4)
	binary.LittleEndian.PutUint16(buffer[34:36], 16)
	copy(buffer[36:40], "data")
	binary.LittleEndian.PutUint32(buffer[40:44], uint32(dataSize))
	return buffer
}

// audioClient answers sound_status and audio_capture; with available=false it
// models the pinned plugin, which reports audio_unavailable.
func audioClient(available bool) *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.status.SupportedOperations = append(client.status.SupportedOperations, "sound_status", "audio_capture")
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "sound_status":
			return json.RawMessage(`{"component":"` + params["component"] + `","ym2612":{"present":true,"registers":{"0x22":128}},"psg":{"present":true,"tone":[1,2,3,4]}}`), nil
		case "audio_capture":
			if !available {
				return nil, &bridge.CommandError{Code: "audio_unavailable", Message: "the pinned plugin does not expose PCM capture"}
			}
			encoded := base64.StdEncoding.EncodeToString(wavFixture(4))
			return json.RawMessage(`{"wav_base64":"` + encoded + `"}`), nil
		}
		return json.RawMessage(`{}`), nil
	}
	return client
}

// TestSoundStatusAbsorbsAudioCapture proves the PCM capture is sound_status'
// wav output, including its artifact payload.
func TestSoundStatusAbsorbsAudioCapture(t *testing.T) {
	arguments := `"duration_ms":10,"sample_rate":44100,"channels":2`
	canonical := canonicalPayload(t, audioClient(true), "sound_status", `{"output":"wav",`+arguments+`}`)
	legacy := canonicalPayload(t, audioClient(true), "audio_capture", `{`+arguments+`}`)

	if canonical["output"] != "wav" {
		t.Fatalf("output = %v", canonical["output"])
	}
	delete(canonical, "output")
	if !jsonEqual(t, normalizeVolatile(canonical), normalizeVolatile(legacy)) {
		t.Fatalf("wav parity failed:\ncanonical = %v\nlegacy = %v", canonical, legacy)
	}
	if canonical["frames"] != float64(4) || canonical["state"] != "complete" {
		t.Fatalf("wav payload lost its capture facts: %v", canonical)
	}
}

// TestSoundStatusWavReportsThePinnedPluginHonestly: the deprecated alias and the
// merged output report the same failure against the pinned bridge.
func TestSoundStatusWavReportsThePinnedPluginHonestly(t *testing.T) {
	canonical := structured(postToolCall(t, newTestServer(t, audioClient(false)), "sound_status", `{"output":"wav","duration_ms":10}`))
	legacy := structured(postToolCall(t, newTestServer(t, audioClient(false)), "audio_capture", `{"duration_ms":10}`))
	if canonical["code"] != "audio_unavailable" {
		t.Fatalf("sound_status{output:wav} code = %v, want audio_unavailable", canonical["code"])
	}
	if legacy["code"] != "audio_unavailable" {
		t.Fatalf("audio_capture code = %v, want audio_unavailable", legacy["code"])
	}
}

// TestSoundStatusArtifactOutput covers the added artifact contract for the large
// register dump, and the state output staying inline.
func TestSoundStatusArtifactOutput(t *testing.T) {
	client := audioClient(false)
	state := canonicalPayload(t, client, "sound_status", `{"component":"ym2612"}`)
	if state["output"] != "state" || state["ym2612"] == nil {
		t.Fatalf("state output must stay inline: %v", state)
	}
	artifact := canonicalPayload(t, client, "sound_status", `{"component":"ym2612","output":"artifact"}`)
	if artifact["output"] != "artifact" || artifact["artifact"] == nil {
		t.Fatalf("artifact output must return a descriptor: %v", artifact)
	}
	if artifact["ym2612"] != nil {
		t.Fatalf("artifact output must not inline the register dump: %v", artifact)
	}
	summary, _ := artifact["summary"].(map[string]any)
	if summary["component"] != "ym2612" {
		t.Fatalf("artifact summary = %v", summary)
	}
	// A field outside the selected output is rejected instead of dropped.
	rejected := structured(postToolCall(t, newTestServer(t, client), "sound_status", `{"output":"state","duration_ms":10}`))
	if rejected["code"] != "unsupported_parameter" || rejected["field"] != "duration_ms" {
		t.Fatalf("expected unsupported_parameter for duration_ms: %v", rejected)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// tools/list catalog gating (issue #17)
// ----------------------------------------------------------------------------------------------------------------------

// modernToolsListResult sends one tools/list request and returns its result
// object, failing on a transport or JSON-RPC error.
func modernToolsListResult(t *testing.T, server *Server, params string) map[string]any {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":%s}`, params)
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/list")
	recorder := newRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		t.Fatalf("tools/list status = %d, body = %s", recorder.status, recorder.body.String())
	}
	var envelope struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(recorder.body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode tools/list response: %v", err)
	}
	return envelope.Result
}

// TestToolsListHidesDeprecatedAliasesByDefault pins the consumer-facing catalog:
// one tool per concept, no deprecation metadata, unless the caller opts in.
func TestToolsListHidesDeprecatedAliasesByDefault(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	result := modernToolsListResult(t, server, fmt.Sprintf(`{"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}`, ModernProtocolVersion))
	tools, _ := result["tools"].([]any)
	if len(tools) != canonicalConceptCount {
		t.Fatalf("default catalog = %d tools, want %d", len(tools), canonicalConceptCount)
	}
	for _, raw := range tools {
		descriptor := raw.(map[string]any)
		if _, present := descriptor["x-deprecated-tool"]; present {
			t.Fatalf("default catalog lists deprecated tool %v", descriptor["name"])
		}
	}
	if deprecatedCatalogCount(toolCatalog(false)) != 0 {
		t.Fatal("the default catalog carries deprecation metadata")
	}
}

// TestToolsListListsDeprecatedAliasesOnRequest pins the opt-in view and the count
// invariant (111 = 72 canonical + 39 aliases).
func TestToolsListListsDeprecatedAliasesOnRequest(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	result := modernToolsListResult(t, server, fmt.Sprintf(`{"include_deprecated":true,"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}`, ModernProtocolVersion))
	tools, _ := result["tools"].([]any)
	if len(tools) != registeredToolCount {
		t.Fatalf("include_deprecated catalog = %d tools, want %d", len(tools), registeredToolCount)
	}
	deprecated := 0
	for _, raw := range tools {
		descriptor := raw.(map[string]any)
		annotation, present := descriptor["x-deprecated-tool"].(map[string]any)
		if !present {
			continue
		}
		deprecated++
		if annotation["replacement"] == nil {
			t.Fatalf("deprecated tool %v has no replacement", descriptor["name"])
		}
	}
	if deprecated != deprecatedAliasCount {
		t.Fatalf("deprecated tools = %d, want %d", deprecated, deprecatedAliasCount)
	}
	// The legacy era publishes the same policy.
	legacyDefault := legacyToolsListCount(t, server, `{}`)
	if legacyDefault != canonicalConceptCount {
		t.Fatalf("legacy default catalog = %d tools, want %d", legacyDefault, canonicalConceptCount)
	}
	legacyAll := legacyToolsListCount(t, server, `{"include_deprecated":true}`)
	if legacyAll != registeredToolCount {
		t.Fatalf("legacy include_deprecated catalog = %d tools, want %d", legacyAll, registeredToolCount)
	}
}

// legacyToolsListCount sends one legacy tools/list request and returns the tool
// count.
func legacyToolsListCount(t *testing.T, server *Server, params string) int {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":%s}`, params)
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	recorder := newRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		t.Fatalf("legacy tools/list status = %d, body = %s", recorder.status, recorder.body.String())
	}
	var envelope struct {
		Result struct {
			Tools []any `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(recorder.body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode legacy tools/list response: %v", err)
	}
	return len(envelope.Result.Tools)
}

// TestHiddenAliasStillExecutes proves hiding is a listing decision only: the
// dispatcher still routes a deprecated name end-to-end.
func TestHiddenAliasStillExecutes(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	catalog := modernToolsListResult(t, server, `{}`)
	for _, raw := range catalog["tools"].([]any) {
		if name := raw.(map[string]any)["name"]; name == "bridge_status" {
			t.Fatal("bridge_status must be hidden from the default catalog")
		}
	}
	result := postToolCall(t, server, "bridge_status", `{}`)
	if result["isError"] == true {
		t.Fatalf("hidden alias failed to execute: %v", result)
	}
	payload := structured(result)
	if payload["connected"] != true {
		t.Fatalf("hidden alias returned %v", payload)
	}
	if payload["deprecated"] == nil {
		t.Fatalf("hidden alias lost its deprecation block: %v", payload)
	}
	// The disassembly alias exercises the canonical path through the dispatcher.
	traceClient := disasmClient()
	result = postToolCall(t, newTestServer(t, traceClient), "m68k_disassemble", `{"count":2}`)
	if structured(result)["code"] != nil {
		t.Fatalf("hidden m68k_disassemble failed: %v", structured(result))
	}
}

// TestToolsListRejectsUnknownParameters keeps the dispatcher endpoint honest.
func TestToolsListRejectsUnknownParameters(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp",
		strings.NewReader(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"page":2,"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}}`, ModernProtocolVersion)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/list")
	recorder := newRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.status, http.StatusBadRequest, recorder.body.String())
	}
	var envelope struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(recorder.body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if envelope.Error["code"] != float64(-32602) {
		t.Fatalf("code = %v, want -32602", envelope.Error["code"])
	}
	data, _ := envelope.Error["data"].(map[string]any)
	if data["field"] != "page" {
		t.Fatalf("error data = %v", data)
	}

	// A non-boolean include_deprecated is rejected, never coerced.
	request, err = http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp",
		strings.NewReader(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"include_deprecated":"yes","_meta":{"io.modelcontextprotocol/protocolVersion":%q}}}`, ModernProtocolVersion)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/list")
	recorder = newRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusBadRequest {
		t.Fatalf("non-boolean include_deprecated status = %d: %s", recorder.status, recorder.body.String())
	}
}

// TestCapabilitiesAdvertiseTheDeprecatedCatalogPolicy publishes the opt-in next
// to the catalog so a client can discover it without guessing.
func TestCapabilitiesAdvertiseTheDeprecatedCatalogPolicy(t *testing.T) {
	policy, ok := capabilities()["x-deprecated-tools"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities publish no x-deprecated-tools policy: %v", capabilities())
	}
	if policy["count"] != deprecatedAliasCount {
		t.Fatalf("count = %v, want %d", policy["count"], deprecatedAliasCount)
	}
	if policy["canonical_count"] != canonicalConceptCount {
		t.Fatalf("canonical_count = %v, want %d", policy["canonical_count"], canonicalConceptCount)
	}
	if policy["listed_by_default"] != false {
		t.Fatalf("listed_by_default = %v", policy["listed_by_default"])
	}
	if policy["include_deprecated_parameter"] != toolsListIncludeDeprecatedParameter {
		t.Fatalf("parameter = %v", policy["include_deprecated_parameter"])
	}
	// The session views publish the same object.
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	discover := modernDiscoverCapabilities(t, server)
	xDeprecated, _ := discover["x-deprecated-tools"].(map[string]any)
	if !jsonEqual(t, xDeprecated, policy) {
		t.Fatalf("server/discover policy = %v, want %v", xDeprecated, policy)
	}
}

// modernDiscoverCapabilities returns the capabilities object of one
// server/discover response.
func modernDiscoverCapabilities(t *testing.T, server *Server) map[string]any {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":%q}}}`, ModernProtocolVersion)
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	request.Header.Set("Mcp-Method", "server/discover")
	recorder := newRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		t.Fatalf("server/discover status = %d, body = %s", recorder.status, recorder.body.String())
	}
	var envelope struct {
		Result struct {
			Capabilities map[string]any `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(recorder.body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode discover response: %v", err)
	}
	return envelope.Result.Capabilities
}

// TestToolsListAcceptsTheSpecificationCursor asserts conformance with the
// MCP tools/list request schema: `cursor` is a defined parameter, so this
// single-page endpoint accepts it (returning the same complete catalog and no
// nextCursor) instead of rejecting it as unknown.
func TestToolsListAcceptsTheSpecificationCursor(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/mcp",
		strings.NewReader(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"any-token","_meta":{"io.modelcontextprotocol/protocolVersion":%q}}}`, ModernProtocolVersion)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("MCP-Protocol-Version", ModernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/list")
	recorder := newRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.status, http.StatusOK, recorder.body.String())
	}
	var response struct {
		Result struct {
			Tools      []map[string]any `json:"tools"`
			NextCursor any              `json:"nextCursor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(recorder.body.Bytes(), &response); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if len(response.Result.Tools) != canonicalConceptCount {
		t.Fatalf("tools = %d, want %d", len(response.Result.Tools), canonicalConceptCount)
	}
	if response.Result.NextCursor != nil {
		t.Fatalf("nextCursor = %v, want none for a single-page catalog", response.Result.NextCursor)
	}
}
