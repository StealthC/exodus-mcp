package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
}

// ----------------------------------------------------------------------------------------------------------------------
// target_status alias parity (group 1)
// ----------------------------------------------------------------------------------------------------------------------

// consolidatedCanonicalTools is the merged catalog. Each consolidation group
// appends its canonical concept here.
var consolidatedCanonicalTools = []string{"target_status", "memory_map", "memory_read", "disassemble", "cpu_step", "debug_instrument", "events_list", "vdp_memory_read", "vdp_render_export"}

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
		for key, entry := range typed {
			if volatileAuditFields[key] {
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

// jsonEqual compares two decoded JSON values structurally.
func jsonEqual(t *testing.T, left, right any) bool {
	t.Helper()
	return jsonText(left) == jsonText(right)
}
