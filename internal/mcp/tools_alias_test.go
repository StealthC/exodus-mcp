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
var consolidatedCanonicalTools = []string{"target_status", "memory_map", "memory_read", "disassemble", "cpu_step", "debug_instrument"}

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
func canonicalPayload(t *testing.T, client *fakeBridgeClient, tool, arguments string) map[string]any {
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

// jsonEqual compares two decoded JSON values structurally.
func jsonEqual(t *testing.T, left, right any) bool {
	t.Helper()
	return jsonText(left) == jsonText(right)
}
