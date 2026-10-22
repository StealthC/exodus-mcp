package mcp

import (
	"context"
	"encoding/json"
	"sort"
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
		block := deprecatedBlock(t, result)
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
var consolidatedCanonicalTools = []string{"target_status", "memory_map"}

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

// jsonEqual compares two decoded JSON values structurally.
func jsonEqual(t *testing.T, left, right any) bool {
	t.Helper()
	return jsonText(left) == jsonText(right)
}
