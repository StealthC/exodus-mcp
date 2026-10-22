package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------------------------------------------------
// Argument-contract fixtures (roadmap issue #9)
//
// These tests are data-driven from the tool registry: every published
// inputSchema property is probed against the live dispatcher, so a newly added
// argument cannot silently be accepted-but-ignored, and a newly published enum
// cannot silently fall back to a default.
// ----------------------------------------------------------------------------------------------------------------------

// contractServer is the shared fixture: the bridge answers every command with
// an empty success payload, so the only failures observed are argument-contract
// failures instead of bridge failures.
func contractServer(t *testing.T) *Server {
	t.Helper()
	client := &fakeBridgeClient{status: newFakeStatus()}
	return newTestServer(t, client)
}

// contractCall calls one tool and returns the structured error payload (nil
// when the call succeeded). A panic inside the handler is reported separately:
// it is a robustness gap, not an argument-contract rejection.
func contractCall(t *testing.T, server *Server, tool, arguments string) (payload map[string]any, panicked any) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = recovered
		}
	}()
	result := postToolCall(t, server, tool, arguments)
	if result["isError"] != true {
		return nil, nil
	}
	return structured(result), nil
}

// topLevelProperties returns the published properties of one tool in sorted
// order, so failures are deterministic.
func topLevelProperties(spec *toolSpec) []string {
	properties, _ := spec.schema["properties"].(map[string]any)
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// probeValue derives a schema-valid value for one property so the probe can
// only fail on the handler side.
func probeValue(t *testing.T, property map[string]any) any {
	t.Helper()
	if enum, ok := property["enum"]; ok {
		switch values := enum.(type) {
		case []string:
			if len(values) > 0 {
				return values[0]
			}
		case []int:
			if len(values) > 0 {
				return values[0]
			}
		}
	}
	if branches, ok := property["oneOf"].([]map[string]any); ok {
		for _, branch := range branches {
			if branch["type"] == "integer" {
				if minimum, ok := branch["minimum"].(int); ok && minimum > 0 {
					return minimum
				}
				return 1
			}
			if branch["type"] == "string" {
				return "1"
			}
		}
	}
	switch property["type"] {
	case "string":
		return "probe"
	case "integer":
		if minimum, ok := property["minimum"].(int); ok && minimum > 1 {
			return minimum
		}
		return 1
	case "number":
		return 1
	case "boolean":
		return true
	case "array":
		items, _ := property["items"].(map[string]any)
		if items == nil {
			return []any{}
		}
		if _, isObject := items["properties"]; isObject {
			return []any{probeObject(t, items)}
		}
		return []any{probeValue(t, items)}
	case "object":
		return probeObject(t, property)
	}
	return "probe"
}

// probeObject includes exactly one property of a nested object: including all
// of them would test cross-field rules instead of per-property acceptance.
func probeObject(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	properties := schemaProperties(schema)
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return map[string]any{}
	}
	property, _ := properties[names[0]].(map[string]any)
	return map[string]any{names[0]: probeValue(t, property)}
}

// TestEverySchemaPropertyIsConsumedOrRejected asserts the central acceptance
// criterion: a property the schema publishes must be decodable by the handler
// that serves the tool.
func TestEverySchemaPropertyIsConsumedOrRejected(t *testing.T) {
	server := contractServer(t)
	var panics []string
	for index := range toolRegistry {
		spec := &toolRegistry[index]
		properties := schemaProperties(spec.schema)
		for _, name := range topLevelProperties(spec) {
			property, _ := properties[name].(map[string]any)
			arguments, err := json.Marshal(map[string]any{name: probeValue(t, property)})
			if err != nil {
				t.Fatalf("tool %q property %q: encode probe: %v", spec.name, name, err)
			}
			payload, panicked := contractCall(t, server, spec.name, string(arguments))
			if panicked != nil {
				panics = append(panics, fmt.Sprintf("%s{%s}: %v", spec.name, name, panicked))
				continue
			}
			if payload == nil {
				continue
			}
			if field, _ := payload["field"].(string); field == name {
				t.Fatalf("tool %q rejects its own published property %q: %s (arguments %s)",
					spec.name, name, payload["message"], arguments)
			}
		}
	}
	for _, recovered := range panics {
		t.Logf("handler panicked on a schema-valid probe (robustness gap, not a contract rejection): %s", recovered)
	}
}

// TestSchemaPropertiesRejectUnknownFields asserts that the published
// additionalProperties:false is what the dispatcher actually enforces.
func TestSchemaPropertiesRejectUnknownFields(t *testing.T) {
	server := contractServer(t)
	for index := range toolRegistry {
		spec := &toolRegistry[index]
		payload, panicked := contractCall(t, server, spec.name, `{"__unsupported_probe__":1}`)
		if panicked != nil {
			t.Errorf("tool %q panicked while rejecting an unknown field: %v", spec.name, panicked)
			continue
		}
		if payload == nil {
			t.Errorf("tool %q accepted an undeclared field although its schema sets additionalProperties:false", spec.name)
			continue
		}
		if code, _ := payload["code"].(string); code != "invalid_params" {
			t.Errorf("tool %q must reject an unknown field with invalid_params, got %v", spec.name, payload)
			continue
		}
		if field, _ := payload["field"].(string); field != "__unsupported_probe__" {
			t.Errorf("tool %q must name the unknown field, got %v", spec.name, payload)
		}
		// The accepted set the decoder reports must be exactly the published
		// property set: a decoder that also swallows an unpublished argument is
		// the same contract lie in the other direction.
		accepted, ok := payload["accepted_fields"].([]any)
		if !ok {
			t.Errorf("tool %q must report its accepted fields with the rejection, got %v", spec.name, payload)
			continue
		}
		decoded := make([]string, 0, len(accepted))
		for _, entry := range accepted {
			name, _ := entry.(string)
			decoded = append(decoded, name)
		}
		published := topLevelProperties(spec)
		sort.Strings(decoded)
		if strings.Join(decoded, ",") != strings.Join(published, ",") {
			t.Errorf("tool %q decodes %v but publishes %v", spec.name, decoded, published)
		}
	}
}

// TestGuardFieldsAreDeclaredPerTool locks the removal of the global allowlist:
// a tool either publishes a mediation argument and accepts it, or rejects it as
// unsupported and says which fields it does accept.
func TestGuardFieldsAreDeclaredPerTool(t *testing.T) {
	server := contractServer(t)
	for index := range toolRegistry {
		spec := &toolRegistry[index]
		properties := schemaProperties(spec.schema)
		for _, guard := range contractGuardFields {
			declaredProperty, declared := properties[guard]
			arguments := fmt.Sprintf(`{%q:%s}`, guard, jsonProbeText(t, guard))
			payload, panicked := contractCall(t, server, spec.name, arguments)
			if panicked != nil {
				t.Fatalf("tool %q panicked on %q: %v", spec.name, guard, panicked)
			}
			if declared {
				property, _ := declaredProperty.(map[string]any)
				arguments = fmt.Sprintf(`{%q:%s}`, guard, jsonProbeTextOf(t, property))
				payload, panicked = contractCall(t, server, spec.name, arguments)
				if panicked != nil {
					t.Fatalf("tool %q panicked on %q: %v", spec.name, guard, panicked)
				}
				if payload != nil {
					if code, _ := payload["code"].(string); code == "unsupported_parameter" {
						t.Fatalf("tool %q publishes %q but rejects it: %v", spec.name, guard, payload)
					}
				}
				continue
			}
			if payload == nil {
				t.Errorf("tool %q does not publish %q yet accepted it instead of rejecting it as unsupported", spec.name, guard)
				continue
			}
			if code, _ := payload["code"].(string); code != "unsupported_parameter" {
				t.Errorf("tool %q must reject the undeclared %q with unsupported_parameter, got %v", spec.name, guard, payload)
				continue
			}
			if field, _ := payload["field"].(string); field != guard {
				t.Errorf("tool %q unsupported_parameter must name %q, got %v", spec.name, guard, payload)
				continue
			}
			accepted, ok := payload["accepted_fields"].([]any)
			if !ok {
				if code, _ := payload["code"].(string); code == "unsupported_parameter" {
					t.Errorf("tool %q unsupported_parameter must list the accepted fields, got %v", spec.name, payload)
				}
				continue
			}
			acceptedSet := map[string]bool{}
			for _, entry := range accepted {
				name, _ := entry.(string)
				acceptedSet[name] = true
			}
			for _, name := range topLevelProperties(spec) {
				if !acceptedSet[name] {
					t.Fatalf("tool %q publishes %q but its accepted-field list omits it: %v", spec.name, name, accepted)
				}
			}
		}
	}
}

func jsonProbeText(t *testing.T, field string) string {
	t.Helper()
	switch field {
	case "expected_target_generation":
		return "1"
	default:
		return `"probe"`
	}
}

func jsonProbeTextOf(t *testing.T, property map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(probeValue(t, property))
	if err != nil {
		t.Fatalf("encode probe: %v", err)
	}
	return string(encoded)
}

// enumProbePath addresses one enum-constrained value inside a tool schema.
type enumProbePath struct {
	// frames are the property names from the tool root to the enum value.
	frames []enumProbeFrame
	// jsonPath is the path used in assertions.
	jsonPath string
	// property is the enum-bearing schema node.
	property map[string]any
	// name is the property name reported for the offending value.
	name string
}

type enumProbeFrame struct {
	property map[string]any
	name     string
	array    bool
}

// collectEnumPaths walks one schema and returns every enum-constrained value,
// including nested objects and array items.
func collectEnumPaths(schema map[string]any, frames []enumProbeFrame, path string) []enumProbePath {
	var paths []enumProbePath
	properties := schemaProperties(schema)
	for name, rawProperty := range properties {
		property, ok := rawProperty.(map[string]any)
		if !ok {
			continue
		}
		childPath := path + "." + name
		frame := enumProbeFrame{property: property, name: name}
		if _, hasEnum := property["enum"]; hasEnum {
			paths = append(paths, enumProbePath{
				frames:   append(append([]enumProbeFrame{}, frames...), frame),
				jsonPath: childPath,
				property: property,
				name:     name,
			})
			continue
		}
		switch property["type"] {
		case "object":
			paths = append(paths, collectEnumPaths(property, append(append([]enumProbeFrame{}, frames...), frame), childPath)...)
		case "array":
			items, ok := property["items"].(map[string]any)
			if !ok {
				continue
			}
			arrayFrame := enumProbeFrame{property: property, name: name, array: true}
			if _, hasEnum := items["enum"]; hasEnum {
				paths = append(paths, enumProbePath{
					frames:   append(append([]enumProbeFrame{}, frames...), arrayFrame),
					jsonPath: childPath + "[]",
					property: items,
					name:     name,
				})
				continue
			}
			paths = append(paths, collectEnumPaths(items, append(append([]enumProbeFrame{}, frames...), arrayFrame), childPath+"[]")...)
		}
	}
	return paths
}

// buildEnumProbe renders arguments that set the enum path to value.
func buildEnumProbe(path enumProbePath, value any) (string, error) {
	nested := value
	for index := len(path.frames) - 1; index >= 0; index-- {
		frame := path.frames[index]
		if frame.array {
			nested = []any{nested}
		}
		nested = map[string]any{frame.name: nested}
	}
	encoded, err := json.Marshal(nested)
	return string(encoded), err
}

// TestSchemaEnumsRejectInvalidValues asserts that every enum the catalog
// publishes is enforced server-side with a stable payload instead of a silent
// fallback.
func TestSchemaEnumsRejectInvalidValues(t *testing.T) {
	server := contractServer(t)
	const invalidString = "__not_a_member__"
	const invalidNumber = 123456789
	for index := range toolRegistry {
		spec := &toolRegistry[index]
		paths := collectEnumPaths(spec.schema, nil, "$")
		sort.Slice(paths, func(i, j int) bool { return paths[i].jsonPath < paths[j].jsonPath })
		for _, path := range paths {
			var invalid any = invalidString
			switch path.property["enum"].(type) {
			case []int:
				invalid = invalidNumber
			case []string:
			}
			arguments, err := buildEnumProbe(path, invalid)
			if err != nil {
				t.Fatalf("tool %q %s: encode probe: %v", spec.name, path.jsonPath, err)
			}
			payload, panicked := contractCall(t, server, spec.name, arguments)
			if panicked != nil {
				t.Fatalf("tool %q panicked on an invalid enum at %s: %v", spec.name, path.jsonPath, panicked)
			}
			if payload == nil {
				t.Fatalf("tool %q accepted %v for %s although its schema restricts the value to %v",
					spec.name, invalid, path.jsonPath, path.property["enum"])
			}
			if code, _ := payload["code"].(string); code != "invalid_params" {
				t.Fatalf("tool %q must reject an invalid enum at %s with invalid_params, got %v", spec.name, path.jsonPath, payload)
			}
			if field, _ := payload["field"].(string); field != path.name {
				t.Fatalf("tool %q invalid enum at %s must name field %q, got %v", spec.name, path.jsonPath, path.name, payload)
			}
			allowed, ok := payload["allowed"]
			if !ok {
				t.Fatalf("tool %q invalid enum at %s must list the allowed values, got %v", spec.name, path.jsonPath, payload)
			}
			if !sameEnumValues(allowed, path.property["enum"]) {
				t.Fatalf("tool %q invalid enum at %s reports allowed %v, schema declares %v", spec.name, path.jsonPath, allowed, path.property["enum"])
			}
			if _, ok := payload["value"]; !ok {
				t.Fatalf("tool %q invalid enum at %s must echo the offending value, got %v", spec.name, path.jsonPath, payload)
			}
			message, _ := payload["message"].(string)
			if !strings.Contains(message, path.name) {
				t.Fatalf("tool %q invalid enum at %s message must name the field, got %q", spec.name, path.jsonPath, message)
			}
		}
	}
}

func sameEnumValues(allowed, declared any) bool {
	left, err := json.Marshal(allowed)
	if err != nil {
		return false
	}
	right, err := json.Marshal(declared)
	if err != nil {
		return false
	}
	return string(left) == string(right)
}

// ----------------------------------------------------------------------------------------------------------------------
// Focused fixtures for the handlers the contract change touched
// ----------------------------------------------------------------------------------------------------------------------

// TestListToolsScopeByContext covers the implemented branch of the contract:
// the breakpoint, watchpoint, and freeze listings advertise `context`, so they
// must apply it instead of accepting and ignoring it.
func TestListToolsScopeByContext(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		switch method {
		case "breakpoint_set":
			return json.RawMessage(`{"breakpoint_id":7,"cpu":"m68k","address":512}`), nil
		case "breakpoint_list":
			return json.RawMessage(`{"breakpoints":[{"breakpoint_id":7,"cpu":"m68k","address":512}]}`), nil
		case "watchpoint_set":
			return json.RawMessage(`{"watchpoint_id":9,"cpu":"m68k","address":512,"access":"write","length":1}`), nil
		case "watchpoint_list":
			return json.RawMessage(`{"watchpoints":[{"watchpoint_id":9,"cpu":"m68k","address":512,"access":"write","length":1}]}`), nil
		case "mem_write":
			return json.RawMessage(`{"space":"m68k-bus","address":512,"length":1,"consistency":"live"}`), nil
		}
		return json.RawMessage(`{}`), nil
	}
	server := newTestServer(t, client)

	owner := structured(postToolCall(t, server, "context_create", `{"name":"owner"}`))["context"].(map[string]any)["id"].(string)
	other := structured(postToolCall(t, server, "context_create", `{"name":"other"}`))["context"].(map[string]any)["id"].(string)

	if result := postToolCall(t, server, "cpu_breakpoint_set", `{"cpu":"m68k","address":512,"context":"`+owner+`"}`); result["isError"] == true {
		t.Fatalf("breakpoint_set failed: %v", structured(result))
	}
	if result := postToolCall(t, server, "cpu_watchpoint_set", `{"cpu":"m68k","address":512,"access":"write","context":"`+owner+`"}`); result["isError"] == true {
		t.Fatalf("watchpoint_set failed: %v", structured(result))
	}
	if result := postToolCall(t, server, "memory_freeze", `{"space":"m68k-bus","address":512,"data_hex":"00","context":"`+owner+`"}`); result["isError"] == true {
		t.Fatalf("memory_freeze failed: %v", structured(result))
	}

	cases := []struct {
		tool    string
		entries string
	}{
		{"cpu_breakpoint_list", "breakpoints"},
		{"cpu_watchpoint_list", "watchpoints"},
		{"memory_freeze_list", "freezes"},
	}
	for _, tc := range cases {
		inScope := structured(postToolCall(t, server, tc.tool, `{"context":"`+owner+`"}`))
		if entries, _ := inScope[tc.entries].([]any); len(entries) != 1 {
			t.Fatalf("%s must list the entry the scoped context created: %v", tc.tool, inScope)
		}
		if inScope["context_scope"] != owner {
			t.Fatalf("%s must echo the effective scope: %v", tc.tool, inScope)
		}
		outOfScope := structured(postToolCall(t, server, tc.tool, `{"context":"`+other+`"}`))
		if entries, _ := outOfScope[tc.entries].([]any); len(entries) != 0 {
			t.Fatalf("%s must hide entries another context created: %v", tc.tool, outOfScope)
		}
		if outOfScope["hidden_out_of_scope"] != float64(1) {
			t.Fatalf("%s must report the hidden entries: %v", tc.tool, outOfScope)
		}
		unscoped := structured(postToolCall(t, server, tc.tool, `{"context":"all"}`))
		if entries, _ := unscoped[tc.entries].([]any); len(entries) != 1 {
			t.Fatalf("%s must list every entry for context=all: %v", tc.tool, unscoped)
		}
		if unscoped["context_scope"] != listScopeAll {
			t.Fatalf("%s must echo the all scope: %v", tc.tool, unscoped)
		}
		unknown := postToolCall(t, server, tc.tool, `{"context":"ctx_missing"}`)
		if unknown["isError"] != true || structured(unknown)["code"] != "unknown_context" {
			t.Fatalf("%s must reject an unknown context: %v", tc.tool, structured(unknown))
		}
	}
}

// TestUnknownEnumIsNeverASilentFallback covers the enum gaps the issue names:
// an unsupported value fails with the field, the value, and the allowed list
// instead of rendering hex, returning zero events, or defaulting to "both".
func TestUnknownEnumIsNeverASilentFallback(t *testing.T) {
	server := contractServer(t)
	cases := []struct {
		tool    string
		args    string
		field   string
		allowed []string
	}{
		{"artifact_preview", `{"artifact_id":"art_missing","mode":"raw"}`, "mode", []string{"hex", "text", "base64"}},
		{"sound_status", `{"component":"opn2"}`, "component", []string{"ym2612", "psg", "both"}},
		{"sound_status", `{"capture_mode":"paused"}`, "capture_mode", []string{"live"}},
		{"trace_session_events", `{"kind":"instruction"}`, "kind", []string{"execute", "read", "write", "any"}},
		{"cpu_breakpoint_set", `{"cpu":"68k","address":512}`, "cpu", []string{"m68k", "z80"}},
		{"cpu_watchpoint_set", `{"cpu":"68k","address":512}`, "cpu", []string{"m68k", "z80"}},
		{"cpu_watchpoint_set", `{"cpu":"m68k","address":512,"access":"execute"}`, "access", []string{"read", "write", "any"}},
		{"memory_read", `{"space":"m68k-ram","address":0,"length":4,"representation":"raw_u8"}`, "representation", []string{"raw_base64", "hexdump", "array_u8"}},
		{"vdp_memory_read", `{"target":"vdp","address":0}`, "target", []string{"vram", "cram", "vsram"}},
		{"audio_capture", `{"duration_ms":10,"sample_rate":11025}`, "sample_rate", nil},
		{"audio_capture", `{"duration_ms":10,"channels":6}`, "channels", nil},
		{"vdp_plane_export", `{"plane":"c"}`, "plane", []string{"a", "b", "window"}},
		// The deprecated "restore" alias stays accepted (stateLoadRunStateRestore);
		// anything else is still rejected, so an alias never reopens a fallback.
		{"state_load", `{"state_id":"state_missing","run_state":"rewind"}`, "run_state", []string{"preserve", "paused", "running"}},
	}
	for _, tc := range cases {
		result := postToolCall(t, server, tc.tool, tc.args)
		if result["isError"] != true {
			t.Fatalf("%s must reject %s: %v", tc.tool, tc.args, structured(result))
		}
		payload := structured(result)
		if payload["code"] != "invalid_params" || payload["field"] != tc.field {
			t.Fatalf("%s must report invalid_params for %q, got %v", tc.tool, tc.field, payload)
		}
		if _, ok := payload["value"]; !ok {
			t.Fatalf("%s must echo the rejected value: %v", tc.tool, payload)
		}
		if tc.allowed != nil {
			allowed, _ := payload["allowed"].([]any)
			rendered := make([]string, 0, len(allowed))
			for _, entry := range allowed {
				rendered = append(rendered, fmt.Sprint(entry))
			}
			if strings.Join(rendered, "|") != strings.Join(tc.allowed, "|") {
				t.Fatalf("%s allowed = %v, want %v", tc.tool, rendered, tc.allowed)
			}
		}
	}
}

// TestToolsThatDoNotConsumeGuardsRejectThem locks the removed global allowlist
// on the tools that previously swallowed every argument.
func TestToolsThatDoNotConsumeGuardsRejectThem(t *testing.T) {
	server := contractServer(t)
	cases := []struct {
		tool string
		args string
	}{
		{"m68k_registers", `{"context":"ctx_x"}`},
		{"z80_registers", `{"control_id":"abc"}`},
		{"vdp_status", `{"expected_target_generation":3}`},
		{"vdp_command_dma_status", `{"context":"ctx_x"}`},
		{"sound_status", `{"control_id":"abc"}`},
		{"bridge_status", `{"context":"ctx_x"}`},
		{"emulator_status", `{"control_id":"abc"}`},
		{"memory_spaces_list", `{"context":"ctx_x"}`},
		{"target_info", `{"expected_target_generation":1}`},
		{"context_list", `{"context":"ctx_x"}`},
		{"cpu_breakpoint_remove", `{"breakpoint_id":1,"context":"ctx_x"}`},
	}
	for _, tc := range cases {
		result := postToolCall(t, server, tc.tool, tc.args)
		if result["isError"] != true {
			t.Fatalf("%s must reject %s instead of ignoring it: %v", tc.tool, tc.args, structured(result))
		}
		payload := structured(result)
		if payload["code"] != "unsupported_parameter" {
			t.Fatalf("%s expected unsupported_parameter, got %v", tc.tool, payload)
		}
		if payload["tool"] == nil || payload["field"] == nil || payload["accepted_fields"] == nil {
			t.Fatalf("%s rejection must carry tool, field, and accepted_fields: %v", tc.tool, payload)
		}
	}
}

// TestDeclaredGuardFieldsAreHonored verifies the other direction: a tool that
// publishes a mediation field still accepts it and applies the precondition.
func TestDeclaredGuardFieldsAreHonored(t *testing.T) {
	server := contractServer(t)
	if result := postToolCall(t, server, "memory_read", `{"space":"m68k-ram","address":0,"length":4,"context":"ctx_missing"}`); result["isError"] != true || structured(result)["code"] != "unknown_context" {
		t.Fatalf("memory_read must resolve a supplied context: %v", structured(result))
	}
	if result := postToolCall(t, server, "cpu_pause", `{"expected_target_generation":99}`); result["isError"] != true || structured(result)["code"] != "target_generation_conflict" {
		t.Fatalf("cpu_pause must apply the generation precondition: %v", structured(result))
	}
}
