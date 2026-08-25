package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

// TestBreakpointConditionalPassthrough verifies that the optional condition,
// range_end, break_on_counter, and break_counter arguments reach the plugin
// with canonical decimal rendering.
func TestBreakpointConditionalPassthrough(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "breakpoint_set" {
			t.Fatalf("unexpected call %s", method)
		}
		return json.RawMessage(`{"breakpoint_id":7,"cpu":"m68k","address":512,"condition":"range","range_end":544,"break_on_counter":false,"break_counter":1}`), nil
	}

	result := callTool(t, client, "cpu_breakpoint_set",
		`{"cpu":"m68k","address":"0x200","condition":"range","range_end":"0x220","break_on_counter":true,"break_counter":2}`)
	if structured(result)["breakpoint_id"] != float64(7) {
		t.Fatalf("response lost: %v", result)
	}
	calls := client.recordedCalls
	if len(calls) != 1 {
		t.Fatalf("expected one bridge call, got %d", len(calls))
	}
	wantParams := map[string]string{
		"cpu":              "m68k",
		"address":          "512",
		"condition":        "range",
		"range_end":        "544",
		"break_on_counter": "true",
		"break_counter":    "2",
	}
	for key, want := range wantParams {
		if calls[0].Params[key] != want {
			t.Fatalf("param %s = %q, want %q (%v)", key, calls[0].Params[key], want, calls[0].Params)
		}
	}
}

// TestBreakpointDefaultsStayCompact verifies the legacy call shape still sends
// exactly the historical parameters: no condition, range_end, or counter
// fields appear for a plain equal breakpoint.
func TestBreakpointDefaultsStayCompact(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	callTool(t, client, "cpu_breakpoint_set", `{"cpu":"z80","address":65535}`)
	calls := client.recordedCalls
	if len(calls) != 1 {
		t.Fatalf("expected one bridge call, got %d", len(calls))
	}
	if calls[0].Params["condition"] != "" || calls[0].Params["range_end"] != "" ||
		calls[0].Params["break_on_counter"] != "" || calls[0].Params["break_counter"] != "" {
		t.Fatalf("plain breakpoint must not send optional params: %v", calls[0].Params)
	}
}

func TestBreakpointConditionalValidation(t *testing.T) {
	for name, arguments := range map[string]string{
		"range with inverted bounds": `{"cpu":"m68k","address":"0x220","condition":"range","range_end":"0x200"}`,
		"range without range_end":    `{"cpu":"m68k","address":"0x200","condition":"range"}`,
		"range_end without range":    `{"cpu":"m68k","address":"0x200","range_end":"0x220"}`,
		"unknown condition":          `{"cpu":"m68k","address":"0x200","condition":"between"}`,
		"counter without flag":       `{"cpu":"m68k","address":"0x200","break_counter":2}`,
		"zero counter":               `{"cpu":"m68k","address":"0x200","break_on_counter":true,"break_counter":0}`,
		"bad range_end address":      `{"cpu":"m68k","address":"0x200","condition":"range","range_end":"nope"}`,
	} {
		client := &fakeBridgeClient{status: newFakeStatus()}
		result := structured(callTool(t, client, "cpu_breakpoint_set", arguments))
		if result["code"] != "invalid_params" {
			t.Fatalf("%s: expected invalid_params, got %v", name, result)
		}
		if len(client.recordedCalls) != 0 {
			t.Fatalf("%s: invalid arguments must not reach the bridge: %v", name, client.recordedCalls)
		}
	}
}

// TestBreakpointBreakOnCounterDefault verifies break_on_counter without an
// explicit counter defaults to every-hit (N = 1) over the wire.
func TestBreakpointBreakOnCounterDefault(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	callTool(t, client, "cpu_breakpoint_set", `{"cpu":"m68k","address":0,"break_on_counter":true}`)
	calls := client.recordedCalls
	if calls[0].Params["break_on_counter"] != "true" || calls[0].Params["break_counter"] != "1" {
		t.Fatalf("break_on_counter defaults wrong: %v", calls[0].Params)
	}
}

// TestBreakpointGreaterConditionPassthrough covers the non-range location
// conditions, which must not carry range_end.
func TestBreakpointGreaterConditionPassthrough(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	callTool(t, client, "cpu_breakpoint_set", `{"cpu":"m68k","address":"0x8000","condition":"greater"}`)
	calls := client.recordedCalls
	if calls[0].Params["condition"] != "greater" || calls[0].Params["range_end"] != "" {
		t.Fatalf("greater condition params wrong: %v", calls[0].Params)
	}
}
