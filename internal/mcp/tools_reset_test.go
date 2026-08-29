package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

// TestTargetResetHardReloadsCurrentROM: with a known cartridge path,
// target_reset performs the documented same-path module reload (the shared
// rom_load mutation path) and reports the hard reset source.
func TestTargetResetHardReloadsCurrentROM(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "rom_load" {
			t.Fatalf("method = %s, want rom_load", method)
		}
		if params["path"] != `F:\roms\kid.bin` || params["run"] != "true" {
			t.Fatalf("params = %v", params)
		}
		return json.RawMessage(`{"loaded":true,"system_running":true}`), nil
	}
	server := newTestServer(t, client)
	server.setROMPath(`F:\roms\kid.bin`)

	before := server.target.Generation()
	result := postToolCall(t, server, "target_reset", `{"kind":"hard"}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("target_reset failed: %v", content)
	}
	if content["reset_source"] != "hard" {
		t.Fatalf("reset_source = %v, want hard", content["reset_source"])
	}
	if content["loaded"] != true || content["system_running"] != true {
		t.Fatalf("reset payload: %v", content)
	}
	if content["target_generation_before"] != float64(before) || content["target_generation_after"] != float64(before+1) {
		t.Fatalf("reset generations wrong: %v", content)
	}
	if server.currentROMPath() != `F:\roms\kid.bin` {
		t.Fatalf("rom path changed: %q", server.currentROMPath())
	}
}

// TestTargetResetWithoutROMFailsReadOnly: no known cartridge path is a
// read-only failure with no native action.
func TestTargetResetWithoutROMFailsReadOnly(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	server := newTestServer(t, client)

	result := postToolCall(t, server, "target_reset", `{"kind":"hard"}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "no_rom_loaded" {
		t.Fatalf("expected no_rom_loaded: %v", result)
	}
	if len(client.recordedCalls) != 0 {
		t.Fatalf("no native action expected, got %v", client.recordedCalls)
	}
}

// TestTargetResetSoftNotDelivered: kind "soft" is rejected with a clear
// message before any native action, and unknown kinds are invalid.
func TestTargetResetSoftNotDelivered(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	server := newTestServer(t, client)
	server.setROMPath(`F:\roms\kid.bin`)

	result := postToolCall(t, server, "target_reset", `{"kind":"soft"}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("expected invalid_params for soft: %v", result)
	}
	if len(client.recordedCalls) != 0 {
		t.Fatalf("no native action expected, got %v", client.recordedCalls)
	}

	result = postToolCall(t, server, "target_reset", `{"kind":"warm"}`)
	if content := structured(result); result["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("expected invalid_params for unknown kind: %v", result)
	}
}

// TestTargetResetGenerationPrecondition: a stale expected generation fails
// with target_generation_conflict and no native action.
func TestTargetResetGenerationPrecondition(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		t.Fatalf("no native action expected, got %s", method)
		return nil, nil
	}
	server := newTestServer(t, client)
	server.setROMPath(`F:\roms\kid.bin`)

	result := postToolCall(t, server, "target_reset", `{"kind":"hard","expected_target_generation":99}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "target_generation_conflict" {
		t.Fatalf("expected target_generation_conflict: %v", result)
	}
}

// TestTargetResetRequiresControlLock: while a control lock is held, a reset
// without the matching control_id fails before native execution.
func TestTargetResetRequiresControlLock(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	server := newTestServer(t, client)
	server.setROMPath(`F:\roms\kid.bin`)
	if _, err := server.controls.Acquire("test-holder", "", 60_000_000_000, server.target.Generation()); err != nil {
		t.Fatal(err)
	}

	result := postToolCall(t, server, "target_reset", `{"kind":"hard"}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "target_control_held" {
		t.Fatalf("expected target_control_held: %v", result)
	}
	if len(client.recordedCalls) != 0 {
		t.Fatalf("no native action expected, got %v", client.recordedCalls)
	}
}
