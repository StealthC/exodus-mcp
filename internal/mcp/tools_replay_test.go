package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// replayFake builds a bridge that answers the deterministic_replay flow:
// state_save writes a real file (so stat/hash succeed), state_load resets the
// per-run frame token counter, frame_advance returns monotonically increasing
// tokens within a run, and regs_get reports pc/a7/d0. nondeterministicRegs
// makes the second run's register snapshot differ from the first.
func replayFake(nondeterministicRegs bool) *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	frameToken := uint64(0)
	regsCalls := 0
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "state_save":
			if err := os.WriteFile(params["path"], []byte("state-bytes"), 0o644); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"saved":true}`), nil
		case "state_load":
			frameToken = 0 // state_load restores the VDP render counter
			return json.RawMessage(`{"loaded":true}`), nil
		case "input_set":
			return json.RawMessage(`{}`), nil
		case "frame_advance":
			frameToken++
			return json.RawMessage(fmt.Sprintf(`{"frames_requested":1,"frames_completed":1,"frame_token":%d,"system_running":false}`, frameToken)), nil
		case "regs_get":
			regsCalls++
			pc := uint64(0x200)
			if nondeterministicRegs && regsCalls == 2 {
				pc = 0x300
			}
			return json.RawMessage(fmt.Sprintf(`{"cpu":"m68k","byte_order":"not-applicable","system_paused_during_read":false,"registers":{"pc":%d,"a7":16776672,"d0":99},"flags":{},"width_bits":32}`, pc)), nil
		default:
			return json.RawMessage(`{}`), nil
		}
	}
	return client
}

func TestDeterministicReplayTrue(t *testing.T) {
	result := callTool(t, replayFake(false), "deterministic_replay",
		`{"steps":[{"inputs":{"1":["a","b"]},"frames":2},{"inputs":{"2":["start"]},"frames":1}],"context":""}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", structured(result))
	}
	content := structured(result)
	if content["deterministic"] != true {
		t.Fatalf("deterministic = %v, want true", content["deterministic"])
	}
	checks, _ := content["checks"].([]any)
	if len(checks) != 3 {
		t.Fatalf("checks = %v", checks)
	}
	for _, entry := range checks {
		check := entry.(map[string]any)
		if check["passed"] != true {
			t.Fatalf("check failed: %v", check)
		}
	}
	run1, _ := content["run_1"].(map[string]any)
	run2, _ := content["run_2"].(map[string]any)
	tokens1, _ := run1["frame_tokens"].([]any)
	tokens2, _ := run2["frame_tokens"].([]any)
	if len(tokens1) != 2 || tokens1[0] != float64(1) || tokens1[1] != float64(2) {
		t.Fatalf("run_1 tokens = %v", tokens1)
	}
	if len(tokens2) != 2 || tokens2[0] != float64(1) || tokens2[1] != float64(2) {
		t.Fatalf("run_2 tokens = %v", tokens2)
	}
	if content["frames_total"] != float64(3) || content["steps"] != float64(2) {
		t.Fatalf("summary = %v", content)
	}
	if content["restored"] != true {
		t.Fatalf("restored = %v, want true", content["restored"])
	}
	artifact, _ := content["artifact"].(map[string]any)
	if artifact["kind"] != "replay-manifest" {
		t.Fatalf("artifact kind = %v", artifact["kind"])
	}
	if content["initial_state_id"] == "" {
		t.Fatalf("initial_state_id missing from result")
	}
}

func TestDeterministicReplayFalseOnRegisterMismatch(t *testing.T) {
	result := callTool(t, replayFake(true), "deterministic_replay",
		`{"steps":[{"inputs":{"1":["a"]},"frames":1}]}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", structured(result))
	}
	content := structured(result)
	if content["deterministic"] != false {
		t.Fatalf("deterministic = %v, want false", content["deterministic"])
	}
	checks, _ := content["checks"].([]any)
	found := false
	for _, entry := range checks {
		check := entry.(map[string]any)
		if check["name"] == "final_registers_match" && check["passed"] == false {
			found = true
		}
	}
	if !found {
		t.Fatalf("register mismatch check missing: %v", checks)
	}
	artifact, _ := content["artifact"].(map[string]any)
	if artifact["kind"] != "replay-manifest" {
		t.Fatalf("mismatch still records a manifest? %v", artifact)
	}
}

func TestDeterministicReplayValidation(t *testing.T) {
	client := replayFake(false)
	result := callTool(t, client, "deterministic_replay", `{"steps":[{"frames":100}]}`)
	content := structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", content["code"])
	}
	result = callTool(t, replayFake(false), "deterministic_replay", `{"steps":[]}`)
	content = structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v for empty steps, want invalid_params", content["code"])
	}
	result = callTool(t, replayFake(false), "deterministic_replay", `{"steps":[{"inputs":{"1":["turbo"]}}]}`)
	content = structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v for unknown button, want invalid_params", content["code"])
	}
	result = callTool(t, replayFake(false), "deterministic_replay", `{"steps":[{"inputs":{"9":["a"]}}]}`)
	content = structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v for bad port, want invalid_params", content["code"])
	}
}

func TestDeterministicReplayUnknownInitialState(t *testing.T) {
	result := callTool(t, replayFake(false), "deterministic_replay",
		`{"initial_state_id":"missing","steps":[{"frames":1}]}`)
	content := structured(result)
	if content["code"] != "unknown_state" {
		t.Fatalf("code = %v, want unknown_state", content["code"])
	}
}
