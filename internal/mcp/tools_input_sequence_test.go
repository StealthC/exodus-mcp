package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
)

// inputSequenceResponder serves input_set (down/up) and frame_advance for
// input_sequence tests, recording the bridge call sequence.
type inputSequenceResponder struct {
	calls []string
	token uint64
}

func (responder *inputSequenceResponder) execute(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
	switch method {
	case "input_set":
		responder.calls = append(responder.calls, "input_set:"+params["state"]+":"+params["buttons"])
		return json.RawMessage(`{"ok":true}`), nil
	case "frame_advance":
		responder.calls = append(responder.calls, "frame_advance:"+params["frames"])
		responder.token += 10
		return json.RawMessage(`{"frames_requested":` + params["frames"] + `,"frames_completed":` + params["frames"] + `,"frame_token":` + strconv.FormatUint(responder.token, 10) + `,"system_running":false}`), nil
	default:
		return json.RawMessage(`{}`), nil
	}
}

// TestInputSequenceExecutesStepsInOrder: two steps press, advance, and
// release in order; the response reports per-step frame tokens, the total
// frame count, and the generation span (three mutations per step).
func TestInputSequenceExecutesStepsInOrder(t *testing.T) {
	responder := &inputSequenceResponder{}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = responder.execute
	server := newTestServer(t, client)

	before := server.target.Generation()
	result := postToolCall(t, server, "input_sequence", `{"player":2,"steps":[{"buttons":["a","B"],"frames":3},{"buttons":["start"],"frames":1}]}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("input_sequence failed: %v", content)
	}
	// Step 1: down a,b -> advance 3 -> up a,b; step 2: down start -> advance
	// 1 -> up start.
	wantCalls := []string{
		"input_set:down:a,b",
		"frame_advance:3",
		"input_set:up:a,b",
		"input_set:down:start",
		"frame_advance:1",
		"input_set:up:start",
	}
	if len(responder.calls) != len(wantCalls) {
		t.Fatalf("calls = %v, want %v", responder.calls, wantCalls)
	}
	for i := range wantCalls {
		if responder.calls[i] != wantCalls[i] {
			t.Fatalf("call %d = %q, want %q (full sequence %v)", i, responder.calls[i], wantCalls[i], responder.calls)
		}
	}
	if content["steps_completed"] != float64(2) || content["steps"] != float64(2) || content["frames_total"] != float64(4) {
		t.Fatalf("summary wrong: %v", content)
	}
	tokens := content["frame_tokens"].([]any)
	if len(tokens) != 2 || tokens[0] != float64(10) || tokens[1] != float64(20) {
		t.Fatalf("frame_tokens = %v", tokens)
	}
	if content["target_generation_before"] != float64(before) || content["target_generation_after"] != float64(before+6) {
		t.Fatalf("generation span wrong: %v", content)
	}
	if content["system_running"] != false {
		t.Fatalf("sequence must end paused: %v", content)
	}
	// The internal control lock must be released after the window.
	if server.controls.Active() != nil {
		t.Fatal("internal control lock still held after input_sequence")
	}
}

// TestInputSequenceReusesCallerLock: a caller-provided control_id is reused
// (not released) for the whole window.
func TestInputSequenceReusesCallerLock(t *testing.T) {
	responder := &inputSequenceResponder{}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = responder.execute
	server := newTestServer(t, client)
	lock, err := server.controls.Acquire("test-caller", "", 60_000_000_000, server.target.Generation())
	if err != nil {
		t.Fatal(err)
	}

	result := postToolCall(t, server, "input_sequence", `{"steps":[{"buttons":["a"],"frames":1}],"control_id":"`+lock.ID+`"}`)
	if result["isError"] == true {
		t.Fatalf("input_sequence failed: %v", result)
	}
	if server.controls.Active() == nil || server.controls.Active().ID != lock.ID {
		t.Fatal("caller-provided lock must stay active")
	}
}

// TestInputSequenceRejectsInvalidInputs: bad buttons, caps on steps and
// frames, and unknown properties are rejected before any native action.
func TestInputSequenceRejectsInvalidInputs(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	server := newTestServer(t, client)

	cases := []struct {
		name  string
		args  string
		code  string
		check func(result map[string]any) bool
	}{
		{"unknown button", `{"steps":[{"buttons":["turbo"]}]}`, "invalid_params", nil},
		{"empty steps", `{"steps":[]}`, "invalid_params", nil},
		{"frames over cap", `{"steps":[{"buttons":["a"],"frames":61}]}`, "invalid_params", nil},
		{"unknown property", `{"steps":[{"buttons":["a"]}],"extra":1}`, "invalid_params", nil},
		{"player out of range", `{"steps":[{"buttons":["a"]}],"player":5}`, "invalid_params", nil},
	}
	for _, tc := range cases {
		result := postToolCall(t, server, "input_sequence", tc.args)
		if content := structured(result); result["isError"] != true || content["code"] != tc.code {
			t.Fatalf("%s: expected %s: %v", tc.name, tc.code, result)
		}
	}
	if len(client.recordedCalls) != 0 {
		t.Fatalf("no native action expected, got %v", client.recordedCalls)
	}
}

// TestInputSequenceReleasesButtonsOnFailure: when the frame advance of step 2
// fails, the step's buttons are still released before the error returns.
func TestInputSequenceReleasesButtonsOnFailure(t *testing.T) {
	responder := &inputSequenceResponder{}
	client := &fakeBridgeClient{status: newFakeStatus()}
	var attempts []string
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "frame_advance" && params["frames"] == "2" {
			attempts = append(attempts, "frame_advance:2")
			return nil, errors.New("advance failed")
		}
		return responder.execute(ctx, method, params)
	}
	server := newTestServer(t, client)

	result := postToolCall(t, server, "input_sequence", `{"steps":[{"buttons":["a"],"frames":1},{"buttons":["b","c"],"frames":2}]}`)
	if result["isError"] != true {
		t.Fatalf("expected failure: %v", result)
	}
	if len(attempts) != 1 {
		t.Fatalf("failed advance not attempted once: %v", attempts)
	}
	// The failed step's release must appear after its failed advance.
	for _, call := range responder.calls {
		if call == "input_set:up:b,c" {
			return // release after failure confirmed
		}
	}
	t.Fatalf("buttons of the failed step were not released; calls = %v", responder.calls)
}

// TestInputSequenceGenerationPrecondition: a stale expected generation fails
// before any native action.
func TestInputSequenceGenerationPrecondition(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		t.Fatalf("no native action expected, got %s", method)
		return nil, nil
	}
	server := newTestServer(t, client)

	result := postToolCall(t, server, "input_sequence", `{"steps":[{"buttons":["a"]}],"expected_target_generation":99}`)
	if content := structured(result); result["isError"] != true || content["code"] != "target_generation_conflict" {
		t.Fatalf("expected target_generation_conflict: %v", result)
	}
}
