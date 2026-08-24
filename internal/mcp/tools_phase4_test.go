package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/bridge"
)

// ----------------------------------------------------------------------------------------------------------------------
// Context leases
// ----------------------------------------------------------------------------------------------------------------------

func TestLeaseLifecycleThroughTools(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})

	acquired := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"boss fight"}`))
	if acquired["lease_id"] == "" {
		t.Fatalf("acquire returned no lease id: %v", acquired)
	}
	leaseID := acquired["lease_id"].(string)
	if acquired["purpose"] != "boss fight" {
		t.Fatalf("purpose not echoed: %v", acquired)
	}

	listed := structured(postToolCall(t, server, "context_lease_list", `{}`))
	leases := listed["leases"].([]any)
	if len(leases) != 1 || leases[0].(map[string]any)["lease_id"] != leaseID {
		t.Fatalf("unexpected lease list: %v", listed)
	}

	renewed := structured(postToolCall(t, server, "context_lease_renew", `{"lease_id":"`+leaseID+`"}`))
	if renewed["lease_id"] != leaseID {
		t.Fatalf("renew lost the lease id: %v", renewed)
	}

	released := structured(postToolCall(t, server, "context_lease_release", `{"lease_id":"`+leaseID+`"}`))
	if released["released"] != true {
		t.Fatalf("release failed: %v", released)
	}
	after := structured(postToolCall(t, server, "context_lease_list", `{}`))
	if len(after["leases"].([]any)) != 0 {
		t.Fatalf("lease should be gone: %v", after)
	}
}

func TestLeaseAcquireIsExclusive(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	first := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"a"}`))
	second := postToolCall(t, server, "context_lease_acquire", `{"purpose":"b"}`)
	content := structured(second)
	if second["isError"] != true || content["code"] != "lease_conflict" {
		t.Fatalf("second acquire must conflict: %v", second)
	}
	if !strings.Contains(content["message"].(string), first["lease_id"].(string)) {
		t.Fatalf("conflict message must name the owning lease: %v", content)
	}
}

func TestLeaseReleaseRequiresOwner(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	postToolCall(t, server, "context_lease_acquire", `{"purpose":"a"}`)
	release := postToolCall(t, server, "context_lease_release", `{"lease_id":"lease_wrong"}`)
	content := structured(release)
	if release["isError"] != true || content["code"] != "lease_invalid" {
		t.Fatalf("foreign release must be lease_invalid: %v", release)
	}
}

func TestLeaseToolsValidatePurposeAndTTL(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	empty := postToolCall(t, server, "context_lease_acquire", `{"purpose":""}`)
	if empty["isError"] != true || structured(empty)["code"] != "lease_conflict" {
		t.Fatalf("empty purpose must fail: %v", empty)
	}
	badTTL := postToolCall(t, server, "context_lease_acquire", `{"purpose":"x","ttl_ms":-1}`)
	if badTTL["isError"] != true || structured(badTTL)["code"] != "invalid_params" {
		t.Fatalf("negative ttl must fail: %v", badTTL)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Mutation guard
// ----------------------------------------------------------------------------------------------------------------------

func TestMutationToolsRequireLease(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	for _, test := range []struct {
		tool string
		args string
	}{
		{"memory_write", `{"space":"m68k-bus","address":0,"data":"AA=="}`},
		{"state_save", `{}`},
		{"state_load", `{"state_id":"state_x"}`},
		{"frame_advance", `{}`},
		{"input_set", `{"buttons":["a"],"state":"down"}`},
	} {
		result := postToolCall(t, server, test.tool, test.args)
		content := structured(result)
		if result["isError"] != true || content["code"] != "lease_required" {
			t.Fatalf("%s without a lease must be lease_required, got %v", test.tool, content)
		}
	}

	acquired := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"x"}`))
	leaseID := acquired["lease_id"].(string)
	wrong := postToolCall(t, server, "memory_write", `{"lease_id":"lease_wrong","space":"m68k-bus","address":0,"data":"AA=="}`)
	if content := structured(wrong); wrong["isError"] != true || content["code"] != "lease_invalid" {
		t.Fatalf("wrong lease id must be lease_invalid: %v", wrong)
	}
	ok := postToolCall(t, server, "memory_write", `{"lease_id":"`+leaseID+`","space":"m68k-bus","address":0,"data":"AA=="}`)
	if ok["isError"] == true {
		t.Fatalf("valid lease must pass: %v", ok)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_write
// ----------------------------------------------------------------------------------------------------------------------

func TestMemoryWriteEchoesAndRecordsAudit(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "mem_write" {
			t.Fatalf("method = %s, want mem_write", method)
		}
		if params["space"] != "m68k-bus" || params["address"] != "16711680" || params["length"] != "3" {
			t.Fatalf("params = %v", params)
		}
		if params["data"] != base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE}) {
			t.Fatalf("data = %s", params["data"])
		}
		return json.RawMessage(`{"space_id":"m68k-bus","kind":"bus","address":16711680,"effective_address":16711680,"length":3,"byte_order":"big-endian","encoding":"base64","consistency":"live","written":"3q2+","system_paused_during_write":true}`), nil
	}
	server := newTestServer(t, client)
	leaseID := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"ram patch"}`))["lease_id"].(string)
	data := base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE})
	result := postToolCall(t, server, "memory_write", `{"lease_id":"`+leaseID+`","space":"m68k-bus","address":"$FF0000","data":"`+data+`"}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", content)
	}
	if content["system_paused_during_write"] != true || content["length"] != float64(3) {
		t.Fatalf("payload not echoed: %v", content)
	}

	log := structured(postToolCall(t, server, "context_mutation_log", `{}`))
	entries := log["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("mutation log must have one entry: %v", log)
	}
	entry := entries[0].(map[string]any)
	if entry["tool"] != "memory_write" || entry["lease_id"] != leaseID {
		t.Fatalf("unexpected ledger entry: %v", entry)
	}
	detail := entry["detail"].(map[string]any)
	if detail["address"] != float64(16711680) || detail["length"] != float64(3) {
		t.Fatalf("ledger detail: %v", detail)
	}
}

func TestMemoryWriteValidatesInput(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	leaseID := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"x"}`))["lease_id"].(string)
	for _, test := range []struct {
		args string
		code string
	}{
		{`{"lease_id":"` + leaseID + `","space":"m68k-bus","address":0,"data":"not-base64!"}`, "invalid_params"},
		{`{"lease_id":"` + leaseID + `","space":"m68k-bus","address":0,"data":""}`, "invalid_params"},
		{`{"lease_id":"` + leaseID + `","space":"m68k-bus","address":-1,"data":"AA=="}`, "invalid_params"},
		{`{"lease_id":"` + leaseID + `","space":"","address":0,"data":"AA=="}`, "invalid_params"},
	} {
		result := postToolCall(t, server, "memory_write", test.args)
		if content := structured(result); result["isError"] != true || content["code"] != test.code {
			t.Fatalf("args %s: expected %s, got %v", test.args, test.code, content)
		}
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// state_save / state_load / state_list
// ----------------------------------------------------------------------------------------------------------------------

func TestStateSaveLoadListCycle(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "state_save":
			if params["path"] == "" {
				t.Fatal("state_save without a path")
			}
			if err := os.MkdirAll(filepath.Dir(params["path"]), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(params["path"], []byte("fake-savestate-bytes"), 0o644); err != nil {
				t.Fatal(err)
			}
			return json.RawMessage(`{"saved":true,"file_type":"zip","system_running":true}`), nil
		case "state_load":
			if params["path"] == "" {
				t.Fatal("state_load without a path")
			}
			return json.RawMessage(`{"loaded":true,"file_type":"zip","system_running":true}`), nil
		default:
			t.Fatalf("unexpected method %s", method)
			return nil, nil
		}
	}
	server := newTestServer(t, client)
	server.SetStatesDir(t.TempDir())
	leaseID := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"snapshot experiment"}`))["lease_id"].(string)

	saved := postToolCall(t, server, "state_save", `{"lease_id":"`+leaseID+`","name":"before-boss"}`)
	content := structured(saved)
	if saved["isError"] == true {
		t.Fatalf("state_save failed: %v", content)
	}
	stateID := content["state_id"].(string)
	if !strings.HasPrefix(stateID, "state_") {
		t.Fatalf("state id %q lacks prefix", stateID)
	}
	if content["sha256"] == "" || content["size_bytes"] != float64(len("fake-savestate-bytes")) {
		t.Fatalf("snapshot metadata missing: %v", content)
	}
	if content["system_running"] != true {
		t.Fatalf("plugin payload not merged: %v", content)
	}

	listed := structured(postToolCall(t, server, "state_list", `{}`))
	snapshots := listed["snapshots"].([]any)
	if len(snapshots) != 1 || snapshots[0].(map[string]any)["state_id"] != stateID {
		t.Fatalf("unexpected snapshot list: %v", listed)
	}
	if snapshots[0].(map[string]any)["name"] != "before-boss" {
		t.Fatalf("snapshot name missing: %v", snapshots[0])
	}

	loaded := postToolCall(t, server, "state_load", `{"lease_id":"`+leaseID+`","state_id":"`+stateID+`"}`)
	content = structured(loaded)
	if loaded["isError"] == true {
		t.Fatalf("state_load failed: %v", content)
	}
	if content["loaded"] != true || content["state_id"] != stateID {
		t.Fatalf("state_load payload: %v", content)
	}

	// State from another context must not resolve.
	createdOther := structured(postToolCall(t, server, "context_create", `{"name":"other"}`))
	otherID := createdOther["context"].(map[string]any)["id"].(string)
	otherLease := structured(postToolCall(t, server, "context_lease_acquire", `{"context":"`+otherID+`","purpose":"x"}`))["lease_id"].(string)
	missing := postToolCall(t, server, "state_load", `{"context":"`+otherID+`","lease_id":"`+otherLease+`","state_id":"`+stateID+`"}`)
	if content := structured(missing); missing["isError"] != true || content["code"] != "state_not_found" {
		t.Fatalf("cross-context load must fail: %v", missing)
	}

	// Releasing the lease must block further saves.
	postToolCall(t, server, "context_lease_release", `{"lease_id":"`+leaseID+`"}`)
	blocked := postToolCall(t, server, "state_save", `{"lease_id":"`+leaseID+`"}`)
	if content := structured(blocked); blocked["isError"] != true || content["code"] != "lease_required" {
		t.Fatalf("save after release must fail: %v", blocked)
	}
}

func TestStateLoadUnknownSnapshot(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	leaseID := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"x"}`))["lease_id"].(string)
	result := postToolCall(t, server, "state_load", `{"lease_id":"`+leaseID+`","state_id":"state_missing"}`)
	if content := structured(result); result["isError"] != true || content["code"] != "state_not_found" {
		t.Fatalf("expected state_not_found: %v", result)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// frame_advance and input_set
// ----------------------------------------------------------------------------------------------------------------------

func TestFrameAdvance(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "frame_advance" {
			t.Fatalf("method = %s", method)
		}
		if params["frames"] != "3" {
			t.Fatalf("frames = %v", params)
		}
		return json.RawMessage(`{"frames_requested":3,"frames_completed":3,"frame_token":1042,"system_running":false}`), nil
	}
	server := newTestServer(t, client)
	leaseID := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"frame walk"}`))["lease_id"].(string)
	result := postToolCall(t, server, "frame_advance", `{"lease_id":"`+leaseID+`","frames":3}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("frame_advance failed: %v", content)
	}
	if content["frame_token"] != float64(1042) {
		t.Fatalf("frame token not echoed: %v", content)
	}

	overCap := postToolCall(t, server, "frame_advance", `{"lease_id":"`+leaseID+`","frames":61}`)
	if content := structured(overCap); overCap["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("frames over cap must fail: %v", overCap)
	}
}

func TestInputSetNormalizesAndValidates(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "input_set" {
			t.Fatalf("method = %s", method)
		}
		if params["player"] != "2" || params["buttons"] != "a,start" || params["state"] != "down" {
			t.Fatalf("params = %v", params)
		}
		return json.RawMessage(`{"player":2,"buttons":["a","start"],"state":"down","controller_instance":"Controller","button_count":2}`), nil
	}
	server := newTestServer(t, client)
	leaseID := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"input"}`))["lease_id"].(string)
	result := postToolCall(t, server, "input_set", `{"lease_id":"`+leaseID+`","player":2,"buttons":["A","START"],"state":"down"}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("input_set failed: %v", content)
	}
	if content["button_count"] != float64(2) {
		t.Fatalf("payload not echoed: %v", content)
	}

	badButton := postToolCall(t, server, "input_set", `{"lease_id":"`+leaseID+`","buttons":["turbo"],"state":"down"}`)
	if content := structured(badButton); badButton["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("unknown button must fail: %v", badButton)
	}
	badState := postToolCall(t, server, "input_set", `{"lease_id":"`+leaseID+`","buttons":["a"],"state":"tap"}`)
	if content := structured(badState); badState["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("tap state must fail: %v", badState)
	}
}

func TestControllerMissingSurfacesPluginError(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(context.Context, string, map[string]string) (json.RawMessage, error) {
		return nil, &bridge.CommandError{Code: "controller_not_found", Message: "No controller device is connected to player port 1"}
	}
	server := newTestServer(t, client)
	leaseID := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"input"}`))["lease_id"].(string)
	result := postToolCall(t, server, "input_set", `{"lease_id":"`+leaseID+`","buttons":["a"],"state":"down"}`)
	if content := structured(result); result["isError"] != true || content["code"] != "controller_not_found" {
		t.Fatalf("expected controller_not_found: %v", result)
	}
}

func TestPhase4ToolsRejectUnknownContext(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	leaseID := structured(postToolCall(t, server, "context_lease_acquire", `{"purpose":"x"}`))["lease_id"].(string)
	result := postToolCall(t, server, "memory_write", `{"context":"ctx_bogus","lease_id":"`+leaseID+`","space":"m68k-bus","address":0,"data":"AA=="}`)
	if content := structured(result); result["isError"] != true || content["code"] != "unknown_context" {
		t.Fatalf("expected unknown_context: %v", result)
	}
}

func TestLeasesScopedToContexts(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	first := structured(postToolCall(t, server, "context_create", `{"name":"one"}`))["context"].(map[string]any)
	second := structured(postToolCall(t, server, "context_create", `{"name":"two"}`))["context"].(map[string]any)
	postToolCall(t, server, "context_lease_acquire", `{"context":"`+first["id"].(string)+`","purpose":"a"}`)
	acquired := structured(postToolCall(t, server, "context_lease_acquire", `{"context":"`+second["id"].(string)+`","purpose":"b"}`))
	if acquired["lease_id"] == "" {
		t.Fatalf("independent contexts must hold independent leases: %v", acquired)
	}
}

func TestContextCloseReleasesLeaseThroughTools(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	created := structured(postToolCall(t, server, "context_create", `{"name":"temp"}`))["context"].(map[string]any)
	contextID := created["id"].(string)
	leaseID := structured(postToolCall(t, server, "context_lease_acquire", `{"context":"`+contextID+`","purpose":"a"}`))["lease_id"].(string)
	postToolCall(t, server, "context_close", `{"context_id":"`+contextID+`"}`)
	if server.contexts.Leases.Active(contextID) != nil {
		t.Fatal("closing the context must release its lease")
	}
	_ = leaseID
	_ = analysis.NewSnapshotID
}
