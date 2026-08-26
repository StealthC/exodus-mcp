package mcp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/bridge"
)

func TestMetricsEndpointTracksCallsErrorsAndArtifacts(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: bridge.Status{ProtocolVersion: 2}})

	// target_info fails with unsupported_plugin (no supported operations);
	// context_create succeeds without touching the bridge.
	if structured(postToolCall(t, server, "target_info", "{}"))["code"] != "unsupported_plugin" {
		t.Fatal("expected target_info to fail with unsupported_plugin")
	}
	if structured(postToolCall(t, server, "context_create", `{"name":"research"}`))["code"] != nil {
		t.Fatal("expected context_create to succeed")
	}
	// Artifact creation must be observed through the shared store hook.
	if _, err := server.store.Put("ctx", "memory-dump", "application/octet-stream", []byte("x")); err != nil {
		t.Fatalf("put artifact: %v", err)
	}

	recorder := newRecorder()
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8768/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.status, http.StatusOK)
	}

	var body struct {
		Tools map[string]struct {
			Calls     uint64  `json:"calls"`
			Errors    uint64  `json:"errors"`
			ErrorRate float64 `json:"error_rate"`
		} `json:"tools"`
		Artifacts struct {
			ByKind map[string]uint64 `json:"by_kind"`
			Total  uint64            `json:"total"`
		} `json:"artifacts"`
		Totals struct {
			Calls  uint64 `json:"calls"`
			Errors uint64 `json:"errors"`
		} `json:"totals"`
	}
	if err := json.Unmarshal(recorder.body.Bytes(), &body); err != nil {
		t.Fatalf("decode metrics %s: %v", recorder.body.String(), err)
	}

	tool, present := body.Tools["target_info"]
	if !present {
		t.Fatalf("metrics missing target_info: %s", recorder.body.String())
	}
	if tool.Calls != 1 || tool.Errors != 1 || tool.ErrorRate != 1 {
		t.Fatalf("target_info metrics = %+v, want calls=1 errors=1 error_rate=1", tool)
	}
	tool, present = body.Tools["context_create"]
	if !present {
		t.Fatalf("metrics missing context_create: %s", recorder.body.String())
	}
	if tool.Calls != 1 || tool.Errors != 0 || tool.ErrorRate != 0 {
		t.Fatalf("context_create metrics = %+v, want calls=1 errors=0 error_rate=0", tool)
	}
	if body.Artifacts.ByKind["memory-dump"] != 1 || body.Artifacts.Total != 1 {
		t.Fatalf("artifacts = %+v, want memory-dump=1 total=1", body.Artifacts)
	}
	if body.Totals.Calls != 2 || body.Totals.Errors != 1 {
		t.Fatalf("totals = %+v, want calls=2 errors=1", body.Totals)
	}
}

func TestMetricsEndpointRequiresGet(t *testing.T) {
	recorder := newRecorder()
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8768/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	NewHandler("test").ServeHTTP(recorder, request)
	if recorder.status != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.status, http.StatusMethodNotAllowed)
	}
	if recorder.header.Get("Allow") != http.MethodGet {
		t.Fatalf("Allow = %q, want %q", recorder.header.Get("Allow"), http.MethodGet)
	}
}
