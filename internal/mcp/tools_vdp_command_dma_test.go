package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/bridge"
)

func TestVDPCommandDMAStatusUsesNativeObservation(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.status.SupportedOperations = append(client.status.SupportedOperations, "vdp_command_dma_status")
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method != "vdp_command_dma_status" {
			t.Fatalf("method = %s", method)
		}
		return json.RawMessage(`{"vdp_found":true,"registers":[],"command_latch":{"address":null,"observability":"unavailable"},"dma":{"enabled":true,"active":false,"length_counter":0}}`), nil
	}
	server := newTestServer(t, client)
	result := structured(postToolCall(t, server, "vdp_command_dma_status", `{}`))
	if result["schema_version"] != "vdp-command-dma/1" {
		t.Fatalf("schema = %v", result["schema_version"])
	}
	latch := result["command_latch"].(map[string]any)
	if latch["address"] != nil || latch["observability"] != "unavailable" {
		t.Fatalf("latch = %v", latch)
	}
}

func TestVDPCommandDMAStatusOldPluginIsUnsupported(t *testing.T) {
	client := &fakeBridgeClient{status: bridge.Status{ProtocolVersion: 2, SupportedOperations: []string{"status"}}}
	server := newTestServer(t, client)
	result := postToolCall(t, server, "vdp_command_dma_status", `{}`)
	if result["isError"] != true || structured(result)["code"] != "unsupported_plugin" {
		t.Fatalf("result = %v", result)
	}
}

func TestSoftResetUsesOnlyVersionedNativeOperation(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.status.SupportedOperations = append(client.status.SupportedOperations, "soft_reset")
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "soft_reset" {
			t.Fatalf("unexpected method %s", method)
		}
		if len(params) != 0 {
			t.Fatalf("params = %v", params)
		}
		return json.RawMessage(`{"reset_kind":"soft","reset_source":"hardware_reset_line","system_running":false,"ram_preserved":true,"vector_fetch":{"sp":16711680,"pc":4096,"byte_order":"big-endian","address_space":"m68k-bus"}}`), nil
	}
	server := newTestServer(t, client)
	result := structured(postToolCall(t, server, "target_reset", `{"kind":"soft"}`))
	if result["reset_source"] != "hardware_reset_line" || result["ram_preserved"] != true {
		t.Fatalf("result = %v", result)
	}
	vectors := result["vector_fetch"].(map[string]any)
	if vectors["sp"] != float64(0xFF0000) || vectors["pc"] != float64(0x1000) {
		t.Fatalf("vectors = %v", vectors)
	}
	if len(client.recordedCalls) != 1 || client.recordedCalls[0].Method != "soft_reset" {
		t.Fatalf("calls = %v", client.recordedCalls)
	}
}
