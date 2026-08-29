package mcp

import (
	"testing"
)

// TestEmulatorStatusSurfacesDiscoveredROM: a cartridge loaded through the
// Exodus UI (not via the MCP rom_load bridge) is reported by the plugin from
// the loaded program module. The server must surface the honest path_source
// ("loaded_module") and adopt the discovered path as its ROM identity so
// provenance, staleness, and the rom_load reset recipe see the same path.
func TestEmulatorStatusSurfacesDiscoveredROM(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = emulatorStatusResponder(`{"system_running":true,"modules":[],"devices":[],"rom":{"loaded":true,"size_bytes":123456,"padded_size_bytes":0,"path":"C:\\ROMS\\kid.bin","path_source":"loaded_module"}}`)
	server := newTestServer(t, client)

	result := postToolCall(t, server, "emulator_status", `{}`)
	content := structured(result)
	rom, ok := content["rom"].(map[string]any)
	if !ok {
		t.Fatalf("rom = %v, want object", content["rom"])
	}
	if rom["path"] != `C:\ROMS\kid.bin` {
		t.Fatalf("rom.path = %v, want C:\\ROMS\\kid.bin", rom["path"])
	}
	if rom["path_source"] != "loaded_module" {
		t.Fatalf("rom.path_source = %v, want loaded_module", rom["path_source"])
	}
	if server.currentROMPath() != `C:\ROMS\kid.bin` {
		t.Fatalf("server rom path = %q, want the discovered cartridge path", server.currentROMPath())
	}
}

// TestEmulatorStatusDiscoveredROMClearsPathOnUnload: when no cartridge is
// loaded (no MCP rom_load ever ran and the program module is gone), the
// server's ROM identity must be cleared, not left pointing at a stale path.
func TestEmulatorStatusDiscoveredROMClearsPathOnUnload(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = emulatorStatusResponder(`{"system_running":false,"modules":[],"devices":[],"rom":{"loaded":false,"size_bytes":0,"padded_size_bytes":0,"path":"","path_source":"none"}}`)
	server := newTestServer(t, client)

	_ = postToolCall(t, server, "emulator_status", `{}`)
	if server.currentROMPath() != "" {
		t.Fatalf("server rom path = %q, want empty when no cartridge is loaded", server.currentROMPath())
	}
}
