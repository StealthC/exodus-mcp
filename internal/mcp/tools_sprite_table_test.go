package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------------------------------------------------
// vdp_sprite_table chain-vs-entries divergence (roadmap P1 "Atomic VDP
// capture"): chain_visible_count, table_entry_count, warning, and the paused
// read flag.
// ----------------------------------------------------------------------------------------------------------------------

// vdpSpritesPayload builds a sprite table where 15 entries are populated but
// the link chain renders only entries 0 and 5 (0 -> 5 -> 0).
func vdpSpritesPayload(t *testing.T) string {
	t.Helper()
	table := make([]byte, vdpSpriteTableMaxEntries*8)
	populate := func(index, link, tile int) {
		if index < 0 || index >= vdpSpriteTableMaxEntries {
			t.Fatalf("sprite index %d out of range", index)
		}
		offset := index * 8
		table[offset+0] = 0x00 // y raw 0 (off-screen top)
		table[offset+1] = 0x00
		table[offset+2] = byte(link) // w1 high byte: link occupies bits 8-14
		table[offset+3] = 0x00
		table[offset+4] = 0x00 // w2: tile in low 11 bits
		table[offset+5] = byte(tile)
		table[offset+6] = 0x00 // w3: x raw = 128 (on-screen origin)
		table[offset+7] = 0x80
	}
	populate(0, 5, 1)
	populate(5, 0, 6)
	for index := 1; index <= 4; index++ {
		populate(index, 0, index+1)
	}
	for index := 6; index <= 14; index++ {
		populate(index, 0, index+1)
	}
	return fmt.Sprintf(`{"data":"%s"}`, base64.StdEncoding.EncodeToString(table))
}

func vdpStatusForSpritePayload() string {
	return `{"vdp_found":true,"registers":[],"decoded":{"display_enabled":true,"extended_vram":false,"name_table_base_sprite":0}}`
}

func TestVdpSpriteTableReportsChainDivergence(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	spritePayload := vdpSpritesPayload(t)
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		switch method {
		case "vdp_status":
			return json.RawMessage(vdpStatusForSpritePayload()), nil
		case "vdp_mem_read":
			return json.RawMessage(spritePayload), nil
		}
		return json.RawMessage(`{}`), nil
	}
	result := callTool(t, client, "vdp_sprite_table", `{"offset":0,"count":16}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", result)
	}
	content := structured(result)
	if content["chain_visible_count"] != float64(2) {
		t.Fatalf("chain_visible_count = %v, want 2 (chain [0,5])", content["chain_visible_count"])
	}
	if content["table_entry_count"] != float64(15) {
		t.Fatalf("table_entry_count = %v, want 15 populated entries", content["table_entry_count"])
	}
	warning := content["warning"].(string)
	if !strings.Contains(warning, "link chain renders 2 of 15 entries") {
		t.Fatalf("warning must explain the divergence: %v", warning)
	}
}

func TestVdpSpriteTableConsistentChainHasNoWarning(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	table := make([]byte, vdpSpriteTableMaxEntries*8)
	// Two chained sprites: 0 -> 1 -> 0, and nothing else populated.
	for index, link := range map[int]int{0: 1, 1: 0} {
		offset := index * 8
		table[offset+2] = byte(link) // w1 high byte: link occupies bits 8-14
		table[offset+3] = 0x00
		table[offset+5] = byte(index + 1) // tile
		table[offset+7] = 0x80            // x raw 128
	}
	payload := fmt.Sprintf(`{"data":"%s"}`, base64.StdEncoding.EncodeToString(table))
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		switch method {
		case "vdp_status":
			return json.RawMessage(vdpStatusForSpritePayload()), nil
		case "vdp_mem_read":
			return json.RawMessage(payload), nil
		}
		return json.RawMessage(`{}`), nil
	}
	result := callTool(t, client, "vdp_sprite_table", `{"offset":0,"count":4}`)
	content := structured(result)
	if content["chain_visible_count"] != float64(2) {
		t.Fatalf("chain_visible_count = %v, want 2", content["chain_visible_count"])
	}
	if content["table_entry_count"] != float64(2) {
		t.Fatalf("table_entry_count = %v, want 2", content["table_entry_count"])
	}
	if content["warning"].(string) != "" {
		t.Fatalf("consistent chain must carry an empty warning: %v", content["warning"])
	}
}

func TestVdpSpriteTablePropagatesPausedFlag(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	spritePayload := vdpSpritesPayload(t)
	spritePayload = strings.Replace(spritePayload, `{"data":"`, `{"system_paused_during_read":true,"data":"`, 1)
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		switch method {
		case "vdp_status":
			return json.RawMessage(vdpStatusForSpritePayload()), nil
		case "vdp_mem_read":
			return json.RawMessage(spritePayload), nil
		}
		return json.RawMessage(`{}`), nil
	}
	result := callTool(t, client, "vdp_sprite_table", `{"offset":0,"count":2}`)
	content := structured(result)
	if content["system_paused_during_read"] != true {
		t.Fatalf("system_paused_during_read = %v, want true", content["system_paused_during_read"])
	}
}
