package mcp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/bridge"
)

// memReadFromBlob serves mem_read requests from one in-memory blob anchored at
// a base address, mirroring the plugin payload shape for processor bus spaces.
func memReadFromBlob(blob []byte, baseAddress uint64) func(context.Context, string, map[string]string) (json.RawMessage, error) {
	return func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "mem_read" {
			return nil, fmt.Errorf("unexpected method %s", method)
		}
		address, err := strconv.ParseUint(params["address"], 10, 64)
		if err != nil {
			return nil, err
		}
		length, err := strconv.ParseUint(params["length"], 10, 64)
		if err != nil {
			return nil, err
		}
		if address < baseAddress {
			return nil, fmt.Errorf("address %d below fixture base %d", address, baseAddress)
		}
		start := address - baseAddress
		if start+length > uint64(len(blob)) {
			return nil, fmt.Errorf("range out of fixture: addr=%d len=%d base=%d blob=%d", address, length, baseAddress, len(blob))
		}
		data := blob[start : start+length]
		payload := fmt.Sprintf(`{"space_id":"m68k-bus","kind":"bus","address":%d,"effective_address":%d,"length":%d,"byte_order":"big-endian","encoding":"base64","consistency":"live","data":%q}`,
			address, address, length, base64.StdEncoding.EncodeToString(data))
		return json.RawMessage(payload), nil
	}
}

func countCalls(client *fakeBridgeClient, method string) int {
	count := 0
	for _, call := range client.recordedCalls {
		if call.Method == method {
			count++
		}
	}
	return count
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_search
// ----------------------------------------------------------------------------------------------------------------------

func TestMemorySearchFindsMatchesAndArtifact(t *testing.T) {
	blob := []byte{0x00, 0x53, 0x45, 0x47, 0x41, 0x00, 0x53, 0x45, 0x47, 0x41} // "SEGA" at offsets 1 and 6
	client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadFromBlob(blob, 0x100)}
	result := callTool(t, client, "memory_search", `{"space":"m68k-bus","pattern":"53454741","start_address":"0x100","length":10}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", result)
	}
	content := structured(result)
	summary := content["summary"].(map[string]any)
	if summary["matches_total"] != float64(2) {
		t.Fatalf("matches_total = %v, want 2", summary["matches_total"])
	}
	if summary["searched_start_address"] != float64(0x100) || summary["searched_byte_length"] != float64(10) {
		t.Fatalf("range summary wrong: %v", summary)
	}
	matches := content["matches"].([]any)
	if len(matches) != 2 {
		t.Fatalf("inline matches = %v", matches)
	}
	first := matches[0].(map[string]any)
	if first["address"] != float64(0x101) || first["address_hex"] != "0x101" {
		t.Fatalf("first match address wrong: %v", first)
	}
	second := matches[1].(map[string]any)
	if second["address"] != float64(0x106) {
		t.Fatalf("second match address wrong: %v", second)
	}
	artifactDesc := content["artifact"].(map[string]any)
	if artifactDesc["kind"] != "memory-search-results" || artifactDesc["mime_type"] != "application/json" {
		t.Fatalf("results artifact wrong: %v", artifactDesc)
	}
	if len(client.recordedCalls) != 1 || client.recordedCalls[0].Method != "mem_read" {
		t.Fatalf("expected exactly one mem_read: %v", client.recordedCalls)
	}
}

func TestMemorySearchTruncatesInlineMatches(t *testing.T) {
	blob := make([]byte, 16)
	for index := 0; index < 8; index++ {
		blob[index*2] = 0xAB
		blob[index*2+1] = 0xCD
	}
	client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadFromBlob(blob, 0)}
	result := callTool(t, client, "memory_search", `{"space":"m68k-bus","pattern":"abcd","length":16,"max_matches":2}`)
	content := structured(result)
	summary := content["summary"].(map[string]any)
	if summary["matches_total"] != float64(8) {
		t.Fatalf("matches_total = %v, want 8", summary["matches_total"])
	}
	if summary["inline_matches_shown"] != float64(2) || summary["matches_truncated"] != true {
		t.Fatalf("truncation flags wrong: %v", summary)
	}
	if len(content["matches"].([]any)) != 2 {
		t.Fatalf("inline matches not bounded: %v", content["matches"])
	}
}

func TestMemorySearchSnapshotModeSkipsBridge(t *testing.T) {
	blob := []byte("xxABABzz")
	client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadFromBlob(blob, 0)}
	server := newTestServer(t, client)

	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"m68k-bus","address":0,"length":8}`))
	artifactID := dump["artifact"].(map[string]any)["id"].(string)
	memCalls := countCalls(client, "mem_read")
	if memCalls != 1 {
		t.Fatalf("dump should issue one mem_read, got %d", memCalls)
	}

	search := postToolCall(t, server, "memory_search", fmt.Sprintf(`{"space":"m68k-bus","pattern":"41 42","snapshot_id":%q}`, artifactID))
	content := structured(search)
	sum := content["summary"].(map[string]any)
	if sum["matches_total"] != float64(2) {
		t.Fatalf("matches_total = %v, want 2", sum["matches_total"])
	}
	snapshot, _ := sum["snapshot"].(map[string]any)
	if snapshot["id"] != artifactID {
		t.Fatalf("snapshot descriptor should reference the searched artifact: %v", snapshot)
	}
	if got := countCalls(client, "mem_read"); got != memCalls {
		t.Fatalf("snapshot search must not read the bridge again (mem_read grew %d -> %d)", memCalls, got)
	}
}

func TestMemorySearchSnapshotMismatch(t *testing.T) {
	blob := []byte{1, 2, 3, 4}
	client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadFromBlob(blob, 0)}
	server := newTestServer(t, client)
	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"m68k-bus","address":0,"length":4}`))
	artifactID := dump["artifact"].(map[string]any)["id"].(string)
	result := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"space":"m68k-bus","pattern":"01","snapshot_id":%q,"length":3}`, artifactID)))
	if result["code"] != "invalid_params" {
		t.Fatalf("length mismatch must be rejected: %v", result)
	}
}

func TestMemorySearchRejectsBadPatterns(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	for _, arguments := range []string{
		`{"space":"m68k-bus","pattern":""}`,
		`{"space":"m68k-bus","pattern":"123"}`,
		`{"space":"m68k-bus","pattern":"zz"}`,
		`{"pattern":"4142"}`,
		`{"space":"m68k-bus","pattern":"41","length":9000000}`,
	} {
		result := structured(callTool(t, client, "memory_search", arguments))
		if result["code"] != "invalid_params" && result["code"] != "length_out_of_range" {
			t.Fatalf("%s: code = %v (%v)", arguments, result["code"], result)
		}
	}
	if len(client.recordedCalls) != 0 {
		t.Fatalf("invalid requests must not reach the bridge: %v", client.recordedCalls)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_diff
// ----------------------------------------------------------------------------------------------------------------------

// memReadSequence serves mem_read requests from successive blobs anchored at
// one base address; the final blob repeats once the list is exhausted.
func memReadSequence(blobs [][]byte, baseAddress uint64) func(context.Context, string, map[string]string) (json.RawMessage, error) {
	index := 0
	return func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		blob := blobs[index]
		if index < len(blobs)-1 {
			index++
		}
		return memReadFromBlob(blob, baseAddress)(ctx, method, params)
	}
}

// diffSnapshotIDs dumps the given space twice and returns both artifact ids
// plus the server, mirroring the cheat-finder workflow of two consistent
// snapshots around an action.
func diffSnapshotIDs(t *testing.T, client *fakeBridgeClient, blobs [][]byte, base uint64) (*Server, string, string) {
	t.Helper()
	server := newTestServer(t, client)
	first := structured(postToolCall(t, server, "memory_dump", fmt.Sprintf(`{"space":"m68k-bus","address":%d,"length":%d}`, base, len(blobs[0]))))
	beforeID := first["artifact"].(map[string]any)["id"].(string)
	second := structured(postToolCall(t, server, "memory_dump", fmt.Sprintf(`{"space":"m68k-bus","address":%d,"length":%d}`, base, len(blobs[len(blobs)-1]))))
	afterID := second["artifact"].(map[string]any)["id"].(string)
	return server, beforeID, afterID
}

func TestMemoryDiffChangedWordBigEndian(t *testing.T) {
	before := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	after := append([]byte{}, before...)
	after[4], after[5] = 0x40, 0x41 // word at offset 4: 0x0405 -> 0x4041
	after[12] = 0xFE                // word at offset 12: 0x0C0D -> 0xFE0D
	client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadSequence([][]byte{before, after}, 0xFF0000)}
	server, beforeID, afterID := diffSnapshotIDs(t, client, [][]byte{before, after}, 0xFF0000)

	result := postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed","width":"word","start_address":"0xFF0000"}`, beforeID, afterID))
	content := structured(result)
	if content["code"] != nil {
		t.Fatalf("unexpected error: %v", result)
	}
	summary := content["summary"].(map[string]any)
	if summary["matches_total"] != float64(2) {
		t.Fatalf("matches_total = %v, want 2", summary["matches_total"])
	}
	if summary["width"] != "word" || summary["byte_order"] != "big-endian" {
		t.Fatalf("width/byte order wrong: %v", summary)
	}
	rangeInfo := summary["range"].(map[string]any)
	if rangeInfo["cells_scanned"] != float64(8) || rangeInfo["trailing_bytes_ignored"] != float64(0) {
		t.Fatalf("range info wrong: %v", rangeInfo)
	}
	matches := content["matches"].([]any)
	if len(matches) != 2 {
		t.Fatalf("inline matches = %v", matches)
	}
	first := matches[0].(map[string]any)
	if first["address"] != float64(0xFF0004) || first["before"] != float64(0x0405) || first["after"] != float64(0x4041) || first["delta"] != float64(0x3C3C) {
		t.Fatalf("first match wrong: %v", first)
	}
	second := matches[1].(map[string]any)
	if second["address"] != float64(0xFF000C) || second["before"] != float64(0x0C0D) || second["after"] != float64(0xFE0D) || second["delta"] != float64(0xF200) {
		t.Fatalf("second match wrong: %v", second)
	}
	artifactDesc := content["artifact"].(map[string]any)
	if artifactDesc["kind"] != "memory-diff-results" {
		t.Fatalf("results artifact wrong: %v", artifactDesc)
	}
	// The full-results artifact records every match.
	records, _, err := server.store.Bytes(artifactDesc["id"].(string), server.contexts.Default().ID)
	if err != nil {
		t.Fatalf("read results artifact: %v", err)
	}
	var document struct {
		Matches []map[string]any `json:"matches"`
		Total   uint64           `json:"matches_total"`
	}
	if err := json.Unmarshal(records, &document); err != nil {
		t.Fatalf("decode results artifact: %v", err)
	}
	if document.Total != 2 || len(document.Matches) != 2 {
		t.Fatalf("artifact records wrong: %+v", document)
	}
	if got := countCalls(client, "mem_read"); got != 2 {
		t.Fatalf("expected exactly two mem_read calls (two dumps), got %d", got)
	}
}

func TestMemoryDiffFreshAfterRead(t *testing.T) {
	before := []byte{1, 1, 1, 1}
	after := []byte{1, 2, 1, 2}
	client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadSequence([][]byte{before, after}, 0)}
	server := newTestServer(t, client)
	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"m68k-bus","address":0,"length":4}`))
	beforeID := dump["artifact"].(map[string]any)["id"].(string)

	result := postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"mode":"unchanged","space":"m68k-bus","start_address":0}`, beforeID))
	content := structured(result)
	if content["code"] != nil {
		t.Fatalf("unexpected error: %v", result)
	}
	summary := content["summary"].(map[string]any)
	if summary["matches_total"] != float64(2) {
		t.Fatalf("unchanged matches = %v, want 2 (offsets 0 and 2)", summary["matches_total"])
	}
	if summary["fresh_after_read"] != true {
		t.Fatalf("fresh after read not reported: %v", summary)
	}
	if got := countCalls(client, "mem_read"); got != 2 {
		t.Fatalf("expected one dump plus one fresh read (2 mem_read total), got %d", got)
	}
	afterSnapshot := summary["after_snapshot"].(map[string]any)
	if afterSnapshot["kind"] != "memory-snapshot" {
		t.Fatalf("fresh snapshot kind wrong: %v", afterSnapshot)
	}
}

func TestMemoryDiffModes(t *testing.T) {
	before := []byte{5, 5, 5, 7, 9, 9, 9, 255, 1, 2, 3, 4}
	after := []byte{5, 6, 4, 7, 8, 9, 10, 254, 1, 2, 33, 4}
	cases := []struct {
		mode     string
		extra    string
		expected []int
	}{
		{mode: "changed", expected: []int{1, 2, 4, 6, 7, 10}},
		{mode: "unchanged", expected: []int{0, 3, 5, 8, 9, 11}},
		{mode: "increased", expected: []int{1, 6, 10}},
		{mode: "decreased", expected: []int{2, 4, 7}},
		{mode: "changed_by", extra: `,"value":1`, expected: []int{1, 6}},
		{mode: "changed_by", extra: `,"value":-1`, expected: []int{2, 4, 7}},
		{mode: "equal_to", extra: `,"value":5`, expected: []int{0}},
		{mode: "in_range", extra: `,"min_value":8,"max_value":10`, expected: []int{4, 5, 6}},
	}
	for _, tc := range cases {
		client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadSequence([][]byte{before, after}, 0)}
		server, beforeID, afterID := diffSnapshotIDs(t, client, [][]byte{before, after}, 0)
		result := postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":%q,"start_address":0%s}`, beforeID, afterID, tc.mode, tc.extra))
		content := structured(result)
		if content["code"] != nil {
			t.Fatalf("%s: unexpected error: %v", tc.mode, result)
		}
		summary := content["summary"].(map[string]any)
		if summary["matches_total"] != float64(len(tc.expected)) {
			t.Fatalf("%s: matches_total = %v, want %d (matches: %v)", tc.mode, summary["matches_total"], len(tc.expected), content["matches"])
		}
		matches := content["matches"].([]any)
		if len(matches) != len(tc.expected) {
			t.Fatalf("%s: inline matches = %v", tc.mode, matches)
		}
		for index, match := range matches {
			address := match.(map[string]any)["address"].(float64)
			if address != float64(tc.expected[index]) {
				t.Fatalf("%s: match %d address = %v, want %d", tc.mode, index, address, tc.expected[index])
			}
		}
	}
}

func TestMemoryDiffAlignment(t *testing.T) {
	before := []byte{0x00, 0x00, 0x00, 0x00}
	after := []byte{0x00, 0x00, 0x01, 0x00}
	client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadSequence([][]byte{before, after}, 0)}
	server, beforeID, afterID := diffSnapshotIDs(t, client, [][]byte{before, after}, 0)

	aligned := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed","width":"word","start_address":0}`, beforeID, afterID)))
	if aligned["code"] != nil {
		t.Fatalf("aligned diff failed: %v", aligned)
	}
	if aligned["summary"].(map[string]any)["matches_total"] != float64(1) {
		t.Fatalf("aligned word scan should see only the even cell (offset 2): %v", aligned["summary"])
	}
	if aligned["summary"].(map[string]any)["alignment"] != "aligned-to-width" {
		t.Fatalf("alignment policy not reported: %v", aligned["summary"])
	}

	misaligned := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed","width":"word","start_address":0,"allow_misaligned":true}`, beforeID, afterID)))
	if misaligned["summary"].(map[string]any)["matches_total"] != float64(2) {
		t.Fatalf("misaligned scan should also see the odd cell (offset 1): %v", misaligned["summary"])
	}
	if misaligned["summary"].(map[string]any)["alignment"] != "misaligned-scan" {
		t.Fatalf("alignment policy not reported: %v", misaligned["summary"])
	}
}

func TestMemoryDiffInlineTruncation(t *testing.T) {
	before := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	after := []byte{1, 1, 1, 1, 1, 1, 1, 1}
	client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadSequence([][]byte{before, after}, 0)}
	server, beforeID, afterID := diffSnapshotIDs(t, client, [][]byte{before, after}, 0)

	result := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed","max_matches":2}`, beforeID, afterID)))
	summary := result["summary"].(map[string]any)
	if summary["matches_total"] != float64(8) || summary["inline_matches_shown"] != float64(2) || summary["matches_truncated"] != true {
		t.Fatalf("truncation flags wrong: %v", summary)
	}
	if len(result["matches"].([]any)) != 2 {
		t.Fatalf("inline matches not bounded: %v", result["matches"])
	}
}

func TestMemoryDiffValidation(t *testing.T) {
	blob := []byte{1, 2, 3, 4}
	client := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadSequence([][]byte{blob, blob}, 0)}
	server, beforeID, afterID := diffSnapshotIDs(t, client, [][]byte{blob, blob}, 0)
	shortClient := &fakeBridgeClient{status: newFakeStatus(), executeFunc: memReadSequence([][]byte{blob, []byte{0, 0, 0, 0, 0, 0, 0, 0}}, 0)}
	shortServer, shortBefore, shortAfter := diffSnapshotIDs(t, shortClient, [][]byte{blob, []byte{0, 0, 0, 0, 0, 0, 0, 0}}, 0)

	cases := []struct {
		name      string
		server    *Server
		arguments string
		code      string
	}{
		{"missing before", server, `{"mode":"changed"}`, "invalid_params"},
		{"bad mode", server, fmt.Sprintf(`{"snapshot_before_id":%q,"mode":"frobbed"}`, beforeID), "invalid_params"},
		{"bad width", server, fmt.Sprintf(`{"snapshot_before_id":%q,"mode":"changed","width":"dword"}`, beforeID), "invalid_params"},
		{"bad byte order", server, fmt.Sprintf(`{"snapshot_before_id":%q,"mode":"changed","byte_order":"middle"}`, beforeID), "invalid_params"},
		{"equal_to without value", server, fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"equal_to"}`, beforeID, afterID), "invalid_params"},
		{"equal_to out of range", server, fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"equal_to","value":300,"width":"byte"}`, beforeID, afterID), "invalid_params"},
		{"changed_by without value", server, fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed_by"}`, beforeID, afterID), "invalid_params"},
		{"in_range without bounds", server, fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"in_range"}`, beforeID, afterID), "invalid_params"},
		{"in_range inverted", server, fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"in_range","min_value":5,"max_value":2}`, beforeID, afterID), "invalid_params"},
		{"length mismatch", shortServer, fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed"}`, shortBefore, shortAfter), "invalid_params"},
		{"fresh read without space", server, fmt.Sprintf(`{"snapshot_before_id":%q,"mode":"changed"}`, beforeID), "invalid_params"},
		{"unknown artifact", server, `{"snapshot_before_id":"art_nope","mode":"changed"}`, "unknown_artifact"},
	}
	for _, tc := range cases {
		result := structured(postToolCall(t, tc.server, "memory_diff", tc.arguments))
		if result["code"] != tc.code {
			t.Fatalf("%s: code = %v (%v)", tc.name, result["code"], result)
		}
	}
	// Validation failures must never reach the bridge.
	if got := countCalls(shortClient, "mem_read"); got != 2 {
		t.Fatalf("validation runs should not read the bridge: mem_read = %d", got)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// rom_info
// ----------------------------------------------------------------------------------------------------------------------

type mdROMFixture struct {
	Header []byte
	Body   []byte
	// FileSize is the total cartridge size (header 0x100 + body).
	FileSize uint64
}

// buildMDROMFixture assembles a 256-byte header plus a body of known content.
// The stored checksum is computed by the caller so tests can flip it.
func buildMDROMFixture(body []byte) *mdROMFixture {
	header := make([]byte, 0x100)
	copy(header[0x00:0x10], "SEGA MEGA DRIVE ")
	copy(header[0x10:0x20], "(C)SEGA 1992.SEP ")
	copy(header[0x20:0x50], "TEST GAME")
	copy(header[0x50:0x80], "TEST GAME WORLDWIDE")
	copy(header[0x80:0x8E], "GM 1234567-01")
	// checksum at 0x8E set by caller
	copy(header[0x90:0xA0], "J6              ")
	binary.BigEndian.PutUint32(header[0xA0:0xA4], 0)
	// The ROM file spans 0x000000-0x0001FF (vector table + header) plus the
	// body from 0x200, so the checksum body is [0x200, fileSize).
	fileSize := uint64(0x200) + uint64(len(body))
	binary.BigEndian.PutUint32(header[0xA4:0xA8], uint32(fileSize-1))
	binary.BigEndian.PutUint32(header[0xA8:0xAC], 0xFF0000)
	binary.BigEndian.PutUint32(header[0xAC:0xB0], 0xFFFFFF)
	copy(header[0xB0:0xB2], "RA")
	header[0xB2] = 0x80 // backup flag
	header[0xB3] = 0x00 // word access
	binary.BigEndian.PutUint32(header[0xB4:0xB8], 0x200000)
	binary.BigEndian.PutUint32(header[0xB8:0xBC], 0x203FFF)
	copy(header[0xBC:0xC8], "              ")
	copy(header[0xC8:0xF0], "MEMO                             ")
	copy(header[0xF0:0xF3], "JUE")
	return &mdROMFixture{Header: header, Body: body, FileSize: fileSize}
}

// romInfoClient serves emulator_status (with the ROM size) plus header/body
// mem_read from one fixture, mirroring the loaded ROM layout at 0x100.
func romInfoClient(fixture *mdROMFixture, storedChecksum uint16, romSize uint64) *fakeBridgeClient {
	binary.BigEndian.PutUint16(fixture.Header[0x8E:0x90], storedChecksum)
	full := append(append([]byte{}, fixture.Header...), fixture.Body...)
	if romSize == 0 {
		romSize = fixture.FileSize
	}
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "emulator_status":
			payload := fmt.Sprintf(`{"system_running":true,"modules":[{"id":1,"display_name":"ROM","instance_name":"ROM"}],"devices":[],"rom":{"loaded":true,"size_bytes":%d,"padded_size_bytes":%d,"path":"F:\\roms\\kid.bin"}}`, romSize, romSize)
			return json.RawMessage(payload), nil
		case "mem_read":
			return memReadFromBlob(full, 0x100)(ctx, method, params)
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	return client
}

func TestROMInfoParsesHeaderAndChecksum(t *testing.T) {
	body := make([]byte, 0x600)
	for index := range body {
		body[index] = byte(index * 7)
	}
	fixture := buildMDROMFixture(body)
	expected := computeSegaChecksum(body)
	client := romInfoClient(fixture, expected, 0)
	server := newTestServer(t, client)

	call := postToolCall(t, server, "rom_info", `{}`)
	if call["isError"] == true {
		t.Fatalf("unexpected error: %v", call)
	}
	content := structured(call)
	if content["identified"] != true {
		t.Fatalf("not identified: %v", content)
	}
	header := content["header"].(map[string]any)
	if header["system_type"] != "SEGA MEGA DRIVE" {
		t.Fatalf("system_type wrong: %v", header["system_type"])
	}
	if header["overseas_name"] != "TEST GAME WORLDWIDE" || header["domestic_name"] != "TEST GAME" {
		t.Fatalf("names wrong: %v", header)
	}
	if header["copyright"] != "(C)SEGA 1992.SEP" {
		t.Fatalf("copyright wrong: %v", header["copyright"])
	}
	serial := header["serial"].(map[string]any)
	if serial["raw"] != "GM 1234567-01" || serial["catalog_number"] != "1234567" || serial["version"] != "01" || serial["product_type"] != "GM" {
		t.Fatalf("serial decode wrong: %v", serial)
	}
	checksum := header["checksum"].(map[string]any)
	if checksum["stored"] != float64(expected) || checksum["computed"] != float64(expected) || checksum["matches"] != true {
		t.Fatalf("checksum decode wrong: %v", checksum)
	}
	ioSupport := header["io_support"].([]any)
	if len(ioSupport) != 2 {
		t.Fatalf("io support length wrong: %v", ioSupport)
	}
	firstIO := ioSupport[0].(map[string]any)
	if !strings.Contains(firstIO["device"].(string), "Joypad") {
		t.Fatalf("io support decode wrong: %v", firstIO)
	}
	backup := header["backup_ram"].(map[string]any)
	if backup["present"] != true || !strings.Contains(backup["type"].(string), "word") ||
		backup["start_address"] != float64(0x200000) || backup["end_address"] != float64(0x203FFF) {
		t.Fatalf("backup ram decode wrong: %v", backup)
	}
	region := header["region"].(map[string]any)
	countries := region["countries"].([]any)
	if len(countries) != 3 {
		t.Fatalf("region countries wrong: %v", region)
	}
	mapping := content["mapping"].(map[string]any)
	if len(mapping["reference"].([]any)) != 9 {
		t.Fatalf("reference mapping wrong: %v", mapping)
	}

	artifactDesc := content["artifact"].(map[string]any)
	if artifactDesc["kind"] != "rom-header" {
		t.Fatalf("header artifact wrong: %v", artifactDesc)
	}
	preview := structured(postToolCall(t, server, "artifact_preview", fmt.Sprintf(`{"artifact_id":%q,"mode":"text","length":16}`, artifactDesc["id"])))
	if !strings.Contains(fmt.Sprintf("%v", preview), "SEGA MEGA DRIVE") {
		t.Fatalf("header artifact must contain the system type: %v", preview)
	}
}

func TestROMInfoReportsChecksumMismatch(t *testing.T) {
	body := make([]byte, 0x200)
	for index := range body {
		body[index] = byte(index)
	}
	fixture := buildMDROMFixture(body)
	client := romInfoClient(fixture, 0x0000, 0)
	content := structured(callTool(t, client, "rom_info", `{}`))
	checksum := content["header"].(map[string]any)["checksum"].(map[string]any)
	if checksum["matches"] != false || checksum["computed"] == checksum["stored"] {
		t.Fatalf("mismatch must be reported: %v", checksum)
	}
}

func TestROMInfoRejectsNoCartridge(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "emulator_status" {
			return json.RawMessage(`{"system_running":true,"modules":[],"devices":[],"rom":{"loaded":false,"size_bytes":0}}`), nil
		}
		if method == "mem_read" {
			return json.RawMessage(fmt.Sprintf(`{"space_id":"m68k-bus","address":256,"effective_address":256,"length":256,"byte_order":"big-endian","encoding":"base64","data":%q}`, base64.StdEncoding.EncodeToString(make([]byte, 256)))), nil
		}
		return nil, fmt.Errorf("unexpected method %s", method)
	}
	result := structured(callTool(t, client, "rom_info", `{}`))
	if result["code"] != "no_cartridge" {
		t.Fatalf("expected no_cartridge: %v", result)
	}
}

func TestTargetInfoIdentifiesLoadedROM(t *testing.T) {
	body := make([]byte, 0x200)
	fixture := buildMDROMFixture(body)
	binary.BigEndian.PutUint16(fixture.Header[0x8E:0x90], 0)
	full := append(append([]byte{}, fixture.Header...), fixture.Body...)
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "status":
			return json.RawMessage(`{"plugin_version":"0.7.0","lifecycle":"ready"}`), nil
		case "emulator_status":
			return json.RawMessage(`{"system_running":true,"modules":[{"id":1,"display_name":"ROM","instance_name":"ROM"}],"devices":[],"rom":{"loaded":true,"size_bytes":768}}`), nil
		case "mem_read":
			return memReadFromBlob(full, 0x100)(ctx, method, params)
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	content := structured(callTool(t, client, "target_info", `{}`))
	rom := content["rom"].(map[string]any)
	if rom["identified"] != true {
		t.Fatalf("rom not identified: %v", rom)
	}
	if rom["title"] != "TEST GAME WORLDWIDE" || rom["serial"] != "GM 1234567-01" || rom["region"] != "JUE" {
		t.Fatalf("rom summary wrong: %v", rom)
	}
}

func TestTargetInfoROMWithoutCartridge(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		switch method {
		case "status":
			return json.RawMessage(`{"plugin_version":"0.7.0","lifecycle":"ready"}`), nil
		case "emulator_status":
			return json.RawMessage(`{"system_running":true,"modules":[],"devices":[],"rom":{"loaded":false,"size_bytes":0}}`), nil
		case "mem_read":
			return json.RawMessage(fmt.Sprintf(`{"space_id":"m68k-bus","address":256,"effective_address":256,"length":256,"byte_order":"big-endian","encoding":"base64","data":%q}`, base64.StdEncoding.EncodeToString(make([]byte, 256)))), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	content := structured(callTool(t, client, "target_info", `{}`))
	rom := content["rom"].(map[string]any)
	if rom["identified"] != false {
		t.Fatalf("rom must report no cartridge: %v", rom)
	}
}

func TestSegaChecksumOddTail(t *testing.T) {
	// A trailing odd byte becomes the high byte of the final word.
	got := computeSegaChecksum([]byte{0x00, 0x01, 0xAB})
	if got != uint16(0x0001+0xAB00) {
		t.Fatalf("odd tail checksum = %04X", got)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// cpu_trace_capture_watchpoint
// ----------------------------------------------------------------------------------------------------------------------

func TestCpuTraceCaptureWatchpointPassesParams(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "trace_capture" {
			t.Fatalf("method = %s", method)
		}
		if params["watchpoint_id"] != "3" || params["max_entries"] != "2" || params["timeout_ms"] != "900" {
			t.Fatalf("params = %v", params)
		}
		payload := fmt.Sprintf(`{"cpu":"m68k","requested_entries":2,"captured":2,"timed_out":false,"duration_ms":40,`+
			`"watchpoint_mode":true,"watchpoint_id":3,"stopped_on_watchpoint":true,"stop_reason":"watchpoint_hit","watchpoint_ids_hit":[3],`+
			`"event_note":"event note",`+
			`"sampling_note":"mode note",`+
			`"sample":[{"address":2064,"cycle":10,"text":"2064 10 move.l"}],"trace_text":%q}`, "2064 10 move.l d0,-(sp)\n2066 22 rts")
		return json.RawMessage(payload), nil
	}
	content := structured(callTool(t, client, "cpu_trace_capture_watchpoint", `{"watchpoint_id":3,"max_entries":2,"timeout_ms":900}`))
	summary := content["summary"].(map[string]any)
	if summary["stopped_on_watchpoint"] != true || summary["stop_reason"] != "watchpoint_hit" {
		t.Fatalf("stop fields wrong: %v", summary)
	}
	hits := summary["watchpoint_ids_hit"].([]any)
	if len(hits) != 1 || hits[0] != float64(3) {
		t.Fatalf("watchpoint_ids_hit wrong: %v", summary["watchpoint_ids_hit"])
	}
	if summary["watchpoint_id"] != float64(3) {
		t.Fatalf("watchpoint_id echo wrong: %v", summary["watchpoint_id"])
	}
	if summary["sampling_note"] != "mode note" {
		t.Fatalf("mode sampling note lost: %v", summary["sampling_note"])
	}
	artifactDesc := content["artifact"].(map[string]any)
	if artifactDesc["mime_type"] != "text/plain; charset=utf-8" {
		t.Fatalf("trace mime wrong: %v", artifactDesc)
	}
}

func TestCpuTraceCaptureWatchpointSurfacesBridgeError(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		return nil, &bridge.CommandError{Code: "invalid_params", Message: "unknown watchpoint_id 9: list managed watchpoints with watchpoint_list"}
	}
	result := callTool(t, client, "cpu_trace_capture_watchpoint", `{"watchpoint_id":9}`)
	content := structured(result)
	if result["isError"] != true || content["code"] != "invalid_params" {
		t.Fatalf("bridge error must surface: %v", result)
	}
	if content["message"] != "unknown watchpoint_id 9: list managed watchpoints with watchpoint_list" {
		t.Fatalf("message lost: %v", content)
	}
}

func TestCpuTraceCaptureWatchpointRequiresId(t *testing.T) {
	result := callTool(t, &fakeBridgeClient{status: newFakeStatus()}, "cpu_trace_capture_watchpoint", `{"watchpoint_id":0}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("zero watchpoint_id must be rejected: %v", result)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// cpu_coverage_capture
// ----------------------------------------------------------------------------------------------------------------------

func TestCpuCoverageCaptureBuildsCoverage(t *testing.T) {
	trace := "0000100 10 move.l d0,-(sp)\n0000101 22 lea     0xFF0000,a0\n0000100 10 move.l d0,-(sp)\n0000104  7 rts\n0000200 14 nop"
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "trace_capture" {
			t.Fatalf("method = %s", method)
		}
		if params["cpu"] != "m68k" || params["timeout_ms"] != "500" {
			t.Fatalf("params = %v", params)
		}
		payload := fmt.Sprintf(`{"cpu":"m68k","requested_entries":10000,"captured":5,"timed_out":true,"duration_ms":500,"sample":[],"trace_text":%q}`, trace)
		return json.RawMessage(payload), nil
	}
	content := structured(callTool(t, client, "cpu_coverage_capture", `{"cpu":"m68k","duration_ms":500}`))
	summary := content["summary"].(map[string]any)
	if summary["entries_total"] != float64(5) {
		t.Fatalf("entries_total = %v", summary["entries_total"])
	}
	// Distinct: 0x100, 0x101, 0x104, 0x200.
	if summary["distinct_total"] != float64(4) {
		t.Fatalf("distinct_total = %v", summary["distinct_total"])
	}
	if summary["ranges_count"] != float64(3) {
		t.Fatalf("ranges_count = %v", summary["ranges_count"])
	}
	if summary["sha256"] == "" {
		t.Fatalf("summary missing sha256: %v", summary)
	}
	artifactDesc := content["artifact"].(map[string]any)
	if artifactDesc["kind"] != "cpu-coverage" || artifactDesc["mime_type"] != "application/json" {
		t.Fatalf("coverage artifact wrong: %v", artifactDesc)
	}
	server := newTestServer(t, client)
	preview := structured(postToolCall(t, server, "artifact_get", fmt.Sprintf(`{"artifact_id":%q}`, artifactDesc["id"])))
	if preview == nil {
		t.Fatal("coverage artifact not retrievable")
	}
}

func TestCpuCoverageCaptureRegionFilter(t *testing.T) {
	trace := "0000100 1 nop\n0000101 1 nop\n0000200 1 nop"
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		payload := fmt.Sprintf(`{"cpu":"m68k","requested_entries":10000,"captured":3,"timed_out":true,"duration_ms":500,"sample":[],"trace_text":%q}`, trace)
		return json.RawMessage(payload), nil
	}
	content := structured(callTool(t, client, "cpu_coverage_capture", `{"cpu":"m68k","region_start":256,"region_end":512}`))
	summary := content["summary"].(map[string]any)
	if summary["distinct_total"] != float64(2) {
		t.Fatalf("region filter must exclude 0x200: %v", summary)
	}
	// All lines are inside the [256,512) window except 0x200, but every entry
	// still counts toward entries_total.
	if summary["entries_total"] != float64(3) {
		t.Fatalf("entries_total = %v", summary["entries_total"])
	}
}

func TestCpuCoverageCaptureRejectsBadArgs(t *testing.T) {
	result := callTool(t, &fakeBridgeClient{status: newFakeStatus()}, "cpu_coverage_capture", `{"cpu":"sparc"}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("bad cpu must be rejected: %v", result)
	}
	result = callTool(t, &fakeBridgeClient{status: newFakeStatus()}, "cpu_coverage_capture", `{"cpu":"m68k","duration_ms":60000}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("oversized duration must be rejected: %v", result)
	}
	result = callTool(t, &fakeBridgeClient{status: newFakeStatus()}, "cpu_coverage_capture", `{"cpu":"m68k","region_start":512,"region_end":256}`)
	if structured(result)["code"] != "invalid_params" {
		t.Fatalf("inverted region must be rejected: %v", result)
	}
}

func TestParseTraceAddresses(t *testing.T) {
	trace := "0000100 10 move.l d0,-(sp)\n0000102 22 rts\n badline\n\n0000200  7 nop"
	addrs := parseTraceAddresses(trace)
	want := []uint64{0x100, 0x102, 0x200}
	if len(addrs) != len(want) {
		t.Fatalf("addresses = %v, want %v", addrs, want)
	}
	for index := range want {
		if addrs[index] != want[index] {
			t.Fatalf("addresses = %v, want %v", addrs, want)
		}
	}
}
