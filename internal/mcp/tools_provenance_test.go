package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------------------------------------------------
// P0: artifact capture provenance
// ----------------------------------------------------------------------------------------------------------------------

// ramBlobClient serves a mem-ram blob anchored at 0xFF0000 (the 68000 work RAM
// bus window), reporting the mem-ram space id and big-endian byte order.
func ramBlobClient(blob []byte) *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "mem_read" {
			return nil, fmt.Errorf("unexpected method %s", method)
		}
		return memReadFromBlob(blob, 0xFF0000)(context.Background(), method, params)
	}
	return client
}

// z80BlobClient serves a z80-bus blob anchored at 0, little-endian.
func z80BlobClient(blob []byte) *fakeBridgeClient {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "mem_read" {
			return nil, fmt.Errorf("unexpected method %s", method)
		}
		address, err := parseUintParam(params, "address")
		if err != nil {
			return nil, err
		}
		length, err := parseUintParam(params, "length")
		if err != nil {
			return nil, err
		}
		if address+length > uint64(len(blob)) {
			return nil, fmt.Errorf("range out of z80 fixture: addr=%d len=%d blob=%d", address, length, len(blob))
		}
		data := blob[address : address+length]
		payload := fmt.Sprintf(`{"space_id":"z80-bus","kind":"bus","address":%d,"effective_address":%d,"length":%d,"byte_order":"little-endian","encoding":"base64","consistency":"live","data":%q}`,
			address, address, length, base64.StdEncoding.EncodeToString(data))
		return json.RawMessage(payload), nil
	}
	return client
}

func parseUintParam(params map[string]string, key string) (uint64, error) {
	var value uint64
	_, err := fmt.Sscanf(params[key], "%d", &value)
	return value, err
}

// provenanceOf extracts the provenance map of one artifact descriptor.
func provenanceOf(result map[string]any) map[string]any {
	descriptor, _ := result["artifact"].(map[string]any)
	provenance, _ := descriptor["provenance"].(map[string]any)
	return provenance
}

func TestMemoryDumpRecordsFullCaptureProvenance(t *testing.T) {
	blob := make([]byte, 16)
	for index := range blob {
		blob[index] = byte(index)
	}
	client := ramBlobClient(blob)
	server := newTestServer(t, client)

	result := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":16}`))
	if result["code"] != nil {
		t.Fatalf("dump failed: %v", result)
	}
	summary := result["summary"].(map[string]any)
	if summary["effective_address"] != float64(0xFF0000) || summary["effective_address_hex"] != "0xFF0000" {
		t.Fatalf("effective address wrong: %v", summary)
	}
	provenance := provenanceOf(result)
	if provenance["artifact_schema"] != "artifact-provenance/1" || provenance["state"] != "complete" {
		t.Fatalf("envelope not stamped: %v", provenance)
	}
	if provenance["address_space"] != "mem-ram" || provenance["device"] != "68000 work RAM" {
		t.Fatalf("space/device wrong: %v", provenance)
	}
	if provenance["start_address"] != float64(0xFF0000) || provenance["effective_address"] != float64(0xFF0000) {
		t.Fatalf("addresses wrong: %v", provenance)
	}
	if provenance["byte_length"] != float64(16) || provenance["byte_order"] != "big-endian" {
		t.Fatalf("length/order wrong: %v", provenance)
	}
	if provenance["raw_byte_ordering"] != "address-order" {
		t.Fatalf("raw ordering wrong: %v", provenance)
	}
	if provenance["space_kind"] != "bus" || provenance["consistency"] != "live" {
		t.Fatalf("kind/consistency wrong: %v", provenance)
	}
	if provenance["target_generation"] != float64(1) {
		t.Fatalf("generation wrong: %v", provenance)
	}
	if _, present := provenance["captured_at"]; !present {
		t.Fatalf("captured_at missing: %v", provenance)
	}
}

func TestMemorySearchDerivesAddressingFromProvenance(t *testing.T) {
	// "SEGA" at offsets 2 and 7 of a mem-ram window anchored at 0xFF0000.
	blob := []byte{0x00, 0x00, 0x53, 0x45, 0x47, 0x41, 0x00, 0x53, 0x45, 0x47, 0x41}
	client := ramBlobClient(blob)
	server := newTestServer(t, client)

	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":11}`))
	artifactID := dump["artifact"].(map[string]any)["id"].(string)

	// No space, no start_address, no length: everything derives from the
	// snapshot's provenance, and the matches land in the captured range.
	search := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"pattern":"53454741","snapshot_id":%q}`, artifactID)))
	if search["code"] != nil {
		t.Fatalf("derived search failed: %v", search)
	}
	summary := search["summary"].(map[string]any)
	if summary["address_space"] != "mem-ram" {
		t.Fatalf("space not derived: %v", summary)
	}
	if summary["searched_start_address"] != float64(0xFF0000) {
		t.Fatalf("start not derived from provenance: %v", summary)
	}
	if summary["searched_byte_length"] != float64(11) {
		t.Fatalf("length not derived: %v", summary)
	}
	if summary["byte_order"] != "big-endian" {
		t.Fatalf("byte order not derived: %v", summary)
	}
	if summary["matches_total"] != float64(2) {
		t.Fatalf("matches_total wrong: %v", summary)
	}
	sourceRange := summary["source_range"].(map[string]any)
	if sourceRange["start_address"] != float64(0xFF0000) || sourceRange["end_address"] != float64(0xFF000A) {
		t.Fatalf("source range wrong: %v", sourceRange)
	}
	matches := search["matches"].([]any)
	first := matches[0].(map[string]any)
	if first["address"] != float64(0xFF0002) || first["address_hex"] != "0xFF0002" {
		t.Fatalf("match must be anchored in the captured range: %v", first)
	}
	// The results artifact embeds the source descriptor with its range.
	if search["artifact"].(map[string]any)["provenance_state"] != "complete" {
		t.Fatalf("results artifact lacks provenance: %v", search["artifact"])
	}
	if memReads := countCalls(client, "mem_read"); memReads != 1 {
		t.Fatalf("derived search must not re-read the bridge: mem_read = %d", memReads)
	}
}

func TestMemorySearchRejectsProvenanceAssertionMismatch(t *testing.T) {
	blob := make([]byte, 8)
	client := ramBlobClient(blob)
	server := newTestServer(t, client)
	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":8}`))
	artifactID := dump["artifact"].(map[string]any)["id"].(string)

	// A space assertion contradicting the captured space is rejected.
	spaceConflict := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"space":"z80-bus","pattern":"00","snapshot_id":%q}`, artifactID)))
	if spaceConflict["code"] != "provenance_conflict" {
		t.Fatalf("space assertion mismatch must be provenance_conflict: %v", spaceConflict)
	}
	// A start_address assertion contradicting the captured start is rejected.
	startConflict := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"pattern":"00","start_address":"0x100","snapshot_id":%q}`, artifactID)))
	if startConflict["code"] != "provenance_conflict" {
		t.Fatalf("start assertion mismatch must be provenance_conflict: %v", startConflict)
	}
	if memReads := countCalls(client, "mem_read"); memReads != 1 {
		t.Fatalf("assertion failures must not read the bridge: mem_read = %d", memReads)
	}
}

func TestMemorySearchLegacySnapshotWithoutProvenance(t *testing.T) {
	client := ramBlobClient(make([]byte, 8))
	server := newTestServer(t, client)
	// Legacy artifact: stored without capture metadata in the default context.
	defaultContext, failure := resolveContext(server, "")
	if failure != nil {
		t.Fatalf("resolve default context: %v", failure)
	}
	legacy, err := server.store.Put(defaultContext.ID, "memory-dump", "application/octet-stream", []byte{0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatal(err)
	}

	// Space cannot be derived from a legacy snapshot: required.
	noSpace := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"pattern":"0102","snapshot_id":%q}`, legacy.ID)))
	if noSpace["code"] != "invalid_params" {
		t.Fatalf("legacy snapshot without space must be rejected: %v", noSpace)
	}
	// With caller addressing the search works and warns about the unknown origin.
	result := structured(postToolCall(t, server, "memory_search", fmt.Sprintf(`{"space":"mem-ram","pattern":"0102","start_address":"0xFF0000","snapshot_id":%q}`, legacy.ID)))
	if result["code"] != nil {
		t.Fatalf("legacy snapshot search failed: %v", result)
	}
	summary := result["summary"].(map[string]any)
	if summary["matches_total"] != float64(1) {
		t.Fatalf("legacy search matches wrong: %v", summary)
	}
	if _, warned := summary["provenance_warning"]; !warned {
		t.Fatalf("legacy search must warn about unknown provenance: %v", summary)
	}
	matches := result["matches"].([]any)
	if matches[0].(map[string]any)["address"] != float64(0xFF0000) {
		t.Fatalf("legacy match anchoring wrong: %v", matches)
	}
	// artifact_describe reports provenance_unknown honestly.
	described := structured(postToolCall(t, server, "artifact_describe", fmt.Sprintf(`{"artifact_id":%q}`, legacy.ID)))
	provenance := described["provenance"].(map[string]any)
	if provenance["state"] != "provenance_unknown" {
		t.Fatalf("legacy artifact must describe provenance_unknown: %v", provenance)
	}
}

func TestMemoryDiffRejectsIncompatibleProvenanceByDefault(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch params["space"] {
		case "mem-ram":
			return memReadFromBlob([]byte{1, 2, 3, 4}, 0xFF0000)(ctx, method, params)
		case "z80-bus":
			return z80BlobClient([]byte{1, 2, 3, 4}).executeFunc(ctx, method, params)
		default:
			return nil, fmt.Errorf("unexpected space %q", params["space"])
		}
	}
	server := newTestServer(t, client)
	ramDump := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	z80Dump := structured(postToolCall(t, server, "memory_dump", `{"space":"z80-bus","address":0,"length":4}`))
	ramID := ramDump["artifact"].(map[string]any)["id"].(string)
	z80ID := z80Dump["artifact"].(map[string]any)["id"].(string)

	// Comparing M68K RAM to Z80 RAM fails by default.
	rejected := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed"}`, ramID, z80ID)))
	if rejected["code"] != "incompatible_provenance" {
		t.Fatalf("cross-space diff must fail with incompatible_provenance: %v", rejected)
	}
	reasons, _ := rejected["reasons"].([]any)
	found := false
	for _, reason := range reasons {
		if fmt.Sprint(reason) == "address space differs: mem-ram vs z80-bus" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rejection must name the space difference: %v", reasons)
	}
	if _, hasBefore := rejected["before_snapshot"]; !hasBefore {
		t.Fatalf("rejection must carry the before manifest: %v", rejected)
	}

	// Explicit opt-in compares with a prominent warning and both manifests.
	forced := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"snapshot_after_id":%q,"mode":"changed","allow_incompatible_provenance":true}`, ramID, z80ID)))
	if forced["code"] != nil {
		t.Fatalf("forced cross-space diff failed: %v", forced)
	}
	summary := forced["summary"].(map[string]any)
	warning, _ := summary["provenance_warning"].(string)
	if warning == "" || !strings.Contains(warning, "no common address origin") {
		t.Fatalf("forced diff must warn prominently: %v", summary)
	}
}

func TestMemoryDiffDerivesRangeAndByteOrderFromProvenance(t *testing.T) {
	// Before: little-endian Z80 RAM bytes 0x34 0x12 (word 0x1234).
	// After:  little-endian Z80 RAM bytes 0x78 0x56 (word 0x5678).
	client := &fakeBridgeClient{status: newFakeStatus()}
	reads := 0
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if params["space"] != "z80-bus" {
			return nil, fmt.Errorf("unexpected space %q", params["space"])
		}
		reads++
		if reads == 1 {
			return z80BlobClient([]byte{0x34, 0x12}).executeFunc(ctx, method, params)
		}
		return z80BlobClient([]byte{0x78, 0x56}).executeFunc(ctx, method, params)
	}
	server := newTestServer(t, client)
	before := structured(postToolCall(t, server, "memory_dump", `{"space":"z80-bus","address":0,"length":2}`))
	beforeID := before["artifact"].(map[string]any)["id"].(string)

	// Fresh after read: space, start, length, and byte order all derive from
	// the before snapshot's provenance; no caller restatement needed.
	diff := structured(postToolCall(t, server, "memory_diff", fmt.Sprintf(`{"snapshot_before_id":%q,"mode":"changed","width":"word"}`, beforeID)))
	if diff["code"] != nil {
		t.Fatalf("derived diff failed: %v", diff)
	}
	summary := diff["summary"].(map[string]any)
	if summary["byte_order"] != "little-endian" {
		t.Fatalf("byte order must derive from provenance: %v", summary)
	}
	rangeInfo := summary["range"].(map[string]any)
	if rangeInfo["address_space"] != "z80-bus" {
		t.Fatalf("space must derive from provenance: %v", rangeInfo)
	}
	matches := diff["matches"].([]any)
	if len(matches) != 1 {
		t.Fatalf("expected one changed word: %v", matches)
	}
	first := matches[0].(map[string]any)
	if first["address"] != float64(0) || first["before"] != float64(0x1234) || first["after"] != float64(0x5678) {
		t.Fatalf("little-endian decode wrong: %v", first)
	}
	if summary["fresh_after_read"] != true {
		t.Fatalf("fresh after read expected: %v", summary)
	}
}

func TestArtifactDescribeReturnsTypedEnvelope(t *testing.T) {
	client := ramBlobClient(make([]byte, 4))
	server := newTestServer(t, client)
	dump := structured(postToolCall(t, server, "memory_dump", `{"space":"mem-ram","address":"0xFF0000","length":4}`))
	artifactID := dump["artifact"].(map[string]any)["id"].(string)

	described := structured(postToolCall(t, server, "artifact_describe", fmt.Sprintf(`{"artifact_id":%q}`, artifactID)))
	if described["code"] != nil {
		t.Fatalf("artifact_describe failed: %v", described)
	}
	provenance := described["provenance"].(map[string]any)
	if provenance["artifact_schema"] != "artifact-provenance/1" || provenance["state"] != "complete" {
		t.Fatalf("envelope wrong: %v", provenance)
	}
	for _, key := range []string{"address_space", "start_address", "effective_address", "start_address_hex", "effective_address_hex", "byte_length", "byte_order", "raw_byte_ordering", "device", "target_generation", "captured_at"} {
		if _, present := provenance[key]; !present {
			t.Fatalf("envelope missing %s: %v", key, provenance)
		}
	}
	// artifact_get now carries the provenance reference too.
	got := structured(postToolCall(t, server, "artifact_get", fmt.Sprintf(`{"artifact_id":%q}`, artifactID)))
	if got["artifact"].(map[string]any)["provenance_state"] != "complete" {
		t.Fatalf("artifact_get must reference provenance: %v", got)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// P2: rom_identity and honest checksum completeness
// ----------------------------------------------------------------------------------------------------------------------

// writeFixtureROM writes a cartridge file in the real Sega layout — 0x100
// bytes of vector-table slack, then the 256-byte header at file offset 0x100,
// then the body at 0x200 — so the file-derived identity (SHA-256, header at
// 0x100, checksum over [0x200, declared end)) matches the fixture's declared
// ROM end (file size = 0x200 + body length). Returns a client whose
// emulator_status reports that path and size.
func writeFixtureROM(t *testing.T, fixture *mdROMFixture, paddedSize uint64) (*fakeBridgeClient, string) {
	t.Helper()
	fileBytes := make([]byte, 0, 0x200+len(fixture.Body))
	fileBytes = append(fileBytes, make([]byte, 0x100)...) // vector table slack
	fileBytes = append(fileBytes, fixture.Header...)
	fileBytes = append(fileBytes, fixture.Body...)
	path := filepath.Join(t.TempDir(), "cartridge.bin")
	if err := os.WriteFile(path, fileBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	fileSize := uint64(len(fileBytes))
	if paddedSize == 0 {
		paddedSize = fileSize
	}
	full := append(append([]byte{}, fixture.Header...), fixture.Body...)
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "emulator_status":
			payload := fmt.Sprintf(`{"system_running":true,"modules":[{"id":1,"display_name":"ROM","instance_name":"ROM"}],"devices":[],"rom":{"loaded":true,"size_bytes":%d,"padded_size_bytes":%d,"path":%q}}`, fileSize, paddedSize, path)
			return json.RawMessage(payload), nil
		case "mem_read":
			return memReadFromBlob(full, 0x100)(ctx, method, params)
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	return client, path
}

func TestROMInfoReportsROMIdentityFromFile(t *testing.T) {
	body := make([]byte, 0x600)
	for index := range body {
		body[index] = byte(index * 3)
	}
	fixture := buildMDROMFixture(body)
	stored := computeSegaChecksum(body)
	binary.BigEndian.PutUint16(fixture.Header[0x8E:0x90], stored)
	client, path := writeFixtureROM(t, fixture, 0)
	server := newTestServer(t, client)

	content := structured(postToolCall(t, server, "rom_info", `{}`))
	if content["identified"] != true {
		t.Fatalf("rom not identified: %v", content)
	}
	identity := content["rom_identity"].(map[string]any)
	if identity["rom_sha256_available"] != true {
		t.Fatalf("file identity must be available: %v", identity)
	}
	sum := sha256.Sum256(mustReadFile(t, path))
	if identity["rom_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("rom_sha256 mismatch: %v", identity)
	}
	if identity["title"] != "TEST GAME WORLDWIDE" || identity["serial"] != "GM 1234567-01" {
		t.Fatalf("file header identity wrong: %v", identity)
	}
	if identity["header_identified"] != true || identity["mapped_image_base"] != "0x000000" {
		t.Fatalf("identity flags wrong: %v", identity)
	}
	if identity["target_generation"] != float64(1) {
		t.Fatalf("identity generation wrong: %v", identity)
	}
	checksum := identity["checksum"].(map[string]any)
	if checksum["complete"] != true || checksum["cap_reason"] != "none" {
		t.Fatalf("declared-end file checksum must be complete: %v", checksum)
	}
	if checksum["stored"] != checksum["computed"] || checksum["matches"] != true {
		t.Fatalf("file checksum mismatch: %v", checksum)
	}
	// The bus-side checksum view is also complete for a licensed-style header.
	header := content["header"].(map[string]any)
	busChecksum := header["checksum"].(map[string]any)
	if busChecksum["complete"] != true || busChecksum["cap_reason"] != "none" {
		t.Fatalf("bus checksum must be complete: %v", busChecksum)
	}
	expected := busChecksum["expected_range"].(map[string]any)
	if expected["byte_length"] != float64(0x600) {
		t.Fatalf("expected range wrong: %v", expected)
	}
}

func TestROMInfoChecksumIncompleteWhenFileShorterThanDeclared(t *testing.T) {
	body := make([]byte, 0x200)
	for index := range body {
		body[index] = byte(index)
	}
	fixture := buildMDROMFixture(body)
	// Grow the declared end to claim a body the file does not contain.
	declared := uint64(0x1000)
	binary.BigEndian.PutUint32(fixture.Header[0xA4:0xA8], uint32(declared-1))
	client, _ := writeFixtureROM(t, fixture, 0)
	server := newTestServer(t, client)

	content := structured(postToolCall(t, server, "rom_info", `{}`))
	identity := content["rom_identity"].(map[string]any)
	checksum := identity["checksum"].(map[string]any)
	if checksum["complete"] != false {
		t.Fatalf("file checksum must be incomplete: %v", checksum)
	}
	if checksum["cap_reason"] != "declared_end_beyond_file" {
		t.Fatalf("cap reason wrong: %v", checksum)
	}
	if checksum["bytes_covered"] != float64(0x200) || checksum["expected_byte_length"] != float64(0xE00) {
		t.Fatalf("coverage facts wrong: %v", checksum)
	}
	// The bus-side view must not claim validation either.
	busChecksum := content["header"].(map[string]any)["checksum"].(map[string]any)
	if busChecksum["complete"] != false || busChecksum["cap_reason"] != "declared_end_beyond_file" {
		t.Fatalf("bus checksum must report incomplete honestly: %v", busChecksum)
	}
	if note, _ := busChecksum["note"].(string); !strings.Contains(note, "NOT full header-checksum validation") {
		t.Fatalf("incomplete checksum needs the honesty note: %v", busChecksum)
	}
}

func TestROMInfoChecksumIncompleteUnderDumpCap(t *testing.T) {
	body := make([]byte, dumpCapBytes+0x200)
	fixture := buildMDROMFixture(body)
	// Declared end covers the whole body; only the dump cap cuts the read.
	declared := uint64(len(fixture.Header)) + uint64(len(body))
	binary.BigEndian.PutUint32(fixture.Header[0xA4:0xA8], uint32(declared-1))
	client, _ := writeFixtureROM(t, fixture, 0)
	server := newTestServer(t, client)

	content := structured(postToolCall(t, server, "rom_info", `{}`))
	busChecksum := content["header"].(map[string]any)["checksum"].(map[string]any)
	if busChecksum["complete"] != false || busChecksum["cap_reason"] != "dump_cap" {
		t.Fatalf("dump cap must be reported: %v", busChecksum)
	}
	if busChecksum["bytes_covered"] != float64(dumpCapBytes) {
		t.Fatalf("covered bytes wrong: %v", busChecksum)
	}
	// The file identity is still complete: the file itself holds the body.
	identity := content["rom_identity"].(map[string]any)
	fileChecksum := identity["checksum"].(map[string]any)
	if fileChecksum["complete"] != true {
		t.Fatalf("file identity must stay complete under the bus dump cap: %v", fileChecksum)
	}
}

func TestROMIdentityUnavailableForUnreadableFile(t *testing.T) {
	body := make([]byte, 0x200)
	fixture := buildMDROMFixture(body)
	client := romInfoClient(fixture, computeSegaChecksum(body), 0) // reports F:\roms\kid.bin
	server := newTestServer(t, client)

	content := structured(postToolCall(t, server, "rom_info", `{}`))
	identity := content["rom_identity"].(map[string]any)
	if identity["rom_sha256_available"] != false || identity["rom_sha256"] != "" {
		t.Fatalf("unreadable file must report no sha: %v", identity)
	}
	if identity["header_identified"] != false {
		t.Fatalf("unreadable file must not invent header facts: %v", identity)
	}
	if note, _ := identity["note"].(string); !strings.Contains(note, "not readable") {
		t.Fatalf("unreadable identity needs the honesty note: %v", identity)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// P2: data_hex and read-back verification
// ----------------------------------------------------------------------------------------------------------------------

func TestMemoryWriteHexInputAndEcho(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method == "mem_write" {
			if params["data"] != base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE}) {
				return nil, fmt.Errorf("hex input must normalize to the same bytes, got %q", params["data"])
			}
			return json.RawMessage(`{"space_id":"m68k-bus","kind":"bus","address":0,"effective_address":0,"length":3,"byte_order":"big-endian","encoding":"base64","consistency":"live","written":"3q2+","system_paused_during_write":false}`), nil
		}
		return nil, fmt.Errorf("unexpected method %s", method)
	}
	server := newTestServer(t, client)
	result := structured(postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data_hex":"DE AD BE"}`))
	if result["code"] != nil {
		t.Fatalf("hex write failed: %v", result)
	}
	echo, _ := result["data_hex_echo"].(map[string]any)
	if echo["hex"] != "DEADBE" || echo["bytes_total"] != float64(3) || echo["truncated"] != false {
		t.Fatalf("hex echo wrong: %v", echo)
	}
}

func TestMemoryWriteHexValidation(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	server := newTestServer(t, client)
	cases := []struct {
		arguments string
		code      string
	}{
		{`{"space":"m68k-bus","address":0}`, "invalid_params"},                               // neither data nor data_hex
		{`{"space":"m68k-bus","address":0,"data":"AA==","data_hex":"AA"}`, "invalid_params"}, // both
		{`{"space":"m68k-bus","address":0,"data_hex":"zz"}`, "invalid_params"},               // bad hex
		{`{"space":"m68k-bus","address":0,"data_hex":"123"}`, "invalid_params"},              // odd digits
	}
	for _, tc := range cases {
		result := structured(postToolCall(t, server, "memory_write", tc.arguments))
		if result["code"] != tc.code {
			t.Fatalf("%s: code = %v (%v)", tc.arguments, result["code"], result)
		}
	}
	if calls := countCalls(client, "mem_write"); calls != 0 {
		t.Fatalf("invalid hex must not reach the bridge: %d", calls)
	}
}

func TestMemoryWriteReadbackVerification(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	readCount := 0
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		switch method {
		case "mem_write":
			return json.RawMessage(`{"space_id":"m68k-bus","kind":"bus","address":0,"effective_address":0,"length":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","written":"2a41","system_paused_during_write":false}`), nil
		case "mem_read":
			readCount++
			data := []byte{0x2A, 0x41}
			return json.RawMessage(fmt.Sprintf(`{"space_id":"m68k-bus","kind":"bus","address":0,"effective_address":0,"length":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","data":%q}`, base64.StdEncoding.EncodeToString(data))), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	server := newTestServer(t, client)
	result := structured(postToolCall(t, server, "memory_write", `{"space":"m68k-bus","address":0,"data_hex":"2A41","verify_readback":true}`))
	if result["code"] != nil {
		t.Fatalf("readback write failed: %v", result)
	}
	readback := result["readback"].(map[string]any)
	if readback["verified"] != true || readback["matches"] != true {
		t.Fatalf("readback must match: %v", readback)
	}
	echo, _ := readback["hex"].(map[string]any)
	if echo["hex"] != "2A41" {
		t.Fatalf("readback echo wrong: %v", echo)
	}
	if readCount != 1 {
		t.Fatalf("verify_readback must issue one mem_read, got %d", readCount)
	}
}

func TestMemoryWriteReadbackMismatchNote(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "mem_write" {
			return json.RawMessage(`{"space_id":"m68k-bus","kind":"bus","address":0,"effective_address":0,"length":1,"byte_order":"big-endian","encoding":"base64","consistency":"live","written":"AA==","system_paused_during_write":false}`), nil
		}
		if method == "mem_read" {
			return json.RawMessage(`{"space_id":"mem-rom","kind":"memory","address":0,"effective_address":0,"length":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","data":"QUI="}`), nil // 0x41 0x42
		}
		return nil, fmt.Errorf("unexpected method %s", method)
	}
	server := newTestServer(t, client)
	// Length 1 written, read-back returns 2 different bytes: mismatch + note.
	result := structured(postToolCall(t, server, "memory_write", `{"space":"mem-rom","address":0,"data":"AA==","verify_readback":true}`))
	if result["code"] != nil {
		t.Fatalf("write failed: %v", result)
	}
	readback := result["readback"].(map[string]any)
	if readback["matches"] != false {
		t.Fatalf("mismatch must be reported: %v", readback)
	}
	if note, _ := readback["note"].(string); !strings.Contains(note, "differ") {
		t.Fatalf("mismatch needs the transform note: %v", readback)
	}
}

func TestMemoryFreezeAcceptsHexInput(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "mem_write" {
			return nil, fmt.Errorf("unexpected method %s", method)
		}
		if params["data"] != base64.StdEncoding.EncodeToString([]byte{0xCA, 0xFE}) {
			return nil, fmt.Errorf("freeze hex must normalize, got %q", params["data"])
		}
		return json.RawMessage(`{"space_id":"m68k-bus","kind":"bus","address":0,"effective_address":0,"length":2,"byte_order":"big-endian","encoding":"base64","consistency":"live","written":"yv4=","system_paused_during_write":false}`), nil
	}
	server := newTestServer(t, client)
	result := structured(postToolCall(t, server, "memory_freeze", `{"space":"m68k-bus","address":0,"data_hex":"CAFE"}`))
	if result["code"] != nil {
		t.Fatalf("hex freeze failed: %v", result)
	}
	echo, _ := result["data_hex_echo"].(map[string]any)
	if echo["hex"] != "CAFE" {
		t.Fatalf("freeze hex echo wrong: %v", echo)
	}
	if result["data_sha256"] != sha256Hex([]byte{0xCA, 0xFE}) {
		t.Fatalf("freeze sha wrong: %v", result)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Provenance on states
// ----------------------------------------------------------------------------------------------------------------------

func TestStateSaveRecordsROMSHA256(t *testing.T) {
	body := make([]byte, 0x200)
	for index := range body {
		body[index] = byte(index)
	}
	fixture := buildMDROMFixture(body)
	full := append(append([]byte{}, fixture.Header...), fixture.Body...)
	client, path := writeFixtureROM(t, fixture, 0)
	client.executeFunc = func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		switch method {
		case "emulator_status":
			payload := fmt.Sprintf(`{"system_running":true,"modules":[],"devices":[],"rom":{"loaded":true,"size_bytes":%d,"padded_size_bytes":%d,"path":%q}}`, len(full)+0x100, len(full)+0x100, path)
			return json.RawMessage(payload), nil
		case "mem_read":
			return memReadFromBlob(full, 0x100)(ctx, method, params)
		case "state_save":
			if err := os.WriteFile(params["path"], []byte("zip-bytes"), 0o600); err != nil {
				return nil, err
			}
			return json.RawMessage(`{"saved":true}`), nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	server := newTestServer(t, client)
	// Establish the ROM path via an emulator_status observation first.
	status := structured(postToolCall(t, server, "emulator_status", `{}`))
	if status["code"] != nil {
		t.Fatalf("emulator_status failed: %v", status)
	}
	saved := structured(postToolCall(t, server, "state_save", `{"name":"checkpoint"}`))
	if saved["code"] != nil {
		t.Fatalf("state_save failed: %v", saved)
	}
	listed := structured(postToolCall(t, server, "state_list", `{}`))
	entries := listed["snapshots"].([]any)
	entry := entries[0].(map[string]any)
	if entry["rom_sha256"] == "" {
		t.Fatalf("state must record rom_sha256: %v", entry)
	}
	sum := sha256.Sum256(mustReadFile(t, path))
	if entry["rom_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("state rom_sha256 mismatch: %v", entry)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------------------------------------------------

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
