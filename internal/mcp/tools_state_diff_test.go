package mcp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

func TestStateDiffMetadataAndFileBytes(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	context, err := server.contexts.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pathBefore := filepath.Join(dir, "before.zip")
	pathAfter := filepath.Join(dir, "after.zip")
	if err := os.WriteFile(pathBefore, []byte("AAAABBBB"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathAfter, []byte("AAAACCCC"), 0o644); err != nil {
		t.Fatal(err)
	}
	beforeHash, err := fileSHA256(pathBefore)
	if err != nil {
		t.Fatal(err)
	}
	afterHash, err := fileSHA256(pathAfter)
	if err != nil {
		t.Fatal(err)
	}
	server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID: "before-1", ContextID: context.ID, Name: "start", Path: pathBefore,
		SHA256: beforeHash, SizeBytes: 8, CreatedAt: time.Now().UTC(),
		ROMPath: "/rom.bin", ROMSHA256: "aa", TargetGeneration: 5,
	})
	server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID: "after-1", ContextID: context.ID, Name: "end", Path: pathAfter,
		SHA256: afterHash, SizeBytes: 8, CreatedAt: time.Now().UTC(),
		ROMPath: "/rom.bin", ROMSHA256: "aa", TargetGeneration: 7,
	})

	result := postToolCall(t, server, "state_diff", `{"snapshot_before_id":"before-1","snapshot_after_id":"after-1","context":""}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", structured(result))
	}
	content := structured(result)
	metadata, _ := content["metadata_diff"].(map[string]any)
	if metadata == nil || metadata["identical"] != false {
		t.Fatalf("metadata_diff = %v", metadata)
	}
	differences, _ := metadata["differences"].([]any)
	if len(differences) < 3 { // name, sha256, target_generation
		t.Fatalf("differences = %v", differences)
	}
	if metadata["rom_identity"] != "same" {
		t.Fatalf("rom_identity = %v, want same", metadata["rom_identity"])
	}
	fileDiff, _ := content["file_diff"].(map[string]any)
	if fileDiff["identical"] != false || fileDiff["total_diffs"] != float64(4) {
		t.Fatalf("file_diff = %v", fileDiff)
	}
	if fileDiff["compared_bytes"] != float64(8) {
		t.Fatalf("compared_bytes = %v", fileDiff["compared_bytes"])
	}
	semantic, _ := content["semantic"].(map[string]any)
	if semantic["complete"] != false {
		t.Fatalf("semantic.complete = %v, want false", semantic["complete"])
	}
	registersSection, _ := semantic["registers"].(map[string]any)
	if registersSection["performed"] != false {
		t.Fatalf("semantic.registers.performed = %v", registersSection["performed"])
	}
	if content["identical"] != false {
		t.Fatalf("top-level identical = %v, want false", content["identical"])
	}
	artifact, _ := content["artifact"].(map[string]any)
	if artifact["kind"] != "state-diff-results" {
		t.Fatalf("artifact kind = %v", artifact["kind"])
	}
}

func TestStateDiffIdenticalSnapshots(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	context, err := server.contexts.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "same.zip")
	if err := os.WriteFile(path, []byte("SAME-BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID: "a", ContextID: context.ID, Path: path, SHA256: hash, SizeBytes: 10, CreatedAt: now, TargetGeneration: 3,
	})
	server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID: "b", ContextID: context.ID, Path: path, SHA256: hash, SizeBytes: 10, CreatedAt: now, TargetGeneration: 3,
	})
	result := postToolCall(t, server, "state_diff", `{"snapshot_before_id":"a","snapshot_after_id":"b"}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", structured(result))
	}
	content := structured(result)
	if content["identical"] != true {
		t.Fatalf("identical = %v, want true", content["identical"])
	}
}

func TestStateDiffUnknownState(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	result := postToolCall(t, server, "state_diff", `{"snapshot_before_id":"missing","snapshot_after_id":"also-missing"}`)
	content := structured(result)
	if content["code"] != "unknown_state" {
		t.Fatalf("code = %v, want unknown_state", content["code"])
	}
}

func TestStateDiffMissingFile(t *testing.T) {
	server := newTestServer(t, &fakeBridgeClient{status: newFakeStatus()})
	context, err := server.contexts.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID: "gone", ContextID: context.ID, Path: filepath.Join(t.TempDir(), "nope.zip"), SHA256: "x", SizeBytes: 1,
	})
	server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID: "also-gone", ContextID: context.ID, Path: filepath.Join(t.TempDir(), "nope2.zip"), SHA256: "x", SizeBytes: 1,
	})
	result := postToolCall(t, server, "state_diff", `{"snapshot_before_id":"gone","snapshot_after_id":"also-gone"}`)
	content := structured(result)
	if content["code"] != "state_file_missing" {
		t.Fatalf("code = %v, want state_file_missing", content["code"])
	}
}
