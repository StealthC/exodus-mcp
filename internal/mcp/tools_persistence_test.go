package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// ----------------------------------------------------------------------------------------------------------------------
// Restart persistence and workspace reclamation (roadmap issue #18)
//
// These tests boot two servers over the same artifact root instead of inspecting
// in-memory state, so a regression in annotation/context/artifact persistence
// fails the same way a real restart would.
// ----------------------------------------------------------------------------------------------------------------------

// persistedServer opens one server over an artifact root, as the launcher does.
func persistedServer(t *testing.T, dir string, client *fakeBridgeClient) *Server {
	t.Helper()
	store, err := artifact.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := analysis.OpenRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	return NewServer("test", client, store, registry, "http://127.0.0.1")
}

func TestAnnotationsSurviveServerRestart(t *testing.T) {
	dir := t.TempDir()
	first := persistedServer(t, dir, &fakeBridgeClient{status: newFakeStatus()})
	created := structured(postToolCall(t, first, "annotation_create",
		`{"title":"lives counter","text":"0xFF1234 counts lives","tags":["hud"],"address":"0xFF1234","address_space":"m68k-bus"}`))
	if created["code"] != nil {
		t.Fatalf("annotation_create failed: %v", created)
	}
	annotationRecord := created["annotation"].(map[string]any)
	annotationID := annotationRecord["id"].(string)
	contextID := annotationRecord["context_id"].(string)

	second := persistedServer(t, dir, &fakeBridgeClient{status: newFakeStatus()})
	listed := structured(postToolCall(t, second, "annotation_list", `{"context":"`+contextID+`"}`))
	if listed["code"] != nil {
		t.Fatalf("annotation_list after restart failed: %v", listed)
	}
	annotations, _ := listed["annotations"].([]any)
	if len(annotations) != 1 {
		t.Fatalf("the annotation did not survive the restart: %v", listed)
	}
	entry := annotations[0].(map[string]any)
	if entry["id"] != annotationID || entry["title"] != "lives counter" {
		t.Fatalf("reloaded annotation changed: %v", entry)
	}
	if entry["stale"] == true {
		t.Fatalf("a reloaded annotation must keep its stamps, not be flagged stale: %v", entry)
	}
}

func TestArtifactsAndContextHandleSurviveServerRestart(t *testing.T) {
	dir := t.TempDir()
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(context.Context, string, map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayload([]byte{1, 2, 3, 4}, "big-endian", 0)), nil
	}
	first := persistedServer(t, dir, client)
	createdContext := structured(postToolCall(t, first, "context_create", `{"name":"persisted"}`))
	contextID := createdContext["context"].(map[string]any)["id"].(string)
	dumped := structured(postToolCall(t, first, "memory_dump",
		fmt.Sprintf(`{"space":"m68k-ram","address":0,"length":4,"context":%q}`, contextID)))
	if dumped["code"] != nil {
		t.Fatalf("memory_dump failed: %v", dumped)
	}
	artifactID := dumped["artifact"].(map[string]any)["id"].(string)

	second := persistedServer(t, dir, &fakeBridgeClient{status: newFakeStatus()})
	listed := structured(postToolCall(t, second, "artifact_list", fmt.Sprintf(`{"context":%q}`, contextID)))
	if listed["code"] != nil {
		t.Fatalf("the persisted context handle must still resolve: %v", listed)
	}
	artifacts, _ := listed["artifacts"].([]any)
	if len(artifacts) != 1 || artifacts[0].(map[string]any)["artifact_id"] != artifactID {
		t.Fatalf("the artifact index did not survive the restart: %v", listed)
	}
	got := structured(postToolCall(t, second, "artifact_get", fmt.Sprintf(`{"artifact_id":%q,"context":%q}`, artifactID, contextID)))
	if got["code"] != nil {
		t.Fatalf("artifact_get after restart failed: %v", got)
	}
}

// stateFixtureServer uses the state_load bridge so a snapshot really lands on
// disk, then points the server at a temp states directory.
func stateFixtureServer(t *testing.T) (*Server, string) {
	t.Helper()
	bridge := newStateLoadPreserveBridge(false)
	server := newTestServer(t, bridge.client)
	server.SetStatesDir(t.TempDir())
	saved := structured(postToolCall(t, server, "state_save", `{"name":"before-boss"}`))
	if saved["state_id"] == nil {
		t.Fatalf("state_save failed: %v", saved)
	}
	return server, saved["state_id"].(string)
}

func TestStateDeleteRemovesRecordAndFile(t *testing.T) {
	server, stateID := stateFixtureServer(t)
	listed := structured(postToolCall(t, server, "state_list", `{}`))
	snapshots := listed["snapshots"].([]any)
	if len(snapshots) != 1 {
		t.Fatalf("expected one saved snapshot: %v", listed)
	}
	path := filepath.Join(server.StatesDir(), listed["context_id"].(string), stateID+".zip")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot file missing before delete: %v", err)
	}
	deleted := structured(postToolCall(t, server, "state_delete", fmt.Sprintf(`{"state_id":%q}`, stateID)))
	if deleted["code"] != nil {
		t.Fatalf("state_delete failed: %v", deleted)
	}
	if deleted["deleted"] != true || deleted["file_removed"] != true {
		t.Fatalf("delete facts wrong: %v", deleted)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("state_delete must remove the snapshot file")
	}
	if remaining := structured(postToolCall(t, server, "state_list", `{}`))["snapshots"].([]any); len(remaining) != 0 {
		t.Fatalf("deleted snapshot still listed: %v", remaining)
	}
	if _, err := postToolCall(t, server, "state_delete", fmt.Sprintf(`{"state_id":%q}`, stateID))["isError"].(bool); !err {
		t.Fatal("deleting an unknown snapshot must fail")
	}
}

func TestStateLoadByName(t *testing.T) {
	bridge := newStateLoadPreserveBridge(false)
	server := newTestServer(t, bridge.client)
	server.SetStatesDir(t.TempDir())
	first := structured(postToolCall(t, server, "state_save", `{"name":"shared"}`))
	if first["state_id"] == nil {
		t.Fatalf("state_save failed: %v", first)
	}
	loaded := structured(postToolCall(t, server, "state_load", `{"name":"shared"}`))
	if loaded["code"] != nil {
		t.Fatalf("state_load by name failed: %v", loaded)
	}
	if loaded["state_id"] != first["state_id"] {
		t.Fatalf("loaded %v, want %v", loaded["state_id"], first["state_id"])
	}

	// A second snapshot with the same name makes the selector ambiguous instead
	// of silently picking one.
	if second := structured(postToolCall(t, server, "state_save", `{"name":"shared"}`)); second["state_id"] == nil {
		t.Fatalf("second state_save failed: %v", second)
	}
	ambiguous := structured(postToolCall(t, server, "state_load", `{"name":"shared"}`))
	if ambiguous["code"] != "invalid_params" {
		t.Fatalf("an ambiguous name must be refused: %v", ambiguous)
	}
	if matches, _ := ambiguous["matches"].([]any); len(matches) != 2 {
		t.Fatalf("the refusal must name the candidates: %v", ambiguous)
	}
	both := structured(postToolCall(t, server, "state_load", `{"state_id":"state_x","name":"shared"}`))
	if both["code"] != "invalid_params" {
		t.Fatalf("state_id and name together must be refused: %v", both)
	}
}

func TestContextPruneReclaimsClosedContext(t *testing.T) {
	dir := t.TempDir()
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(context.Context, string, map[string]string) (json.RawMessage, error) {
		return json.RawMessage(memReadPayload([]byte{9, 9}, "big-endian", 0)), nil
	}
	server := persistedServer(t, dir, client)
	server.SetStatesDir(t.TempDir())
	contextID := structured(postToolCall(t, server, "context_create", `{"name":"finished"}`))["context"].(map[string]any)["id"].(string)
	if created := structured(postToolCall(t, server, "annotation_create",
		fmt.Sprintf(`{"title":"done","context":%q}`, contextID))); created["code"] != nil {
		t.Fatalf("annotation_create failed: %v", created)
	}
	if dumped := structured(postToolCall(t, server, "memory_dump",
		fmt.Sprintf(`{"space":"m68k-ram","address":0,"length":2,"context":%q}`, contextID))); dumped["code"] != nil {
		t.Fatalf("memory_dump failed: %v", dumped)
	}

	open := structured(postToolCall(t, server, "context_prune", fmt.Sprintf(`{"context_id":%q}`, contextID)))
	if open["code"] != "context_still_open" {
		t.Fatalf("an open context must not be pruned: %v", open)
	}
	if closed := structured(postToolCall(t, server, "context_close", fmt.Sprintf(`{"context_id":%q}`, contextID))); closed["code"] != nil {
		t.Fatalf("context_close failed: %v", closed)
	}
	pruned := structured(postToolCall(t, server, "context_prune", fmt.Sprintf(`{"context_id":%q}`, contextID)))
	if pruned["code"] != nil {
		t.Fatalf("context_prune failed: %v", pruned)
	}
	if pruned["annotations_removed"] != float64(1) || pruned["artifacts_removed"] != float64(1) {
		t.Fatalf("reclamation facts wrong: %v", pruned)
	}

	// The context is gone from disk, so a fresh server does not resurrect it and
	// the artifact bytes are really reclaimed.
	reopened := persistedServer(t, dir, &fakeBridgeClient{status: newFakeStatus()})
	if resolved := structured(postToolCall(t, reopened, "artifact_list", fmt.Sprintf(`{"context":%q}`, contextID))); resolved["code"] != "unknown_context" {
		t.Fatalf("a pruned context handle must not resolve after restart: %v", resolved)
	}
	entries, err := os.ReadDir(filepath.Join(analysis.WorkspaceDir(dir), "annotations"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == contextID+".json" {
			t.Fatal("prune must delete the annotation document")
		}
	}
	if _, err := os.Stat(filepath.Join(analysis.WorkspaceDir(dir), "annotations", contextID+".json")); !os.IsNotExist(err) {
		t.Fatal("annotation document still on disk after prune")
	}
}
