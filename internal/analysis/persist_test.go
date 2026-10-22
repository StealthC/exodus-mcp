package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

// ----------------------------------------------------------------------------------------------------------------------
// Workspace persistence (roadmap issue #18)
//
// An analysis is only worth the name if it survives the process that produced
// it. These tests reopen the workspace from disk instead of inspecting in-memory
// state, so they fail if persistence regresses.
// ----------------------------------------------------------------------------------------------------------------------

func TestWorkspaceSurvivesReopen(t *testing.T) {
	root := t.TempDir()
	registry, err := OpenRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	defaultID := registry.Default().ID
	context, err := registry.Create("boss analysis")
	if err != nil {
		t.Fatal(err)
	}
	created, err := context.Annotations.Create(context.ID, testAnnotation())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := context.Annotations.Create(context.ID, Annotation{Title: "second", Kind: "observation"}); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenRegistry(root)
	if err != nil {
		t.Fatalf("reopen workspace: %v", err)
	}
	if reopened.Default() == nil || reopened.Default().ID != defaultID {
		t.Fatalf("the default context must keep its handle across a restart: was %s, now %v", defaultID, reopened.Default())
	}
	restored, err := reopened.Resolve(context.ID)
	if err != nil {
		t.Fatalf("a created context must resolve after a restart: %v", err)
	}
	if restored.Name != "boss analysis" {
		t.Fatalf("context name lost: %q", restored.Name)
	}
	annotations := restored.Annotations.Export(context.ID)
	if len(annotations) != 2 {
		t.Fatalf("annotations lost across restart: %v", annotations)
	}
	found := false
	for _, annotation := range annotations {
		if annotation.ID != created.ID {
			continue
		}
		found = true
		if annotation.Title != created.Title || annotation.Text != created.Text || annotation.TargetGeneration != created.TargetGeneration {
			t.Fatalf("annotation fields changed across restart: %+v", annotation)
		}
		if annotation.Links.Artifacts == nil || annotation.Links.Artifacts[0] != created.Links.Artifacts[0] {
			t.Fatalf("annotation links lost: %+v", annotation.Links)
		}
	}
	if !found {
		t.Fatalf("the created annotation is missing after restart: %v", annotations)
	}
}

func TestWorkspacePersistsMutations(t *testing.T) {
	root := t.TempDir()
	registry, err := OpenRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	defaults := registry.Default()
	created, err := defaults.Annotations.Create(defaults.ID, testAnnotation())
	if err != nil {
		t.Fatal(err)
	}
	title := "renamed after review"
	if _, err := defaults.Annotations.Update(defaults.ID, created.ID, AnnotationUpdate{Title: &title}); err != nil {
		t.Fatal(err)
	}
	deleted, err := defaults.Annotations.Create(defaults.ID, Annotation{Title: "temporary", Kind: "observation"})
	if err != nil {
		t.Fatal(err)
	}
	if err := defaults.Annotations.Delete(defaults.ID, deleted.ID); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	annotations := reopened.Default().Annotations.Export(reopened.Default().ID)
	if len(annotations) != 1 {
		t.Fatalf("expected the surviving annotation only: %v", annotations)
	}
	if annotations[0].Title != title {
		t.Fatalf("update was not persisted: %+v", annotations[0])
	}
}

func TestReopenRejectsCorruptWorkspace(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(WorkspaceDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(WorkspaceDir(root), "contexts.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"analysis-contexts/1","contexts":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegistry(root); err == nil {
		t.Fatal("an undecodable context document must fail startup instead of silently discarding the workspace")
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"analysis-contexts/99","contexts":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegistry(root); err == nil {
		t.Fatal("an unsupported context schema must fail startup")
	}
}

func TestReopenRejectsCorruptAnnotations(t *testing.T) {
	root := t.TempDir()
	registry, err := OpenRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	context, err := registry.Create("corrupt me")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(WorkspaceDir(root), "annotations", context.ID+".json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"annotations/1","annotations":[{"title":""}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegistry(root); err == nil {
		t.Fatal("an invalid persisted annotation must fail startup instead of being dropped")
	}
}

func TestPruneReclaimsOnlyClosedContexts(t *testing.T) {
	root := t.TempDir()
	registry, err := OpenRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Prune(registry.Default().ID); err == nil {
		t.Fatal("the default context must not be prunable")
	}
	context, err := registry.Create("finished")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := context.Annotations.Create(context.ID, testAnnotation()); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Prune(context.ID); err == nil {
		t.Fatal("an open context must not be prunable")
	}
	if _, err := registry.Close(context.ID); err != nil {
		t.Fatal(err)
	}
	pruned, err := registry.Prune(context.ID)
	if err != nil {
		t.Fatalf("prune a closed context: %v", err)
	}
	if pruned.ID != context.ID {
		t.Fatalf("pruned the wrong context: %+v", pruned)
	}
	if _, err := os.Stat(filepath.Join(WorkspaceDir(root), "annotations", context.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("prune must remove the annotation document")
	}
	reopened, err := OpenRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Resolve(context.ID); err == nil {
		t.Fatal("a pruned context must not reappear after a restart")
	}
}

func TestInMemoryRegistryHasNoSideEffects(t *testing.T) {
	registry := NewRegistry()
	if registry.Dir() != "" {
		t.Fatalf("NewRegistry must stay in-memory, dir = %q", registry.Dir())
	}
	context, err := registry.Create("scratch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := context.Annotations.Create(context.ID, testAnnotation()); err != nil {
		t.Fatal(err)
	}
}

// TestAnnotationStorePersistsAcrossRestart is the store-level half: a bound
// store reloads its own document.
func TestAnnotationStorePersistsAcrossRestart(t *testing.T) {
	root := t.TempDir()
	registry, err := OpenRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	context, err := registry.Create("store-level")
	if err != nil {
		t.Fatal(err)
	}
	created, err := context.Annotations.Create(context.ID, testAnnotation())
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadAnnotationStore(registry.annotationPath(context.ID), context.ID)
	if err != nil {
		t.Fatalf("reload annotation document: %v", err)
	}
	got, err := reloaded.Get(context.ID, created.ID)
	if err != nil {
		t.Fatalf("reloaded store lost the annotation: %v", err)
	}
	if got.Title != created.Title {
		t.Fatalf("title = %q", got.Title)
	}
}
