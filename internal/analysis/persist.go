package analysis

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/StealthC/exodus-mcp/internal/symbols"
)

// This file makes one analysis workspace survive a server restart. Contexts,
// and the annotations each context owns, are written under
//
//	<artifact-dir>/analysis/contexts.json
//	<artifact-dir>/analysis/annotations/<context-id>.json
//
// The location is deliberately a subdirectory of the artifact directory the
// artifact index already uses: the artifact store treats unknown directories as
// unavailable to it (it only reclaims unknown *files*), so the two indexes
// coexist without either deleting the other.
//
// Context handles stay opaque, but they are no longer regenerated on every
// start: a reloaded context keeps its id, name, creation time, and closed flag,
// which is what lets the artifact index (keyed by context id) and the
// annotation documents find their owner again. Symbols are not persisted;
// re-declare them with symbols_set, or re-derive them from a symbol export.

const (
	// ContextsSchema is the versioned schema of the persisted context registry.
	ContextsSchema = "analysis-contexts/1"
	// AnnotationsSchema is the versioned schema of one persisted annotation
	// document. It is per context and separate from the annotation-export/1
	// artifact, which is an analyst-facing snapshot with ROM identity.
	AnnotationsSchema = "annotations/1"
	// workspaceDirName is the subdirectory of the artifact root that anchors
	// the analysis workspace.
	workspaceDirName = "analysis"
)

// ErrAnnotationStore wraps a persistence failure so the tool layer can report
// it as a workspace failure instead of a validation error.
var ErrAnnotationStore = errors.New("annotation store persistence failed")

// ErrContextStore wraps a context-registry persistence failure.
var ErrContextStore = errors.New("context registry persistence failed")

// persistedContext is the durable part of one context. Symbols are deliberately
// not part of it (see the package comment).
type persistedContext struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Default   bool      `json:"default"`
	Closed    bool      `json:"closed"`
}

// contextsDocument is the on-disk context registry.
type contextsDocument struct {
	SchemaVersion string             `json:"schema_version"`
	Contexts      []persistedContext `json:"contexts"`
}

// annotationsDocument is the on-disk annotation set of one context.
type annotationsDocument struct {
	SchemaVersion string       `json:"schema_version"`
	ContextID     string       `json:"context_id"`
	Annotations   []Annotation `json:"annotations"`
}

// WorkspaceDir reports the directory that anchors contexts and annotations for
// one artifact root.
func WorkspaceDir(artifactDir string) string {
	return filepath.Join(artifactDir, workspaceDirName)
}

// OpenRegistry reopens the analysis workspace stored under artifactDir,
// creating it on first use. It returns an error (instead of silently starting
// empty) when a persisted document exists but cannot be read or decoded: a
// workspace that quietly loses its annotations is worse than a startup failure.
func OpenRegistry(artifactDir string) (*Registry, error) {
	root := WorkspaceDir(artifactDir)
	if err := os.MkdirAll(filepath.Join(root, "annotations"), 0o700); err != nil {
		return nil, fmt.Errorf("%w: create workspace directory: %v", ErrContextStore, err)
	}
	registry := &Registry{
		defaults: make(map[string]bool),
		contexts: make(map[string]*Context),
		States:   newStateStore(),
		dir:      root,
	}
	document, present, err := readContextsDocument(filepath.Join(root, "contexts.json"))
	if err != nil {
		return nil, err
	}
	if present && document.SchemaVersion != ContextsSchema {
		return nil, fmt.Errorf("%w: unsupported schema %q (expected %s)", ErrContextStore, document.SchemaVersion, ContextsSchema)
	}
	if !present || len(document.Contexts) == 0 {
		context := registry.create("default", true)
		registry.defaults[context.ID] = true
		if err := registry.persistLocked(); err != nil {
			return nil, err
		}
		return registry, nil
	}
	for _, persisted := range document.Contexts {
		if persisted.ID == "" || persisted.Name == "" {
			return nil, fmt.Errorf("%w: persisted context has no id or name", ErrContextStore)
		}
		annotations, err := loadAnnotationStore(registry.annotationPath(persisted.ID), persisted.ID)
		if err != nil {
			return nil, err
		}
		registry.contexts[persisted.ID] = &Context{
			ID:          persisted.ID,
			Name:        persisted.Name,
			CreatedAt:   persisted.CreatedAt,
			Default:     persisted.Default,
			Closed:      persisted.Closed,
			Symbols:     symbols.NewStore(),
			Annotations: annotations,
		}
		if persisted.Default {
			registry.defaults[persisted.ID] = true
		}
	}
	if len(registry.defaults) == 0 {
		// A workspace written by an older revision (or hand-edited) may have no
		// default context; add one instead of failing every empty-handle call.
		context := registry.create("default", true)
		registry.defaults[context.ID] = true
		if err := registry.persistLocked(); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// readContextsDocument loads the context registry; present reports whether a
// document exists at all.
func readContextsDocument(path string) (contextsDocument, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return contextsDocument{}, false, nil
	}
	if err != nil {
		return contextsDocument{}, false, fmt.Errorf("%w: read %s: %v", ErrContextStore, path, err)
	}
	var document contextsDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return contextsDocument{}, false, fmt.Errorf("%w: decode %s: %v", ErrContextStore, path, err)
	}
	return document, true, nil
}

// Dir reports the workspace directory; empty for an in-memory registry.
func (registry *Registry) Dir() string { return registry.dir }

// annotationPath is the persisted document of one context.
func (registry *Registry) annotationPath(contextID string) string {
	if registry.dir == "" {
		return ""
	}
	return filepath.Join(registry.dir, "annotations", contextID+".json")
}

// persistLocked writes the context registry. Callers must hold the mutex.
func (registry *Registry) persistLocked() error {
	if registry.dir == "" {
		return nil
	}
	document := contextsDocument{SchemaVersion: ContextsSchema}
	for _, context := range registry.contexts {
		document.Contexts = append(document.Contexts, persistedContext{
			ID:        context.ID,
			Name:      context.Name,
			CreatedAt: context.CreatedAt,
			Default:   context.Default,
			Closed:    context.Closed,
		})
	}
	sort.Slice(document.Contexts, func(i, j int) bool {
		if document.Contexts[i].CreatedAt.Equal(document.Contexts[j].CreatedAt) {
			return document.Contexts[i].ID < document.Contexts[j].ID
		}
		return document.Contexts[i].CreatedAt.Before(document.Contexts[j].CreatedAt)
	})
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode contexts: %v", ErrContextStore, err)
	}
	if err := writeFileAtomic(filepath.Join(registry.dir, "contexts.json"), data); err != nil {
		return fmt.Errorf("%w: %v", ErrContextStore, err)
	}
	return nil
}

// Prune removes one closed, non-default context from the workspace so it stops
// reappearing at startup. It reports the context that was removed; the caller
// owns the artifacts, snapshots, and trace data keyed by its id. The default
// context and an open context are refused: prune reclaims a finished workspace,
// it never destroys a live one.
func (registry *Registry) Prune(id string) (*Context, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	context, present := registry.contexts[id]
	if !present {
		return nil, fmt.Errorf("unknown analysis context %q", id)
	}
	if registry.defaults[id] {
		return nil, fmt.Errorf("the default analysis context cannot be pruned")
	}
	if !context.Closed {
		return nil, fmt.Errorf("analysis context %q is still open; close it before pruning", id)
	}
	delete(registry.contexts, id)
	if registry.dir != "" {
		if err := os.Remove(filepath.Join(registry.dir, "annotations", id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: remove annotation document: %v", ErrAnnotationStore, err)
		}
	}
	if err := registry.persistLocked(); err != nil {
		return nil, err
	}
	return context, nil
}

// writeFileAtomic writes one document durably: a temp file in the destination
// directory, then a rename, so a crash never leaves a half-written index.
func writeFileAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		os.Remove(name)
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		os.Remove(name)
		return err
	}
	if err := temporary.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// ----------------------------------------------------------------------------------------------------------------------
// Annotation persistence
// ----------------------------------------------------------------------------------------------------------------------

// loadAnnotationStore reopens the annotation document of one context. A missing
// document is an empty store; an undecodable one fails startup.
func loadAnnotationStore(path, contextID string) (*AnnotationStore, error) {
	store := NewAnnotationStore()
	if path == "" {
		return store, nil
	}
	store.path = path
	store.contextID = contextID
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrAnnotationStore, path, err)
	}
	var document annotationsDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("%w: decode %s: %v", ErrAnnotationStore, path, err)
	}
	if document.SchemaVersion != AnnotationsSchema {
		return nil, fmt.Errorf("%w: unsupported schema %q in %s (expected %s)", ErrAnnotationStore, document.SchemaVersion, path, AnnotationsSchema)
	}
	for _, annotation := range document.Annotations {
		if annotation.ContextID != "" && annotation.ContextID != contextID {
			// A hand-copied file must not smuggle another context's records in.
			return nil, fmt.Errorf("%w: %s holds an annotation of context %q", ErrAnnotationStore, path, annotation.ContextID)
		}
		if err := validateAnnotation(&annotation); err != nil {
			return nil, fmt.Errorf("%w: %s holds an invalid annotation: %v", ErrAnnotationStore, path, err)
		}
		annotation.ContextID = contextID
		store.byID[annotation.ID] = annotation
		store.byCtx[contextID] = append(store.byCtx[contextID], annotation.ID)
	}
	store.sortByCtxLocked(contextID)
	return store, nil
}

// persistLocked writes one context's annotations. Callers must hold the lock.
func (store *AnnotationStore) persistLocked() error {
	if store.path == "" {
		return nil
	}
	// Persist the durable order (codepoint order of the ids) so a reload does
	// not depend on insertion order; readers sort by created_at anyway.
	ids := make([]string, 0, len(store.byCtx[store.contextID]))
	ids = append(ids, store.byCtx[store.contextID]...)
	sort.Strings(ids)
	document := annotationsDocument{
		SchemaVersion: AnnotationsSchema,
		ContextID:     store.contextID,
		Annotations:   make([]Annotation, 0, len(ids)),
	}
	for _, id := range ids {
		if annotation, present := store.byID[id]; present {
			document.Annotations = append(document.Annotations, annotation)
		}
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode annotations: %v", ErrAnnotationStore, err)
	}
	if err := writeFileAtomic(store.path, data); err != nil {
		return fmt.Errorf("%w: %v", ErrAnnotationStore, err)
	}
	return nil
}

// newAnnotationStore binds the annotation store of a freshly generated context
// to its document path, so the first mutation persists it. The id is new, so
// there is nothing to read back here.
func (registry *Registry) newAnnotationStore(contextID string) *AnnotationStore {
	store := NewAnnotationStore()
	store.contextID = contextID
	store.path = registry.annotationPath(contextID)
	return store
}
