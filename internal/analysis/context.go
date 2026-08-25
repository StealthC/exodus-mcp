// Package analysis implements explicit analysis-context handles. Contexts are
// application concepts, not MCP protocol sessions: they scope symbols,
// artifacts, snapshots, and resource provenance. They are namespaces for
// analysis data only, never virtual emulator instances.
package analysis

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/StealthC/exodus-mcp/internal/symbols"
)

// Context is one agent-scoped analysis workspace.
type Context struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Default   bool      `json:"default"`
	Closed    bool      `json:"closed"`

	Symbols *symbols.Store `json:"-"`
}

// Registry owns every context for one server process.
type Registry struct {
	mu       sync.Mutex
	defaults map[string]bool
	contexts map[string]*Context

	// States stores context-scoped snapshots; the registry lives for the
	// server process like the contexts themselves.
	States *StateStore
}

// NewRegistry creates the registry plus the implicit default context.
func NewRegistry() *Registry {
	registry := &Registry{
		defaults: make(map[string]bool),
		contexts: make(map[string]*Context),
		States:   newStateStore(),
	}
	context := registry.create("default", true)
	registry.defaults[context.ID] = true
	return registry
}

// Create registers a new named context.
func (registry *Registry) Create(name string) (*Context, error) {
	if name == "" {
		return nil, fmt.Errorf("context name must not be empty")
	}
	if len(name) > 100 {
		return nil, fmt.Errorf("context name must be at most 100 characters")
	}
	return registry.create(name, false), nil
}

// Default returns the implicit default context.
func (registry *Registry) Default() *Context {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for id := range registry.defaults {
		return registry.contexts[id]
	}
	return nil
}

// Resolve maps an optional context handle to a live context, falling back to
// the default when the handle is empty.
func (registry *Registry) Resolve(id string) (*Context, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if id == "" {
		for contextID := range registry.defaults {
			return registry.contexts[contextID], nil
		}
		return nil, fmt.Errorf("no default analysis context exists")
	}
	context, present := registry.contexts[id]
	if !present || context.Closed {
		return nil, fmt.Errorf("unknown analysis context %q", id)
	}
	return context, nil
}

// List returns open contexts ordered by creation time.
func (registry *Registry) List() []*Context {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	contexts := make([]*Context, 0, len(registry.contexts))
	for _, context := range registry.contexts {
		if !context.Closed {
			contexts = append(contexts, context)
		}
	}
	sort.Slice(contexts, func(i, j int) bool { return contexts[i].CreatedAt.Before(contexts[j].CreatedAt) })
	return contexts
}

// Close marks one context closed; the default context is protected. Any
// process-wide target control lock acquired under this context is released by
// the server layer, which records why it ended.
func (registry *Registry) Close(id string) (*Context, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	context, present := registry.contexts[id]
	if !present || context.Closed {
		return nil, fmt.Errorf("unknown analysis context %q", id)
	}
	if registry.defaults[id] {
		return nil, fmt.Errorf("the default analysis context cannot be closed")
	}
	context.Closed = true
	return context, nil
}

func (registry *Registry) create(name string, isDefault bool) *Context {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	context := &Context{
		ID:        newID(),
		Name:      name,
		CreatedAt: time.Now().UTC(),
		Default:   isDefault,
		Symbols:   symbols.NewStore(),
	}
	registry.contexts[context.ID] = context
	return context
}

func newID() string {
	buffer := make([]byte, 9)
	if _, err := rand.Read(buffer); err != nil {
		panic(fmt.Sprintf("generate analysis context id: %v", err))
	}
	return "ctx_" + base64.RawURLEncoding.EncodeToString(buffer)
}
