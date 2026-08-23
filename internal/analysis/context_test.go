package analysis

import (
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/symbols"
)

func TestRegistryCreatesDefaultContext(t *testing.T) {
	registry := NewRegistry()
	def := registry.Default()
	if def == nil || def.Name != "default" || !def.Default {
		t.Fatalf("default context missing: %+v", def)
	}
	resolved, err := registry.Resolve("")
	if err != nil || resolved.ID != def.ID {
		t.Fatalf("empty handle must resolve to default: %v", err)
	}
}

func TestCreateResolveCloseLifecycle(t *testing.T) {
	registry := NewRegistry()
	context, err := registry.Create("research")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.Create(""); err == nil {
		t.Fatal("empty name must be rejected")
	}
	if len(registry.List()) != 2 {
		t.Fatalf("list count = %d", len(registry.List()))
	}
	closed, err := registry.Close(context.ID)
	if err != nil || !closed.Closed {
		t.Fatalf("close failed: %v", err)
	}
	if _, err = registry.Resolve(context.ID); err == nil {
		t.Fatal("closed context must not resolve")
	}
	if _, err = registry.Close(context.ID); err == nil {
		t.Fatal("double close must fail")
	}
}

func TestCloseRejectsDefault(t *testing.T) {
	registry := NewRegistry()
	def := registry.Default()
	_, err := registry.Close(def.ID)
	if err == nil || !strings.Contains(err.Error(), "cannot be closed") {
		t.Fatalf("default close must be protected: %v", err)
	}
}

func TestContextSymbolsAreIsolated(t *testing.T) {
	registry := NewRegistry()
	first, _ := registry.Create("a")
	second, _ := registry.Create("b")
	if _, err := first.Symbols.Set([]symbols.Symbol{{Name: "main", Address: 256}}); err != nil {
		t.Fatal(err)
	}
	if got := len(second.Symbols.List("")); got != 0 {
		t.Fatalf("symbol leaked across contexts: %d", got)
	}
}
