// Package symbols stores per-analysis-context symbol tables. Symbols are a
// server-side convenience: they never mutate emulator state.
package symbols

import (
	"errors"
	"sort"
	"sync"
)

var errInvalidSymbol = errors.New("symbol name must not be empty")

// Symbol binds one name to an address inside an address space.
type Symbol struct {
	Name    string `json:"name"`
	SpaceID string `json:"space_id,omitempty"`
	Address uint64 `json:"address"`
}

// Store is one context's symbol table with upsert semantics.
type Store struct {
	mu     sync.RWMutex
	byName map[string]Symbol
}

// NewStore returns an empty symbol store.
func NewStore() *Store {
	return &Store{byName: make(map[string]Symbol)}
}

// Set upserts the given symbols and reports how many were written.
func (store *Store) Set(symbols []Symbol) (int, error) {
	if len(symbols) == 0 {
		return 0, nil
	}
	prepared := make([]Symbol, 0, len(symbols))
	for _, symbol := range symbols {
		if symbol.Name == "" {
			return 0, errInvalidSymbol
		}
		prepared = append(prepared, Symbol{Name: symbol.Name, SpaceID: symbol.SpaceID, Address: symbol.Address})
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, symbol := range prepared {
		store.byName[symbol.Name] = symbol
	}
	return len(prepared), nil
}

// List returns every symbol ordered by address, then name. An empty prefix
// matches everything; otherwise names must start with the prefix.
func (store *Store) List(prefix string) []Symbol {
	store.mu.RLock()
	symbols := make([]Symbol, 0, len(store.byName))
	for _, symbol := range store.byName {
		if prefix != "" && !hasPrefixFold(symbol.Name, prefix) {
			continue
		}
		symbols = append(symbols, symbol)
	}
	store.mu.RUnlock()
	sort.Slice(symbols, func(i, j int) bool {
		if symbols[i].Address != symbols[j].Address {
			return symbols[i].Address < symbols[j].Address
		}
		return symbols[i].Name < symbols[j].Name
	})
	return symbols
}

// Clear removes every symbol and reports how many were removed.
func (store *Store) Clear() int {
	store.mu.Lock()
	count := len(store.byName)
	store.byName = make(map[string]Symbol)
	store.mu.Unlock()
	return count
}

func hasPrefixFold(name, prefix string) bool {
	if len(name) < len(prefix) {
		return false
	}
	for index := 0; index < len(prefix); index++ {
		a, b := name[index], prefix[index]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}
