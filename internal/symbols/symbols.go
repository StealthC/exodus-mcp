// Package symbols stores per-analysis-context symbol tables. Symbols are a
// server-side convenience: they never mutate emulator state.
package symbols

import (
	"errors"
	"sort"
	"sync"
)

var errInvalidSymbol = errors.New("symbol name must not be empty")

// Symbol binds one name to an address. Two coordinates are recorded:
//
//   - SpaceID/Address is the coordinate the caller supplied, for example
//     mem-ram 0x1000. It is exactly what was asked for and never rewritten.
//   - BusSpaceID/BusAddress is the processor-bus coordinate resolved from it,
//     for example m68k-bus 0xFF1000. Disassembly and backtrace annotation
//     compare against this coordinate, so a RAM or Z80-RAM symbol labels the
//     instructions at its real bus address.
//
// A symbol stored before both coordinates were persisted carries only
// SpaceID/Address; BusCoordinate reports false and callers derive the bus
// coordinate from the space mapping. A symbol with an empty SpaceID is untyped:
// it has no space coordinate and resolves against the raw address on every
// processor bus.
//
// ROMSHA256 binds the symbol to the cartridge it was derived from: a symbol
// recorded while a ROM was loaded is never applied to a different cartridge,
// because equal addresses in two ROMs are unrelated code. An empty ROMSHA256 is
// an explicitly unbound (ROM-independent) symbol, which resolution reports
// separately.
type Symbol struct {
	Name       string `json:"name"`
	SpaceID    string `json:"space_id,omitempty"`
	Address    uint64 `json:"address"`
	BusSpaceID string `json:"bus_space_id,omitempty"`
	BusAddress uint64 `json:"bus_address"`
	ROMSHA256  string `json:"rom_sha256,omitempty"`
}

// BusCoordinate reports the recorded processor-bus coordinate. Symbols created
// before both coordinates were stored report false; callers then resolve the
// bus coordinate from SpaceID/Address instead of guessing.
func (symbol Symbol) BusCoordinate() (spaceID string, address uint64, ok bool) {
	if symbol.BusSpaceID == "" {
		return "", 0, false
	}
	return symbol.BusSpaceID, symbol.BusAddress, true
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
	for _, symbol := range symbols {
		if symbol.Name == "" {
			return 0, errInvalidSymbol
		}
	}
	// Store the symbols verbatim: rebuilding them field by field silently drops
	// any coordinate a later caller adds to Symbol.
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, symbol := range symbols {
		store.byName[symbol.Name] = symbol
	}
	return len(symbols), nil
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

// ListForROM returns every symbol that may be applied to a cartridge with the
// given SHA-256: symbols bound to that cartridge plus unbound symbols. A symbol
// bound to a different cartridge is suppressed, never silently remapped.
func (store *Store) ListForROM(prefix, romSHA256 string) []Symbol {
	bound := store.List(prefix)
	applicable := make([]Symbol, 0, len(bound))
	for _, symbol := range bound {
		if symbol.ROMSHA256 != "" && symbol.ROMSHA256 != romSHA256 {
			continue
		}
		applicable = append(applicable, symbol)
	}
	return applicable
}

// CountBound reports how many symbols are bound to a ROM hash.
func (store *Store) CountBound() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	bound := 0
	for _, symbol := range store.byName {
		if symbol.ROMSHA256 != "" {
			bound++
		}
	}
	return bound
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
