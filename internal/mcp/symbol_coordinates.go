package mcp

import (
	"sort"
	"strings"

	"github.com/StealthC/exodus-mcp/internal/symbols"
)

// Space-relative symbol coordinates.
//
// symbols_set accepts a space id from memory_spaces_list (mem-ram, mem-rom,
// z80-bus, ...), whose addresses are space-relative. Disassembly and backtrace
// annotation compare against processor-bus addresses, so every stored symbol is
// annotated from its bus coordinate instead of its raw space address. The
// translation is the documented Mega Drive baseline in spacemap.go:
//
//	bus_address = bus_base + bus_offset + space_relative_address
//
// Symbols stored before both coordinates were persisted carry only
// SpaceID/Address; they are translated here at annotation time, which keeps
// historical `space_id: "m68k-bus"` symbols working unchanged.

// symbolBusTarget is where one stored symbol annotates. SpaceID is the
// processor-bus space id ("m68k-bus", "z80-bus"); an untyped symbol reports an
// empty SpaceID and applies to every processor bus at Address. Applies is false
// when the symbol has no CPU-bus coordinate at all (for example a VDP space
// stored by an older build), in which case it never annotates.
type symbolBusTarget struct {
	SpaceID string
	Address uint64
	Applies bool
}

// symbolBusTargetFor resolves the processor-bus coordinate of one stored
// symbol. The recorded coordinate wins; otherwise the caller-supplied space is
// translated through the documented bus mapping.
func symbolBusTargetFor(symbol symbols.Symbol) symbolBusTarget {
	if spaceID, address, ok := symbol.BusCoordinate(); ok {
		return symbolBusTarget{SpaceID: spaceID, Address: address, Applies: true}
	}
	if strings.TrimSpace(symbol.SpaceID) == "" {
		// Untyped symbols historically annotate every processor bus at the raw
		// address. Preserve that behavior.
		return symbolBusTarget{Address: symbol.Address, Applies: true}
	}
	mapping, known := mdSpaceBusMap[symbol.SpaceID]
	if !known || mapping.Bus == "" {
		return symbolBusTarget{}
	}
	base := mapping.BusBase + mapping.BusOffset
	if symbol.Address > ^uint64(0)-base {
		return symbolBusTarget{}
	}
	return symbolBusTarget{SpaceID: mapping.Bus + "-bus", Address: base + symbol.Address, Applies: true}
}

// symbolBusSpaceFor returns the processor-bus space id of a caller-supplied
// space id and whether that space has a documented CPU-bus mapping. A space
// without a mapping cannot annotate disassembly, so symbols_set rejects it
// instead of storing an inert symbol.
func symbolBusSpaceFor(spaceID string) (string, bool) {
	mapping, known := mdSpaceBusMap[strings.TrimSpace(spaceID)]
	if !known || mapping.Bus == "" {
		return "", false
	}
	return mapping.Bus + "-bus", true
}

// symbolSpaceNote returns the documented explanation for a space that exists
// but is not linearly mapped on any processor bus. It is empty for spaces the
// server does not know at all.
func symbolSpaceNote(spaceID string) string {
	return mdSpaceBusNotes[strings.TrimSpace(spaceID)]
}

// symbolBusIndex resolves masked processor-bus addresses against the context
// symbols that apply to one bus. byAddress holds exact matches; sorted holds
// the same symbols ordered by masked address for bounded nearest-below
// resolution.
type symbolBusIndex struct {
	byAddress map[uint64]string
	sorted    []symbols.Symbol
	mask      uint64
}

// newSymbolBusIndex indexes every applicable symbol of one context against one
// processor bus. Symbols are visited in store order (address, then name), so a
// duplicated address keeps the first name deterministically.
func newSymbolBusIndex(store *symbols.Store, romSHA256, busSpaceID string) *symbolBusIndex {
	_, mask := addressBusWidthMask(busSpaceID)
	if mask == 0 {
		mask = ^uint64(0)
	}
	index := &symbolBusIndex{byAddress: map[uint64]string{}, mask: mask}
	if store == nil {
		return index
	}
	for _, symbol := range store.ListForROM("", romSHA256) {
		target := symbolBusTargetFor(symbol)
		if !target.Applies {
			continue
		}
		// An untyped symbol applies to every bus; a typed one only to its own.
		if target.SpaceID != "" && target.SpaceID != busSpaceID {
			continue
		}
		masked := target.Address & mask
		if _, exists := index.byAddress[masked]; !exists {
			index.byAddress[masked] = symbol.Name
		}
		index.sorted = append(index.sorted, symbols.Symbol{Name: symbol.Name, Address: masked})
	}
	sort.SliceStable(index.sorted, func(i, j int) bool { return index.sorted[i].Address < index.sorted[j].Address })
	return index
}

// lookup reports the symbol at the exact masked bus address.
func (index *symbolBusIndex) lookup(address uint64) (string, bool) {
	name, ok := index.byAddress[address&index.mask]
	return name, ok
}

// empty reports whether no symbol applies to this bus.
func (index *symbolBusIndex) empty() bool {
	return len(index.byAddress) == 0
}

// symbolsView renders stored symbols with both coordinates: the caller-supplied
// space coordinate (space_id/address) and the resolved processor-bus coordinate
// (bus_space_id/bus_address). It is the echo shared by symbols_set and
// symbols_list.
func symbolsView(stored []symbols.Symbol) []map[string]any {
	views := make([]map[string]any, 0, len(stored))
	for _, symbol := range stored {
		views = append(views, symbolView(symbol))
	}
	return views
}

// symbolView renders one stored symbol with both coordinates.
func symbolView(symbol symbols.Symbol) map[string]any {
	view := map[string]any{
		"name":        symbol.Name,
		"address":     symbol.Address,
		"address_hex": canonicalHex(symbol.Address),
	}
	target := symbolBusTargetFor(symbol)
	if strings.TrimSpace(symbol.SpaceID) == "" {
		view["space_id"] = ""
		view["address_space"] = ""
		view["untyped"] = true
		view["bus_space_id"] = ""
		view["bus_address"] = symbol.Address
		view["bus_address_hex"] = canonicalHex(symbol.Address)
		view["coordinate_note"] = "untyped symbol: resolves against the raw address on every processor bus"
		return view
	}
	view["space_id"] = symbol.SpaceID
	view["address_space"] = symbol.SpaceID
	view["space_address"] = symbol.Address
	view["space_address_hex"] = canonicalHex(symbol.Address)
	view["untyped"] = false
	if !target.Applies {
		view["bus_space_id"] = ""
		view["coordinate_note"] = "this space has no documented CPU-bus coordinate, so the symbol never annotates disassembly"
		return view
	}
	view["bus_space_id"] = target.SpaceID
	view["bus_address"] = target.Address
	view["bus_address_hex"] = canonicalHex(target.Address)
	if width, mask := addressBusWidthMask(target.SpaceID); width != 0 {
		view["address_width_bits"] = width
		view["address_mask_hex"] = canonicalHex(mask)
	}
	return view
}
