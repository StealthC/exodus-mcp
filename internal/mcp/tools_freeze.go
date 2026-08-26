package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"
)

// freezeTickInterval is how often the server re-applies frozen cells while at
// least one entry exists. The Mega Drive timer ticks once per second, so 20 Hz
// leaves ample margin at negligible pipe load; the mechanism still holds cells
// that churn every frame.
const freezeTickInterval = 50 * time.Millisecond

// freezeMaxEntries caps the number of simultaneous frozen ranges so a runaway
// client cannot fill the bridge queue with periodic writes.
const freezeMaxEntries = 16

var errFreezeLimit = errors.New("freeze entry limit reached")

// freezeEntry is one server-maintained frozen cell range. The server re-writes
// data through the bridge at freezeTickInterval while the entry exists, so the
// emulated program's own updates to the range are continuously undone. The
// provenance fields describe who created the entry and at which target
// generation; they are not an authorization boundary.
type freezeEntry struct {
	ID               string
	Space            string
	Address          uint64
	Data             []byte
	CreatedAt        time.Time
	LastWriteAt      time.Time
	WriteCount       uint64
	LastError        string
	ContextID        string
	ControlID        string
	TargetGeneration uint64
	ROMPath          string
}

// freezeProvenance records who created a freeze entry and when.
type freezeProvenance struct {
	ContextID        string
	ControlID        string
	TargetGeneration uint64
	ROMPath          string
}

// freezeRegistry owns the process-wide freeze set. Entries are machine-level,
// like breakpoints: a freeze applies to whatever cartridge is loaded, which is
// why rom_load purges the whole set (stale addresses would be written into the
// new program's memory map).
type freezeRegistry struct {
	mu     sync.Mutex
	nextID uint64
	byID   map[string]*freezeEntry
	byKey  map[string]string // space + ":" + address -> freeze id
	order  []*freezeEntry    // stable listing order
}

func newFreezeRegistry() *freezeRegistry {
	return &freezeRegistry{
		byID:  make(map[string]*freezeEntry),
		byKey: make(map[string]string),
	}
}

func freezeKey(space string, address uint64) string {
	return space + ":" + strconv.FormatUint(address, 10)
}

// set registers or replaces the frozen bytes at one space+address. It returns
// the entry, whether an earlier entry was replaced, and errFreezeLimit when
// the set is full and the address is not already frozen. Replacing an entry
// refreshes its provenance to the new mutation.
func (registry *freezeRegistry) set(space string, address uint64, data []byte, provenance freezeProvenance) (*freezeEntry, bool, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	key := freezeKey(space, address)
	if id := registry.byKey[key]; id != "" {
		entry := registry.byID[id]
		entry.Data = append(entry.Data[:0], data...)
		entry.ContextID = provenance.ContextID
		entry.ControlID = provenance.ControlID
		entry.TargetGeneration = provenance.TargetGeneration
		entry.ROMPath = provenance.ROMPath
		return entry, true, nil
	}
	if len(registry.byID) >= freezeMaxEntries {
		return nil, false, errFreezeLimit
	}
	registry.nextID++
	entry := &freezeEntry{
		ID:               "frz_" + strconv.FormatUint(registry.nextID, 36),
		Space:            space,
		Address:          address,
		Data:             append([]byte{}, data...),
		CreatedAt:        time.Now().UTC(),
		ContextID:        provenance.ContextID,
		ControlID:        provenance.ControlID,
		TargetGeneration: provenance.TargetGeneration,
		ROMPath:          provenance.ROMPath,
	}
	registry.byID[entry.ID] = entry
	registry.byKey[key] = entry.ID
	registry.order = append(registry.order, entry)
	return entry, false, nil
}

// has reports whether an entry with the id exists.
func (registry *freezeRegistry) has(id string) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.byID[id] != nil
}

// getAt returns the entry frozen at one space+address, or nil.
func (registry *freezeRegistry) getAt(space string, address uint64) *freezeEntry {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	id := registry.byKey[freezeKey(space, address)]
	if id == "" {
		return nil
	}
	entry := registry.byID[id]
	copy := *entry
	copy.Data = append([]byte{}, entry.Data...)
	return &copy
}

// ids returns the ids of every registered entry, for audited invalidation
// batches on rom_load.
func (registry *freezeRegistry) ids() []string {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	ids := make([]string, 0, len(registry.byID))
	for id := range registry.byID {
		ids = append(ids, id)
	}
	return ids
}

// remove deletes one entry by id and reports whether it existed.
func (registry *freezeRegistry) remove(id string) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry, present := registry.byID[id]
	if !present {
		return false
	}
	delete(registry.byID, id)
	delete(registry.byKey, freezeKey(entry.Space, entry.Address))
	for index, candidate := range registry.order {
		if candidate.ID == id {
			registry.order = append(registry.order[:index], registry.order[index+1:]...)
			break
		}
	}
	return true
}

// purge removes every entry, returning how many were dropped. Called when a
// new cartridge is loaded so stale ranges are never written into a different
// program's address map.
func (registry *freezeRegistry) purge() int {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	count := len(registry.byID)
	registry.byID = make(map[string]*freezeEntry)
	registry.byKey = make(map[string]string)
	registry.order = nil
	return count
}

// list returns a stable snapshot of the entries in creation order.
func (registry *freezeRegistry) list() []*freezeEntry {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	out := make([]*freezeEntry, len(registry.order))
	for index, entry := range registry.order {
		entry := *entry
		entry.Data = append([]byte{}, entry.Data...)
		out[index] = &entry
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// touch records the outcome of one periodic re-write for an entry.
func (registry *freezeRegistry) touch(id, lastError string, wrote bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry := registry.byID[id]
	if entry == nil {
		return
	}
	entry.LastError = lastError
	if !wrote {
		return
	}
	entry.WriteCount++
	entry.LastWriteAt = time.Now().UTC()
}

// memWriteCommand issues one bridge memory write for the given raw bytes and
// returns the plugin payload, mirroring the memory_write tool's wire format.
func (server *Server) memWriteCommand(ctx context.Context, space string, address uint64, data []byte) (map[string]any, *toolFailure) {
	return server.executeCommand(ctx, "mem_write", map[string]string{
		"space":   space,
		"address": strconv.FormatUint(address, 10),
		"length":  strconv.Itoa(len(data)),
		"data":    base64.StdEncoding.EncodeToString(data),
	})
}

// StartFreezeSweeper launches the background loop that re-applies frozen
// ranges at freezeTickInterval. The goroutine dies with the process; every
// write goes through the serialized bridge queue like any other command.
func (server *Server) StartFreezeSweeper() {
	go func() {
		ticker := time.NewTicker(freezeTickInterval)
		defer ticker.Stop()
		for range ticker.C {
			server.applyFreezes()
		}
	}()
}

// applyFreezes re-writes every registered freeze range once.
func (server *Server) applyFreezes() {
	entries := server.freezes.list()
	if len(entries) == 0 {
		return
	}
	for _, entry := range entries {
		_, failure := server.memWriteCommand(context.Background(), entry.Space, entry.Address, entry.Data)
		if failure != nil {
			server.freezes.touch(entry.ID, failure.Code+": "+failure.Message, false)
			continue
		}
		server.freezes.touch(entry.ID, "", true)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Tools
// ----------------------------------------------------------------------------------------------------------------------

func freezeToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "memory_freeze",
			description: "Register a cell range that the server re-writes at about 20 Hz, undoing the emulated program's own updates to it. Applies the bytes once immediately (like memory_write), then keeps them pinned while the entry exists. Bytes arrive as exactly one of data (base64) or data_hex (hex bytes with optional spaces). Replacing an entry at the same space+address updates the pinned bytes; rom_load purges the whole set with an audited invalidation. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"context":                    contextProperty(),
				"space":                      stringProperty("Space id from memory_spaces_list, such as m68k-bus."),
				"address":                    addressProperty(),
				"data":                       stringProperty("Bytes to keep in place, base64-encoded (up to 4096 bytes). Mutually exclusive with data_hex."),
				"data_hex":                   stringProperty("Bytes to keep in place as hex with optional spaces, e.g. \"4A 42 41\" (up to 4096 bytes). Mutually exclusive with data."),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"space", "address"}),
			run: runMemoryFreeze,
		},
		{
			name:        "memory_freeze_list",
			description: "List the cell ranges currently frozen by this server process, with byte lengths, write counts, last write time, provenance (context, target generation, ROM), and any last error from the periodic re-write.",
			schema:      objectSchema(map[string]any{}, nil),
			run:         runMemoryFreezeList,
		},
		{
			name:        "memory_freeze_remove",
			description: "Remove one frozen cell range so the emulated program can update it again. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"context":                    contextProperty(),
				"freeze_id":                  stringProperty("Freeze entry id returned by memory_freeze."),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"freeze_id"}),
			run: runMemoryFreezeRemove,
		},
		{
			name:        "memory_freeze_clear",
			description: "Remove every frozen cell range at once, so the emulated program can update all of them again. Returns how many entries were removed. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"context":                    contextProperty(),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, nil),
			run: runMemoryFreezeClear,
		},
	}
}

type memoryFreezeArgs struct {
	Context string `json:"context"`
	Space   string `json:"space"`
	Address any    `json:"address"`
	Data    string `json:"data"`
	DataHex string `json:"data_hex"`
	guardArgs
}

func runMemoryFreeze(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memoryFreezeArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := parseAddress(parsed.Address)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.Space == "" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "space must name a space id from memory_spaces_list"}, tc.modern)
	}
	bytes, failure := decodeWriteBytes(parsed.Data, parsed.DataHex)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if len(bytes) < 1 || len(bytes) > maxMemoryWriteBytes {
		return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("data must hold between 1 and %d bytes", maxMemoryWriteBytes)}, tc.modern)
	}

	var entry *freezeEntry
	var replaced bool
	var freezeID string
	_, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "memory_freeze",
		operation: "mem_write",
		params: map[string]string{
			"space":   parsed.Space,
			"address": strconv.FormatUint(address, 10),
			"length":  strconv.Itoa(len(bytes)),
			"data":    base64.StdEncoding.EncodeToString(bytes),
		},
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"space":   parsed.Space,
			"address": address,
			"length":  len(bytes),
			"sha256":  sha256Hex(bytes),
			"input":   "data_hex",
		},
		prepare: func() *toolFailure {
			existing := tc.server.freezes.getAt(parsed.Space, address)
			if existing == nil && len(tc.server.freezes.list()) >= freezeMaxEntries {
				return &toolFailure{Code: "freeze_limit", Message: "the freeze set is full (" + strconv.Itoa(freezeMaxEntries) + " entries); remove an entry with memory_freeze_remove first"}
			}
			return nil
		},
		commit: func() {
			var err error
			entry, replaced, err = tc.server.freezes.set(parsed.Space, address, bytes, freezeProvenance{
				ContextID:        context.ID,
				ControlID:        parsed.ControlID,
				TargetGeneration: tc.server.target.Generation(),
				ROMPath:          tc.server.currentROMPath(),
			})
			if err != nil {
				// The scheduler serializes every mutating tool, so the
				// prepare check cannot race; treat this as a logic bug.
				panic(err)
			}
			freezeID = entry.ID
		},
		resources: func() []string {
			if freezeID == "" {
				return nil
			}
			return []string{freezeID}
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	result := map[string]any{
		"freeze_id":     entry.ID,
		"space":         entry.Space,
		"address":       entry.Address,
		"address_hex":   fmt.Sprintf("0x%X", entry.Address),
		"byte_length":   len(entry.Data),
		"data_sha256":   sha256Hex(entry.Data),
		"data_hex_echo": hexEcho(entry.Data, 256),
		"created_at":    entry.CreatedAt,
		"replaced":      replaced,
		"rewrite_hz":    1 / freezeTickInterval.Seconds(),
	}
	return okResult(stampGenerations(result, before, after), tc.modern)
}

func freezeEntryView(entry *freezeEntry) map[string]any {
	view := map[string]any{
		"freeze_id":         entry.ID,
		"space":             entry.Space,
		"address":           entry.Address,
		"address_hex":       fmt.Sprintf("0x%X", entry.Address),
		"byte_length":       len(entry.Data),
		"data_sha256":       sha256Hex(entry.Data),
		"created_at":        entry.CreatedAt,
		"write_count":       entry.WriteCount,
		"context_id":        entry.ContextID,
		"target_generation": entry.TargetGeneration,
		"rom_path":          entry.ROMPath,
	}
	if entry.ControlID != "" {
		view["control_id"] = entry.ControlID
	}
	if !entry.LastWriteAt.IsZero() {
		view["last_write_at"] = entry.LastWriteAt
	}
	if entry.LastError != "" {
		view["last_error"] = entry.LastError
	}
	return view
}

func runMemoryFreezeList(tc toolContext, _ json.RawMessage) map[string]any {
	entries := tc.server.freezes.list()
	views := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		views = append(views, freezeEntryView(entry))
	}
	return okResult(map[string]any{"freezes_total": len(views), "freezes": views}, tc.modern)
}

type memoryFreezeRemoveArgs struct {
	Context  string `json:"context"`
	FreezeID string `json:"freeze_id"`
	guardArgs
}

func runMemoryFreezeRemove(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memoryFreezeRemoveArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	var removed bool
	_, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "memory_freeze_remove",
		operation: "",
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"freeze_id": parsed.FreezeID,
		},
		prepare: func() *toolFailure {
			if !tc.server.freezes.has(parsed.FreezeID) {
				return &toolFailure{Code: "unknown_freeze", Message: "no freeze entry with id " + parsed.FreezeID + "; list entries with memory_freeze_list"}
			}
			return nil
		},
		commit: func() {
			removed = tc.server.freezes.remove(parsed.FreezeID)
		},
		resources: func() []string { return []string{parsed.FreezeID} },
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(stampGenerations(map[string]any{"freeze_id": parsed.FreezeID, "removed": removed}, before, after), tc.modern)
}

type memoryFreezeClearArgs struct {
	Context string `json:"context"`
	guardArgs
}

func runMemoryFreezeClear(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memoryFreezeClearArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	var removedIDs []string
	_, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "memory_freeze_clear",
		operation: "",
		guard:     parsed.guard(),
		contextID: context.ID,
		detail:    map[string]any{},
		prepare: func() *toolFailure {
			removedIDs = tc.server.freezes.ids()
			return nil
		},
		commit: func() {
			tc.server.freezes.purge()
		},
		resources: func() []string { return removedIDs },
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(stampGenerations(map[string]any{"removed": len(removedIDs), "freezes_total": 0}, before, after), tc.modern)
}
