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
// emulated program's own updates to the range are continuously undone.
type freezeEntry struct {
	ID          string
	Space       string
	Address     uint64
	Data        []byte
	CreatedAt   time.Time
	LastWriteAt time.Time
	WriteCount  uint64
	LastError   string
}

// freezeRegistry owns the process-wide freeze set. Entries are machine-level,
// like breakpoints: a freeze applies to whatever cartridge is loaded, which is
// why rom_load purges the whole set (stale addresses would be written into the
// new program's memory map).
type freezeRegistry struct {
	mu    sync.Mutex
	byID  map[string]*freezeEntry
	byKey map[string]string // space + ":" + address -> freeze id
	order []*freezeEntry    // stable listing order
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
// the set is full and the address is not already frozen.
func (registry *freezeRegistry) set(space string, address uint64, data []byte) (*freezeEntry, bool, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	key := freezeKey(space, address)
	if id := registry.byKey[key]; id != "" {
		entry := registry.byID[id]
		entry.Data = append(entry.Data[:0], data...)
		return entry, true, nil
	}
	if len(registry.byID) >= freezeMaxEntries {
		return nil, false, errFreezeLimit
	}
	entry := &freezeEntry{
		ID:        "frz_" + strconv.FormatInt(time.Now().UnixNano(), 36),
		Space:     space,
		Address:   address,
		Data:      append([]byte{}, data...),
		CreatedAt: time.Now().UTC(),
	}
	registry.byID[entry.ID] = entry
	registry.byKey[key] = entry.ID
	registry.order = append(registry.order, entry)
	return entry, false, nil
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
			description: "Register a cell range that the server re-writes at about 20 Hz, undoing the emulated program's own updates to it. Applies the bytes once immediately (like memory_write), then keeps them pinned while the entry exists. Replacing an entry at the same space+address updates the pinned bytes; rom_load purges the whole set. Requires an exclusive context lease.",
			schema: objectSchema(map[string]any{
				"context":  contextProperty(),
				"lease_id": stringProperty("Active lease id from context_lease_acquire."),
				"space":    stringProperty("Space id from memory_spaces_list, such as m68k-bus."),
				"address":  addressProperty(),
				"data":     stringProperty("Bytes to keep in place, base64-encoded (up to 4096 bytes)."),
			}, []string{"lease_id", "space", "address", "data"}),
			run: runMemoryFreeze,
		},
		{
			name:        "memory_freeze_list",
			description: "List the cell ranges currently frozen by this server process, with byte lengths, write counts, last write time, and any last error from the periodic re-write.",
			schema:      objectSchema(map[string]any{}, nil),
			run:         runMemoryFreezeList,
		},
		{
			name:        "memory_freeze_remove",
			description: "Remove one frozen cell range so the emulated program can update it again. Requires an exclusive context lease.",
			schema: objectSchema(map[string]any{
				"context":   contextProperty(),
				"lease_id":  stringProperty("Active lease id from context_lease_acquire."),
				"freeze_id": stringProperty("Freeze entry id returned by memory_freeze."),
			}, []string{"lease_id", "freeze_id"}),
			run: runMemoryFreezeRemove,
		},
	}
}

type memoryFreezeArgs struct {
	Context string `json:"context"`
	LeaseID string `json:"lease_id"`
	Space   string `json:"space"`
	Address any    `json:"address"`
	Data    string `json:"data"`
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
	if failure := tc.server.requireLease(context, parsed.LeaseID, "memory_freeze"); failure != nil {
		return failureResult(failure, tc.modern)
	}
	address, failure := parseAddress(parsed.Address)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.Space == "" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "space must name a space id from memory_spaces_list"}, tc.modern)
	}
	bytes, err := base64.StdEncoding.DecodeString(parsed.Data)
	if err != nil {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "data must be valid base64"}, tc.modern)
	}
	if len(bytes) < 1 || len(bytes) > maxMemoryWriteBytes {
		return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("data must hold between 1 and %d bytes", maxMemoryWriteBytes)}, tc.modern)
	}

	var entry *freezeEntry
	var replaced bool
	_, failure = tc.server.memWriteCommand(tc.ctx, parsed.Space, address, bytes)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	entry, replaced, err = tc.server.freezes.set(parsed.Space, address, bytes)
	if err != nil {
		return failureResult(&toolFailure{Code: "freeze_limit", Message: "the freeze set is full (" + strconv.Itoa(freezeMaxEntries) + " entries); remove an entry with memory_freeze_remove first"}, tc.modern)
	}

	tc.server.recordMutation(context, parsed.LeaseID, "memory_freeze", map[string]any{
		"space":    parsed.Space,
		"address":  address,
		"length":   len(bytes),
		"sha256":   sha256Hex(bytes),
		"replaced": replaced,
	})

	result := map[string]any{
		"freeze_id":   entry.ID,
		"space":       entry.Space,
		"address":     entry.Address,
		"address_hex": fmt.Sprintf("0x%X", entry.Address),
		"byte_length": len(entry.Data),
		"data_sha256": sha256Hex(entry.Data),
		"created_at":  entry.CreatedAt,
		"replaced":    replaced,
		"rewrite_hz":  1 / freezeTickInterval.Seconds(),
	}
	return okResult(result, tc.modern)
}

func freezeEntryView(entry *freezeEntry) map[string]any {
	view := map[string]any{
		"freeze_id":   entry.ID,
		"space":       entry.Space,
		"address":     entry.Address,
		"address_hex": fmt.Sprintf("0x%X", entry.Address),
		"byte_length": len(entry.Data),
		"data_sha256": sha256Hex(entry.Data),
		"created_at":  entry.CreatedAt,
		"write_count": entry.WriteCount,
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
	LeaseID  string `json:"lease_id"`
	FreezeID string `json:"freeze_id"`
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
	if failure := tc.server.requireLease(context, parsed.LeaseID, "memory_freeze_remove"); failure != nil {
		return failureResult(failure, tc.modern)
	}
	if !tc.server.freezes.remove(parsed.FreezeID) {
		return failureResult(&toolFailure{Code: "unknown_freeze", Message: "no freeze entry with id " + parsed.FreezeID + "; list entries with memory_freeze_list"}, tc.modern)
	}
	tc.server.recordMutation(context, parsed.LeaseID, "memory_freeze_remove", map[string]any{
		"freeze_id": parsed.FreezeID,
	})
	return okResult(map[string]any{"freeze_id": parsed.FreezeID, "removed": true}, tc.modern)
}
