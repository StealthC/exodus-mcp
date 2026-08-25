package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

const (
	maxMemoryWriteBytes = 4096
	maxFrameAdvance     = 60
	maxInputButtons     = 16
)

var inputButtonNames = map[string]bool{
	"up": true, "down": true, "left": true, "right": true,
	"a": true, "b": true, "c": true, "start": true,
	"x": true, "y": true, "z": true, "mode": true,
}

// phase4ToolSpecs implements controlled experimentation. Every tool that
// mutates the target runs through the serialized scheduler with optional
// expected_target_generation and control_id preconditions; state_save is
// read-only for the target and only records provenance.
func phase4ToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "frame_advance",
			description: "Pause the system, execute exactly the requested number of rendered frames, and pause again. The response reports the frames completed, the final VDP frame token, and the target generations before/after. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"context":                    contextProperty(),
				"frames":                     integerProperty(fmt.Sprintf("Number of frames to execute (default 1, cap %d).", maxFrameAdvance), 1),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, nil),
			run: runFrameAdvance,
		},
		{
			name:        "input_set",
			description: "Press or release buttons on a Mega Drive controller connected to a player port. A press is not observable until the system runs, so pair input_set down with frame_advance or cpu_run before sending up. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"context":                    contextProperty(),
				"player":                     integerProperty("Player port (1-based) selecting the controller device (default 1).", 1),
				"buttons":                    enumArrayProperty("Buttons to press or release.", []string{"up", "down", "left", "right", "a", "b", "c", "start", "x", "y", "z", "mode"}),
				"state":                      enumProperty("Button state to apply.", []string{"down", "up"}),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"buttons", "state"}),
			run: runInputSet,
		},
		{
			name:        "memory_write",
			description: "Write bytes into a memory space through the emulator debugger path. Only CPU bus spaces and non-timed memory devices are writable; ROM writes are discarded by the bus like real hardware. The response echoes the exact bytes written and the target generations before/after, and the call is recorded in the target audit stream. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"context":                    contextProperty(),
				"space":                      stringProperty("Space id from memory_spaces_list, such as m68k-bus."),
				"address":                    addressProperty(),
				"data":                       stringProperty("Bytes to write, base64-encoded (up to 4096 bytes)."),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"space", "address", "data"}),
			run: runMemoryWrite,
		},
		{
			name:        "state_list",
			description: "List the system snapshots saved through this analysis context, newest first, with SHA-256 digests, sizes, and provenance (target generation, ROM, control lock). Entries captured under a different ROM or generation are flagged stale/generation_mismatch but preserved for historical analysis.",
			schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
			run:         runStateList,
		},
		{
			name:        "state_load",
			description: "Load a previously saved system snapshot back into the emulator. The snapshot must belong to the same analysis context and, in practice, to the same loaded ROM: device state from another cartridge is ignored by Exodus with a logged warning. Accepts optional expected_target_generation and control_id.",
			schema: objectSchema(map[string]any{
				"context":                    contextProperty(),
				"state_id":                   stringProperty("Snapshot id returned by state_save."),
				"expected_target_generation": integerProperty("Optional target generation the caller last observed; fails with target_generation_conflict on mismatch.", 1),
				"control_id":                 stringProperty("Optional control id from target_control_acquire; required while the control lock is active."),
			}, []string{"state_id"}),
			run: runStateLoad,
		},
		{
			name:        "state_save",
			description: "Pause the system and save a full machine snapshot (CPU, memory, VDP, audio, and device state) through the emulator's native save-state path. The snapshot is anchored to this analysis context, verified with SHA-256, and can be reloaded with state_load. The snapshot records the observed target generation, ROM, and optional control id as provenance.",
			schema: objectSchema(map[string]any{
				"context":    contextProperty(),
				"name":       stringProperty("Optional short name for the snapshot, such as \"before-boss\"."),
				"control_id": stringProperty("Optional control id recorded as provenance on the snapshot; not required, since state_save does not mutate the target."),
			}, nil),
			run: runStateSave,
		},
	}
}

func enumArrayProperty(description string, values []string) map[string]any {
	return map[string]any{
		"type":        "array",
		"description": description,
		"items":       map[string]any{"type": "string", "enum": values},
		"minItems":    1,
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// frame_advance
// ----------------------------------------------------------------------------------------------------------------------

type frameAdvanceArgs struct {
	Context string  `json:"context"`
	Frames  *uint64 `json:"frames"`
	guardArgs
}

func runFrameAdvance(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[frameAdvanceArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	frames := uint64(1)
	if parsed.Frames != nil {
		if *parsed.Frames < 1 || *parsed.Frames > maxFrameAdvance {
			return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("frames must be between 1 and %d", maxFrameAdvance)}, tc.modern)
		}
		frames = *parsed.Frames
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "frame_advance",
		operation: "frame_advance",
		params:    map[string]string{"frames": strconv.FormatUint(frames, 10)},
		guard:     parsed.guard(),
		contextID: context.ID,
		detail:    map[string]any{"frames": frames},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// input_set
// ----------------------------------------------------------------------------------------------------------------------

type inputSetArgs struct {
	Context string   `json:"context"`
	Player  *uint64  `json:"player"`
	Buttons []string `json:"buttons"`
	State   string   `json:"state"`
	guardArgs
}

func runInputSet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[inputSetArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.State != "down" && parsed.State != "up" {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "state must be down or up"}, tc.modern)
	}
	if len(parsed.Buttons) == 0 || len(parsed.Buttons) > maxInputButtons {
		return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("buttons must name between 1 and %d buttons", maxInputButtons)}, tc.modern)
	}
	normalized := make([]string, 0, len(parsed.Buttons))
	for _, button := range parsed.Buttons {
		name := strings.ToLower(button)
		if !inputButtonNames[name] {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "unknown button " + button}, tc.modern)
		}
		normalized = append(normalized, name)
	}
	player := uint64(1)
	if parsed.Player != nil {
		if *parsed.Player < 1 || *parsed.Player > 4 {
			return failureResult(&toolFailure{Code: "invalid_params", Message: "player must be between 1 and 4"}, tc.modern)
		}
		player = *parsed.Player
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "input_set",
		operation: "input_set",
		params: map[string]string{
			"player":  strconv.FormatUint(player, 10),
			"buttons": strings.Join(normalized, ","),
			"state":   parsed.State,
		},
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"player":  player,
			"buttons": normalized,
			"state":   parsed.State,
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_write
// ----------------------------------------------------------------------------------------------------------------------

type memoryWriteArgs struct {
	Context string `json:"context"`
	Space   string `json:"space"`
	Address any    `json:"address"`
	Data    string `json:"data"`
	guardArgs
}

func runMemoryWrite(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[memoryWriteArgs](args)
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
	bytes, err := base64.StdEncoding.DecodeString(parsed.Data)
	if err != nil {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "data must be valid base64"}, tc.modern)
	}
	if len(bytes) < 1 || len(bytes) > maxMemoryWriteBytes {
		return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("data must hold between 1 and %d bytes", maxMemoryWriteBytes)}, tc.modern)
	}
	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "memory_write",
		operation: "mem_write",
		params: map[string]string{
			"space":   parsed.Space,
			"address": strconv.FormatUint(address, 10),
			"length":  strconv.Itoa(len(bytes)),
			"data":    parsed.Data,
		},
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"space":   parsed.Space,
			"address": address,
			"length":  len(bytes),
			"sha256":  sha256Hex(bytes),
		},
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	return okResult(stampGenerations(payload, before, after), tc.modern)
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// ----------------------------------------------------------------------------------------------------------------------
// state_save / state_load / state_list
// ----------------------------------------------------------------------------------------------------------------------

type stateSaveArgs struct {
	Context   string `json:"context"`
	Name      string `json:"name"`
	ControlID string `json:"control_id"`
}

func runStateSave(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[stateSaveArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if len(parsed.Name) > 100 {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "name must be at most 100 characters"}, tc.modern)
	}

	contextDir := filepath.Join(tc.server.StatesDir(), context.ID)
	if err := os.MkdirAll(contextDir, 0o755); err != nil {
		return failureResult(&toolFailure{Code: "state_store_error", Message: "create snapshot directory: " + err.Error()}, tc.modern)
	}
	snapshotID := analysis.NewSnapshotID()
	path := filepath.Join(contextDir, snapshotID+".zip")

	// state_save does not mutate the target: no scheduler window, no
	// generation advance; the observed generation is recorded as provenance.
	generation := tc.server.target.Generation()
	payload, failure := tc.server.executeCommand(tc.ctx, "state_save", map[string]string{"path": path})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	info, err := os.Stat(path)
	if err != nil {
		return failureResult(&toolFailure{Code: "state_store_error", Message: "verify snapshot file: " + err.Error()}, tc.modern)
	}
	digest, err := fileSHA256(path)
	if err != nil {
		return failureResult(&toolFailure{Code: "state_store_error", Message: "hash snapshot file: " + err.Error()}, tc.modern)
	}

	snapshot := tc.server.contexts.States.Create(context.ID, &analysis.Snapshot{
		ID:               snapshotID,
		ContextID:        context.ID,
		Name:             parsed.Name,
		Path:             path,
		SHA256:           digest,
		SizeBytes:        info.Size(),
		CreatedAt:        time.Now().UTC(),
		ROMPath:          tc.server.currentROMPath(),
		ControlID:        parsed.ControlID,
		TargetGeneration: generation,
	})
	tc.server.recordAudit(analysis.AuditEntry{
		Tool:      "state_save",
		ContextID: context.ID,
		ControlID: parsed.ControlID,
		Outcome:   analysis.OutcomeOK,
		Detail: map[string]any{
			"state_id": snapshot.ID,
			"name":     parsed.Name,
			"sha256":   digest,
			"size":     info.Size(),
		},
		Result:      map[string]any{"target_generation": generation},
		ROMBefore:   snapshot.ROMPath,
		ResourceIDs: []string{snapshot.ID},
	})

	result := map[string]any{
		"state_id":          snapshot.ID,
		"name":              snapshot.Name,
		"created_at":        snapshot.CreatedAt,
		"size_bytes":        snapshot.SizeBytes,
		"sha256":            snapshot.SHA256,
		"target_generation": generation,
	}
	for key, value := range payload {
		result[key] = value
	}
	return okResult(result, tc.modern)
}

type stateLoadArgs struct {
	Context string `json:"context"`
	StateID string `json:"state_id"`
	guardArgs
}

func runStateLoad(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[stateLoadArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	snapshot, err := tc.server.contexts.States.Get(context.ID, parsed.StateID)
	if err != nil {
		return failureResult(&toolFailure{Code: "state_not_found", Message: err.Error()}, tc.modern)
	}
	if _, err := os.Stat(snapshot.Path); err != nil {
		return failureResult(&toolFailure{Code: "state_file_missing", Message: "snapshot file " + snapshot.Path + " no longer exists"}, tc.modern)
	}

	payload, before, after, failure := tc.server.executeMutation(tc.ctx, mutationCall{
		tool:      "state_load",
		operation: "state_load",
		params:    map[string]string{"path": snapshot.Path},
		guard:     parsed.guard(),
		contextID: context.ID,
		detail: map[string]any{
			"state_id": snapshot.ID,
			"sha256":   snapshot.SHA256,
		},
		resources: func() []string { return []string{snapshot.ID} },
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	result := map[string]any{"state_id": snapshot.ID, "sha256": snapshot.SHA256}
	for key, value := range payload {
		result[key] = value
	}
	return okResult(stampGenerations(result, before, after), tc.modern)
}

func runStateList(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[struct {
		Context string `json:"context"`
	}](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	currentROM := tc.server.currentROMPath()
	currentGen := tc.server.target.Generation()
	snapshots := tc.server.contexts.States.List(context.ID)
	view := make([]map[string]any, 0, len(snapshots))
	for _, snapshot := range snapshots {
		stale := snapshot.ROMPath != "" && snapshot.ROMPath != currentROM
		entry := map[string]any{
			"state_id":            snapshot.ID,
			"name":                snapshot.Name,
			"created_at":          snapshot.CreatedAt,
			"size_bytes":          snapshot.SizeBytes,
			"sha256":              snapshot.SHA256,
			"target_generation":   snapshot.TargetGeneration,
			"rom_path":            snapshot.ROMPath,
			"stale":               stale,
			"generation_mismatch": snapshot.TargetGeneration != 0 && snapshot.TargetGeneration != currentGen,
		}
		if snapshot.ControlID != "" {
			entry["control_id"] = snapshot.ControlID
		}
		if stale {
			entry["stale_reason"] = "captured under a different ROM than the loaded target"
		}
		view = append(view, entry)
	}
	return okResult(map[string]any{"context_id": context.ID, "snapshots": view}, tc.modern)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
