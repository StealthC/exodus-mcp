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

// phase4ToolSpecs implements controlled experimentation with exclusive
// context leases: every tool here mutates emulator state and therefore
// requires an active context lease plus audit metadata.
func phase4ToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "frame_advance",
			description: "Pause the system, execute exactly the requested number of rendered frames, and pause again. The response reports the frames completed and the final VDP frame token. Requires an exclusive context lease.",
			schema: objectSchema(map[string]any{
				"context":  contextProperty(),
				"lease_id": stringProperty("Active lease id from context_lease_acquire."),
				"frames":   integerProperty(fmt.Sprintf("Number of frames to execute (default 1, cap %d).", maxFrameAdvance), 1),
			}, []string{"lease_id"}),
			run: runFrameAdvance,
		},
		{
			name:        "input_set",
			description: "Press or release buttons on a Mega Drive controller connected to a player port. A press is not observable until the system runs, so pair input_set down with frame_advance or cpu_run before sending up. Requires an exclusive context lease.",
			schema: objectSchema(map[string]any{
				"context":  contextProperty(),
				"lease_id": stringProperty("Active lease id from context_lease_acquire."),
				"player":   integerProperty("Player port (1-based) selecting the controller device (default 1).", 1),
				"buttons":  enumArrayProperty("Buttons to press or release.", []string{"up", "down", "left", "right", "a", "b", "c", "start", "x", "y", "z", "mode"}),
				"state":    enumProperty("Button state to apply.", []string{"down", "up"}),
			}, []string{"lease_id", "buttons", "state"}),
			run: runInputSet,
		},
		{
			name:        "memory_write",
			description: "Write bytes into a memory space through the emulator debugger path. Only CPU bus spaces and non-timed memory devices are writable; ROM writes are discarded by the bus like real hardware. The response echoes the exact bytes written, and the call is recorded in the context mutation log. Requires an exclusive context lease.",
			schema: objectSchema(map[string]any{
				"context":  contextProperty(),
				"lease_id": stringProperty("Active lease id from context_lease_acquire."),
				"space":    stringProperty("Space id from memory_spaces_list, such as m68k-bus."),
				"address":  addressProperty(),
				"data":     stringProperty("Bytes to write, base64-encoded (up to 4096 bytes)."),
			}, []string{"lease_id", "space", "address", "data"}),
			run: runMemoryWrite,
		},
		{
			name:        "state_list",
			description: "List the system snapshots saved through this analysis context, newest first, with SHA-256 digests and sizes.",
			schema:      objectSchema(map[string]any{"context": contextProperty()}, nil),
			run:         runStateList,
		},
		{
			name:        "state_load",
			description: "Load a previously saved system snapshot back into the emulator. The snapshot must belong to the same analysis context and, in practice, to the same loaded ROM: device state from another cartridge is ignored by Exodus with a logged warning. Requires an exclusive context lease.",
			schema: objectSchema(map[string]any{
				"context":  contextProperty(),
				"lease_id": stringProperty("Active lease id from context_lease_acquire."),
				"state_id": stringProperty("Snapshot id returned by state_save."),
			}, []string{"lease_id", "state_id"}),
			run: runStateLoad,
		},
		{
			name:        "state_save",
			description: "Pause the system and save a full machine snapshot (CPU, memory, VDP, audio, and device state) through the emulator's native save-state path. The snapshot is anchored to this analysis context, verified with SHA-256, and can be reloaded with state_load. Requires an exclusive context lease.",
			schema: objectSchema(map[string]any{
				"context":  contextProperty(),
				"lease_id": stringProperty("Active lease id from context_lease_acquire."),
				"name":     stringProperty("Optional short name for the snapshot, such as \"before-boss\"."),
			}, []string{"lease_id"}),
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
	LeaseID string  `json:"lease_id"`
	Frames  *uint64 `json:"frames"`
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
	if failure := tc.server.requireLease(context, parsed.LeaseID, "frame_advance"); failure != nil {
		return failureResult(failure, tc.modern)
	}
	frames := uint64(1)
	if parsed.Frames != nil {
		if *parsed.Frames < 1 || *parsed.Frames > maxFrameAdvance {
			return failureResult(&toolFailure{Code: "invalid_params", Message: fmt.Sprintf("frames must be between 1 and %d", maxFrameAdvance)}, tc.modern)
		}
		frames = *parsed.Frames
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "frame_advance", map[string]string{"frames": strconv.FormatUint(frames, 10)})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	tc.server.recordMutation(context, parsed.LeaseID, "frame_advance", map[string]any{"frames": frames})
	return okResult(payload, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// input_set
// ----------------------------------------------------------------------------------------------------------------------

type inputSetArgs struct {
	Context string   `json:"context"`
	LeaseID string   `json:"lease_id"`
	Player  *uint64  `json:"player"`
	Buttons []string `json:"buttons"`
	State   string   `json:"state"`
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
	if failure := tc.server.requireLease(context, parsed.LeaseID, "input_set"); failure != nil {
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
	payload, failure := tc.server.executeCommand(tc.ctx, "input_set", map[string]string{
		"player":  strconv.FormatUint(player, 10),
		"buttons": strings.Join(normalized, ","),
		"state":   parsed.State,
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	tc.server.recordMutation(context, parsed.LeaseID, "input_set", map[string]any{
		"player":  player,
		"buttons": normalized,
		"state":   parsed.State,
	})
	return okResult(payload, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// memory_write
// ----------------------------------------------------------------------------------------------------------------------

type memoryWriteArgs struct {
	Context string `json:"context"`
	LeaseID string `json:"lease_id"`
	Space   string `json:"space"`
	Address any    `json:"address"`
	Data    string `json:"data"`
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
	if failure := tc.server.requireLease(context, parsed.LeaseID, "memory_write"); failure != nil {
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
	payload, failure := tc.server.executeCommand(tc.ctx, "mem_write", map[string]string{
		"space":   parsed.Space,
		"address": strconv.FormatUint(address, 10),
		"length":  strconv.Itoa(len(bytes)),
		"data":    parsed.Data,
	})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	tc.server.recordMutation(context, parsed.LeaseID, "memory_write", map[string]any{
		"space":   parsed.Space,
		"address": address,
		"length":  len(bytes),
		"sha256":  sha256Hex(bytes),
	})
	return okResult(payload, tc.modern)
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// ----------------------------------------------------------------------------------------------------------------------
// state_save / state_load / state_list
// ----------------------------------------------------------------------------------------------------------------------

type stateSaveArgs struct {
	Context string `json:"context"`
	LeaseID string `json:"lease_id"`
	Name    string `json:"name"`
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
	if failure := tc.server.requireLease(context, parsed.LeaseID, "state_save"); failure != nil {
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
		ID:        snapshotID,
		ContextID: context.ID,
		Name:      parsed.Name,
		Path:      path,
		SHA256:    digest,
		SizeBytes: info.Size(),
		CreatedAt: time.Now().UTC(),
	})
	tc.server.recordMutation(context, parsed.LeaseID, "state_save", map[string]any{
		"state_id": snapshot.ID,
		"name":     parsed.Name,
		"sha256":   digest,
		"size":     info.Size(),
	})

	result := map[string]any{
		"state_id":   snapshot.ID,
		"name":       snapshot.Name,
		"created_at": snapshot.CreatedAt,
		"size_bytes": snapshot.SizeBytes,
		"sha256":     snapshot.SHA256,
	}
	for key, value := range payload {
		result[key] = value
	}
	return okResult(result, tc.modern)
}

type stateLoadArgs struct {
	Context string `json:"context"`
	LeaseID string `json:"lease_id"`
	StateID string `json:"state_id"`
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
	if failure := tc.server.requireLease(context, parsed.LeaseID, "state_load"); failure != nil {
		return failureResult(failure, tc.modern)
	}
	snapshot, err := tc.server.contexts.States.Get(context.ID, parsed.StateID)
	if err != nil {
		return failureResult(&toolFailure{Code: "state_not_found", Message: err.Error()}, tc.modern)
	}
	if _, err := os.Stat(snapshot.Path); err != nil {
		return failureResult(&toolFailure{Code: "state_file_missing", Message: "snapshot file " + snapshot.Path + " no longer exists"}, tc.modern)
	}

	payload, failure := tc.server.executeCommand(tc.ctx, "state_load", map[string]string{"path": snapshot.Path})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	tc.server.recordMutation(context, parsed.LeaseID, "state_load", map[string]any{
		"state_id": snapshot.ID,
		"sha256":   snapshot.SHA256,
	})

	result := map[string]any{"state_id": snapshot.ID, "sha256": snapshot.SHA256}
	for key, value := range payload {
		result[key] = value
	}
	return okResult(result, tc.modern)
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
	snapshots := tc.server.contexts.States.List(context.ID)
	view := make([]map[string]any, 0, len(snapshots))
	for _, snapshot := range snapshots {
		view = append(view, map[string]any{
			"state_id":   snapshot.ID,
			"name":       snapshot.Name,
			"created_at": snapshot.CreatedAt,
			"size_bytes": snapshot.SizeBytes,
			"sha256":     snapshot.SHA256,
		})
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
