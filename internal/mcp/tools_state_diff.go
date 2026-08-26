package mcp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
)

// state_diff (roadmap P7): compare two state_save snapshots of one analysis
// context into a structured differences report. The tool is read-only: it
// compares snapshot metadata plus the raw snapshot files byte-by-byte and
// stores a bounded state-diff-results artifact. Registers/memory/VDP semantic
// comparison would require loading each snapshot into the emulator
// (state_load, a target mutation), which is out of scope for this read-only
// tool; those sections are reported as not performed with the reason.

const (
	defaultStateDiffMaxDiffs = 64
	maxStateDiffMaxDiffs     = 1024
	stateDiffFileCapBytes    = 8 << 20 // compare at most 8 MiB of each file
	stateDiffPreviewBytes    = 1024
	stateDiffInlineSnippet   = 16 // bytes of before/after hex shown per inline diff
	stateDiffKind            = "state-diff-results"
	stateDiffSemanticNote    = "register/memory/VDP semantic comparison requires loading each snapshot into the emulator (state_load), which mutates the target; state_diff is read-only and reports differences at the snapshot-file byte level instead. Use deterministic_replay or live capture tools to compare machine semantics."
	stateDiffProvenanceNote  = "state_diff compares on-disk snapshot files; no live capture is performed, so capture_consistency is not applicable and no emulator state was read."
)

func stateDiffToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "state_diff",
			description: "Compare two state_save snapshots of one analysis context into a structured differences report: metadata (name, size, SHA-256, target generation, ROM identity, created_at, control id) and a raw snapshot-file byte diff (per-byte counts, contiguous diff regions, bounded inline before/after hex, first-1KB previews). Read-only: the register/memory/VDP semantic sections are reported as not performed because decoding them requires loading each snapshot into the emulator (a target mutation). The full report is stored as a state-diff-results artifact.",
			schema: objectSchema(map[string]any{
				"snapshot_before_id": stringProperty("State id returned by state_save for the before side."),
				"snapshot_after_id":  stringProperty("State id returned by state_save for the after side."),
				"max_diffs":          integerProperty(fmt.Sprintf("Maximum inline diff regions (default %d, cap %d).", defaultStateDiffMaxDiffs, maxStateDiffMaxDiffs), 1),
				"include_memory":     booleanProperty("Request the memory comparison section (default true); reported as not performed in this read-only mode."),
				"include_registers":  booleanProperty("Request the registers comparison section (default true); reported as not performed in this read-only mode."),
				"include_vdp":        booleanProperty("Request the VDP comparison section (default true); reported as not performed in this read-only mode."),
				"context":            contextProperty(),
			}, []string{"snapshot_before_id", "snapshot_after_id"}),
			run: runStateDiff,
		},
	}
}

type stateDiffArgs struct {
	SnapshotBeforeID string `json:"snapshot_before_id"`
	SnapshotAfterID  string `json:"snapshot_after_id"`
	MaxDiffs         uint64 `json:"max_diffs"`
	IncludeMemory    bool   `json:"include_memory"`
	IncludeRegisters bool   `json:"include_registers"`
	IncludeVDP       bool   `json:"include_vdp"`
	Context          string `json:"context"`
}

func runStateDiff(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[stateDiffArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if parsed.SnapshotBeforeID == "" || parsed.SnapshotAfterID == "" {
		return errorResult("invalid_params", "snapshot_before_id and snapshot_after_id are required", tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	maxDiffs := parsed.MaxDiffs
	if maxDiffs == 0 {
		maxDiffs = defaultStateDiffMaxDiffs
	}
	if maxDiffs > maxStateDiffMaxDiffs {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("max_diffs is capped at %d inline diff regions.", maxStateDiffMaxDiffs),
		}, tc.modern)
	}

	before, err := tc.server.contexts.States.Get(context.ID, parsed.SnapshotBeforeID)
	if err != nil {
		return failureResult(&toolFailure{Code: "unknown_state", Message: "before snapshot: " + err.Error()}, tc.modern)
	}
	after, err := tc.server.contexts.States.Get(context.ID, parsed.SnapshotAfterID)
	if err != nil {
		return failureResult(&toolFailure{Code: "unknown_state", Message: "after snapshot: " + err.Error()}, tc.modern)
	}
	beforeBytes, beforeSize, beforeTruncated, failure := readStateDiffFile(before.Path)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	afterBytes, afterSize, afterTruncated, failure := readStateDiffFile(after.Path)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	metadataDiff := stateMetadataDiff(before, after)
	fileDiff := stateFileDiff(beforeBytes, afterBytes, maxDiffs)
	fileDiff["before_file_truncated"] = beforeTruncated
	fileDiff["after_file_truncated"] = afterTruncated
	if beforeTruncated || afterTruncated {
		fileDiff["note"] = fmt.Sprintf("Files are compared through the first %d bytes only; the full snapshot bytes stay available on disk.", stateDiffFileCapBytes)
	}

	// Semantic sections: requested but never performed by this read-only tool.
	semantic := map[string]any{
		"complete": false,
		"note":     stateDiffSemanticNote,
		"registers": map[string]any{
			"requested": parsed.IncludeRegisters,
			"performed": false,
			"note":      "Would load each snapshot (state_load) and diff regs_get output; not performed because state_diff is read-only.",
		},
		"memory": map[string]any{
			"requested": parsed.IncludeMemory,
			"performed": false,
			"note":      "Would load each snapshot (state_load) and diff mem_read output; not performed because state_diff is read-only.",
		},
		"vdp": map[string]any{
			"requested": parsed.IncludeVDP,
			"performed": false,
			"note":      "Would load each snapshot (state_load) and diff vdp_status output; not performed because state_diff is read-only.",
		},
	}

	document := map[string]any{
		"kind":            stateDiffKind,
		"before_snapshot": stateSnapshotView(before),
		"after_snapshot":  stateSnapshotView(after),
		"metadata_diff":   metadataDiff,
		"file_diff":       fileDiff,
		"semantic":        semantic,
		"provenance": map[string]any{
			"note": stateDiffProvenanceNote,
		},
	}
	documentBytes, err := json.Marshal(document)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}
	provenance := genericProvenance(tc.server, stateDiffKind, time.Now().UTC())
	stored, err := tc.server.store.PutWithProvenance(context.ID, stateDiffKind, "application/json", documentBytes, provenance)
	if err != nil {
		return failureResult(&toolFailure{Code: "artifact_error", Message: err.Error()}, tc.modern)
	}

	identical := false
	if metadataIdentical, ok := metadataDiff["identical"].(bool); ok {
		identical = metadataIdentical
	}
	if fileIdentical, ok := fileDiff["identical"].(bool); ok {
		identical = identical && fileIdentical
	}

	result := map[string]any{
		"kind":             "state-diff",
		"identical":        identical,
		"metadata_diff":    metadataDiff,
		"file_diff":        fileDiff,
		"semantic":         semantic,
		"provenance_note":  stateDiffProvenanceNote,
		"before_snapshot":  stateSnapshotView(before),
		"after_snapshot":   stateSnapshotView(after),
		"artifact":         artifactDescriptor(tc.server, stored, context.ID),
		"sha256":           stored.SHA256,
		"before_file_size": beforeSize,
		"after_file_size":  afterSize,
	}
	return okResult(result, tc.modern)
}

func stateSnapshotView(snapshot *analysis.Snapshot) map[string]any {
	return map[string]any{
		"state_id":          snapshot.ID,
		"name":              snapshot.Name,
		"created_at":        snapshot.CreatedAt,
		"size_bytes":        snapshot.SizeBytes,
		"sha256":            snapshot.SHA256,
		"target_generation": snapshot.TargetGeneration,
		"rom_path":          snapshot.ROMPath,
		"rom_sha256":        snapshot.ROMSHA256,
		"control_id":        snapshot.ControlID,
	}
}

// stateMetadataDiff compares the stored snapshot metadata and reports every
// differing field plus the ROM identity verdict.
func stateMetadataDiff(before, after *analysis.Snapshot) map[string]any {
	differences := []string{}
	addIf := func(condition bool, field, beforeValue, afterValue string) {
		if condition {
			differences = append(differences, fmt.Sprintf("%s: %q vs %q", field, beforeValue, afterValue))
		}
	}
	addIf(before.Name != after.Name, "name", before.Name, after.Name)
	addIf(before.SizeBytes != after.SizeBytes, "size_bytes", fmt.Sprintf("%d", before.SizeBytes), fmt.Sprintf("%d", after.SizeBytes))
	addIf(before.SHA256 != after.SHA256, "sha256", before.SHA256, after.SHA256)
	addIf(before.TargetGeneration != after.TargetGeneration, "target_generation", fmt.Sprintf("%d", before.TargetGeneration), fmt.Sprintf("%d", after.TargetGeneration))
	addIf(!before.CreatedAt.Equal(after.CreatedAt), "created_at", before.CreatedAt.Format(time.RFC3339), after.CreatedAt.Format(time.RFC3339))
	addIf(before.ROMPath != after.ROMPath, "rom_path", before.ROMPath, after.ROMPath)
	addIf(before.ROMSHA256 != after.ROMSHA256, "rom_sha256", before.ROMSHA256, after.ROMSHA256)
	addIf(before.ControlID != after.ControlID, "control_id", before.ControlID, after.ControlID)

	romIdentity := "unknown"
	switch {
	case before.ROMSHA256 != "" && after.ROMSHA256 != "":
		if before.ROMSHA256 == after.ROMSHA256 {
			romIdentity = "same"
		} else {
			romIdentity = "different"
		}
	case before.ROMPath != "" && before.ROMPath == after.ROMPath:
		romIdentity = "same"
	case before.ROMPath != "" && after.ROMPath != "":
		romIdentity = "different"
	}
	return map[string]any{
		"before":           stateSnapshotView(before),
		"after":            stateSnapshotView(after),
		"differences":      differences,
		"difference_count": len(differences),
		"identical":        len(differences) == 0,
		"rom_identity":     romIdentity,
	}
}

// readStateDiffFile reads a snapshot file bounded at the diff cap, reporting
// the total on-disk size and whether the returned bytes were truncated.
func readStateDiffFile(path string) ([]byte, int64, bool, *toolFailure) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, false, &toolFailure{Code: "state_file_missing", Message: "snapshot file " + path + " no longer exists"}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, false, &toolFailure{Code: "state_store_error", Message: "open snapshot file: " + err.Error()}
	}
	defer file.Close()
	if info.Size() <= stateDiffFileCapBytes {
		data, err := io.ReadAll(file)
		if err != nil {
			return nil, 0, false, &toolFailure{Code: "state_store_error", Message: "read snapshot file: " + err.Error()}
		}
		return data, info.Size(), false, nil
	}
	data := make([]byte, stateDiffFileCapBytes)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, 0, false, &toolFailure{Code: "state_store_error", Message: "read snapshot file: " + err.Error()}
	}
	return data, info.Size(), true, nil
}

// stateFileDiff compares two snapshot byte buffers in address order and
// reports per-byte counts, contiguous diff regions, and bounded inline hex.
func stateFileDiff(before, after []byte, maxDiffs uint64) map[string]any {
	compared := len(before)
	if len(after) > compared {
		compared = len(after)
	}
	type region struct {
		start, length int
	}
	regions := []region{}
	totalDiffs := 0
	common := len(before)
	if len(after) < common {
		common = len(after)
	}
	inRegion := false
	for i := 0; i < common; i++ {
		if before[i] != after[i] {
			totalDiffs++
			if !inRegion {
				regions = append(regions, region{start: i, length: 1})
				inRegion = true
			} else {
				regions[len(regions)-1].length++
			}
		} else {
			inRegion = false
		}
	}
	if len(before) != len(after) {
		// The shorter file's tail counts as differing bytes.
		tailLength := compared - common
		totalDiffs += tailLength
		if len(regions) > 0 && regions[len(regions)-1].start+regions[len(regions)-1].length == common {
			regions[len(regions)-1].length += tailLength
		} else {
			regions = append(regions, region{start: common, length: tailLength})
		}
	}

	inline := make([]map[string]any, 0, maxDiffs)
	inlineTruncated := uint64(len(regions)) > maxDiffs
	for i, entry := range regions {
		if uint64(i) >= maxDiffs {
			break
		}
		show := entry.length
		if show > stateDiffInlineSnippet {
			show = stateDiffInlineSnippet
		}
		beforeHex, beforeCut := snippetHex(before, entry.start, show)
		afterHex, afterCut := snippetHex(after, entry.start, show)
		view := map[string]any{
			"offset":        entry.start,
			"offset_hex":    canonicalHex(uint64(entry.start)),
			"region_length": entry.length,
			"before_hex":    beforeHex,
			"after_hex":     afterHex,
		}
		if beforeCut || afterCut || entry.length > show {
			view["hex_truncated"] = true
		}
		inline = append(inline, view)
	}

	regionsView := make([]map[string]any, 0, maxDiffs)
	regionsTotal := len(regions)
	for i, entry := range regions {
		if uint64(i) >= maxDiffs {
			break
		}
		regionsView = append(regionsView, map[string]any{
			"start":     entry.start,
			"start_hex": canonicalHex(uint64(entry.start)),
			"length":    entry.length,
		})
	}

	return map[string]any{
		"identical":          totalDiffs == 0,
		"before_size":        len(before),
		"after_size":         len(after),
		"compared_bytes":     compared,
		"total_diffs":        totalDiffs,
		"diff_regions_total": regionsTotal,
		"diff_regions":       regionsView,
		"inline_diffs":       inline,
		"inline_truncated":   inlineTruncated,
		"preview": map[string]any{
			"before_hex":       stateDiffPreviewHex(before),
			"after_hex":        stateDiffPreviewHex(after),
			"bytes_shown":      stateDiffPreviewBytes,
			"before_truncated": len(before) > stateDiffPreviewBytes,
			"after_truncated":  len(after) > stateDiffPreviewBytes,
		},
	}
}

func snippetHex(data []byte, start, length int) (string, bool) {
	if start >= len(data) {
		return "", true
	}
	end := start + length
	if end > len(data) {
		end = len(data)
	}
	return strings.ToUpper(hex.EncodeToString(data[start:end])), end-start < length
}

func stateDiffPreviewHex(data []byte) string {
	if len(data) > stateDiffPreviewBytes {
		data = data[:stateDiffPreviewBytes]
	}
	return strings.ToUpper(hex.EncodeToString(data))
}
