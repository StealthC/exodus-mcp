package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// snapshot_diff is the single snapshot-comparison tool (roadmap issue #17). One
// concept: "compare two recorded snapshots". sections selects which comparison
// runs, and each section keeps the handler it had:
//
//   - state: byte-level comparison of two state_save snapshots (metadata plus the
//     raw snapshot files), read-only;
//   - memory: cell-by-cell comparison of two memory snapshots with a comparison
//     mode, width, byte order, and #11 cursor paging.
//
// A state and a memory comparison need different inputs, so an argument that no
// requested section consumes is rejected instead of ignored. The merged tool is a
// facade: the section payloads are the absorbed handlers' own, so verdicts,
// provenance checks, artifacts and cursors cannot drift.

// snapshotDiffSectionVocab is the closed section vocabulary. state is first so a
// schema-only probe of `sections` reads the metadata-only comparison.
var snapshotDiffSectionVocab = newEnumVocab("sections", "state", "memory")

type snapshotDiffArgs struct {
	Sections []string `json:"sections"`

	SnapshotBeforeID string `json:"snapshot_before_id"`
	SnapshotAfterID  string `json:"snapshot_after_id"`
	Context          string `json:"context"`

	// state section
	MaxDiffs         uint64 `json:"max_diffs"`
	IncludeMemory    bool   `json:"include_memory"`
	IncludeRegisters bool   `json:"include_registers"`
	IncludeVDP       bool   `json:"include_vdp"`

	// memory section
	Space                       string  `json:"space"`
	Mode                        string  `json:"mode"`
	Width                       string  `json:"width"`
	ByteOrder                   string  `json:"byte_order"`
	Value                       *int64  `json:"value"`
	MinValue                    *uint64 `json:"min_value"`
	MaxValue                    *uint64 `json:"max_value"`
	StartAddress                any     `json:"start_address"`
	AddressSpace                string  `json:"address_space"`
	MaxMatches                  uint64  `json:"max_matches"`
	AllowMisaligned             bool    `json:"allow_misaligned"`
	AllowIncompatibleProvenance bool    `json:"allow_incompatible_provenance"`
	Cursor                      string  `json:"cursor"`
}

func snapshotDiffSpec() toolSpec {
	return toolSpec{
		name:        "snapshot_diff",
		description: "Compare two recorded snapshots. sections selects the comparisons (default: the sections the supplied arguments address, state otherwise): state compares two state_save snapshots read-only (metadata plus a bounded raw snapshot-file byte diff, with the register/memory/VDP semantic sections reported as not performed because decoding them would need state_load, a target mutation); memory compares two memory snapshots cell by cell with mode changed/unchanged/increased/decreased/changed_by/equal_to/in_range, width byte/word/long, explicit byte order, provenance compatibility checking, and cursor paging (without snapshot_after_id the region is read fresh into a snapshot first). Each section returns the payload of the tool that owned it, under results, including its verdict, artifact and next_cursor. An argument that no requested section consumes is rejected.",
		schema: objectSchema(map[string]any{
			"sections": map[string]any{
				"type":        "array",
				"description": "Comparisons to run. state compares state snapshots, memory compares memory snapshots; both may be requested in one call.",
				"items":       map[string]any{"type": "string", "enum": snapshotDiffSectionVocab.values},
				"minItems":    1,
			},
			"snapshot_before_id":            stringProperty("Before side: a state id from state_save for section state, or a memory-dump/memory-snapshot artifact id for section memory."),
			"snapshot_after_id":             stringProperty("After side. Section state requires it (a state id). Section memory treats it as optional: without it the before range is read fresh into a snapshot first."),
			"max_diffs":                     integerProperty(fmt.Sprintf("Section state: maximum inline diff regions (default %d, cap %d).", defaultStateDiffMaxDiffs, maxStateDiffMaxDiffs), 1),
			"include_memory":                booleanProperty("Section state: request the memory comparison section (reported as not performed in this read-only mode)."),
			"include_registers":             booleanProperty("Section state: request the registers comparison section (reported as not performed in this read-only mode)."),
			"include_vdp":                   booleanProperty("Section state: request the VDP comparison section (reported as not performed in this read-only mode)."),
			"space":                         stringProperty("Section memory: address space id, required when snapshot_after_id is omitted and the before snapshot lacks provenance."),
			"mode":                          enumProperty("Section memory: comparison mode (required unless cursor is given).", []string{"changed", "unchanged", "increased", "decreased", "changed_by", "equal_to", "in_range"}),
			"width":                         enumProperty("Section memory: cell width; word/long cells honor byte_order.", []string{"byte", "word", "long"}),
			"byte_order":                    enumProperty("Section memory: byte order for word/long cells; defaults to the before snapshot's captured order, otherwise big-endian.", []string{"big-endian", "little-endian"}),
			"value":                         integerProperty("Section memory: value for equal_to or the signed delta for changed_by.", 0),
			"min_value":                     integerProperty("Section memory: lower bound for in_range.", 0),
			"max_value":                     integerProperty("Section memory: upper bound for in_range.", 0),
			"start_address":                 addressProperty(),
			"max_matches":                   integerProperty(fmt.Sprintf("Section memory: maximum inline matches (default %d, cap %d).", defaultSearchMaxMatches, maxSearchMaxMatches), 1),
			"allow_misaligned":              booleanProperty("Section memory: scan every cell offset instead of aligning to the cell width."),
			"allow_incompatible_provenance": booleanProperty("Section memory: compare snapshots whose capture provenance differs and warn instead of failing with incompatible_provenance."),
			"cursor":                        stringProperty("Section memory: next_cursor from a previous memory comparison. The cursor carries both snapshots, the mode, width, byte order, comparison values and alignment policy, so a later page needs only the cursor."),
			"context":                       contextProperty(),
		}, []string{"sections"}),
		run: runSnapshotDiff,
	}
}

func runSnapshotDiff(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[snapshotDiffArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	sections, failure := resolveSnapshotDiffSections(parsed)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	raw, failure := decodeArgumentMap(args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if failure := validateSnapshotDiffArguments(raw, sections); failure != nil {
		return failureResult(failure, tc.modern)
	}

	results := map[string]any{}
	returned := 0
	nextCursor := ""
	hasMore := false
	for _, section := range sections {
		var payload map[string]any
		switch section {
		case "state":
			arguments := pickArguments(raw, "snapshot_before_id", "snapshot_after_id", "max_diffs", "include_memory", "include_registers", "include_vdp", "context")
			payload, failure = composeTool(tc, runStateDiff, arguments)
		default:
			arguments := pickArguments(raw,
				"snapshot_before_id", "snapshot_after_id", "space", "mode", "width", "byte_order",
				"value", "min_value", "max_value", "start_address", "address_space", "max_matches",
				"allow_misaligned", "allow_incompatible_provenance", "cursor", "context")
			payload, failure = composeTool(tc, runMemoryDiff, arguments)
		}
		if failure != nil {
			return failureResult(failure, tc.modern)
		}
		results[section] = payload
		if value, ok := numberAsUint64(payload["returned"]); ok {
			returned += int(value)
		}
		if cursor, ok := payload["next_cursor"].(string); ok && cursor != "" {
			hasMore = true
			if len(sections) == 1 {
				nextCursor = cursor
			}
		}
	}

	result := map[string]any{
		"sections": sections,
		"results":  results,
		"returned": returned,
		"has_more": hasMore,
		"note":     "Each section is the payload of the comparison that owns it, including its verdict, artifact, totals and next_cursor. Sections are independent: a state diff never loads the snapshots and a memory diff never compares state files.",
	}
	if len(sections) == 1 {
		section, _ := results[sections[0]].(map[string]any)
		for _, key := range []string{"identical", "total", "truncated", "comparison"} {
			if value, present := section[key]; present {
				result[key] = value
			}
		}
		if nextCursor != "" {
			result["next_cursor"] = nextCursor
		} else {
			result["next_cursor"] = nil
		}
	}
	if len(sections) > 1 {
		// A combined verdict is only meaningful when both sections reached one.
		identical := true
		for _, section := range sections {
			payload, _ := results[section].(map[string]any)
			value, present := payload["identical"].(bool)
			if !present {
				identical = false
				break
			}
			identical = identical && value
		}
		result["identical"] = identical
	}
	return okResult(result, tc.modern)
}

// resolveSnapshotDiffSections validates and de-duplicates the requested sections,
// inferring the pair the supplied arguments address when none was given.
func resolveSnapshotDiffSections(parsed *snapshotDiffArgs) ([]string, *toolFailure) {
	if len(parsed.Sections) == 0 {
		return inferSnapshotDiffSections(*parsed), nil
	}
	requested := parsed.Sections
	seen := map[string]bool{}
	sections := make([]string, 0, len(requested))
	for _, section := range requested {
		if failure := snapshotDiffSectionVocab.validate(section); failure != nil {
			return nil, failure
		}
		if seen[section] {
			return nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("sections lists %q twice", section),
				Data:    map[string]any{"field": "sections", "value": section},
			}
		}
		seen[section] = true
		sections = append(sections, section)
	}
	return sections, nil
}

// inferSnapshotDiffSections derives the default selection from the arguments a
// section owns, so a section-specific argument is never accepted and then
// ignored. The state comparison is the default when nothing points at memory.
func inferSnapshotDiffSections(parsed snapshotDiffArgs) []string {
	state := parsed.MaxDiffs != 0 || parsed.IncludeMemory || parsed.IncludeRegisters || parsed.IncludeVDP
	memory := parsed.Space != "" || parsed.Mode != "" || parsed.Width != "" || parsed.ByteOrder != "" ||
		parsed.Value != nil || parsed.MinValue != nil || parsed.MaxValue != nil || parsed.StartAddress != nil ||
		parsed.AddressSpace != "" || parsed.MaxMatches != 0 || parsed.AllowMisaligned ||
		parsed.AllowIncompatibleProvenance || parsed.Cursor != ""
	switch {
	case state && memory:
		return []string{"state", "memory"}
	case memory:
		return []string{"memory"}
	default:
		return []string{"state"}
	}
}

// snapshotDiffConsumers maps each argument to the sections that consume it.
func snapshotDiffConsumers() map[string][]string {
	return map[string][]string{
		"sections":                      {"state", "memory"},
		"snapshot_before_id":            {"state", "memory"},
		"snapshot_after_id":             {"state", "memory"},
		"context":                       {"state", "memory"},
		"max_diffs":                     {"state"},
		"include_memory":                {"state"},
		"include_registers":             {"state"},
		"include_vdp":                   {"state"},
		"space":                         {"memory"},
		"mode":                          {"memory"},
		"width":                         {"memory"},
		"byte_order":                    {"memory"},
		"value":                         {"memory"},
		"min_value":                     {"memory"},
		"max_value":                     {"memory"},
		"start_address":                 {"memory"},
		"address_space":                 {"memory"},
		"max_matches":                   {"memory"},
		"allow_misaligned":              {"memory"},
		"allow_incompatible_provenance": {"memory"},
		"cursor":                        {"memory"},
	}
}

// validateSnapshotDiffArguments rejects an argument that no requested section
// consumes, naming the accepted set.
func validateSnapshotDiffArguments(raw map[string]json.RawMessage, sections []string) *toolFailure {
	consumers := snapshotDiffConsumers()
	requested := map[string]bool{}
	for _, section := range sections {
		requested[section] = true
	}
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		appliesTo, known := consumers[key]
		if !known {
			// The strict decoder already rejects fields outside the schema.
			continue
		}
		consumed := false
		for _, section := range appliesTo {
			if requested[section] {
				consumed = true
				break
			}
		}
		if consumed {
			continue
		}
		accepted := []string{"sections"}
		for name, candidates := range consumers {
			for _, section := range candidates {
				if requested[section] {
					accepted = append(accepted, name)
					break
				}
			}
		}
		sort.Strings(accepted)
		return &toolFailure{
			Code:    "unsupported_parameter",
			Message: fmt.Sprintf("%q is not consumed by any requested section (%s); it applies to %s", key, strings.Join(sections, ","), strings.Join(appliesTo, ",")),
			Data: map[string]any{
				"field":           key,
				"path":            "$." + key,
				"sections":        sections,
				"consumed_by":     appliesTo,
				"accepted_fields": accepted,
			},
		}
	}
	return nil
}
