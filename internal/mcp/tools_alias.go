package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
)

// This file is the single declaration of the deprecated tool aliases
// (roadmap issue #17, catalog consolidation).
//
// One concept per tool: the catalog exposes one canonical implementation per
// concept (target_status, memory_map, cpu_step, debug_instrument, ...). Every
// tool name that predates the consolidation stays registered for one release as
// an alias of the canonical tool, because an agent transcript outlives a server
// version. An alias:
//
//   - keeps its published inputSchema, so existing arguments keep validating
//     exactly as before;
//   - runs the exact handler it ran before, so the payload shape is the shape
//     the caller already parses;
//   - additionally carries a `deprecated` block naming the replacement and the
//     mapping between the two payloads, so a caller can migrate from the
//     response alone.
//
// toolAliasRecords is authoritative: the registry test proves every alias is
// registered, every replacement is a canonical (non-alias) tool, and every
// alias response carries a well-formed `deprecated` block.

// aliasDeprecatedCode is the success-payload marker of an alias response. Like
// artifact_describe_deprecated it is a warning marker, not an error code: the
// call succeeded, and the marker tells the caller which tool to migrate to.
const aliasDeprecatedCode = "tool_alias_deprecated"

// aliasRemovalPolicy is published in every alias response so a client can decide
// when to migrate instead of guessing.
const aliasRemovalPolicy = "The alias stays available for one release and is removed afterwards."

// toolAliasRecord declares one deprecated tool name.
type toolAliasRecord struct {
	// Alias is the legacy tool name that stays registered.
	Alias string
	// Replacement is the canonical tool that now owns the concept.
	Replacement string
	// Mapping states, for a caller reading one response, which canonical field
	// carries the alias' payload (or how the alias payload is composed).
	Mapping string
}

// toolAliasRecords declares every deprecated alias in the catalog.
var toolAliasRecords = []toolAliasRecord{
	{
		Alias:       "bridge_status",
		Replacement: "target_status",
		Mapping:     "bridge_status returns the legacy flat bridge object; target_status.bridge carries the same fields.",
	},
	{
		Alias:       "emulator_status",
		Replacement: "target_status",
		Mapping:     "emulator_status returns the legacy flat object; target_status.run_state, devices and rom carry the same fields (modules and devices move under devices).",
	},
	{
		Alias:       "target_info",
		Replacement: "target_status",
		Mapping:     "target_info returns the legacy flat object; target_status.emulator, devices, platform and rom (rom.summary) carry the same fields.",
	},
}

// toolAliasByName indexes the records so the alias wrapper cannot drift from the
// declaration.
var toolAliasByName = func() map[string]toolAliasRecord {
	index := make(map[string]toolAliasRecord, len(toolAliasRecords))
	for _, record := range toolAliasRecords {
		index[record.Alias] = record
	}
	return index
}()

// aliasRun wraps the unchanged legacy handler of one deprecated tool so its
// successful and failed payloads both name the replacement.
func aliasRun(tool string, legacy func(toolContext, json.RawMessage) map[string]any) func(toolContext, json.RawMessage) map[string]any {
	return func(tc toolContext, args json.RawMessage) map[string]any {
		return attachAliasDeprecation(legacy(tc, args), tool)
	}
}

// attachAliasDeprecation adds the `deprecated` block to a completed alias
// result. Both encodings are patched: structuredContent for modern clients and
// the JSON text content for legacy clients. A failure text such as
// "invalid_params: ..." is not JSON and is left alone; the structured payload
// still carries the marker.
func attachAliasDeprecation(result map[string]any, tool string) map[string]any {
	if result == nil {
		return result
	}
	record, present := toolAliasByName[tool]
	if !present {
		// A registered alias without a record is a defect the registry test
		// catches; never publish a half-formed migration hint.
		record = toolAliasRecord{Alias: tool, Replacement: "unregistered_alias"}
	}
	block := map[string]any{
		"code":        aliasDeprecatedCode,
		"tool":        record.Alias,
		"replacement": record.Replacement,
		"removal":     aliasRemovalPolicy,
		"message":     fmt.Sprintf("%s is a deprecated alias of %s and returns its legacy payload shape. Use %s; the alias is removed after one release.", record.Alias, record.Replacement, record.Replacement),
	}
	if record.Mapping != "" {
		block["mapping"] = record.Mapping
	}
	if structured, ok := result["structuredContent"].(map[string]any); ok {
		structured["deprecated"] = block
	}
	content, ok := result["content"].([]map[string]string)
	if !ok || len(content) == 0 {
		return result
	}
	var value map[string]any
	if json.Unmarshal([]byte(content[0]["text"]), &value) != nil {
		return result
	}
	value["deprecated"] = block
	if encoded, err := json.Marshal(value); err == nil {
		content[0]["text"] = string(encoded)
	}
	return result
}

// aliasToolNames returns the sorted alias names, for diagnostics and tests.
func aliasToolNames() []string {
	names := make([]string, 0, len(toolAliasRecords))
	for _, record := range toolAliasRecords {
		names = append(names, record.Alias)
	}
	sort.Strings(names)
	return names
}

// deprecationAnnotation renders the machine-readable migration marker published
// next to an alias' inputSchema, so a client can warn before calling it.
func deprecationAnnotation(tool string) map[string]any {
	record, present := toolAliasByName[tool]
	if !present {
		return nil
	}
	return map[string]any{
		"replacement": record.Replacement,
		"removal":     aliasRemovalPolicy,
		"mapping":     record.Mapping,
	}
}
