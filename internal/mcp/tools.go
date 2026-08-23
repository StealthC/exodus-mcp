package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
)

const (
	inlineReadCapBytes = 4096
	dumpCapBytes       = 8 << 20
	defaultPreviewLen  = 512
	maxPreviewLen      = artifact.MaxPreviewBytes
)

type toolFailure struct {
	Code    string
	Message string
	Data    map[string]any
}

type toolContext struct {
	server *Server
	ctx    context.Context
	modern bool
}

type toolSpec struct {
	name        string
	description string
	schema      map[string]any
	run         func(tc toolContext, args json.RawMessage) map[string]any
}

var toolRegistry = buildToolRegistry()

func buildToolRegistry() []toolSpec {
	specs := append(phase1ToolSpecs(), cpuToolSpecs()...)
	specs = append(specs, controlToolSpecs()...)
	specs = append(specs, vdpToolSpecs()...)
	sort.Slice(specs, func(i, j int) bool { return specs[i].name < specs[j].name })
	return specs
}

// toolSchemas renders deterministic tool descriptors shared by both eras.
func toolSchemas() []map[string]any {
	schemas := make([]map[string]any, 0, len(toolRegistry))
	for _, spec := range toolRegistry {
		schemas = append(schemas, map[string]any{
			"name":        spec.name,
			"description": spec.description,
			"inputSchema": spec.schema,
		})
	}
	return schemas
}

func (server *Server) callTool(ctx context.Context, params json.RawMessage, modern bool) map[string]any {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil || call.Name == "" {
		return errorResult("invalid_params", "tools/call requires a tool name", modern)
	}
	for _, spec := range toolRegistry {
		if spec.name != call.Name {
			continue
		}
		if len(call.Arguments) == 0 {
			call.Arguments = json.RawMessage("{}")
		}
		return spec.run(toolContext{server: server, ctx: ctx, modern: modern}, call.Arguments)
	}
	return errorResult("unknown_tool", "Unknown tool: "+call.Name, modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// Result shaping
// ----------------------------------------------------------------------------------------------------------------------
func okResult(value any, modern bool) map[string]any {
	text, err := json.Marshal(value)
	if err != nil {
		text = []byte("{}")
	}
	result := map[string]any{
		"content":           []map[string]string{{"type": "text", "text": string(text)}},
		"structuredContent": value,
		"isError":           false,
	}
	if !modern {
		delete(result, "structuredContent")
	}
	return result
}

func errorResult(code, message string, modern bool) map[string]any {
	return failureResult(&toolFailure{Code: code, Message: message}, modern)
}

func failureResult(failure *toolFailure, modern bool) map[string]any {
	structured := map[string]any{"code": failure.Code, "message": failure.Message}
	for key, value := range failure.Data {
		structured[key] = value
	}
	result := map[string]any{
		"content":           []map[string]string{{"type": "text", "text": failure.Code + ": " + failure.Message}},
		"structuredContent": structured,
		"isError":           true,
	}
	if !modern {
		delete(result, "structuredContent")
	}
	return result
}

// ----------------------------------------------------------------------------------------------------------------------
// Schema helpers
// ----------------------------------------------------------------------------------------------------------------------
func objectSchema(properties map[string]any, required []string) map[string]any {
	schema := map[string]any{"type": "object", "properties": properties}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func stringProperty(description string) map[string]any {
	return map[string]any{"type": "string", "description": description}
}

func integerProperty(description string, minimum int64) map[string]any {
	property := map[string]any{"type": "integer", "description": description}
	if minimum > 0 {
		property["minimum"] = minimum
	}
	return property
}

func enumProperty(description string, values []string) map[string]any {
	return map[string]any{"type": "string", "enum": values, "description": description}
}

func booleanProperty(description string) map[string]any {
	return map[string]any{"type": "boolean", "description": description}
}

func addressProperty() map[string]any {
	return stringProperty("Address as an integer, 0x hex, $ Motorola hex, or h-suffixed Zilog hex.")
}

func decodeSchemaProperty() map[string]any {
	return map[string]any{
		"type":        "object",
		"description": "Optional decoded-value view. Multi-byte types require a byte order that matches the space declaration.",
		"properties": map[string]any{
			"type":       enumProperty("Value type to decode.", []string{"u8", "u16", "u32", "i16", "i32"}),
			"byte_order": enumProperty("Byte order for multi-byte types.", []string{"big-endian", "little-endian"}),
		},
		"required": []string{"type"},
	}
}

func contextProperty() map[string]any {
	return stringProperty("Analysis context handle; omitted means the implicit default context.")
}

// ----------------------------------------------------------------------------------------------------------------------
// Argument helpers
// ----------------------------------------------------------------------------------------------------------------------
func decodeArgs[T any](args json.RawMessage) (*T, *toolFailure) {
	var parsed T
	if err := json.Unmarshal(args, &parsed); err != nil {
		return nil, &toolFailure{Code: "invalid_params", Message: "invalid arguments: " + err.Error()}
	}
	return &parsed, nil
}

// parseAddress accepts integral JSON numbers or the roadmap address string
// formats: decimal, 0x-prefixed hex, $-prefixed Motorola hex, and Zilog
// h-suffixed hex such as "C000h".
func parseAddress(raw any) (uint64, *toolFailure) {
	switch value := raw.(type) {
	case float64:
		if value < 0 || value != float64(uint64(value)) {
			return 0, &toolFailure{Code: "invalid_params", Message: "address must be a non-negative integer"}
		}
		return uint64(value), nil
	case string:
		if parsed, ok := parseFlexibleNumber(value); ok {
			return parsed, nil
		}
		return 0, &toolFailure{Code: "invalid_params", Message: fmt.Sprintf("invalid address %q: use an integer, 0x hex, $ hex, or h-suffixed hex", value)}
	default:
		return 0, &toolFailure{Code: "invalid_params", Message: "address must be a number or hex string"}
	}
}

func parseFlexibleNumber(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	if value[0] == '$' {
		parsed, err := strconv.ParseUint(value[1:], 16, 64)
		return parsed, err == nil
	}
	if last := len(value) - 1; last > 0 && (value[last] == 'h' || value[last] == 'H') {
		parsed, err := strconv.ParseUint(value[:last], 16, 64)
		return parsed, err == nil
	}
	parsed, err := strconv.ParseUint(value, 0, 64)
	return parsed, err == nil
}

func resolveContext(server *Server, handle string) (*analysis.Context, *toolFailure) {
	resolved, err := server.contexts.Resolve(handle)
	if err != nil {
		return nil, &toolFailure{Code: "unknown_context", Message: err.Error()}
	}
	return resolved, nil
}

func artifactDescriptor(server *Server, stored artifact.Artifact, contextID string) map[string]any {
	return map[string]any{
		"id":           stored.ID,
		"kind":         stored.Kind,
		"mime_type":    stored.MimeType,
		"size_bytes":   stored.SizeBytes,
		"sha256":       stored.SHA256,
		"url":          fmt.Sprintf("%s/artifacts/%s?context=%s", server.baseURL, stored.ID, contextID),
		"resource_uri": "exodus://artifacts/" + stored.ID,
	}
}

func jsonText(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
