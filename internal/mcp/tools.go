package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

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

// toolRegistry is the deterministic alphabetical catalog shared by the
// modern and legacy dispatchers. It is filled in init() because experiment
// tool handlers dispatch back through lookupTool at runtime; a declaration-
// time initializer would create an initialization cycle between the registry
// and the experiment executor.
var toolRegistry []toolSpec

func init() {
	toolRegistry = buildToolRegistry()
}

func buildToolRegistry() []toolSpec {
	specs := append(phase1ToolSpecs(), cpuToolSpecs()...)
	specs = append(specs, controlToolSpecs()...)
	specs = append(specs, vdpToolSpecs()...)
	specs = append(specs, targetToolSpecs()...)
	specs = append(specs, phase4ToolSpecs()...)
	specs = append(specs, freezeToolSpecs()...)
	specs = append(specs, phase5ToolSpecs()...)
	specs = append(specs, experimentToolSpecs()...)
	specs = append(specs, annotationToolSpecs()...)
	specs = append(specs, backtraceToolSpecs()...)
	specs = append(specs, stateDiffToolSpecs()...)
	specs = append(specs, replayToolSpecs()...)
	specs = append(specs, registerConditionToolSpecs()...)
	sort.Slice(specs, func(i, j int) bool { return specs[i].name < specs[j].name })
	return specs
}

// lookupTool returns the registered spec of one tool, or nil. Experiment
// scripts dispatch through the same registry so their steps run through the
// exact handlers the MCP clients call.
func lookupTool(name string) *toolSpec {
	for index := range toolRegistry {
		if toolRegistry[index].name == name {
			return &toolRegistry[index]
		}
	}
	return nil
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
	spec := lookupTool(call.Name)
	if spec == nil {
		return errorResult("unknown_tool", "Unknown tool: "+call.Name, modern)
	}
	if len(call.Arguments) == 0 {
		call.Arguments = json.RawMessage("{}")
	}
	result := spec.run(toolContext{server: server, ctx: ctx, modern: modern}, call.Arguments)
	failed, _ := result["isError"].(bool)
	server.metrics.recordCall(call.Name, failed)
	result = injectResultType(result, call.Name)
	// Every result carries the target generation observed at response
	// completion; mutations additionally report before/after.
	return injectTargetGeneration(server, result)
}

func injectResultType(result map[string]any, toolName string) map[string]any {
	if result == nil {
		return result
	}
	if isError, ok := result["isError"].(bool); ok && isError {
		return result
	}
	if structured, ok := result["structuredContent"].(map[string]any); ok {
		if _, exists := structured["result_type"]; !exists {
			structured["result_type"] = toolName
		}
		if _, exists := structured["schema_version"]; !exists {
			structured["schema_version"] = "1"
		}
		return result
	}
	// Legacy: patch the content text.
	content, ok := result["content"].([]map[string]string)
	if !ok || len(content) == 0 {
		return result
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(content[0]["text"]), &value); err != nil {
		return result
	}
	if _, exists := value["result_type"]; !exists {
		value["result_type"] = toolName
	}
	if _, exists := value["schema_version"]; !exists {
		value["schema_version"] = "1"
	}
	if encoded, err := json.Marshal(value); err == nil {
		content[0]["text"] = string(encoded)
	}
	return result
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
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
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
	return map[string]any{
		"description": "Address as an integer, 0x hex, $ Motorola hex, or h-suffixed Zilog hex.",
		"oneOf": []map[string]any{
			{"type": "integer", "minimum": 0},
			{"type": "string", "pattern": "^(\\$[0-9a-fA-F]+|[0-9a-fA-F]+[hH]|0[xX][0-9a-fA-F]+|[0-9]+)$"},
		},
	}
}

func decodeSchemaProperty() map[string]any {
	return map[string]any{
		"type":                 "object",
		"description":          "Optional decoded-value view. Multi-byte types require a byte order that matches the space declaration.",
		"additionalProperties": false,
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

// captureModeProperty is the optional capture guard: "paused" pauses once
// before the read and restores the prior run state (temporally atomic, but
// perturbs real-time behavior); "live" (default) never pauses.
func captureModeProperty() map[string]any {
	return enumProperty("Capture guard. \"paused\" pauses once before the read and restores the prior run state (temporally atomic, perturbs timing-sensitive software); \"live\" (default) never pauses and samples a possibly inconsistent instant.", []string{"live", "paused"})
}

// ----------------------------------------------------------------------------------------------------------------------
// Argument helpers
// ----------------------------------------------------------------------------------------------------------------------
func decodeArgs[T any](args json.RawMessage) (*T, *toolFailure) {
	var parsed T
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	if failure := strictValidateArgs(args, reflect.TypeOf(&parsed).Elem(), "$"); failure != nil {
		return nil, failure
	}
	if err := json.Unmarshal(args, &parsed); err != nil {
		return nil, &toolFailure{Code: "invalid_params", Message: "invalid arguments: " + err.Error()}
	}
	return &parsed, nil
}

func isGloballyAllowedField(key string) bool {
	switch key {
	case "context", "control_id", "expected_target_generation":
		return true
	default:
		return false
	}
}

// strictValidateArgs rejects unknown JSON properties with a full JSON path such as $.ranges[0].address.
// Map types (e.g. experiment arguments) are treated as open extension points and their inner keys are not validated.
func strictValidateArgs(raw json.RawMessage, typ reflect.Type, path string) *toolFailure {
	// Dereference pointers.
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		// Allow null for struct pointers already handled; raw "null" means missing.
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || string(trimmed) == "null" {
			return nil
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			// Not an object — let the decoder report type errors.
			return nil
		}
		allowed := structFieldMap(typ)
		for key, value := range fields {
			if isGloballyAllowedField(key) {
				continue
			}
			fieldType, ok := allowed[key]
			if !ok {
				return &toolFailure{
					Code:    "invalid_params",
					Message: fmt.Sprintf("unknown field %q at %s.%s", key, path, key),
					Data:    map[string]any{"field": key, "path": path + "." + key},
				}
			}
			// Recurse into known field value.
			fieldPath := path + "." + key
			if failure := strictValidateArgs(value, fieldType, fieldPath); failure != nil {
				return failure
			}
		}
		return nil
	case reflect.Slice, reflect.Array:
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || string(trimmed) == "null" {
			return nil
		}
		var elements []json.RawMessage
		if err := json.Unmarshal(raw, &elements); err != nil {
			return nil
		}
		elemType := typ.Elem()
		for index, element := range elements {
			elementPath := fmt.Sprintf("%s[%d]", path, index)
			if failure := strictValidateArgs(element, elemType, elementPath); failure != nil {
				return failure
			}
		}
		return nil
	case reflect.Map:
		// Maps are open extension points (e.g. experiment arguments); do not validate inner keys.
		return nil
	case reflect.Interface:
		// any / interface{} leaf (address fields that accept int|string) — do not recurse.
		return nil
	default:
		return nil
	}
}

func structFieldMap(typ reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath != "" && !field.Anonymous {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := ""
		if tag != "" {
			name = strings.Split(tag, ",")[0]
		}
		if name == "" {
			name = strings.ToLower(field.Name[:1]) + field.Name[1:]
		}
		if field.Anonymous {
			fieldType := field.Type
			for fieldType.Kind() == reflect.Ptr {
				fieldType = fieldType.Elem()
			}
			if fieldType.Kind() == reflect.Struct {
				nested := structFieldMap(fieldType)
				for key, nestedType := range nested {
					out[key] = nestedType
				}
				continue
			}
		}
		out[name] = field.Type
	}
	return out
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
	descriptor := map[string]any{
		"id":           stored.ID,
		"kind":         stored.Kind,
		"mime_type":    stored.MimeType,
		"size_bytes":   stored.SizeBytes,
		"sha256":       stored.SHA256,
		"url":          fmt.Sprintf("%s/artifacts/%s?context=%s", server.baseURL, stored.ID, contextID),
		"resource_uri": "exodus://artifacts/" + stored.ID,
	}
	if stored.Provenance != nil {
		descriptor["provenance"] = provenanceEnvelopeView(*stored.Provenance)
		descriptor["provenance_state"] = stored.Provenance.State
	} else {
		descriptor["provenance"] = provenanceUnknownView()
		descriptor["provenance_state"] = artifact.ProvenanceStateUnknown
	}
	return descriptor
}

func jsonText(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
