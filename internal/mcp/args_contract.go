package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// This file is the single source of truth for the argument contract:
//
//   - enumVocab (and intEnumVocab) owns one closed vocabulary and renders both
//     the published schema property and the decode-time validation, so a schema
//     enum and the handler that consumes it cannot drift apart.
//   - validateToolArguments walks the published inputSchema before any handler
//     runs and rejects a value outside a declared enum with invalid_params,
//     naming the field, the offending value, and the allowed values. A handler
//     default can therefore never silently replace an unsupported request.
//   - unsupportedParameterFailure is the stable rejection for a mediation field
//     (context, control_id, expected_target_generation) that the addressed tool
//     does not consume.

// noArgs is the decoded argument set of a tool that consumes no arguments. It
// exists so the strict decoder rejects every supplied field, including the
// mediation fields, instead of accepting arguments the handler would ignore.
type noArgs struct{}

// ----------------------------------------------------------------------------------------------------------------------
// Enum vocabularies
// ----------------------------------------------------------------------------------------------------------------------

// enumVocab is one closed string vocabulary shared by schema generation and
// argument decoding.
type enumVocab struct {
	field  string
	values []string
}

func newEnumVocab(field string, values ...string) enumVocab {
	return enumVocab{field: field, values: values}
}

// property renders the published schema property of the vocabulary.
func (vocab enumVocab) property(description string) map[string]any {
	return map[string]any{"type": "string", "enum": vocab.values, "description": description}
}

// valuesEcho copies the vocabulary for responses and error payloads.
func (vocab enumVocab) valuesEcho() []string {
	echo := make([]string, len(vocab.values))
	copy(echo, vocab.values)
	return echo
}

// accepts reports whether value is a member of the vocabulary.
func (vocab enumVocab) accepts(value string) bool {
	for _, candidate := range vocab.values {
		if candidate == value {
			return true
		}
	}
	return false
}

// validate rejects a value outside the vocabulary. The empty string means the
// argument was omitted and leaves the documented default in force.
func (vocab enumVocab) validate(value string) *toolFailure {
	if value == "" || vocab.accepts(value) {
		return nil
	}
	return invalidEnumFailure(vocab.field, value, vocab.valuesEcho())
}

// resolve validates a supplied value and applies the documented default when it
// was omitted.
func (vocab enumVocab) resolve(value, fallback string) (string, *toolFailure) {
	if failure := vocab.validate(value); failure != nil {
		return "", failure
	}
	if value == "" {
		return fallback, nil
	}
	return value, nil
}

// coerce keeps a value that belongs to the vocabulary and substitutes the
// fallback otherwise, reporting whether it had to substitute. It is the output
// counterpart of validate: a response field cannot publish a value the schema
// does not declare, and the caller reports the substitution instead of hiding
// it.
func (vocab enumVocab) coerce(value, fallback string) (string, bool) {
	if value != "" && vocab.accepts(value) {
		return value, false
	}
	return fallback, true
}

// intEnumVocab is the integer counterpart of enumVocab; zero is reserved for
// "omitted" so a caller can rely on the documented default.
type intEnumVocab struct {
	field  string
	values []int
}

func newIntEnumVocab(field string, values ...int) intEnumVocab {
	return intEnumVocab{field: field, values: values}
}

func (vocab intEnumVocab) property(description string) map[string]any {
	return map[string]any{"type": "integer", "enum": vocab.values, "description": description}
}

func (vocab intEnumVocab) valuesEcho() []int {
	echo := make([]int, len(vocab.values))
	copy(echo, vocab.values)
	return echo
}

func (vocab intEnumVocab) accepts(value int) bool {
	for _, candidate := range vocab.values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (vocab intEnumVocab) validate(value int) *toolFailure {
	if value == 0 || vocab.accepts(value) {
		return nil
	}
	return invalidEnumFailure(vocab.field, value, vocab.valuesEcho())
}

func (vocab intEnumVocab) resolve(value, fallback int) (int, *toolFailure) {
	if failure := vocab.validate(value); failure != nil {
		return 0, failure
	}
	if value == 0 {
		return fallback, nil
	}
	return value, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// Catalog-wide vocabularies
//
// One declaration per closed vocabulary; the schema property and the handler
// validation both read it, so a handler cannot validate a different value set
// than the one it publishes.
// ----------------------------------------------------------------------------------------------------------------------

var (
	cpuVocab                    = newEnumVocab("cpu", "m68k", "z80")
	breakpointConditionVocab    = newEnumVocab("condition", "equal", "greater", "less", "range")
	watchAccessVocab            = newEnumVocab("access", "read", "write", "any")
	debugEventDirectionVocab    = newEnumVocab("direction", "read", "write", "execute", "any")
	debugEventResourceKindVocab = newEnumVocab("resource_kind", "breakpoint", "watchpoint", "any")
	captureModeVocab            = newEnumVocab("capture_mode", captureModeLive, captureModePaused)
	soundComponentVocab         = newEnumVocab("component", "ym2612", "psg", "both")
	soundCaptureModeVocab       = newEnumVocab("capture_mode", "live")
	audioSampleRateVocab        = newIntEnumVocab("sample_rate", 22050, 44100, 48000)
	audioChannelsVocab          = newIntEnumVocab("channels", 1, 2)
	artifactPreviewModeVocab    = newEnumVocab("mode", "hex", "text", "base64")
	vdpBufferVocab              = newEnumVocab("target", "vram", "cram", "vsram")
	vdpPlaneVocab               = newEnumVocab("plane", "a", "b", "window")
	vdpRepresentationVocab      = newEnumVocab("representation", "hexdump", "array_u8", "raw_base64", "array_u16", "cram_rgb333")
	memoryRepresentationVocab   = newEnumVocab("representation", "raw_base64", "hexdump", "array_u8")
)

// ----------------------------------------------------------------------------------------------------------------------
// Response vocabularies
//
// These are the closed vocabularies of the fields the server *emits*, not
// consumes. They are declared once here so a producer cannot introduce a
// second spelling of the same concept: the capture-consistency renderer, the
// published catalog, and the conformance tests all read the same declaration.
// ----------------------------------------------------------------------------------------------------------------------

var (
	// captureStateVocab is capture_consistency.state. The first four states
	// describe one capture; the two extended states keep the distinctions the
	// existing contract already promised (a restored snapshot is not a live
	// capture, and a composite that spanned moments is not a coherent instant).
	captureStateVocab = newEnumVocab("state",
		consistencyLive,
		consistencyAtomic,
		consistencyPaused,
		consistencyCompositeNonAtomic,
		consistencyStateRestored,
		consistencyUnknown,
	)
	// runStateVocab is the observed run state: capture_consistency's
	// initial_run_state and final_run_state, provenance cpu_run_state, the
	// emulator_status run_state, and a debug event's run_state.
	runStateVocab = newEnumVocab("run_state", runStateRunning, runStatePaused, runStateUnknown)
	// pauseSourceVocab is who caused the current run state (pause_source).
	pauseSourceVocab = newEnumVocab("pause_source",
		pauseSourceBreakpointOrWatchpoint,
		pauseSourceMCP,
		pauseSourceUIOrExternal,
		pauseSourceUnknown,
	)
	// stopSourceVocab is why execution stopped (stop_source): the run_until_*
	// family, structured debug events, and emulator_status.
	stopSourceVocab = newEnumVocab("stop_source",
		stopSourceInstrument,
		stopSourceExternal,
		stopSourceMCP,
		stopSourceNone,
		stopSourceUnknown,
	)
	// runUntilStopReasonVocab is the stop_reason of a run_until_* call, a label
	// for which instrument ended the window. It is not stop_source: the two
	// answer different questions and must not be compared.
	runUntilStopReasonVocab = newEnumVocab("stop_reason", stopReasonBreakpointHit, stopReasonWatchpointHit, consistencyUnknown)
)

// responseVocabularyDeclaration renders every emitted vocabulary as one
// machine-readable object, published next to each tool's inputSchema so a
// client can build one conditional without parsing prose or per-tool special
// cases.
func responseVocabularyDeclaration() map[string]any {
	return map[string]any{
		"capture_consistency.state":             captureStateVocab.valuesEcho(),
		"capture_consistency.initial_run_state": runStateVocab.valuesEcho(),
		"capture_consistency.final_run_state":   runStateVocab.valuesEcho(),
		"cpu_run_state":                         runStateVocab.valuesEcho(),
		"run_state":                             runStateVocab.valuesEcho(),
		"pause_source":                          pauseSourceVocab.valuesEcho(),
		"stop_source":                           stopSourceVocab.valuesEcho(),
		"stop_reason":                           runUntilStopReasonVocab.valuesEcho(),
		"capture_mode":                          captureModeVocab.valuesEcho(),
	}
}

// responseDeprecationDeclaration names every response field kept only for
// backwards compatibility, its replacement, and whether it is derived from that
// replacement (a derived alias can never become a second source of truth).
func responseDeprecationDeclaration() map[string]any {
	return map[string]any{
		"consistency": map[string]any{
			"replacement": "capture_consistency.state",
			"derived":     true,
			"note":        consistencyDeprecatedFieldNote,
		},
		"capture_consistency.paused_by_tool": map[string]any{
			"replacement": "capture_consistency.execution_paused_by_tool",
			"derived":     true,
			"note":        "paused_by_tool mirrors execution_paused_by_tool for consumers of the older capture objects; the two are always equal.",
		},
	}
}

// responseVocabularySchemaKey is the JSON-Schema annotation that publishes the
// emitted vocabularies. It is an extension key, so a client that does not know
// it ignores it, and a client that checks its output can validate every value
// the server is allowed to emit.
const responseVocabularySchemaKey = "x-response-vocabularies"

// responseDeprecationSchemaKey is the companion annotation for deprecated
// response fields.
const responseDeprecationSchemaKey = "x-deprecated-response-fields"

// invalidEnumFailure is the stable rejection for a value outside a declared
// vocabulary: code invalid_params plus the field, the offending value, and the
// allowed values.
func invalidEnumFailure(field string, value any, allowed any) *toolFailure {
	return &toolFailure{
		Code:    "invalid_params",
		Message: fmt.Sprintf("%s must be one of %s", field, renderEnumValues(allowed)),
		Data:    map[string]any{"field": field, "value": value, "allowed": allowed},
	}
}

// renderEnumValues formats an enum list for the human-readable message while
// the structured payload keeps the original list type.
func renderEnumValues(allowed any) string {
	switch values := allowed.(type) {
	case []string:
		return strings.Join(values, ", ")
	case []int:
		rendered := make([]string, 0, len(values))
		for _, value := range values {
			rendered = append(rendered, fmt.Sprint(value))
		}
		return strings.Join(rendered, ", ")
	default:
		return fmt.Sprint(allowed)
	}
}

// scopeExperimentArguments injects the experiment's context and control id into
// the arguments of the tools that publish them. A tool that does not consume a
// mediation field rejects it, so injecting it blindly would fail the step.
func scopeExperimentArguments(spec *toolSpec, arguments map[string]any, contextID, controlID string) {
	if spec == nil {
		return
	}
	properties := schemaProperties(spec.schema)
	if _, published := properties["context"]; published && contextID != "" {
		arguments["context"] = contextID
	}
	if _, published := properties["control_id"]; published && controlID != "" {
		arguments["control_id"] = controlID
	}
}

// unsupportedParameterFailure reports a field the addressed tool does not
// consume, naming the accepted top-level fields so the caller can repair the
// call instead of guessing which argument was silently ignored.
func unsupportedParameterFailure(field, path string, accepted []string) *toolFailure {
	acceptedText := "(none)"
	if len(accepted) > 0 {
		acceptedText = strings.Join(accepted, ", ")
	}
	return &toolFailure{
		Code:    "unsupported_parameter",
		Message: fmt.Sprintf("%s is not accepted by this tool; accepted fields: %s", field, acceptedText),
		Data: map[string]any{
			"field":           field,
			"path":            path,
			"accepted_fields": accepted,
		},
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Schema-driven enum validation at dispatch
// ----------------------------------------------------------------------------------------------------------------------

// contractGuardFields are the optional mediation arguments a tool may consume.
// Declaring one in a tool schema is a promise that the handler applies it; a
// tool that does not declare it rejects it instead of letting the caller
// believe a guard was honored.
var contractGuardFields = []string{"context", "control_id", "expected_target_generation"}

func isContractGuardField(field string) bool {
	for _, candidate := range contractGuardFields {
		if candidate == field {
			return true
		}
	}
	return false
}

// schemaProperties returns the published property map of one schema node.
func schemaProperties(schema map[string]any) map[string]any {
	properties, _ := schema["properties"].(map[string]any)
	return properties
}

// deprecatedEnumAliases records a documented, deprecated compatibility value
// next to the normative enum. The published enum stays authoritative for new
// callers; the schema guard accepts a listed alias so a handler that resolves
// it (and reports deprecated_parameter_value) is not blocked by the guard.
func deprecatedEnumAliases(property map[string]any, aliases ...string) map[string]any {
	property[deprecatedEnumAliasesKey] = aliases
	return property
}

const deprecatedEnumAliasesKey = "x-deprecated-enum-aliases"

// validateToolArguments enforces the closed vocabularies in the published
// schema of a tool before its handler runs. Scalars declared inside an array of
// scalars are matched case-insensitively because handlers normalize them (input
// button names are lowercased); object properties are matched exactly.
func validateToolArguments(spec *toolSpec, raw json.RawMessage) *toolFailure {
	if spec == nil || len(spec.schema) == 0 {
		return nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil {
		// Not an object: the argument decoder reports the type error with its path.
		return nil
	}
	return validateObjectEnums(spec.name, spec.schema, object, "$")
}

func validateObjectEnums(tool string, schema map[string]any, object map[string]json.RawMessage, path string) *toolFailure {
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}
	// Sorted so a request with several bad values reports a deterministic one.
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		property, ok := properties[key].(map[string]any)
		if !ok {
			continue
		}
		if failure := validatePropertyEnums(tool, property, object[key], path+"."+key, false); failure != nil {
			return failure
		}
	}
	return nil
}

func validatePropertyEnums(tool string, property map[string]any, raw json.RawMessage, path string, caseInsensitive bool) *toolFailure {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	if allowed, ok := property["enum"]; ok {
		if failure := checkEnumMember(tool, propertyName(path), path, allowed, property[deprecatedEnumAliasesKey], trimmed, caseInsensitive); failure != nil {
			return failure
		}
		return nil
	}
	switch property["type"] {
	case "object":
		var nested map[string]json.RawMessage
		if json.Unmarshal(trimmed, &nested) != nil {
			return nil
		}
		return validateObjectEnums(tool, property, nested, path)
	case "array":
		items, ok := property["items"].(map[string]any)
		if !ok {
			return nil
		}
		var elements []json.RawMessage
		if json.Unmarshal(trimmed, &elements) != nil {
			return nil
		}
		_, itemsAreObject := items["properties"]
		for index, element := range elements {
			elementPath := fmt.Sprintf("%s[%d]", path, index)
			if failure := validatePropertyEnums(tool, items, element, elementPath, !itemsAreObject); failure != nil {
				return failure
			}
		}
	}
	return nil
}

// checkEnumMember compares one JSON value against a published enum list.
func checkEnumMember(tool, field, path string, allowed, aliases any, raw []byte, caseInsensitive bool) *toolFailure {
	if values, ok := allowed.([]string); ok {
		var supplied string
		if json.Unmarshal(raw, &supplied) != nil {
			return invalidEnumFailure(field, rawJSONText(raw), allowed).withTool(tool, path)
		}
		for _, candidate := range values {
			if candidate == supplied || (caseInsensitive && strings.EqualFold(candidate, supplied)) {
				return nil
			}
		}
		if aliasList, ok := aliases.([]string); ok {
			for _, alias := range aliasList {
				if alias == supplied {
					return nil
				}
			}
		}
		return invalidEnumFailure(field, supplied, allowed).withTool(tool, path)
	}
	if values, ok := allowed.([]int); ok {
		var supplied float64
		if json.Unmarshal(raw, &supplied) != nil {
			return invalidEnumFailure(field, rawJSONText(raw), allowed).withTool(tool, path)
		}
		for _, candidate := range values {
			if float64(candidate) == supplied {
				return nil
			}
		}
		return invalidEnumFailure(field, supplied, allowed).withTool(tool, path)
	}
	return nil
}

// withTool adds the tool name and the JSON path of the offending value; the
// code, field, value, and allowed payload stay stable.
func (failure *toolFailure) withTool(tool, path string) *toolFailure {
	if failure == nil {
		return nil
	}
	if failure.Data == nil {
		failure.Data = map[string]any{}
	}
	failure.Data["tool"] = tool
	failure.Data["path"] = path
	return failure
}

func propertyName(path string) string {
	if index := strings.LastIndex(path, "."); index >= 0 {
		path = path[index+1:]
	}
	if index := strings.Index(path, "["); index >= 0 {
		path = path[:index]
	}
	return path
}

// sortedArgumentFieldNames renders the accepted top-level argument names of one tool.
func sortedArgumentFieldNames(fields map[string]reflect.Type) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func rawJSONText(raw []byte) string {
	var decoded string
	if json.Unmarshal(raw, &decoded) == nil {
		return decoded
	}
	return string(raw)
}
