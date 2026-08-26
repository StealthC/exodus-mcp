package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// cpu_register_condition_evaluate (roadmap P7): server-side post-hit
// evaluation of register conditions. IBreakpoint has no register condition,
// so the loop is: set a plain breakpoint with cpu_breakpoint_set, wait for
// the system to pause on the hit, call this tool to sample registers and
// evaluate, and resume with cpu_run when the condition is false. The
// evaluation is derived and heuristic — it is not a native emulator
// breakpoint condition — and the pause/resume cycle perturbs timing.

// registerConditionOperators is scanned longest-first so >= and <= win over
// the bare > and <.
var registerConditionOperators = []string{">=", "<=", "==", "!=", ">", "<"}

func registerConditionToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "cpu_register_condition_evaluate",
			description: `Evaluate a register condition such as "D0 == $1234", "A7 >= $FF0000", or "D1 != 0" against the current CPU registers. Derived, heuristic evaluation — not a native emulator breakpoint condition: IBreakpoint has no register condition, so this is the server-side post-hit evaluation loop primitive. Intended workflow: set a plain breakpoint with cpu_breakpoint_set; when the system pauses, call this tool; if matched is false, resume with cpu_run. Supported operators: ==, !=, >, <, >=, <=, plus && (all sides must match) and || (any side must match) compound conditions; compound support has no parentheses, so chaining separate calls remains the documented fallback for complex logic. m68k registers: D0-D7, A0-A7, PC, SR, CCR, USP, SSP (SP aliases A7). Z80 registers: A, F, B, C, D, E, H, L (derived from the AF/BC/DE/HL pairs), the AF/BC/DE/HL pairs, IX, IY, SP, PC, I, R, plus shadow register pairs AF2/BC2/DE2/HL2 and primed 8-bit forms (A'..L'). Register names are case-insensitive; expected values accept decimal, $ hex, 0x hex, and h-suffixed hex; comparisons are unsigned. Sampled values are the values at the moment of regs_get: the system was already paused when registers were sampled, and the pause/resume cycle perturbs timing with a race window where the system could have been resumed externally between the breakpoint pause and this evaluation.`,
			schema: objectSchema(map[string]any{
				"cpu":       enumProperty("Processor whose registers are sampled by regs_get.", []string{"m68k", "z80"}),
				"condition": stringProperty(`Register condition, e.g. "D0 == $1234", "A7 >= $FF0000", "D1 != 0", or "D0 >= $100 && D0 <= $200". Operators: ==, !=, >, <, >=, <=, &&, ||. Register names are case-insensitive; values accept decimal, $ hex, 0x hex, and h-suffixed hex.`),
				"context":   contextProperty(),
			}, []string{"cpu", "condition"}),
			run: runRegisterConditionEvaluate,
		},
	}
}

type registerConditionArgs struct {
	CPU       string `json:"cpu"`
	Condition string `json:"condition"`
	Context   string `json:"context"`
}

// registerComparison is one "<register> <operator> <value>" term.
type registerComparison struct {
	Register string
	Operator string
	Expected uint64
}

// registerCondition is either a single comparison or an AND/OR compound tree.
type registerCondition struct {
	Comparison *registerComparison  // set when this node is one comparison
	Logic      string               // "and" or "or" when compound
	Parts      []*registerCondition // compound operands
}

// registerComparisonResult is one evaluated comparison with the sampled value.
type registerComparisonResult struct {
	Register      string
	RegisterValue uint64
	Operator      string
	Expected      uint64
	Matched       bool
}

func runRegisterConditionEvaluate(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[registerConditionArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	if _, failure = resolveContext(tc.server, parsed.Context); failure != nil {
		return failureResult(failure, tc.modern)
	}
	cpu := strings.ToLower(strings.TrimSpace(parsed.CPU))
	if cpu != "m68k" && cpu != "z80" {
		return failureResult(&toolFailure{
			Code:    "invalid_params",
			Message: "cpu must be m68k or z80",
		}, tc.modern)
	}
	condition, failure := parseRegisterCondition(parsed.Condition)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	// Validate register names before the bridge round-trip so an unknown
	// register is rejected without touching the emulator.
	if failure = validateRegisterConditionNames(condition, cpu); failure != nil {
		return failureResult(failure, tc.modern)
	}
	payload, failure := tc.server.executeCommand(tc.ctx, "regs_get", map[string]string{"cpu": cpu})
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	registers := normalizeRegisterPayload(payload)
	matched, outcomes, failure := condition.evaluate(registers, cpu)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}

	result := map[string]any{
		"matched":          matched,
		"condition":        strings.TrimSpace(parsed.Condition),
		"cpu":              cpu,
		"method":           "server-side register condition evaluated from regs_get after the breakpoint pause; not a native emulator breakpoint condition",
		"evaluation":       "server_side_post_hit",
		"derived":          true,
		"heuristic":        true,
		"native":           false,
		"comparison_count": len(outcomes),
		"note":             "Server-side evaluation: the system was already paused when registers were sampled; if the breakpoint hit and the condition is false, the caller must resume with cpu_run. The pause/resume cycle perturbs timing and has a race window where the system could have been resumed externally between the breakpoint pause and this evaluation.",
	}
	views := make([]map[string]any, 0, len(outcomes))
	for _, outcome := range outcomes {
		views = append(views, map[string]any{
			"register":           outcome.Register,
			"register_value":     outcome.RegisterValue,
			"register_value_hex": canonicalHex(outcome.RegisterValue),
			"operator":           outcome.Operator,
			"expected_value":     outcome.Expected,
			"expected_value_hex": canonicalHex(outcome.Expected),
			"matched":            outcome.Matched,
		})
	}
	if len(outcomes) == 1 {
		// Flatten the single comparison into the documented top-level field set.
		outcome := outcomes[0]
		result["register"] = outcome.Register
		result["register_value"] = outcome.RegisterValue
		result["register_value_hex"] = canonicalHex(outcome.RegisterValue)
		result["operator"] = outcome.Operator
		result["expected_value"] = outcome.Expected
		result["expected_hex"] = canonicalHex(outcome.Expected)
	} else {
		result["logic"] = condition.Logic
	}
	result["comparisons"] = views
	return okResult(result, tc.modern)
}

// ----------------------------------------------------------------------------------------------------------------------
// Condition parsing
// ----------------------------------------------------------------------------------------------------------------------

// parseRegisterCondition splits && and || first (|| binds looser), then falls
// back to one comparison. Recursion keeps the tree plain: a || b && c becomes
// or(a, and(b, c)); parentheses are not supported.
func parseRegisterCondition(expression string) (*registerCondition, *toolFailure) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return nil, &toolFailure{Code: "invalid_params", Message: "condition must not be empty"}
	}
	if strings.Contains(expression, "||") {
		return parseRegisterCompound("or", strings.Split(expression, "||"))
	}
	if strings.Contains(expression, "&&") {
		return parseRegisterCompound("and", strings.Split(expression, "&&"))
	}
	comparison, failure := parseRegisterComparison(expression)
	if failure != nil {
		return nil, failure
	}
	return &registerCondition{Comparison: comparison}, nil
}

func parseRegisterCompound(logic string, parts []string) (*registerCondition, *toolFailure) {
	parsed := &registerCondition{Logic: logic, Parts: make([]*registerCondition, 0, len(parts))}
	for _, part := range parts {
		child, failure := parseRegisterCondition(part)
		if failure != nil {
			return nil, failure
		}
		parsed.Parts = append(parsed.Parts, child)
	}
	return parsed, nil
}

func parseRegisterComparison(text string) (*registerComparison, *toolFailure) {
	text = strings.TrimSpace(text)
	opIndex := -1
	operator := ""
	for _, candidate := range registerConditionOperators {
		if index := strings.Index(text, candidate); index >= 0 && (opIndex == -1 || index < opIndex) {
			opIndex = index
			operator = candidate
		}
	}
	if opIndex <= 0 || opIndex+len(operator) >= len(text) {
		return nil, &toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("invalid condition %q: expected \"<register> <operator> <value>\" with one of == != > < >= <=", text),
		}
	}
	registerText := strings.TrimSpace(text[:opIndex])
	valueText := strings.TrimSpace(text[opIndex+len(operator):])
	value, ok := parseFlexibleNumber(valueText)
	if !ok {
		return nil, &toolFailure{
			Code:    "invalid_params",
			Message: fmt.Sprintf("invalid value %q in condition %q: use decimal, $ hex, 0x hex, or h-suffixed hex", valueText, text),
		}
	}
	return &registerComparison{Register: registerText, Operator: operator, Expected: value}, nil
}

// ----------------------------------------------------------------------------------------------------------------------
// Register access
// ----------------------------------------------------------------------------------------------------------------------

func normalizeRegisterName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// validRegisterName reports whether name (lower-cased) is a supported register
// of the CPU. m68k and z80 accept disjoint sets, so a cross-CPU name such as
// "B" on m68k is rejected as unknown.
func validRegisterName(cpu, name string) bool {
	switch cpu {
	case "m68k":
		switch name {
		case "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
			"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
			"pc", "sr", "ccr", "usp", "ssp", "sp":
			return true
		}
	case "z80":
		switch name {
		case "a", "f", "b", "c", "d", "e", "h", "l",
			"a'", "f'", "b'", "c'", "d'", "e'", "h'", "l'",
			"af", "bc", "de", "hl", "af2", "bc2", "de2", "hl2",
			"ix", "iy", "sp", "pc", "i", "r":
			return true
		}
	}
	return false
}

// registerWidthBits is the natural register width used to mask the sampled
// value before comparison: 32-bit for M68K registers, 16-bit for Z80 pairs
// and 8-bit for the derived Z80 single registers. Comparisons are unsigned.
func registerWidthBits(cpu, name string) uint {
	if cpu == "m68k" {
		return 32
	}
	switch name {
	case "a", "f", "b", "c", "d", "e", "h", "l", "a'", "f'", "b'", "c'", "d'", "e'", "h'", "l'":
		return 8
	default:
		return 16
	}
}

// readRegisterValue resolves one register to its sampled number. The plugin
// exposes Z80 register pairs only (af/bc/de/hl and the shadow af2/bc2/de2/
// hl2), so the 8-bit names are derived: A from AF >> 8, F from AF & 0xFF, and
// so on. SP aliases A7 on the M68K.
func readRegisterValue(registers map[string]uint64, cpu, name string) (uint64, bool) {
	if cpu == "m68k" {
		if name == "sp" {
			name = "a7"
		}
		value, ok := registers[name]
		return value, ok
	}
	// z80Pair picks the plain pair unless the requested name is primed (A'..L'
	// resolve to the shadow AF2/BC2/DE2/HL2, mirroring the Z80 alternate set).
	z80Pair := func(plain, shadow string) (uint64, bool) {
		pair := plain
		if strings.HasSuffix(name, "'") {
			pair = shadow
		}
		value, ok := registers[pair]
		return value, ok
	}
	switch name {
	case "a", "a'":
		value, ok := z80Pair("af", "af2")
		return value >> 8, ok
	case "f", "f'":
		value, ok := z80Pair("af", "af2")
		return value & 0xFF, ok
	case "b", "b'":
		value, ok := z80Pair("bc", "bc2")
		return value >> 8, ok
	case "c", "c'":
		value, ok := z80Pair("bc", "bc2")
		return value & 0xFF, ok
	case "d", "d'":
		value, ok := z80Pair("de", "de2")
		return value >> 8, ok
	case "e", "e'":
		value, ok := z80Pair("de", "de2")
		return value & 0xFF, ok
	case "h", "h'":
		value, ok := z80Pair("hl", "hl2")
		return value >> 8, ok
	case "l", "l'":
		value, ok := z80Pair("hl", "hl2")
		return value & 0xFF, ok
	default:
		value, ok := registers[name]
		return value, ok
	}
}

// normalizeRegisterPayload extracts a lower-cased key -> numeric value map
// from the regs_get payload, tolerating both the nested "registers" object the
// plugin emits and a flattened payload from older plugin builds. Non-numeric
// fields (flags, notes) are skipped.
func normalizeRegisterPayload(payload map[string]any) map[string]uint64 {
	registers, ok := payload["registers"].(map[string]any)
	if !ok {
		registers = payload
	}
	out := map[string]uint64{}
	for key, raw := range registers {
		value, ok := registerRawNumber(raw)
		if ok {
			out[strings.ToLower(key)] = value
		}
	}
	return out
}

// registerRawNumber converts one JSON register value to uint64 (numbers arrive
// as float64 through the generic decoder; other encodings are tolerated).
func registerRawNumber(raw any) (uint64, bool) {
	switch value := raw.(type) {
	case float64:
		if value >= 0 && value == float64(uint64(value)) {
			return uint64(value), true
		}
	case json.Number:
		if parsed, err := value.Int64(); err == nil && parsed >= 0 {
			return uint64(parsed), true
		}
	case int:
		if value >= 0 {
			return uint64(value), true
		}
	case int64:
		if value >= 0 {
			return uint64(value), true
		}
	case uint64:
		return value, true
	case string:
		if parsed, ok := parseFlexibleNumber(value); ok {
			return parsed, true
		}
	}
	return 0, false
}

// ----------------------------------------------------------------------------------------------------------------------
// Evaluation
// ----------------------------------------------------------------------------------------------------------------------

// validateRegisterConditionNames walks the parsed tree and rejects registers
// that are not supported on the target CPU before any bridge round-trip.
func validateRegisterConditionNames(condition *registerCondition, cpu string) *toolFailure {
	if condition.Comparison != nil {
		registerName := normalizeRegisterName(condition.Comparison.Register)
		if !validRegisterName(cpu, registerName) {
			return &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("unknown register %s for cpu %s", strings.TrimSpace(condition.Comparison.Register), cpu),
			}
		}
		return nil
	}
	for _, part := range condition.Parts {
		if failure := validateRegisterConditionNames(part, cpu); failure != nil {
			return failure
		}
	}
	return nil
}

func (condition *registerCondition) evaluate(registers map[string]uint64, cpu string) (bool, []registerComparisonResult, *toolFailure) {
	if condition.Comparison != nil {
		comparison := condition.Comparison
		registerName := normalizeRegisterName(comparison.Register)
		if !validRegisterName(cpu, registerName) {
			return false, nil, &toolFailure{
				Code:    "invalid_params",
				Message: fmt.Sprintf("unknown register %s for cpu %s", strings.TrimSpace(comparison.Register), cpu),
			}
		}
		value, present := readRegisterValue(registers, cpu, registerName)
		if !present {
			return false, nil, &toolFailure{
				Code:    "bridge_error",
				Message: fmt.Sprintf("the %s register payload (regs_get cpu=%s) provides no value for %s", cpu, cpu, strings.ToUpper(registerName)),
			}
		}
		width := registerWidthBits(cpu, registerName)
		masked := value & (uint64(1)<<width - 1)
		matched := compareUnsigned(masked, comparison.Operator, comparison.Expected)
		outcome := registerComparisonResult{
			Register:      strings.ToUpper(registerName),
			RegisterValue: masked,
			Operator:      comparison.Operator,
			Expected:      comparison.Expected,
			Matched:       matched,
		}
		return matched, []registerComparisonResult{outcome}, nil
	}

	combined := condition.Logic == "and"
	outcomes := []registerComparisonResult{}
	for _, part := range condition.Parts {
		partMatched, partOutcomes, failure := part.evaluate(registers, cpu)
		if failure != nil {
			return false, nil, failure
		}
		outcomes = append(outcomes, partOutcomes...)
		if condition.Logic == "and" {
			combined = combined && partMatched
		} else {
			combined = combined || partMatched
		}
	}
	return combined, outcomes, nil
}

// compareUnsigned compares two unsigned 64-bit values; register values are
// masked to their natural width before comparison and expected values are
// compared as parsed.
func compareUnsigned(left uint64, operator string, right uint64) bool {
	switch operator {
	case "==":
		return left == right
	case "!=":
		return left != right
	case ">":
		return left > right
	case "<":
		return left < right
	case ">=":
		return left >= right
	case "<=":
		return left <= right
	}
	return false
}
