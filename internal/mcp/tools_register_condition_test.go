package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// z80RegsPayload builds the plugin-shaped regs_get response for the Z80,
// writing only the register keys present in the map.
func z80RegsPayload(registers map[string]uint64) string {
	fields := make([]string, 0, len(registers))
	names := []string{"af", "bc", "de", "hl", "af2", "bc2", "de2", "hl2", "ix", "iy", "sp", "pc", "i", "r"}
	for _, name := range names {
		value, ok := registers[name]
		if !ok {
			continue
		}
		fields = append(fields, fmt.Sprintf("%q:%d", name, value))
	}
	return fmt.Sprintf(`{"cpu":"z80","byte_order":"not-applicable","register_note":"Values are plain host integers; byte order is not applicable.","system_paused_during_read":false,"registers":{%s},"flags":{},"width_bits":16}`, strings.Join(fields, ","))
}

// registerConditionFake returns an executeFunc serving regs_get for the given
// cpu with the given register set, verifying the cpu parameter on the wire.
func registerConditionFake(cpu string, registers map[string]uint64) func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
	return func(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
		if method != "regs_get" || params["cpu"] != cpu {
			return nil, fmt.Errorf("unexpected call %s %v", method, params)
		}
		if cpu == "z80" {
			return json.RawMessage(z80RegsPayload(registers)), nil
		}
		return json.RawMessage(m68kRegsPayload(registers)), nil
	}
}

// numericField extracts a uint64 from a structured result field, tolerating
// the float64 representation of JSON numbers.
func numericField(t *testing.T, content map[string]any, key string) uint64 {
	t.Helper()
	switch value := content[key].(type) {
	case uint64:
		return value
	case float64:
		return uint64(value)
	case json.Number:
		parsed, _ := value.Int64()
		return uint64(parsed)
	}
	t.Fatalf("field %q has type %T (value %v)", key, content[key], content[key])
	return 0
}

func TestRegisterConditionM68kSimpleComparison(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = registerConditionFake("m68k", map[string]uint64{"d0": 0x1234, "a7": 0x00FFF000})

	result := callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"D0 == $1234"}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", structured(result))
	}
	content := structured(result)
	if content["matched"] != true {
		t.Fatalf("matched = %v, want true", content["matched"])
	}
	if content["condition"] != "D0 == $1234" || content["cpu"] != "m68k" {
		t.Fatalf("echo fields wrong: %v", content)
	}
	if content["register"] != "D0" || content["operator"] != "==" {
		t.Fatalf("comparison identity wrong: %v", content)
	}
	if numericField(t, content, "register_value") != 0x1234 || content["register_value_hex"] != "0x001234" {
		t.Fatalf("register value wrong: %v", content)
	}
	if numericField(t, content, "expected_value") != 0x1234 || content["expected_hex"] != "0x001234" {
		t.Fatalf("expected value wrong: %v", content)
	}
	if content["derived"] != true || content["heuristic"] != true || content["native"] != false {
		t.Fatalf("derived/heuristic/native flags wrong: %v", content)
	}
	if !strings.Contains(content["method"].(string), "not a native emulator breakpoint condition") {
		t.Fatalf("method must flag the heuristic derivation: %q", content["method"])
	}
	note, _ := content["note"].(string)
	if !strings.Contains(note, "resume with cpu_run") || !strings.Contains(note, "race window") {
		t.Fatalf("note must document the resume step and race: %q", note)
	}
}

func TestRegisterConditionA7Range(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = registerConditionFake("m68k", map[string]uint64{"a7": 0x00FFF000})
	result := callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"A7 >= $FF0000"}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", content)
	}
	if content["matched"] != true || content["register_value_hex"] != "0xFFF000" || content["expected_hex"] != "0xFF0000" {
		t.Fatalf("A7 >= $FF0000 with A7=0xFFF000 must match: %v", content)
	}

	below := &fakeBridgeClient{status: newFakeStatus()}
	below.executeFunc = registerConditionFake("m68k", map[string]uint64{"a7": 0x0000F000})
	result = callTool(t, below, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"a7 >= $FF0000"}`)
	content = structured(result)
	if content["matched"] != false || content["register"] != "A7" {
		t.Fatalf("A7 >= $FF0000 with A7=0x00F000 must not match: %v", content)
	}
}

func TestRegisterConditionValueFormats(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = registerConditionFake("m68k", map[string]uint64{"d0": 0xFF, "d1": 0x10})
	for name, condition := range map[string]string{
		"dollar hex":  "D0 == $FF",
		"0x hex":      "D0 == 0xFF",
		"decimal":     "D0 == 255",
		"h suffix":    "D0 == FFh",
		"not equal":   "D1 != 0",
		"strict less": "D1 > 0",
	} {
		result := callTool(t, client, "cpu_register_condition_evaluate", fmt.Sprintf(`{"cpu":"m68k","condition":%q}`, condition))
		if result["isError"] == true {
			t.Fatalf("%s: unexpected error: %v", name, structured(result))
		}
		content := structured(result)
		if content["matched"] != true {
			t.Fatalf("%s (%s) must match: %v", name, condition, content)
		}
	}

	// D1 == 0 -> not-equal is false.
	zero := &fakeBridgeClient{status: newFakeStatus()}
	zero.executeFunc = registerConditionFake("m68k", map[string]uint64{"d1": 0})
	result := callTool(t, zero, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"D1 != 0"}`)
	content := structured(result)
	if content["matched"] != false || content["register_value_hex"] != "0x000000" {
		t.Fatalf("D1 != 0 with D1=0 must not match: %v", content)
	}
}

func TestRegisterConditionZ80DerivedAndPair(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = registerConditionFake("z80", map[string]uint64{"af": 0x7FFF, "bc": 0x0005, "bc2": 0x0500, "hl": 0x07FF, "sp": 0xFFF0, "pc": 0x100})

	// A is the high byte of AF.
	result := callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"z80","condition":"A == $7F"}`)
	content := structured(result)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", content)
	}
	if content["matched"] != true || content["register"] != "A" || content["register_value_hex"] != "0x00007F" {
		t.Fatalf("A derived from AF: %v", content)
	}

	// F is the low byte; B is the high byte of BC.
	result = callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"z80","condition":"F == $FF && B == 0"}`)
	content = structured(result)
	if content["matched"] != true || content["logic"] != "and" || content["comparison_count"] != float64(2) {
		t.Fatalf("F/B decomposition: %v", content)
	}
	comparisons, _ := content["comparisons"].([]any)
	if len(comparisons) != 2 {
		t.Fatalf("comparisons = %v", content["comparisons"])
	}

	// Primes select the shadow pair BC2.
	result = callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"z80","condition":"B' == 5"}`)
	content = structured(result)
	if content["matched"] != true || content["register"] != "B'" || content["register_value_hex"] != "0x000005" {
		t.Fatalf("B' from BC2: %v", content)
	}

	// 16-bit pair direct.
	result = callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"z80","condition":"HL == $7FF"}`)
	content = structured(result)
	if content["matched"] != true || content["expected_hex"] != "0x0007FF" {
		t.Fatalf("HL pair: %v", content)
	}

	// SP comparison.
	result = callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"z80","condition":"SP >= $FF00"}`)
	content = structured(result)
	if content["matched"] != true || content["register_value_hex"] != "0x00FFF0" {
		t.Fatalf("SP: %v", content)
	}
}

func TestRegisterConditionCompoundLogic(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = registerConditionFake("m68k", map[string]uint64{"d0": 0x150})

	result := callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"D0 >= $100 && D0 <= $200"}`)
	content := structured(result)
	if content["matched"] != true || content["logic"] != "and" || content["comparison_count"] != float64(2) {
		t.Fatalf("and compound: %v", content)
	}
	if comparisons, _ := content["comparisons"].([]any); len(comparisons) != 2 {
		t.Fatalf("and compound comparisons: %v", content["comparisons"])
	}

	result = callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"D0 == 1 || D0 == 0x150"}`)
	content = structured(result)
	if content["matched"] != true || content["logic"] != "or" {
		t.Fatalf("or compound: %v", content)
	}

	// Mixed precedence: or binds looser than and.
	result = callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"D0 == 1 || D0 >= 0x100 && D0 <= 0x200"}`)
	content = structured(result)
	if content["matched"] != true || content["comparison_count"] != float64(3) {
		t.Fatalf("mixed precedence: %v", content)
	}

	result = callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"D0 == 1 || D0 == 2"}`)
	content = structured(result)
	if content["matched"] != false {
		t.Fatalf("or compound false case: %v", content)
	}
}

func TestRegisterConditionUnknownRegister(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = registerConditionFake("m68k", map[string]uint64{"d0": 1})
	result := callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"B == 1"}`)
	content := structured(result)
	if content["code"] != "invalid_params" {
		t.Fatalf("code = %v, want invalid_params", content)
	}
	message, _ := content["message"].(string)
	if !strings.Contains(message, "unknown register B for cpu m68k") {
		t.Fatalf("message = %q", message)
	}
	if len(client.recordedCalls) != 0 {
		t.Fatalf("unknown register must be rejected before regs_get: %v", client.recordedCalls)
	}

	zclient := &fakeBridgeClient{status: newFakeStatus()}
	result = callTool(t, zclient, "cpu_register_condition_evaluate", `{"cpu":"z80","condition":"X == 1"}`)
	content = structured(result)
	if content["code"] != "invalid_params" || !strings.Contains(content["message"].(string), "unknown register X for cpu z80") {
		t.Fatalf("z80 unknown register: %v", content)
	}
}

func TestRegisterConditionPayloadMissingRegister(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = registerConditionFake("m68k", map[string]uint64{"pc": 0x200})
	result := callTool(t, client, "cpu_register_condition_evaluate", `{"cpu":"m68k","condition":"D0 == 1"}`)
	content := structured(result)
	if content["code"] != "bridge_error" {
		t.Fatalf("code = %v, want bridge_error", content)
	}
	if !strings.Contains(content["message"].(string), "D0") {
		t.Fatalf("message must name the missing register: %v", content)
	}
}

func TestRegisterConditionInvalidSyntax(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = registerConditionFake("m68k", map[string]uint64{"d0": 1})
	for name, arguments := range map[string]string{
		"missing cpu":      `{"condition":"D0 == 1"}`,
		"bad cpu":          `{"cpu":"sparc","condition":"D0 == 1"}`,
		"empty condition":  `{"cpu":"m68k","condition":""}`,
		"missing value":    `{"cpu":"m68k","condition":"D0 =="}`,
		"non numeric":      `{"cpu":"m68k","condition":"D0 == foo"}`,
		"no operator":      `{"cpu":"m68k","condition":"D0 1"}`,
		"unknown operator": `{"cpu":"m68k","condition":"D0 =< 5"}`,
	} {
		result := callTool(t, client, "cpu_register_condition_evaluate", arguments)
		content := structured(result)
		if content["code"] != "invalid_params" {
			t.Fatalf("%s: expected invalid_params, got %v", name, content)
		}
	}
}

func TestRegisterConditionRegisteredInRegistry(t *testing.T) {
	spec := lookupTool("cpu_register_condition_evaluate")
	if spec == nil {
		t.Fatal("cpu_register_condition_evaluate is not registered")
	}
	if !strings.Contains(spec.description, "not a native emulator breakpoint condition") {
		t.Fatalf("description must flag derivation: %q", spec.description)
	}
	required, _ := spec.schema["required"].([]string)
	if len(required) != 2 || required[0] != "cpu" || required[1] != "condition" {
		t.Fatalf("required = %v, want [cpu condition]", required)
	}
	properties := spec.schema["properties"].(map[string]any)
	cpuProp := properties["cpu"].(map[string]any)
	if enums, _ := cpuProp["enum"].([]string); len(enums) != 2 || enums[0] != "m68k" || enums[1] != "z80" {
		t.Fatalf("cpu enum = %v", cpuProp["enum"])
	}
}
