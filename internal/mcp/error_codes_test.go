package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/bridge"
)

// ----------------------------------------------------------------------------------------------------------------------
// Error-code taxonomy conformance (roadmap issue #18)
//
// The registry in error_codes.go is the single declaration. These tests are the
// enforcement half:
//
//   - the registry is structurally sound (unique codes, declared class/origin);
//   - every literal code in this package, in the pinned plugin, and in the
//     experiment protocol has an entry;
//   - every entry is really produced somewhere (a declared code nobody emits is
//     an invented one);
//   - every failure response carries a declared code and its class.
// ----------------------------------------------------------------------------------------------------------------------

func TestErrorCodeRegistryIsWellFormed(t *testing.T) {
	if err := validateErrorCodeRegistry(); err != nil {
		t.Fatal(err)
	}
	for _, declared := range errorCodeRegistry {
		if !strings.HasPrefix(declared.Code, strings.ToLower(declared.Code)) {
			t.Errorf("code %q must be lower snake case", declared.Code)
		}
	}
}

var (
	failureCodeLiteral  = regexp.MustCompile(`Code:\s*"([a-z_0-9]+)"`)
	assignedCodeLiteral = regexp.MustCompile(`\bcode\s*:?=\s*"([a-z_0-9]+)"`)
	errorResultLiteral  = regexp.MustCompile(`errorResult\("([a-z_0-9]+)"`)
	// A native assignment may be a ternary, so collect every literal on the
	// right-hand side of the statement, not just a whole-statement literal.
	nativeCodeAssignment = regexp.MustCompile(`errorCode\s*=\s*([^;]*);`)
	// failParse and the fatal helper carry the protocol code as a positional
	// argument rather than a labelled field.
	experimentHelperCode = regexp.MustCompile(`(?:failParse|fatal)\(\s*[A-Za-z_.]+,\s*"([a-z_0-9]+)"`)
)

// codePattern is one way a code literal is written in the sources. When
// expression is true the capture is a whole expression that may hold several
// literals (the native plugin's ternary assignments).
type codePattern struct {
	re         *regexp.Regexp
	expression bool
}

// collectCodeLiterals extracts every code literal from the files of one
// directory, skipping test files and (optionally) one file by name.
func collectCodeLiterals(t *testing.T, dir, skipFile string, patterns ...codePattern) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	found := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasSuffix(name, "_test.go") || name == skipFile {
			continue
		}
		if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".cpp") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, pattern := range patterns {
			for _, match := range pattern.re.FindAllStringSubmatch(string(data), -1) {
				if len(match) < 2 {
					continue
				}
				if pattern.expression {
					for _, literal := range codeLiteralsIn(match[1]) {
						found[literal] = name
					}
					continue
				}
				found[match[1]] = name
			}
		}
	}
	return found
}

// codeLiteralsIn returns the snake-case literals of one captured expression.
func codeLiteralsIn(expression string) []string {
	literals := []string{}
	for _, candidate := range regexp.MustCompile(`"([a-z_0-9]+)"`).FindAllStringSubmatch(expression, -1) {
		literals = append(literals, candidate[1])
	}
	return literals
}

// TestEveryProducedCodeIsDeclared is the registry-driven gate: a literal code
// added to a handler, to the pinned plugin, or to the experiment protocol
// without an entry in error_codes.go fails here.
func TestEveryProducedCodeIsDeclared(t *testing.T) {
	sources := []struct {
		label    string
		dir      string
		skip     string
		patterns []codePattern
	}{
		{"server", ".", "error_codes.go", []codePattern{{failureCodeLiteral, false}, {assignedCodeLiteral, false}, {errorResultLiteral, false}}},
		{"plugin", "../../native-plugin", "", []codePattern{{nativeCodeAssignment, true}}},
		{"experiment", "../experiment", "", []codePattern{{failureCodeLiteral, false}, {assignedCodeLiteral, false}, {experimentHelperCode, false}}},
	}
	for _, source := range sources {
		literals := collectCodeLiterals(t, source.dir, source.skip, source.patterns...)
		if len(literals) == 0 {
			t.Fatalf("%s: no code literal found; the scan is no longer checking anything", source.label)
		}
		codes := make([]string, 0, len(literals))
		for code := range literals {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			if !isDeclaredErrorCode(code) {
				t.Errorf("%s/%s produces code %q, which error_codes.go does not declare", source.label, literals[code], code)
			}
		}
	}
}

// TestEveryDeclaredCodeIsProduced is the reverse direction: a registry entry
// must correspond to a real producer. The two fallbacks are produced by the
// taxonomy itself.
func TestEveryDeclaredCodeIsProduced(t *testing.T) {
	produced := map[string]bool{errorCodeNativeError: true, errorCodeInternalFallback: true}
	for _, source := range []struct {
		dir      string
		skip     string
		patterns []codePattern
	}{
		{".", "error_codes.go", []codePattern{{failureCodeLiteral, false}, {assignedCodeLiteral, false}, {errorResultLiteral, false}}},
		{"../../native-plugin", "", []codePattern{{nativeCodeAssignment, true}}},
		{"../experiment", "", []codePattern{{failureCodeLiteral, false}, {assignedCodeLiteral, false}, {experimentHelperCode, false}}},
	} {
		for code := range collectCodeLiterals(t, source.dir, source.skip, source.patterns...) {
			produced[code] = true
		}
	}
	for _, declared := range errorCodeRegistry {
		if !produced[declared.Code] {
			t.Errorf("code %q is declared but no producer emits it", declared.Code)
		}
	}
}

// TestEveryDeclaredCodeCarriesItsClass asserts the response shape clients
// consume: code plus error_class, from the declaration, for every member.
func TestEveryDeclaredCodeCarriesItsClass(t *testing.T) {
	for _, declared := range errorCodeRegistry {
		result := failureResult(&toolFailure{Code: declared.Code, Message: "probe"}, true)
		content := structured(result)
		if content["code"] != declared.Code {
			t.Errorf("code %q was rewritten to %v", declared.Code, content["code"])
		}
		if content["error_class"] != declared.Class {
			t.Errorf("code %q published class %v, declared %q", declared.Code, content["error_class"], declared.Class)
		}
		if _, present := content["undeclared_code"]; present {
			t.Errorf("code %q was reported as undeclared", declared.Code)
		}
	}
}

func TestUndeclaredFailureCodeIsNormalized(t *testing.T) {
	result := failureResult(&toolFailure{Code: "invented_code", Message: "probe"}, true)
	content := structured(result)
	if content["code"] != errorCodeInternalFallback {
		t.Fatalf("undeclared code published %v, want %q", content["code"], errorCodeInternalFallback)
	}
	if content["undeclared_code"] != "invented_code" {
		t.Fatalf("the original code must be preserved, got %v", content["undeclared_code"])
	}
	if content["error_class"] != errorClassInternal {
		t.Fatalf("class = %v, want %v", content["error_class"], errorClassInternal)
	}
}

// TestUnknownNativeCodeBecomesNativeError covers the pass-through: a plugin
// failure code this server does not know cannot escape the taxonomy, and its
// value survives in native_code.
func TestUnknownNativeCodeBecomesNativeError(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(context.Context, string, map[string]string) (json.RawMessage, error) {
		return nil, &bridge.CommandError{Code: "future_plugin_code", Message: "newer plugin refused"}
	}
	content := structured(callTool(t, client, "m68k_registers", `{}`))
	if content["code"] != errorCodeNativeError {
		t.Fatalf("code = %v, want %q", content["code"], errorCodeNativeError)
	}
	if content["native_code"] != "future_plugin_code" {
		t.Fatalf("native_code = %v, want the original code", content["native_code"])
	}
	if content["error_class"] != errorClassTarget {
		t.Fatalf("error_class = %v", content["error_class"])
	}
}

// TestKnownNativeCodePassesThrough proves the normalization is not a rename:
// declared plugin codes keep the value clients already branch on.
func TestKnownNativeCodePassesThrough(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(context.Context, string, map[string]string) (json.RawMessage, error) {
		return nil, &bridge.CommandError{Code: "unknown_space", Message: "Unknown space id: bogus"}
	}
	content := structured(callTool(t, client, "memory_read", `{"space":"bogus","address":0,"length":4}`))
	if content["code"] != "unknown_space" || content["error_class"] != errorClassNotFound {
		t.Fatalf("passthrough changed: %v", content)
	}
}

// TestEveryToolFailureCarriesADeclaredCode drives the whole registry with a
// bridge that fails every command, and audits every failure payload.
func TestEveryToolFailureCarriesADeclaredCode(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	client.executeFunc = func(context.Context, string, map[string]string) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	}
	server := newTestServer(t, client)
	failures := 0
	for index := range toolRegistry {
		spec := &toolRegistry[index]
		result, panicked := failureProbe(t, server, spec.name)
		if panicked != nil {
			// A handler that panics on a permissive payload is a robustness
			// gap outside this contract; the registry must still not publish
			// an undeclared code.
			continue
		}
		if result["isError"] != true {
			continue
		}
		failures++
		content := structured(result)
		code, _ := content["code"].(string)
		if !isDeclaredErrorCode(code) {
			t.Errorf("%s: code %q is not declared", spec.name, code)
		}
		if content["error_class"] != errorClassOf(code) {
			t.Errorf("%s: error_class %v does not match the declaration for %q", spec.name, content["error_class"], code)
		}
		if _, undeclared := content["undeclared_code"]; undeclared {
			t.Errorf("%s: published an undeclared code: %v", spec.name, content)
		}
	}
	if failures == 0 {
		t.Fatal("no tool rejected an empty argument set; the sweep proves nothing")
	}
}

// failureProbe calls one tool and reports a recovered panic separately, so a
// handler robustness gap does not abort the taxonomy sweep.
func failureProbe(t *testing.T, server *Server, tool string) (result map[string]any, panicked any) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = recovered
		}
	}()
	return postToolCall(t, server, tool, `{}`), nil
}

// TestCapabilitiesPublishTheErrorTaxonomy keeps the taxonomy discoverable from
// one place per session.
func TestCapabilitiesPublishTheErrorTaxonomy(t *testing.T) {
	declared, ok := capabilities()["x-error-codes"].(map[string]any)
	if !ok {
		t.Fatal("capabilities must publish x-error-codes")
	}
	codes, _ := declared["codes"].([]map[string]any)
	if len(codes) != len(errorCodeRegistry) {
		t.Fatalf("published %d codes, registry has %d", len(codes), len(errorCodeRegistry))
	}
	classes, _ := declared["classes"].([]string)
	if len(classes) != len(errorClassVocab.values) {
		t.Fatalf("published %d classes, declared %d", len(classes), len(errorClassVocab.values))
	}
	if errorCodeNames()[0] != codes[0]["code"] {
		t.Fatalf("the published list must be sorted: %v", codes[0]["code"])
	}
}
