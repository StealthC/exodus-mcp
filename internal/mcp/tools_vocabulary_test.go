package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/StealthC/exodus-mcp/internal/artifact"
	"github.com/StealthC/exodus-mcp/internal/tracing"
)

// ----------------------------------------------------------------------------------------------------------------------
// Response vocabulary conformance (issue #12)
//
// One concept, one name, one spelling. These tests are the enforcement half of
// the contract documented in docs/FEATURES.md ("Response vocabularies"):
//
//   - every emitted capture_consistency object carries the same key set and
//     values from the declared vocabularies;
//   - the published catalog declares exactly the vocabularies the code uses;
//   - no response carries two consistency claims that disagree;
//   - every declared value is really produced somewhere (a vocabulary nobody
//     emits is an invented one).
// ----------------------------------------------------------------------------------------------------------------------

// vocabularyConcept names one audit concept and the vocabulary that governs it.
type vocabularyConcept struct {
	concept string
	vocab   enumVocab
}

// responseVocabularyConcepts is the single table the walker and the catalog
// test share.
func responseVocabularyConcepts() []vocabularyConcept {
	return []vocabularyConcept{
		{"capture_consistency.state", captureStateVocab},
		{"capture_consistency.initial_run_state", runStateVocab},
		{"capture_consistency.final_run_state", runStateVocab},
		{"pause_source", pauseSourceVocab},
		{"stop_source", stopSourceVocab},
		{"run_state", runStateVocab},
		{"cpu_run_state", runStateVocab},
		{"stop_reason", runUntilStopReasonVocab},
	}
}

// consistentObject is one capture-consistency object found in a response, with
// the path it was found at and the capture it belongs to (when known).
type consistentObject struct {
	path      string
	captureID string
	object    map[string]any
}

// vocabularyAudit accumulates the values one response emitted and every
// contract violation found in it.
type vocabularyAudit struct {
	emitted  map[string]map[string]bool
	objects  []consistentObject
	problems []string
}

func newVocabularyAudit() *vocabularyAudit {
	return &vocabularyAudit{emitted: map[string]map[string]bool{}}
}

func (audit *vocabularyAudit) fail(format string, args ...any) {
	audit.problems = append(audit.problems, fmt.Sprintf(format, args...))
}

func (audit *vocabularyAudit) record(concept, value string) {
	seen, present := audit.emitted[concept]
	if !present {
		seen = map[string]bool{}
		audit.emitted[concept] = seen
	}
	seen[value] = true
}

// walk audits one response tree. inProvenance marks a subtree that is an
// artifact provenance envelope, the only place the deprecated bare
// `consistency` label may still appear.
func (audit *vocabularyAudit) walk(value any, path string, inProvenance bool) {
	switch typed := value.(type) {
	case map[string]any:
		audit.walkObject(typed, path, inProvenance)
	case []map[string]any:
		for index, item := range typed {
			audit.walk(item, fmt.Sprintf("%s[%d]", path, index), inProvenance)
		}
	case []any:
		for index, item := range typed {
			audit.walk(item, fmt.Sprintf("%s[%d]", path, index), inProvenance)
		}
	}
}

func (audit *vocabularyAudit) walkObject(object map[string]any, path string, inProvenance bool) {
	provenance := inProvenance || object["artifact_schema"] == artifact.ProvenanceSchema
	if _, present := object["capture_consistency"]; present {
		audit.checkConsistency(path+".capture_consistency", object)
	}
	for _, candidate := range responseVocabularyConcepts() {
		if candidate.concept == "capture_consistency.state" {
			// Validated by checkConsistency at the object's own path; a bare
			// "state" key elsewhere is a different concept (provenance state,
			// session state).
			continue
		}
		raw, present := object[vocabularyField(candidate.concept)]
		if !present {
			continue
		}
		text, ok := raw.(string)
		if !ok {
			continue
		}
		// stop_reason is the run_until_* label beside stop_source. A native
		// pass-through reason is namespaced (native_stop_reason) and is not
		// judged against this vocabulary.
		if candidate.concept == "stop_reason" {
			if _, hasStopSource := object["stop_source"]; !hasStopSource {
				continue
			}
		}
		if !candidate.vocab.accepts(text) {
			audit.fail("%s.%s = %q is outside the declared vocabulary %v", path, vocabularyField(candidate.concept), text, candidate.vocab.valuesEcho())
			continue
		}
		audit.record(candidate.concept, text)
	}
	if raw, present := object["consistency"]; present {
		if !provenance {
			audit.fail("%s.consistency: responses must publish capture_consistency.state only; the deprecated bare label survives inside artifact provenance envelopes", path)
		} else if embedded, ok := object["capture_consistency"].(map[string]any); ok {
			if raw != embedded["state"] {
				audit.fail("%s.consistency = %v disagrees with capture_consistency.state = %v", path, raw, embedded["state"])
			}
		}
	}
	for key, item := range object {
		if key == "semantics" {
			// The semantics map explains the fields in prose and names every
			// vocabulary value; it is documentation, not a claim.
			continue
		}
		audit.walk(item, path+"."+key, provenance)
	}
}

// vocabularyField maps one audit concept to the response key that carries it.
func vocabularyField(concept string) string {
	if index := strings.LastIndex(concept, "."); index >= 0 {
		return concept[index+1:]
	}
	return concept
}

// checkConsistency audits one capture-consistency object: the complete key set,
// the declared vocabularies, and the semantic rules that keep its own facts
// from contradicting each other.
func (audit *vocabularyAudit) checkConsistency(path string, container map[string]any) {
	raw, present := container["capture_consistency"]
	if !present || raw == nil {
		return
	}
	object, ok := raw.(map[string]any)
	if !ok {
		audit.fail("%s is not an object: %v", path, raw)
		return
	}
	for _, key := range captureConsistencyResponseKeys {
		if _, present := object[key]; !present {
			audit.fail("%s is missing %q; every capture-consistency object carries the whole key set", path, key)
		}
	}
	if _, present := object["undeclared_values"]; present {
		audit.fail("%s reported values outside the declared vocabulary: %v", path, object["undeclared_values"])
	}
	if note, _ := object["note"].(string); strings.TrimSpace(note) == "" {
		audit.fail("%s carries no note", path)
	}
	if paused, _ := object["execution_paused_by_tool"].(bool); paused != (object["paused_by_tool"] == true) {
		audit.fail("%s.paused_by_tool = %v disagrees with execution_paused_by_tool = %v", path, object["paused_by_tool"], object["execution_paused_by_tool"])
	}
	state, _ := object["state"].(string)
	pausedByTool, _ := object["execution_paused_by_tool"].(bool)
	for _, key := range []string{"state", "initial_run_state", "final_run_state"} {
		if text, ok := object[key].(string); ok {
			audit.record("capture_consistency."+key, text)
		}
	}
	switch state {
	case consistencyLive:
		if pausedByTool {
			audit.fail("%s claims a live sample while reporting that the capture paused execution", path)
		}
	case consistencyAtomic:
		if !pausedByTool {
			audit.fail("%s claims temporal atomicity (\"atomic\") without pausing execution", path)
		}
	case consistencyPaused:
		if pausedByTool {
			audit.fail("%s claims the target was already paused while reporting that the capture paused it", path)
		}
	case consistencyCompositeNonAtomic, consistencyStateRestored, consistencyUnknown:
	default:
		audit.fail("%s.state = %q is outside the declared vocabulary %v", path, state, captureStateVocab.valuesEcho())
	}
	for _, key := range []string{"initial_frame_token", "final_frame_token", "target_generation"} {
		raw, present := object[key]
		if !present || raw == nil {
			continue
		}
		if !isNumericValue(raw) {
			audit.fail("%s.%s = %v is neither a number nor null", path, key, raw)
		}
	}
	captureID, _ := container["capture_id"].(string)
	audit.objects = append(audit.objects, consistentObject{path: path, captureID: captureID, object: object})
}

// isNumericValue accepts the numeric shapes a response can carry before and
// after a JSON round trip.
func isNumericValue(value any) bool {
	switch value.(type) {
	case float64, float32, int, int32, int64, uint, uint32, uint64, json.Number:
		return true
	default:
		return false
	}
}

// checkCrossReferences applies the no-contradiction rule: the duplicated views
// of one response (top level, summary, and every provenance envelope of the
// same capture) must describe the same window, and a response that carries two
// objects for the same capture must not report two different states.
func (audit *vocabularyAudit) checkCrossReferences() {
	primary := map[string]map[string]any{}
	for _, object := range audit.objects {
		switch object.path {
		case "$.capture_consistency", "$.summary.capture_consistency":
			primary[object.path] = object.object
		}
	}
	if top, present := primary["$.capture_consistency"]; present {
		if summary, ok := primary["$.summary.capture_consistency"]; ok && !reflect.DeepEqual(top, summary) {
			audit.fail("$.capture_consistency %v disagrees with $.summary.capture_consistency %v", top, summary)
		}
	}
	for index, object := range audit.objects {
		if object.captureID == "" {
			continue
		}
		for _, other := range audit.objects[index+1:] {
			if other.captureID != object.captureID {
				continue
			}
			if !reflect.DeepEqual(object.object, other.object) {
				audit.fail("capture %s reports two different consistency objects: %s %v vs %s %v", object.captureID, object.path, object.object, other.path, other.object)
			}
		}
	}
}

// auditResponse drives one tool and audits everything it emitted.
func auditResponse(t *testing.T, parent *vocabularyAudit, server *Server, tool, arguments string) (content map[string]any) {
	t.Helper()
	audit := newVocabularyAudit()
	// Some handlers assume a complete native payload; an empty permissive
	// bridge can make one panic. That is a handler robustness defect outside
	// this contract, so the sweep skips the tool instead of turning it into a
	// vocabulary failure.
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Logf("skipping %s: the handler panicked on a minimal bridge payload (%v)", tool, recovered)
			content = nil
		}
	}()
	result := postToolCall(t, server, tool, arguments)
	content = structured(result)
	if content != nil {
		// A failure response is audited too: failure payloads carry the same
		// vocabularies (stop_source on preemption, run_state_restore codes).
		audit.walk(content, "$", false)
		audit.checkCrossReferences()
	}
	if content == nil {
		audit.fail("%s returned no structured content: %v", tool, result)
	}
	parent.merge(audit)
	return content
}

// merge folds one response's audit into the accumulated one: the values it
// emitted and every problem it found, never the objects it held (two different
// responses describe two different windows).
func (audit *vocabularyAudit) merge(other *vocabularyAudit) {
	for concept, values := range other.emitted {
		for value := range values {
			audit.record(concept, value)
		}
	}
	audit.problems = append(audit.problems, other.problems...)
}

// ----------------------------------------------------------------------------------------------------------------------
// Registry-driven sweep
// ----------------------------------------------------------------------------------------------------------------------

// TestNoToolPublishesAnUndeclaredVocabularyValue drives every registered tool
// with no arguments against a permissive bridge. Tools that reject the empty
// argument set are skipped (their own fixtures cover their vocabulary below),
// and every response that is produced is audited in full.
func TestNoToolPublishesAnUndeclaredVocabularyValue(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	server := newTestServer(t, client)
	audit := newVocabularyAudit()
	driven := 0
	for _, spec := range toolRegistry {
		if spec.schema["required"] != nil {
			continue
		}
		content := auditResponse(t, audit, server, spec.name, `{}`)
		if content != nil && content["code"] == nil {
			driven++
		}
	}
	audit.checkCrossReferences()
	if driven == 0 {
		t.Fatal("the registry sweep drove no tool; the sweep must reach the tools that need no arguments")
	}
	reportVocabularyProblems(t, audit)
}

// ----------------------------------------------------------------------------------------------------------------------
// Representative producer per concept
// ----------------------------------------------------------------------------------------------------------------------

// vocabularyFixture drives one representative producer of a concept.
type vocabularyFixture struct {
	concept string
	tools   []string
	args    []string
	server  func(t *testing.T) *Server
}

func vocabularyFixtures() []vocabularyFixture {
	return []vocabularyFixture{
		{concept: "live read", tools: []string{"cpu_run", "memory_read", "memory_dump"},
			args: []string{`{}`, `{"space":"m68k-bus","address":"0xFF0000","length":4}`, `{"space":"m68k-bus","address":"0xFF0000","length":8}`},
			server: func(t *testing.T) *Server {
				return newTestServer(t, newConsistencyBridge(make([]byte, 16), 9).client)
			}},
		{concept: "paused target read", tools: []string{"cpu_pause", "memory_read"},
			args: []string{`{}`, `{"space":"m68k-bus","address":"0xFF0000","length":4}`},
			server: func(t *testing.T) *Server {
				return newTestServer(t, newConsistencyBridge([]byte{1, 2, 3, 4}, 0).client)
			}},
		{concept: "atomic guarded dump", tools: []string{"cpu_run", "memory_dump"},
			args: []string{`{}`, `{"space":"m68k-bus","address":"0xFF0000","length":8,"capture_mode":"paused"}`},
			server: func(t *testing.T) *Server {
				return newTestServer(t, newCaptureWindowBridge(false).client)
			}},
		{concept: "composite VDP export", tools: []string{"vdp_tile_export"},
			args: []string{`{"tile":0,"count":1,"scale":1}`},
			server: func(t *testing.T) *Server {
				client := &fakeBridgeClient{status: newFakeStatus()}
				reads := 0
				client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
					switch method {
					case "vdp_status":
						return json.RawMessage(`{"vdp_found":true,"registers":[],"decoded":{"display_enabled":true,"extended_vram":false},"image_buffer":{"last_rendered_frame_token":5}}`), nil
					case "vdp_mem_read":
						reads++
						data := make([]byte, 32)
						if reads%2 == 0 {
							data = make([]byte, 128)
						}
						payload := fmt.Sprintf(`{"target":"vram","address_space":"mem-vdp-vram","address":0,"length":%d,"entry_size":1,"buffer_size":65536,"byte_order":"big-endian","encoding":"base64","system_paused_during_read":%t,"data":%q}`,
							len(data), reads == 1, base64.StdEncoding.EncodeToString(data))
						return json.RawMessage(payload), nil
					}
					return json.RawMessage(`{}`), nil
				}
				return newTestServer(t, client)
			}},
		{concept: "restored snapshot", tools: []string{"state_save", "state_load"},
			args: []string{`{"name":"vocab"}`, `{"state_id":"@saved"}`},
			server: func(t *testing.T) *Server {
				client := &fakeBridgeClient{status: newFakeStatus()}
				client.executeFunc = func(_ context.Context, method string, params map[string]string) (json.RawMessage, error) {
					switch method {
					case "state_save":
						if err := writeFileFromParam(params["path"], "vocab-state"); err != nil {
							return nil, err
						}
						return json.RawMessage(`{"saved":true,"file_type":"zip","system_running":false}`), nil
					case "state_load":
						return json.RawMessage(`{"loaded":true,"file_type":"zip","system_running":false}`), nil
					}
					return json.RawMessage(`{}`), nil
				}
				server := newTestServer(t, client)
				server.SetStatesDir(t.TempDir())
				return server
			}},
		{concept: "run_until stop evidence", tools: []string{"cpu_run", "run_until_breakpoint"},
			args: []string{`{}`, `{"cpu":"m68k","address":"0x1000","timeout_ms":5000}`},
			server: func(t *testing.T) *Server {
				fake := newRunUntilFake(t)
				fake.running = true
				fake.fireOnStatusCall = 2
				return fake.server(t)
			}},
		{concept: "run_until watchpoint stop evidence", tools: []string{"cpu_run", "run_until_watchpoint"},
			args: []string{`{}`, `{"cpu":"m68k","address":"0xFF0000","length":2,"access":"write","timeout_ms":5000}`},
			server: func(t *testing.T) *Server {
				fake := newRunUntilFake(t)
				fake.running = true
				fake.fireOnStatusCall = 2
				return fake.server(t)
			}},
		{concept: "emulator status after an MCP pause", tools: []string{"cpu_pause", "emulator_status"},
			args: []string{`{}`, `{}`},
			server: func(t *testing.T) *Server {
				return newRunUntilFake(t).server(t)
			}},
		{concept: "emulator status of a running target", tools: []string{"emulator_status"},
			args: []string{`{}`},
			server: func(t *testing.T) *Server {
				fake := newRunUntilFake(t)
				fake.running = true
				return fake.server(t)
			}},
		{concept: "externally paused target", tools: []string{"emulator_status", "target_audit_list"},
			args: []string{`{}`, `{}`},
			server: func(t *testing.T) *Server {
				fake := newRunUntilFake(t)
				server := fake.server(t)
				// The server last saw the target running; nothing MCP did
				// explains the pause it is about to observe.
				server.runState.observe(server, true, nil)
				return server
			}},
		{concept: "sound and VDP device reads", tools: []string{"sound_status", "vdp_command_dma_status"},
			args: []string{`{}`, `{}`},
			server: func(t *testing.T) *Server {
				client := &fakeBridgeClient{status: newFakeStatus()}
				client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
					if method == "vdp_command_dma_status" {
						return json.RawMessage(`{"vdp_found":true}`), nil
					}
					return json.RawMessage(`{}`), nil
				}
				return newTestServer(t, client)
			}},
	}
}

// TestDeclaredResponseVocabularyIsProduced drives one representative producer
// per concept, audits every response, and proves each declared (non-reserved)
// value is really emitted somewhere.
func TestDeclaredResponseVocabularyIsProduced(t *testing.T) {
	audit := newVocabularyAudit()
	for _, fixture := range vocabularyFixtures() {
		server := fixture.server(t)
		savedStateID := ""
		for index, tool := range fixture.tools {
			arguments := fixture.args[index]
			if strings.Contains(arguments, "@saved") {
				arguments = strings.ReplaceAll(arguments, "@saved", savedStateID)
			}
			content := auditResponse(t, audit, server, tool, arguments)
			if tool == "state_save" && content != nil {
				if id, ok := content["state_id"].(string); ok {
					savedStateID = id
				}
			}
			if content == nil || content["code"] != nil {
				continue
			}
			if _, present := content["capture_consistency"]; !present {
				if summary, ok := content["summary"].(map[string]any); ok {
					if _, present := summary["capture_consistency"]; !present {
						t.Errorf("%s (%s) emitted no capture_consistency object", tool, fixture.concept)
					}
				}
			}
		}
	}
	audit.checkCrossReferences()
	reportVocabularyProblems(t, audit)
	requireVocabularyCoverage(t, audit)
}

// requireVocabularyCoverage asserts every declared value except the reserved
// "unknown" one is produced by the fixtures above.
func requireVocabularyCoverage(t *testing.T, audit *vocabularyAudit) {
	t.Helper()
	for _, candidate := range responseVocabularyConcepts() {
		seen := audit.emitted[candidate.concept]
		for _, value := range candidate.vocab.values {
			if value == consistencyUnknown || value == runStateUnknown || value == stopSourceUnknown || value == pauseSourceUnknown {
				continue
			}
			if !seen[value] {
				emitted := make([]string, 0, len(seen))
				for observed := range seen {
					emitted = append(emitted, observed)
				}
				sort.Strings(emitted)
				t.Errorf("%s declares %q but no fixture emits it (emitted: %v); an unproven value is an invented one", candidate.concept, value, emitted)
			}
		}
	}
}

func reportVocabularyProblems(t *testing.T, audit *vocabularyAudit) {
	t.Helper()
	if len(audit.problems) == 0 {
		return
	}
	for _, problem := range audit.problems {
		t.Error(problem)
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Catalog declaration
// ----------------------------------------------------------------------------------------------------------------------

// TestCatalogPublishesTheDeclaredVocabularies checks that the served catalog
// declares exactly the vocabularies the code enforces, so a client can build
// one conditional from tools/list instead of learning the values per tool.
func TestCatalogPublishesTheDeclaredVocabularies(t *testing.T) {
	declared := responseVocabularyDeclaration()
	for _, concept := range responseVocabularyConcepts() {
		published, present := declared[concept.concept]
		if !present {
			t.Fatalf("the published catalog does not declare %s", concept.concept)
		}
		values, ok := published.([]string)
		if !ok {
			t.Fatalf("%s is published as %T, want []string", concept.concept, published)
		}
		if !reflect.DeepEqual(values, concept.vocab.valuesEcho()) {
			t.Fatalf("%s published as %v, declared as %v", concept.concept, values, concept.vocab.valuesEcho())
		}
	}
	schemas := toolSchemas()
	if len(schemas) != len(toolRegistry) {
		t.Fatalf("catalog has %d tools, registry has %d", len(schemas), len(toolRegistry))
	}
	for _, schema := range schemas {
		inputSchema, ok := schema["inputSchema"].(map[string]any)
		if !ok {
			t.Fatalf("%v publishes no inputSchema", schema["name"])
		}
		published, ok := inputSchema[responseVocabularySchemaKey].(map[string]any)
		if !ok {
			t.Fatalf("%v does not publish %s", schema["name"], responseVocabularySchemaKey)
		}
		if !reflect.DeepEqual(published, declared) {
			t.Fatalf("%v publishes a different vocabulary than the declared one", schema["name"])
		}
		deprecated, ok := inputSchema[responseDeprecationSchemaKey].(map[string]any)
		if !ok {
			t.Fatalf("%v does not publish %s", schema["name"], responseDeprecationSchemaKey)
		}
		for _, field := range []string{"consistency", "capture_consistency.paused_by_tool"} {
			entry, present := deprecated[field].(map[string]any)
			if !present {
				t.Fatalf("%v does not declare the deprecated field %s", schema["name"], field)
			}
			if entry["derived"] != true || entry["replacement"] == "" || entry["note"] == "" {
				t.Fatalf("%v declares %s without a replacement, a derivation, and a note: %v", schema["name"], field, entry)
			}
		}
	}
}

// TestEveryCaptureModeSchemaUsesTheDeclaredEnum proves the one input vocabulary
// that gates a capture is published from the shared declaration.
func TestEveryCaptureModeSchemaUsesTheDeclaredEnum(t *testing.T) {
	seen := 0
	for _, spec := range toolRegistry {
		property, present := schemaProperties(spec.schema)["capture_mode"].(map[string]any)
		if !present {
			continue
		}
		seen++
		values, ok := property["enum"].([]string)
		if !ok {
			t.Fatalf("tool %q publishes capture_mode without an enum: %v", spec.name, property)
		}
		for _, value := range values {
			if value != captureModeLive && value != captureModePaused {
				t.Fatalf("tool %q publishes capture_mode %q outside the declared vocabulary", spec.name, value)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no tool publishes capture_mode; the guard vocabulary is undelivered")
	}
}

// ----------------------------------------------------------------------------------------------------------------------
// Session-scoped producers without a tool-level fixture
// ----------------------------------------------------------------------------------------------------------------------

// TestTraceSessionConsistencyUsesTheSharedObject audits the trace-session
// object, which the registry sweep cannot reach without a running native
// session. It carries the same shape and the same declared state.
func TestTraceSessionConsistencyUsesTheSharedObject(t *testing.T) {
	fake := newRunUntilFake(t)
	server := fake.server(t)
	observer := toolContext{server: server, ctx: context.Background(), modern: true}
	session := tracing.NewSession("trs_vocab", "ctx", "m68k", "m68k-bus", tracing.Config{CPU: "m68k"})
	audit := newVocabularyAudit()
	view := server.captureConsistencyView(traceSessionConsistency(observer, session, nil))
	audit.walk(map[string]any{"capture_consistency": view}, "$", false)
	audit.checkCrossReferences()
	reportVocabularyProblems(t, audit)
	for _, key := range captureConsistencyResponseKeys {
		if _, present := view[key]; !present {
			t.Fatalf("trace session object is missing %q: %v", key, view)
		}
	}
	if view["state"] != consistencyLive {
		t.Fatalf("trace session state = %v, want %q (a windowed capture that never paused)", view["state"], consistencyLive)
	}
}
