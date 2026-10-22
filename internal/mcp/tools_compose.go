package mcp

import (
	"encoding/json"
)

// This file holds the composition primitive used by the consolidated catalog
// (roadmap issue #17).
//
// A merged tool must not reimplement the behavior of the tools it absorbs: the
// absorbed behavior is the contract (#5 trace completeness, #6 replay
// determinism, #9 argument contract, #11 cursors, #12 vocabularies, #18 error
// taxonomy). composeTool runs the registered handler of one absorbed concept
// in-process, with exactly the arguments the merged tool validated, and hands
// back its structured payload or its failure. The merged tool then adds only the
// new dispatch metadata, so a behavior can never diverge between the canonical
// tool and the deprecated alias of the same concept.

// composeTool runs one handler in-process and returns its payload. The
// nested call always renders structured content, independent of the client's
// MCP era, because the payload is composed rather than returned; the merged
// tool re-encodes the final response for the client.
func composeTool(tc toolContext, run func(toolContext, json.RawMessage) map[string]any, arguments map[string]any) (map[string]any, *toolFailure) {
	raw, err := json.Marshal(arguments)
	if err != nil {
		return nil, &toolFailure{Code: errorCodeInternalFallback, Message: "encode composed arguments: " + err.Error()}
	}
	nested := toolContext{server: tc.server, ctx: tc.ctx, modern: true, invokedAs: tc.invokedAs}
	result := run(nested, raw)
	if failed, _ := result["isError"].(bool); failed {
		return nil, failureFromResult(result)
	}
	payload, ok := result["structuredContent"].(map[string]any)
	if !ok {
		return nil, &toolFailure{Code: errorCodeInternalFallback, Message: "composed tool returned no structured payload"}
	}
	return payload, nil
}

// failureFromResult rebuilds the failure of a composed call so the merged tool
// can return it unchanged: the code and message are the ones the absorbed
// handler produced, and every other structured field is preserved as failure
// data.
func failureFromResult(result map[string]any) *toolFailure {
	structured, _ := result["structuredContent"].(map[string]any)
	code, _ := structured["code"].(string)
	message, _ := structured["message"].(string)
	if code == "" {
		code = errorCodeInternalFallback
	}
	failure := &toolFailure{Code: code, Message: message}
	for key, value := range structured {
		switch key {
		case "code", "message", "error_class":
			continue
		}
		if failure.Data == nil {
			failure.Data = map[string]any{}
		}
		failure.Data[key] = value
	}
	return failure
}

// patchPayloadField adds or replaces one success field in a completed result
// envelope. Both encodings are patched so modern and legacy clients see the same
// payload; a failure result (whose content text is "code: message") keeps its
// text and gains nothing.
func patchPayloadField(result map[string]any, key string, value any) map[string]any {
	if result == nil {
		return result
	}
	if failed, _ := result["isError"].(bool); failed {
		return result
	}
	if structured, ok := result["structuredContent"].(map[string]any); ok {
		structured[key] = value
	}
	content, ok := result["content"].([]map[string]string)
	if !ok || len(content) == 0 {
		return result
	}
	var payload map[string]any
	if json.Unmarshal([]byte(content[0]["text"]), &payload) != nil {
		return result
	}
	payload[key] = value
	if encoded, err := json.Marshal(payload); err == nil {
		content[0]["text"] = string(encoded)
	}
	return result
}
