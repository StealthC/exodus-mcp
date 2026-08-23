package bridge

import (
	"strings"
	"testing"
)

func TestBuildRequestShape(t *testing.T) {
	request := BuildRequest("cap-123", "mem_read", map[string]string{
		"space":   "m68k-ram",
		"length":  "16",
		"address": "4096",
	})
	text := string(request)
	if !strings.HasPrefix(text, "capability=cap-123\n") {
		t.Fatalf("capability line missing: %q", text)
	}
	methodLine := "\nmethod=mem_read\n"
	if !strings.Contains(text, methodLine) {
		t.Fatalf("method line missing: %q", text)
	}
	addressIndex := strings.Index(text, "address=4096")
	lengthIndex := strings.Index(text, "length=16")
	spaceIndex := strings.Index(text, "space=m68k-ram")
	if !(addressIndex < lengthIndex && lengthIndex < spaceIndex) {
		t.Fatal("params must be emitted in sorted key order")
	}
	if !strings.HasSuffix(text, "space=m68k-ram\n\n") {
		t.Fatalf("request must end with a blank terminator line: %q", text)
	}
}

func TestParseResponseOK(t *testing.T) {
	response, err := ParseResponse([]byte(`{"protocol_version":2,"id":"req-1","status":"ok","data":{"spaces":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != "ok" || len(response.Data) == 0 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestParseResponseCommandError(t *testing.T) {
	response, err := ParseResponse([]byte(`{"protocol_version":2,"id":"req-2","status":"error","error":{"code":"out_of_range","message":"too far"}}`))
	commandErr, ok := err.(*CommandError)
	if !ok || commandErr.Code != "out_of_range" || response.Status != "error" {
		t.Fatalf("expected CommandError, got %v", err)
	}
}

func TestParseResponseRejectsWrongProtocol(t *testing.T) {
	if _, err := ParseResponse([]byte(`{"protocol_version":1,"id":"","status":"ok","data":{}}`)); err == nil {
		t.Fatal("protocol version 1 must be rejected")
	}
}

func TestStatusSupportsOperation(t *testing.T) {
	status := Status{SupportedOperations: []string{"status", "mem_read"}}
	if !status.SupportsOperation("mem_read") || status.SupportsOperation("disasm") {
		t.Fatal("operation lookup wrong")
	}
}
