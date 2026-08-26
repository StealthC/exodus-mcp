package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestFrameCaptureReportsNoPause(t *testing.T) {
	client := &fakeBridgeClient{status: newFakeStatus()}
	pixel := make([]byte, 3*2*2)
	client.executeFunc = func(_ context.Context, method string, _ map[string]string) (json.RawMessage, error) {
		if method == "frame_capture" {
			return json.RawMessage(fmt.Sprintf(`{"width":2,"height":2,"pixel_format":"rgb24","encoding":"base64","frame_token":7,"data":"%s"}`, base64.StdEncoding.EncodeToString(pixel))), nil
		}
		return json.RawMessage(`{}`), nil
	}
	result := callTool(t, client, "frame_capture", `{}`)
	if result["isError"] == true {
		t.Fatalf("unexpected error: %v", result)
	}
	summary := structured(result)["summary"].(map[string]any)
	if summary["system_paused_during_read"] != false {
		t.Fatalf("frame_capture must never report a pause: %v", summary)
	}
}
