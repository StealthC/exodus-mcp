//go:build windows

package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/iotest"
	"time"
	"unsafe"
)

var (
	testKernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateNamedPipeW = testKernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe = testKernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedP = testKernel32.NewProc("DisconnectNamedPipe")
	procCancelIoEx       = testKernel32.NewProc("CancelIoEx")
	procCloseHandle      = testKernel32.NewProc("CloseHandle")
)

const (
	pipeAccessDuplex   = 0x3
	errorPipeConnected = syscall.Errno(539)
	invalidHandleValue = ^uintptr(0)
)

type fakePluginHandleFunc = func(id, method string, params map[string]string) (payload string, errCode string, errMessage string)

// fakePlugin is a minimal in-process stand-in for ExodusMcpPlugin. It hosts a
// real byte-mode named pipe through kernel32 so the production client's open,
// framing, deadline, and error paths run against live OS semantics instead of
// mocked readers. Like the real plugin it serves one connection at a time.
type fakePlugin struct {
	pipeName   string
	capability string
	handle     fakePluginHandleFunc

	mu         sync.Mutex
	current    uintptr
	instanceID int
}

func startFakePlugin(t *testing.T, capability string, handle fakePluginHandleFunc) *fakePlugin {
	t.Helper()
	nextRequestID.Add(1)
	plugin := &fakePlugin{
		pipeName:   fmt.Sprintf(`\\.\pipe\exodus-mcp-go-test-%d`, time.Now().UnixNano()),
		capability: capability,
		handle:     handle,
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		plugin.serve()
	}()
	t.Cleanup(func() {
		plugin.mu.Lock()
		current := plugin.current
		plugin.current = 0
		plugin.mu.Unlock()
		if current != 0 && current != invalidHandleValue {
			// Unblock a pending ConnectNamedPipe, if any.
			procCancelIoEx.Call(current, 0)
			procCloseHandle.Call(current)
		}
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Error("fake plugin did not shut down")
		}
	})
	return plugin
}

func (plugin *fakePlugin) addr() string { return plugin.pipeName }

func (plugin *fakePlugin) serve() {
	for {
		plugin.mu.Lock()
		plugin.instanceID++
		name := syscall.StringToUTF16Ptr(plugin.pipeName)
		handle, _, callErr := procCreateNamedPipeW.Call(
			uintptr(unsafe.Pointer(name)),
			pipeAccessDuplex,
			0, // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
			4, // max instances
			4096, 4096,
			0, // default timeout
			0, // security attributes
		)
		if handle == invalidHandleValue {
			plugin.mu.Unlock()
			log.Printf("fake plugin %s create failed: %v", plugin.pipeName, callErr)
			return
		}
		plugin.current = handle
		plugin.mu.Unlock()

		_, _, connectErr := procConnectNamedPipe.Call(handle, 0)
		if errno, _ := connectErr.(syscall.Errno); connectErr != nil && errno != errorPipeConnected && errno != 0 {
			// Interrupted by cleanup or unrecoverable; stop serving.
			procCloseHandle.Call(handle)
			plugin.mu.Lock()
			plugin.current = 0
			plugin.mu.Unlock()
			return
		}

		file := os.NewFile(handle, plugin.pipeName)
		plugin.serveConn(file)
		file.Close()
		procDisconnectNamedP.Call(handle)
	}
}

// serveConn mirrors HandleConnection: read one blank-line-terminated request,
// enforce the capability, answer with one framed JSON envelope, then close.
func (plugin *fakePlugin) serveConn(conn io.ReadWriteCloser) {
	fields, err := readRequestFields(conn)
	if err != nil {
		return
	}
	id := fields["id"]
	method := fields["method"]
	params := make(map[string]string)
	for key, value := range fields {
		switch key {
		case "capability", "id", "method":
		default:
			params[key] = value
		}
	}

	var response string
	if fields["capability"] != plugin.capability {
		response = `{"protocol_version":2,"id":"","status":"error","error":{"code":"unauthorized","message":"bridge capability rejected"}}` + "\n"
	} else if method == "" || id == "" {
		response = `{"protocol_version":2,"id":"","status":"error","error":{"code":"bad_request","message":"unable to parse bridge request"}}` + "\n"
	} else {
		payload, errCode, errMessage := plugin.handle(id, method, params)
		builder := &strings.Builder{}
		builder.WriteString(`{"protocol_version":2,"id":`)
		builder.Write(mustJSON(id))
		if errCode == "" {
			builder.WriteString(`,"status":"ok","data":`)
			builder.WriteString(payload)
		} else {
			builder.WriteString(`,"status":"error","error":{"code":`)
			builder.Write(mustJSON(errCode))
			builder.WriteString(`,"message":`)
			builder.Write(mustJSON(errMessage))
			builder.WriteString(`}`)
		}
		builder.WriteString("}\n")
		response = builder.String()
	}
	writeFramedResponse(conn, response)
}

func readRequestFields(conn io.Reader) (map[string]string, error) {
	fields := make(map[string]string)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			return fields, nil
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("malformed request line %q", line)
		}
		fields[key] = value
	}
	return nil, scanner.Err()
}

// writeFramedResponse reproduces WriteAll: an eight-character hex length
// prefix followed by exactly that many payload bytes, written in two pieces
// to exercise the client's incremental read buffer.
func writeFramedResponse(conn io.Writer, response string) {
	header := fmt.Sprintf("%08X", len(response))
	conn.Write([]byte(header[:4]))
	conn.Write([]byte(header[4:]))
	conn.Write([]byte(response))
}

func mustJSON(value string) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestClientRoundTripOverLivePipe(t *testing.T) {
	plugin := startFakePlugin(t, "cap-live", func(id, method string, params map[string]string) (string, string, string) {
		if method == "status" {
			return `{"protocol_version":2,"plugin_version":"9.9.9-test","lifecycle":"ready","bridge_enabled":true,"loaded_module_count":7,"supported_operations":["status","mem_read"]}`, "", ""
		}
		return fmt.Sprintf(`{"echo_id":%s,"space":%s}`, mustJSON(id), mustJSON(params["space"])), "", ""
	})
	client := NewNamedPipeClient(plugin.addr(), "cap-live")

	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.PluginVersion != "9.9.9-test" || !status.BridgeEnabled || status.LoadedModuleCount != 7 {
		t.Fatalf("unexpected status: %+v", status)
	}
	if !status.SupportsOperation("mem_read") || status.SupportsOperation("disasm") {
		t.Fatalf("operation lookup wrong: %+v", status.SupportedOperations)
	}

	data, err := client.Execute(context.Background(), "mem_read", map[string]string{"space": "m68k-ram"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var payload struct {
		EchoID  string `json:"echo_id"`
		SpaceID string `json:"space"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode payload %s: %v", data, err)
	}
	if payload.SpaceID != "m68k-ram" || !strings.HasPrefix(payload.EchoID, "req-") {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestClientMapsCommandError(t *testing.T) {
	plugin := startFakePlugin(t, "cap-live", func(string, string, map[string]string) (string, string, string) {
		return "", "out_of_range", "requested range exceeds space"
	})
	client := NewNamedPipeClient(plugin.addr(), "cap-live")

	_, err := client.Execute(context.Background(), "mem_read", nil)
	var commandErr *CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("err = %v, want CommandError", err)
	}
	if commandErr.Code != "out_of_range" || commandErr.Message != "requested range exceeds space" {
		t.Fatalf("unexpected command error: %+v", commandErr)
	}
}

func TestClientRejectsWrongCapability(t *testing.T) {
	plugin := startFakePlugin(t, "cap-real", func(string, string, map[string]string) (string, string, string) {
		return "{}", "", ""
	})
	client := NewNamedPipeClient(plugin.addr(), "cap-wrong")

	_, err := client.Status(context.Background())
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Code != "unauthorized" {
		t.Fatalf("err = %v, want unauthorized CommandError", err)
	}
}

func TestClientHandlesLargeFramedResponse(t *testing.T) {
	blobSize := 2 << 20 // 2 MiB of payload text, far above any single read
	plugin := startFakePlugin(t, "cap-live", func(string, string, map[string]string) (string, string, string) {
		return fmt.Sprintf(`{"blob_size":%d,"blob":"%s"}`, blobSize, strings.Repeat("A", blobSize)), "", ""
	})
	client := NewNamedPipeClient(plugin.addr(), "cap-live")

	data, err := client.Execute(context.Background(), "frame_capture", nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var payload struct {
		BlobSize int    `json:"blob_size"`
		Blob     string `json:"blob"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode large payload: %v", err)
	}
	if payload.BlobSize != blobSize || len(payload.Blob) != blobSize {
		t.Fatalf("large payload truncated: declared %d, got %d bytes", payload.BlobSize, len(payload.Blob))
	}
}

func TestClientContextCancelWhilePipeAbsent(t *testing.T) {
	client := NewNamedPipeClient(`\\.\pipe\exodus-mcp-go-test-absent`, "cap-live")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := client.Execute(ctx, "status", nil)
	if !errors.Is(err, ctx.Err()) {
		t.Fatalf("err = %v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %v", elapsed)
	}
}

func TestReadFramedResponseRejectsOversizedFrame(t *testing.T) {
	payload := "FFFFFFFF" // 0xFFFFFFFF far exceeds maxResponseSize
	if _, err := readFramedResponse(strings.NewReader(payload)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want oversized frame rejection", err)
	}
}

func TestReadFramedResponseAssemblesSplitHeader(t *testing.T) {
	body := `{"protocol_version":2,"id":"x","status":"ok","data":{}}`
	frame := fmt.Sprintf("%08X%s", len(body), body)
	// Feed the frame through tiny reads so header assembly cannot depend on
	// message boundaries.
	reader := iotest.OneByteReader(strings.NewReader(frame))
	got, err := readFramedResponse(reader)
	if err != nil {
		t.Fatalf("readFramedResponse: %v", err)
	}
	if string(got) != body {
		t.Fatalf("payload mismatch: %q", got)
	}
}
