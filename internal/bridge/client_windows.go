//go:build windows

package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const (
	genericRead        = 0x80000000
	genericWrite       = 0x40000000
	fileFlagOverlapped = 0x40000000
	openExisting       = 3
	invalidHandle      = ^uintptr(0)
	pipeWaitInterval   = 100 * time.Millisecond
	defaultCommandTTL  = 30 * time.Second
	// maxResponseSize bounds one bridge envelope in memory. The plugin-side
	// per-command caps stay well below it: an 8 MiB memory_dump becomes about
	// 10.7 MiB of base64 inside the JSON envelope, so this limit leaves room
	// without allowing unbounded allocations from a misbehaving peer.
	maxResponseSize = 64 << 20
)

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	createFileW    = kernel32.NewProc("CreateFileW")
	waitNamedPipeW = kernel32.NewProc("WaitNamedPipeW")
)

type namedPipeClient struct {
	pipeName   string
	capability string
}

// NewNamedPipeClient creates the client for the capability-gated plugin pipe.
func NewNamedPipeClient(pipeName, capability string) Client {
	if pipeName == "" || capability == "" {
		return UnavailableClient()
	}
	return &namedPipeClient{pipeName: pipeName, capability: capability}
}

func (client *namedPipeClient) Status(ctx context.Context) (Status, error) {
	// ParseResponse already validated the envelope protocol version; the
	// status payload itself carries lifecycle fields only.
	data, err := client.Execute(ctx, "status", nil)
	if err != nil {
		return Status{}, err
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		return Status{}, fmt.Errorf("decode bridge status response: %w", err)
	}
	return status, nil
}

func (client *namedPipeClient) Execute(ctx context.Context, method string, params map[string]string) (json.RawMessage, error) {
	file, err := openPipe(ctx, client.pipeName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := applyDeadline(ctx, file); err != nil {
		return nil, err
	}
	if _, err := file.Write(BuildRequest(client.capability, method, params)); err != nil {
		return nil, fmt.Errorf("write bridge request: %w", err)
	}
	raw, err := readFramedResponse(file)
	if err != nil {
		return nil, err
	}
	response, err := ParseResponse(raw)
	if err != nil {
		return nil, err
	}
	return response.Data, nil
}

// readFramedResponse consumes one length-prefixed payload ("08X" hex header
// followed by exactly that many bytes). Framing removes any dependence on
// disconnect timing or EOF: the plugin holds the connection until this side
// closes it, which doubles as its drain-complete signal.
func readFramedResponse(reader io.Reader) ([]byte, error) {
	const lengthPrefixBytes = 8
	buffer := make([]byte, 0, 4096)
	chunk := make([]byte, 64*1024)
	for {
		if len(buffer) >= lengthPrefixBytes {
			target, parseErr := strconv.ParseUint(string(buffer[:lengthPrefixBytes]), 16, 64)
			if parseErr != nil {
				return nil, fmt.Errorf("decode bridge frame length: %w", parseErr)
			}
			if target > maxResponseSize {
				return nil, fmt.Errorf("bridge response exceeds %d bytes", maxResponseSize)
			}
			if uint64(len(buffer)) >= target+lengthPrefixBytes {
				return buffer[lengthPrefixBytes : lengthPrefixBytes+uint64(target)], nil
			}
		}
		read, err := reader.Read(chunk)
		if read > 0 {
			buffer = append(buffer, chunk[:read]...)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read bridge response: %w", err)
		}
	}
}

func applyDeadline(ctx context.Context, file *os.File) error {
	deadline := time.Now().Add(defaultCommandTTL)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := file.SetDeadline(deadline); err != nil {
		return fmt.Errorf("arm pipe deadline: %w", err)
	}
	return nil
}

func openPipe(ctx context.Context, pipeName string) (*os.File, error) {
	path, err := syscall.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, fmt.Errorf("invalid pipe name: %w", err)
	}
	loggedWaiting := false
	for {
		handle, _, _ := createFileW.Call(
			uintptr(unsafe.Pointer(path)),
			uintptr(genericRead|genericWrite),
			0,
			0,
			openExisting,
			uintptr(fileFlagOverlapped),
			0,
		)
		if handle != invalidHandle {
			return os.NewFile(handle, pipeName), nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !loggedWaiting {
			log.Printf("bridge pipe %s not ready yet; waiting", pipeName)
			loggedWaiting = true
		}
		// WaitNamedPipeW returns zero when the pipe does not exist (the
		// plugin has not created it yet); sleep instead of hot-spinning.
		result, _, _ := waitNamedPipeW.Call(uintptr(unsafe.Pointer(path)), uintptr(pipeWaitInterval.Milliseconds()))
		if result == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pipeWaitInterval):
			}
		}
	}
}
