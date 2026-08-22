//go:build windows

package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	genericRead      = 0x80000000
	genericWrite     = 0x40000000
	openExisting     = 3
	invalidHandle    = ^uintptr(0)
	pipeWaitInterval = 100 * time.Millisecond
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
	file, err := openPipe(ctx, client.pipeName)
	if err != nil {
		return Status{}, err
	}
	defer file.Close()

	request := []byte("capability=" + client.capability + "\nmethod=status\n")
	if _, err := file.Write(request); err != nil {
		return Status{}, fmt.Errorf("write bridge status request: %w", err)
	}
	response := make([]byte, 1024)
	read, err := file.Read(response)
	if err != nil {
		return Status{}, fmt.Errorf("read bridge status response: %w", err)
	}
	var status Status
	if err := json.Unmarshal(response[:read], &status); err != nil {
		return Status{}, fmt.Errorf("decode bridge status response: %w", err)
	}
	if status.ProtocolVersion != 1 {
		return Status{}, fmt.Errorf("unsupported bridge protocol version %d", status.ProtocolVersion)
	}
	return status, nil
}

func openPipe(ctx context.Context, pipeName string) (*os.File, error) {
	path, err := syscall.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, fmt.Errorf("invalid pipe name: %w", err)
	}
	for {
		handle, _, callErr := createFileW.Call(
			uintptr(unsafe.Pointer(path)),
			uintptr(genericRead|genericWrite),
			0,
			0,
			openExisting,
			0,
			0,
		)
		if handle != invalidHandle {
			return os.NewFile(handle, pipeName), nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		waitNamedPipeW.Call(uintptr(unsafe.Pointer(path)), uintptr(pipeWaitInterval.Milliseconds()))
		if callErr != syscall.Errno(0) {
			continue
		}
	}
}
