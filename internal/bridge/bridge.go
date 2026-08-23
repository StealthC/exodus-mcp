// Package bridge provides the Go side of the local Exodus bridge protocol.
// Protocol version 2 frames requests as key/value lines and responses as one
// UTF-8 JSON envelope streamed over an authenticated Windows named pipe.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
)

// ProtocolVersion is the bridge wire protocol implemented by this build.
const ProtocolVersion = 2

var ErrUnavailable = errors.New("native Exodus bridge is unavailable")

// Status is the bounded, read-only response produced by ExodusMcpPlugin.
type Status struct {
	ProtocolVersion     int      `json:"protocol_version"`
	PluginVersion       string   `json:"plugin_version"`
	Lifecycle           string   `json:"lifecycle"`
	BridgeEnabled       bool     `json:"bridge_enabled"`
	LoadedModuleCount   uint     `json:"loaded_module_count"`
	SupportedOperations []string `json:"supported_operations,omitempty"`
}

// SupportsOperation reports whether the connected plugin advertised a command.
func (status Status) SupportsOperation(operation string) bool {
	for _, candidate := range status.SupportedOperations {
		if candidate == operation {
			return true
		}
	}
	return false
}

// CommandError is a structured failure returned by the native plugin.
type CommandError struct {
	Code    string
	Message string
}

func (e *CommandError) Error() string { return e.Code + ": " + e.Message }

// Client communicates with one locally running ExodusMcpPlugin instance.
type Client interface {
	Status(context.Context) (Status, error)
	Execute(ctx context.Context, method string, params map[string]string) (json.RawMessage, error)
}

type unavailableClient struct{}

func (unavailableClient) Status(context.Context) (Status, error) {
	return Status{}, ErrUnavailable
}

func (unavailableClient) Execute(context.Context, string, map[string]string) (json.RawMessage, error) {
	return nil, ErrUnavailable
}

// UnavailableClient is used when no pipe configuration was supplied.
func UnavailableClient() Client { return unavailableClient{} }

var nextRequestID atomic.Uint64

// BuildRequest renders one bridge request. Params stay flat key/value lines;
// values must therefore avoid newlines, which all supported commands satisfy.
func BuildRequest(capability, method string, params map[string]string) []byte {
	id := nextRequestID.Add(1)
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "capability=%s\n", capability)
	fmt.Fprintf(builder, "id=req-%d\n", id)
	fmt.Fprintf(builder, "method=%s\n", method)
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(builder, "%s=%s\n", key, params[key])
	}
	builder.WriteString("\n")
	return []byte(builder.String())
}

// BridgeResponse is the decoded plugin envelope. Data stays raw so callers
// decode only the payloads they expect.
type BridgeResponse struct {
	ProtocolVersion int             `json:"protocol_version"`
	ID              string          `json:"id"`
	Status          string          `json:"status"`
	Data            json.RawMessage `json:"data,omitempty"`
	Error           *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ParseResponse decodes and validates one plugin response envelope.
func ParseResponse(raw []byte) (BridgeResponse, error) {
	var response BridgeResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return BridgeResponse{}, fmt.Errorf("decode bridge response: %w", err)
	}
	if response.ProtocolVersion != ProtocolVersion {
		return BridgeResponse{}, fmt.Errorf("unsupported bridge protocol version %d, want %d; update the ExodusMcpPlugin extension", response.ProtocolVersion, ProtocolVersion)
	}
	switch response.Status {
	case "ok":
		return response, nil
	case "error":
		if response.Error == nil {
			return BridgeResponse{}, errors.New("bridge command failed without an error payload")
		}
		return response, &CommandError{Code: response.Error.Code, Message: response.Error.Message}
	default:
		return BridgeResponse{}, fmt.Errorf("unknown bridge response status %q", response.Status)
	}
}
