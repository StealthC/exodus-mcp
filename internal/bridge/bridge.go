// Package bridge provides the Go side of the local Exodus bridge protocol.
package bridge

import (
	"context"
	"errors"
)

var ErrUnavailable = errors.New("native Exodus bridge is unavailable")

// Status is the bounded, read-only response produced by ExodusMcpPlugin.
type Status struct {
	ProtocolVersion   int    `json:"protocol_version"`
	PluginVersion     string `json:"plugin_version"`
	Lifecycle         string `json:"lifecycle"`
	BridgeEnabled     bool   `json:"bridge_enabled"`
	LoadedModuleCount uint   `json:"loaded_module_count"`
}

// Client communicates with one locally running ExodusMcpPlugin instance.
type Client interface {
	Status(context.Context) (Status, error)
}

type unavailableClient struct{}

func (unavailableClient) Status(context.Context) (Status, error) {
	return Status{}, ErrUnavailable
}

// UnavailableClient is used when no pipe configuration was supplied.
func UnavailableClient() Client { return unavailableClient{} }
