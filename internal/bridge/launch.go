package bridge

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const pipePrefix = `\\.\pipe\exodus-mcp-`

// LaunchConfig is the server-owned configuration passed to an Exodus child
// process. The capability must stay local to the server and child process.
type LaunchConfig struct {
	Executable string
	Arguments  []string
	PipeName   string
	Capability string
}

// NewLaunchConfig creates a unique pipe name and an unguessable, URL-safe
// capability for one Exodus process.
func NewLaunchConfig(executable string, arguments []string) (LaunchConfig, error) {
	pipeID, err := randomToken(18)
	if err != nil {
		return LaunchConfig{}, err
	}
	capability, err := randomToken(32)
	if err != nil {
		return LaunchConfig{}, err
	}
	return LaunchConfig{
		Executable: executable,
		Arguments:  append([]string(nil), arguments...),
		PipeName:   pipePrefix + pipeID,
		Capability: capability,
	}, nil
}

// StartExodus launches Exodus with the pipe credentials needed by the native
// plugin. It never writes the capability to stdout, logs, or command arguments.
func StartExodus(config LaunchConfig) (*exec.Cmd, error) {
	if config.Executable == "" || config.PipeName == "" || config.Capability == "" {
		return nil, fmt.Errorf("Exodus launch requires executable, pipe name, and capability")
	}
	command := newExodusCommand(config)
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start Exodus: %w", err)
	}
	return command, nil
}

func newExodusCommand(config LaunchConfig) *exec.Cmd {
	command := exec.Command(config.Executable, config.Arguments...)
	// Exodus resolves settings.xml and Data/ relative to its working directory.
	// Launch it beside its executable, not beside exodus-mcp.exe.
	command.Dir = filepath.Dir(config.Executable)
	command.Env = append(os.Environ(),
		"EXODUS_MCP_PIPE_NAME="+config.PipeName,
		"EXODUS_MCP_CAPABILITY="+config.Capability,
	)
	return command
}

func randomToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate bridge capability: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
