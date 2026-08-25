// Package experiment runs bounded, operator-authored experiment scripts and
// declarative fixtures against the emulator through a server-mediated,
// artifact-first protocol.
//
// Scripts (.py) and fixtures (.json) live in an operator-configured scripts
// directory. The Go server owns the process lifecycle, validates every
// message, mediates every tool call through an allowlist, injects the
// experiment's context and lease, and records a reproducible manifest
// artifact plus capped diagnostic output. Scripts never see the native pipe,
// the bridge capability, or the emulator process itself.
package experiment

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Default limits for experiment runs.
const (
	// DefaultTimeout is the wall-clock budget when the caller omits one.
	DefaultTimeout = 30 * time.Second
	// MaxTimeout is the hard per-run cap the runner enforces.
	MaxTimeout = 5 * time.Minute
	// DefaultMaxSteps bounds the tool steps one run may execute.
	DefaultMaxSteps = 200
	// DefaultMaxOutputBytes bounds one script-published artifact and the
	// captured stderr of a run.
	DefaultMaxOutputBytes = 1 << 20
	// maxScriptBytes bounds one script or fixture file.
	maxScriptBytes = 1 << 20
	// maxArtifactsPerRun bounds artifact messages per run.
	maxArtifactsPerRun = 64
	// maxMessageIDBytes bounds protocol message ids.
	maxMessageIDBytes = 128
	// maxStepValueBytes bounds the per-step value echo in the manifest.
	maxStepValueBytes = 4096
)

// Config locates scripts and bounds experiment runs. Zero values fall back to
// the defaults above.
type Config struct {
	// ScriptsDir is the root directory of allowed scripts and fixtures.
	// Empty means os.TempDir()/exodus-mcp/scripts.
	ScriptsDir string

	// PythonCmd is the Python 3 interpreter used for .py scripts. A bare name
	// is resolved through PATH at construction; empty means "python3" (Unix)
	// or "python" (Windows).
	PythonCmd string

	// DefaultTimeout is applied when a run omits timeout_ms.
	DefaultTimeout time.Duration

	// MaxTimeout is the hard cap for one run, applied to every request.
	MaxTimeout time.Duration

	// MaxSteps bounds the tool steps one run may execute.
	MaxSteps int

	// MaxOutputBytes bounds one script-published artifact and the stderr
	// captured into the experiment-output artifact.
	MaxOutputBytes int64

	// ArtifactBaseURL anchors the download URLs handed back to scripts that
	// publish artifacts; empty means http://127.0.0.1.
	ArtifactBaseURL string
}

// normalize fills zero fields with the documented defaults.
func (config Config) normalize() Config {
	if config.ScriptsDir == "" {
		config.ScriptsDir = filepath.Join(os.TempDir(), "exodus-mcp", "scripts")
	}
	if config.PythonCmd == "" {
		if runtime.GOOS == "windows" {
			config.PythonCmd = "python"
		} else {
			config.PythonCmd = "python3"
		}
	}
	if !strings.ContainsAny(config.PythonCmd, `/\`) {
		if resolved, err := exec.LookPath(config.PythonCmd); err == nil {
			config.PythonCmd = resolved
		}
	}
	if config.DefaultTimeout <= 0 {
		config.DefaultTimeout = DefaultTimeout
	}
	if config.MaxTimeout <= 0 {
		config.MaxTimeout = MaxTimeout
	}
	if config.MaxTimeout < config.DefaultTimeout {
		config.MaxTimeout = config.DefaultTimeout
	}
	if config.MaxSteps <= 0 {
		config.MaxSteps = DefaultMaxSteps
	}
	if config.MaxOutputBytes <= 0 {
		config.MaxOutputBytes = DefaultMaxOutputBytes
	}
	config.ArtifactBaseURL = strings.TrimRight(config.ArtifactBaseURL, "/")
	if config.ArtifactBaseURL == "" {
		config.ArtifactBaseURL = "http://127.0.0.1"
	}
	return config
}
