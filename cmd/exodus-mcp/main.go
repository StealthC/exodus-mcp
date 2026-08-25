// Command exodus-mcp provides the local HTTP endpoint for Exodus MCP.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
	"github.com/StealthC/exodus-mcp/internal/bridge"
	"github.com/StealthC/exodus-mcp/internal/experiment"
	"github.com/StealthC/exodus-mcp/internal/mcp"
)

var version = "dev"

const shutdownTimeout = 5 * time.Second

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	listen := flag.String("listen", envOrDefault("EXODUS_MCP_LISTEN", "127.0.0.1:8767"), "local address for the MCP HTTP endpoint")
	pipeName := flag.String("pipe-name", os.Getenv("EXODUS_MCP_PIPE_NAME"), "Windows named pipe used by ExodusMcpPlugin")
	pipeCapability := flag.String("pipe-capability", os.Getenv("EXODUS_MCP_CAPABILITY"), "capability for the Windows named pipe")
	exodusExecutable := flag.String("exodus", "", "launch Exodus with a generated bridge pipe and capability")
	defaultArtifactDir := filepath.Join(os.TempDir(), "exodus-mcp", "artifacts")
	artifactDir := flag.String("artifacts", envOrDefault("EXODUS_MCP_ARTIFACTS", defaultArtifactDir), "directory for immutable tool artifacts")
	artifactTTL := flag.Duration("artifact-ttl", envDurationOrDefault("EXODUS_MCP_ARTIFACT_TTL", 0), "retention lifetime for tool artifacts (0 disables background expiry; e.g. 24h)")
	defaultStatesDir := filepath.Join(os.TempDir(), "exodus-mcp", "states")
	statesDir := flag.String("states", envOrDefault("EXODUS_MCP_STATES_DIR", defaultStatesDir), "directory anchoring context-scoped system snapshots")
	baseURL := flag.String("base-url", "", "external base URL advertised in artifact links; defaults to the listen address's loopback port")
	defaultScriptsDir := filepath.Join(os.TempDir(), "exodus-mcp", "scripts")
	scriptsDir := flag.String("scripts", envOrDefault("EXODUS_MCP_SCRIPTS_DIR", defaultScriptsDir), "directory containing allowed experiment scripts (.py) and fixtures (.json)")
	pythonCmd := flag.String("python", os.Getenv("EXODUS_MCP_PYTHON"), "Python 3 interpreter used for .py experiment scripts")
	experimentTimeout := flag.Duration("experiment-timeout", experiment.MaxTimeout, "hard wall-clock cap for one experiment_run (per-run timeout_ms is clamped to it)")
	experimentMaxSteps := flag.Int("experiment-max-steps", experiment.DefaultMaxSteps, "maximum tool steps in one experiment run")
	experimentMaxOutputBytes := flag.Int64("experiment-max-output-bytes", experiment.DefaultMaxOutputBytes, "maximum script-published artifact size and captured stderr per experiment run")
	var exodusArguments stringList
	flag.Var(&exodusArguments, "exodus-arg", "argument passed to Exodus; repeat for multiple arguments")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return
	}
	*baseURL = resolveBaseURL(*listen, *baseURL)
	store, err := artifact.NewStore(*artifactDir)
	if err != nil {
		log.Fatal(err)
	}
	if *artifactTTL > 0 {
		runArtifactSweeper(store, *artifactTTL)
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen on %s: %v", *listen, err)
	}
	defer listener.Close()

	var exodus *exec.Cmd
	var exodusDone <-chan error
	if *exodusExecutable != "" {
		config, err := bridge.NewLaunchConfig(*exodusExecutable, exodusArguments)
		if err != nil {
			log.Fatal(err)
		}
		exodus, err = bridge.StartExodus(config)
		if err != nil {
			log.Fatal(err)
		}
		exodusDone = waitForProcess(exodus.Wait)
		*pipeName = config.PipeName
		*pipeCapability = config.Capability
		log.Printf("started Exodus with an authenticated local bridge on %s", config.PipeName)
	}

	client := bridge.NewNamedPipeClient(*pipeName, *pipeCapability)
	mcpServer := mcp.NewServer(version, client, store, analysis.NewRegistry(), *baseURL)
	mcpServer.SetStatesDir(*statesDir)
	experimentRunner, err := experiment.NewRunner(experiment.Config{
		ScriptsDir:      *scriptsDir,
		PythonCmd:       *pythonCmd,
		MaxTimeout:      *experimentTimeout,
		MaxSteps:        *experimentMaxSteps,
		MaxOutputBytes:  *experimentMaxOutputBytes,
		ArtifactBaseURL: *baseURL,
	}, store)
	if err != nil {
		log.Fatal(err)
	}
	mcpServer.SetExperimentRunner(experimentRunner)
	server := &http.Server{
		Addr:    *listen,
		Handler: mcpServer.Handler(),
	}

	log.Printf("exodus-mcp listening on http://%s/mcp", *listen)
	log.Printf("artifact store at %s", store.Dir())
	if *artifactTTL > 0 {
		log.Printf("artifact retention: %s (expiry sweep active)", *artifactTTL)
	} else {
		log.Printf("artifact retention: unlimited (set --artifact-ttl / EXODUS_MCP_ARTIFACT_TTL to enable expiry)")
	}
	log.Printf("state snapshots at %s", *statesDir)
	log.Printf("experiment scripts at %s", *scriptsDir)
	if exodusDone == nil {
		log.Fatal(server.Serve(listener))
	}
	if err := runUntilExodusExits(server, exodusDone, func() error {
		return server.Serve(listener)
	}, func() error {
		return stopExodus(exodus)
	}); err != nil {
		log.Fatal(err)
	}
}

func portOf(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return "8767"
	}
	return port
}

// resolveBaseURL derives the artifact-link base from the final listen address
// unless an explicit base URL was supplied. It must run after flag.Parse so
// the advertised port always matches the bound one.
func resolveBaseURL(listenAddress, explicit string) string {
	if explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	return fmt.Sprintf("http://127.0.0.1:%s", portOf(listenAddress))
}

// envOrDefault resolves launch configuration from the process environment so
// wrapper scripts can supply .env values; explicit flags still win.
func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// envDurationOrDefault resolves a duration configuration value the same way,
// logging and ignoring an unparsable value instead of failing the launch.
func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	if raw := os.Getenv(key); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			return parsed
		}
		log.Printf("ignoring invalid %s=%q (want a duration such as 24h)", key, raw)
	}
	return fallback
}

// runArtifactSweeper expires artifacts older than the configured TTL on a
// background ticker. The interval sits between one minute and one hour and is
// half the TTL, so a fresh artifact can be deleted at most one interval after
// it passes the cutoff. The goroutine dies with the process; the store is
// otherwise only touched under its own lock.
func runArtifactSweeper(store *artifact.Store, ttl time.Duration) {
	interval := ttl / 2
	if interval < time.Minute {
		interval = time.Minute
	}
	if interval > time.Hour {
		interval = time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			removed, err := store.ExpireOlderThan(ttl)
			if err != nil {
				log.Printf("artifact sweep: %v", err)
				continue
			}
			if removed > 0 {
				log.Printf("artifact sweep: removed %d expired artifact(s)", removed)
			}
		}
	}()
}

func waitForProcess(wait func() error) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- wait()
	}()
	return done
}

func stopExodus(exodus *exec.Cmd) error {
	if exodus == nil || exodus.Process == nil {
		return nil
	}
	if err := exodus.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("terminate Exodus after MCP server exit: %w", err)
	}
	return nil
}

func runUntilExodusExits(server *http.Server, exodusDone <-chan error, serve func() error, stop func() error) error {
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serve()
	}()

	select {
	case err := <-serverDone:
		if stopErr := stop(); stopErr != nil {
			return stopErr
		}
		return err
	case err := <-exodusDone:
		if err != nil {
			log.Printf("Exodus process exited: %v", err)
		} else {
			log.Print("Exodus process exited; shutting down exodus-mcp")
		}
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if shutdownErr := server.Shutdown(shutdownContext); shutdownErr != nil {
			return fmt.Errorf("shut down MCP server after Exodus exit: %w", shutdownErr)
		}
		if serverErr := <-serverDone; serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
			return serverErr
		}
		return nil
	}
}
