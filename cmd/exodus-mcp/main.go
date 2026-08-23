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
	"path/filepath"
	"strings"
	"time"

	"github.com/StealthC/exodus-mcp/internal/analysis"
	"github.com/StealthC/exodus-mcp/internal/artifact"
	"github.com/StealthC/exodus-mcp/internal/bridge"
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
	listen := flag.String("listen", "127.0.0.1:8767", "local address for the MCP HTTP endpoint")
	pipeName := flag.String("pipe-name", os.Getenv("EXODUS_MCP_PIPE_NAME"), "Windows named pipe used by ExodusMcpPlugin")
	pipeCapability := flag.String("pipe-capability", os.Getenv("EXODUS_MCP_CAPABILITY"), "capability for the Windows named pipe")
	exodusExecutable := flag.String("exodus", "", "launch Exodus with a generated bridge pipe and capability")
	defaultArtifactDir := filepath.Join(os.TempDir(), "exodus-mcp", "artifacts")
	artifactDir := flag.String("artifacts", defaultArtifactDir, "directory for immutable tool artifacts")
	baseURL := flag.String("base-url", fmt.Sprintf("http://127.0.0.1:%s", portOf(*listen)), "external base URL advertised in artifact links")
	var exodusArguments stringList
	flag.Var(&exodusArguments, "exodus-arg", "argument passed to Exodus; repeat for multiple arguments")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return
	}
	var exodusDone <-chan error
	if *exodusExecutable != "" {
		config, err := bridge.NewLaunchConfig(*exodusExecutable, exodusArguments)
		if err != nil {
			log.Fatal(err)
		}
		exodus, err := bridge.StartExodus(config)
		if err != nil {
			log.Fatal(err)
		}
		exodusDone = waitForProcess(exodus.Wait)
		*pipeName = config.PipeName
		*pipeCapability = config.Capability
		log.Printf("started Exodus with an authenticated local bridge on %s", config.PipeName)
	}

	store, err := artifact.NewStore(*artifactDir)
	if err != nil {
		log.Fatal(err)
	}
	client := bridge.NewNamedPipeClient(*pipeName, *pipeCapability)
	server := &http.Server{
		Addr:    *listen,
		Handler: mcp.NewServer(version, client, store, analysis.NewRegistry(), *baseURL).Handler(),
	}

	log.Printf("exodus-mcp listening on http://%s/mcp", *listen)
	log.Printf("artifact store at %s", store.Dir())
	if exodusDone == nil {
		log.Fatal(server.ListenAndServe())
	}
	if err := runUntilExodusExits(server, exodusDone, server.ListenAndServe); err != nil {
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

func waitForProcess(wait func() error) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- wait()
	}()
	return done
}

func runUntilExodusExits(server *http.Server, exodusDone <-chan error, serve func() error) error {
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serve()
	}()

	select {
	case err := <-serverDone:
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
