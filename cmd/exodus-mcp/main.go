// Command exodus-mcp provides the local HTTP endpoint for Exodus MCP.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/StealthC/exodus-mcp/internal/bridge"
	"github.com/StealthC/exodus-mcp/internal/mcp"
)

var version = "dev"

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
	var exodusArguments stringList
	flag.Var(&exodusArguments, "exodus-arg", "argument passed to Exodus; repeat for multiple arguments")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return
	}
	if *exodusExecutable != "" {
		config, err := bridge.NewLaunchConfig(*exodusExecutable, exodusArguments)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := bridge.StartExodus(config); err != nil {
			log.Fatal(err)
		}
		*pipeName = config.PipeName
		*pipeCapability = config.Capability
		log.Printf("started Exodus with an authenticated local bridge on %s", config.PipeName)
	}

	client := bridge.NewNamedPipeClient(*pipeName, *pipeCapability)
	server := &http.Server{
		Addr:    *listen,
		Handler: mcp.NewHandlerWithBridge(version, client),
	}

	log.Printf("exodus-mcp listening on http://%s/mcp", *listen)
	log.Fatal(server.ListenAndServe())
}
