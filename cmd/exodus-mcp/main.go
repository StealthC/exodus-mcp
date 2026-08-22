// Command exodus-mcp provides the local HTTP endpoint for Exodus MCP.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/StealthC/exodus-mcp/internal/mcp"
)

var version = "dev"

func main() {
	listen := flag.String("listen", "127.0.0.1:8767", "local address for the MCP HTTP endpoint")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return
	}

	server := &http.Server{
		Addr:    *listen,
		Handler: mcp.NewHandler(version),
	}

	log.Printf("exodus-mcp listening on http://%s/mcp", *listen)
	log.Fatal(server.ListenAndServe())
}
