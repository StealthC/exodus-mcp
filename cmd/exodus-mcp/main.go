// Command exodus-mcp is the future local HTTP endpoint for the Exodus MCP bridge.
//
// The current scaffold deliberately exposes only a health endpoint. It does not
// claim MCP conformance until the 2026-07-28 transport validation suite exists.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

var version = "dev"

func main() {
	listen := flag.String("listen", "127.0.0.1:8767", "local address for the development health endpoint")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)

	server := &http.Server{
		Addr:    *listen,
		Handler: mux,
	}

	log.Printf("exodus-mcp scaffold listening on http://%s/healthz", *listen)
	log.Fatal(server.ListenAndServe())
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "scaffold",
		"version": version,
	})
}
