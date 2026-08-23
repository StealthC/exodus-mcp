package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRunUntilExodusExitsShutsDownServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	server := &http.Server{Handler: http.NotFoundHandler()}
	exodusDone := make(chan error, 1)
	result := make(chan error, 1)
	go func() {
		result <- runUntilExodusExits(server, exodusDone, func() error {
			return server.Serve(listener)
		})
	}()

	exodusDone <- nil
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runUntilExodusExits: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop after Exodus exited")
	}
}
