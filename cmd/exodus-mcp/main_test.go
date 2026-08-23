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
		}, func() error { return nil })
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

func TestRunUntilExodusExitsStopsChildWhenServerFails(t *testing.T) {
	server := &http.Server{Handler: http.NotFoundHandler()}
	exodusDone := make(chan error)
	stopped := false
	err := runUntilExodusExits(server, exodusDone, func() error {
		return net.ErrClosed
	}, func() error {
		stopped = true
		return nil
	})
	if err != net.ErrClosed {
		t.Fatalf("runUntilExodusExits error = %v, want %v", err, net.ErrClosed)
	}
	if !stopped {
		t.Fatal("child was not stopped after server failure")
	}
}
