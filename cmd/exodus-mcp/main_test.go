package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func TestResolveBaseURLFollowsListenAddress(t *testing.T) {
	cases := []struct {
		name     string
		listen   string
		explicit string
		want     string
	}{
		{"default port", "127.0.0.1:8767", "", "http://127.0.0.1:8767"},
		{"custom listen wins", "127.0.0.1:9000", "", "http://127.0.0.1:9000"},
		{"explicit beats listen", "127.0.0.1:9000", "http://127.0.0.1:9000/", "http://127.0.0.1:9000"},
		{"missing port falls back", "127.0.0.1", "", "http://127.0.0.1:8767"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := resolveBaseURL(testCase.listen, testCase.explicit)
			if got != testCase.want {
				t.Fatalf("resolveBaseURL(%q, %q) = %q, want %q", testCase.listen, testCase.explicit, got, testCase.want)
			}
		})
	}
}

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
