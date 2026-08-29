package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindExodusBeside(t *testing.T) {
	dir := t.TempDir()
	if got := findExodusBeside(dir); got != "" {
		t.Fatalf("findExodusBeside on empty dir = %q, want \"\"", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "exodus.exe"), []byte("binary"), 0o644); err != nil {
		t.Fatalf("write exodus.exe: %v", err)
	}
	if got := findExodusBeside(dir); got != filepath.Join(dir, "exodus.exe") {
		t.Fatalf("findExodusBeside with lowercase exe = %q, want %q", got, filepath.Join(dir, "exodus.exe"))
	}

	upperDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(upperDir, "Exodus.exe"), []byte("binary"), 0o644); err != nil {
		t.Fatalf("write Exodus.exe: %v", err)
	}
	if got := findExodusBeside(upperDir); got != filepath.Join(upperDir, "Exodus.exe") {
		t.Fatalf("findExodusBeside with capitalized exe = %q, want %q", got, filepath.Join(upperDir, "Exodus.exe"))
	}

	// A directory named exodus.exe must not be mistaken for the emulator.
	dirOnly := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirOnly, "exodus.exe"), 0o755); err != nil {
		t.Fatalf("mkdir exodus.exe: %v", err)
	}
	if got := findExodusBeside(dirOnly); got != "" {
		t.Fatalf("findExodusBeside with exodus.exe directory = %q, want \"\"", got)
	}
}

func TestResolveBaseURLFollowsListenAddress(t *testing.T) {
	cases := []struct {
		name     string
		listen   string
		explicit string
		want     string
	}{
		{"default port", "127.0.0.1:8768", "", "http://127.0.0.1:8768"},
		{"custom listen wins", "127.0.0.1:9000", "", "http://127.0.0.1:9000"},
		{"explicit beats listen", "127.0.0.1:9000", "http://127.0.0.1:9000/", "http://127.0.0.1:9000"},
		{"missing port falls back", "127.0.0.1", "", "http://127.0.0.1:8768"},
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
