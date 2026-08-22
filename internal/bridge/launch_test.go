package bridge

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLaunchConfigGeneratesIndependentCredentials(t *testing.T) {
	first, err := NewLaunchConfig("Exodus.exe", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewLaunchConfig("Exodus.exe", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.PipeName, pipePrefix) || first.Capability == "" {
		t.Fatalf("invalid launch configuration: %#v", first)
	}
	if first.PipeName == second.PipeName || first.Capability == second.Capability {
		t.Fatal("launch credentials must be unique")
	}
}

func TestNewExodusCommandUsesExecutableDirectory(t *testing.T) {
	executable := filepath.Join("testdata", "Exodus.exe")
	command := newExodusCommand(LaunchConfig{
		Executable: executable,
		PipeName:   pipePrefix + "test",
		Capability: "test",
	})
	if command.Dir != filepath.Dir(executable) {
		t.Fatalf("working directory = %q, want %q", command.Dir, filepath.Dir(executable))
	}
}
