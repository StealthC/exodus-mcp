package experiment

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveAndReadPythonAndJSON(t *testing.T) {
	root := t.TempDir()
	writeScript(t, root, "scan.py", "print('hello')\n")
	writeScript(t, root, "fixture.json", `{"version":1,"steps":[]}`)

	script, err := ResolveAndRead(root, "scan.py")
	if err != nil {
		t.Fatalf("resolve scan.py: %v", err)
	}
	if script.Kind != "python" || script.Name != "scan.py" || script.SHA256 == "" {
		t.Fatalf("python script metadata wrong: %+v", script)
	}
	// ResolveAndRead reports the canonicalized absolute path; on Windows
	// EvalSymlinks normalizes drive-letter and component case, so compare
	// canonical to canonical instead of against the raw joined path.
	wantPath, err := filepath.EvalSymlinks(filepath.Join(root, "scan.py"))
	if err != nil {
		t.Fatalf("resolve expected path: %v", err)
	}
	if script.Path != wantPath {
		t.Fatalf("path = %q, want %q", script.Path, wantPath)
	}
	fixture, err := ResolveAndRead(root, "fixture.json")
	if err != nil {
		t.Fatalf("resolve fixture.json: %v", err)
	}
	if fixture.Kind != "json" {
		t.Fatalf("fixture kind = %q", fixture.Kind)
	}
}

func TestResolveRejectsNonPlainNames(t *testing.T) {
	root := t.TempDir()
	writeScript(t, root, "scan.py", "")
	for _, name := range []string{"", ".", "..", "sub/scan.py", `sub\scan.py`, "/tmp/scan.py", "scan.py\x00x"} {
		_, err := ResolveAndRead(root, name)
		if !errors.Is(err, ErrScriptDisallowed) {
			t.Fatalf("name %q: err = %v, want ErrScriptDisallowed", name, err)
		}
	}
}

func TestResolveRejectsWrongExtension(t *testing.T) {
	root := t.TempDir()
	writeScript(t, root, "scan.txt", "")
	writeScript(t, root, "scan.sh", "")
	for _, name := range []string{"scan.txt", "scan.sh", "noext"} {
		_, err := ResolveAndRead(root, name)
		if !errors.Is(err, ErrScriptDisallowed) {
			t.Fatalf("name %q: err = %v, want ErrScriptDisallowed", name, err)
		}
	}
}

func TestResolveRejectsMissingFile(t *testing.T) {
	_, err := ResolveAndRead(t.TempDir(), "missing.py")
	if !errors.Is(err, ErrScriptNotFound) {
		t.Fatalf("err = %v, want ErrScriptNotFound", err)
	}
}

func TestResolveRejectsDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dir.py"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := ResolveAndRead(root, "dir.py")
	if !errors.Is(err, ErrScriptDisallowed) {
		t.Fatalf("err = %v, want ErrScriptDisallowed", err)
	}
}

func TestResolveRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.py")
	writeScript(t, outside, "secret.py", "evil")
	link := filepath.Join(root, "link.py")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks: %v", err)
	}
	_, err := ResolveAndRead(root, "link.py")
	if !errors.Is(err, ErrScriptDisallowed) {
		t.Fatalf("err = %v, want ErrScriptDisallowed", err)
	}
}

func TestResolveRejectsOversizedScript(t *testing.T) {
	root := t.TempDir()
	writeScript(t, root, "huge.py", strings.Repeat("x", maxScriptBytes+1))
	_, err := ResolveAndRead(root, "huge.py")
	if !errors.Is(err, ErrScriptTooLarge) {
		t.Fatalf("err = %v, want ErrScriptTooLarge", err)
	}
}
