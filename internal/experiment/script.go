package experiment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Script resolution errors, mapped to stable tool failure codes by the MCP
// layer.
var (
	ErrScriptNotFound   = errors.New("experiment script not found")
	ErrScriptDisallowed = errors.New("experiment script path disallowed")
	ErrScriptTooLarge   = errors.New("experiment script too large")
)

// Script is one validated experiment script or fixture loaded from the
// configured scripts directory.
type Script struct {
	// Name is the plain file name as requested by the caller.
	Name string
	// Kind is "python" for .py files or "json" for declarative fixtures.
	Kind string
	// Path is the canonicalized absolute file path.
	Path string
	// SHA256 is the digest of the script bytes, recorded in the manifest.
	SHA256 string
	// Data holds the script or fixture bytes.
	Data []byte
}

// ResolveAndRead loads one script from the scripts root. Only plain file
// names ending in .py or .json are accepted: no path separators, no
// traversal, no symlinks escaping the root, and no non-regular files. The
// digest is computed before any execution so the manifest can reproduce the
// exact bytes that ran.
func ResolveAndRead(root, name string) (*Script, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: empty script name", ErrScriptDisallowed)
	}
	if strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return nil, fmt.Errorf("%w: %q is not a plain file name", ErrScriptDisallowed, name)
	}
	if name == "." || name == ".." {
		return nil, fmt.Errorf("%w: %q is not a valid script name", ErrScriptDisallowed, name)
	}
	kind := ""
	switch strings.ToLower(filepath.Ext(name)) {
	case ".py":
		kind = "python"
	case ".json":
		kind = "json"
	default:
		return nil, fmt.Errorf("%w: %q must end in .py or .json", ErrScriptDisallowed, name)
	}

	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("%w: scripts root %q: %v", ErrScriptNotFound, root, err)
	}
	realPath, err := filepath.EvalSymlinks(filepath.Join(root, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %q", ErrScriptNotFound, name)
		}
		return nil, fmt.Errorf("%w: %q: %v", ErrScriptDisallowed, name, err)
	}
	relative, err := filepath.Rel(realRoot, realPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%w: %q escapes the scripts root", ErrScriptDisallowed, name)
	}
	info, err := os.Stat(realPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrScriptNotFound, name)
	}
	if info.IsDir() || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrScriptDisallowed, name)
	}
	data, err := os.ReadFile(realPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrScriptNotFound, name, err)
	}
	if len(data) > maxScriptBytes {
		return nil, fmt.Errorf("%w: %q is larger than %d bytes", ErrScriptTooLarge, name, maxScriptBytes)
	}
	digest := sha256.Sum256(data)
	return &Script{
		Name:   name,
		Kind:   kind,
		Path:   realPath,
		SHA256: hex.EncodeToString(digest[:]),
		Data:   data,
	}, nil
}
