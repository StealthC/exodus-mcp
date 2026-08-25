// Package artifact implements the immutable, context-scoped artifact store
// that keeps high-volume emulator output out of model context.
package artifact

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxPreviewBytes = 4096

// MaxPreviewBytes is the hard cap for bounded artifact previews.
const MaxPreviewBytes = maxPreviewBytes

// ErrUnknownArtifact is returned when an id does not resolve in the caller's
// context, or is structurally invalid.
var ErrUnknownArtifact = errUnknownArtifact

var errUnknownArtifact = errors.New("unknown artifact")

// Artifact is the bounded metadata returned in tool results.
type Artifact struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	MimeType  string    `json:"mime_type"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	ContextID string    `json:"context_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Store persists immutable artifacts on disk with an in-memory index.
type Store struct {
	dir       string
	mu        sync.RWMutex
	artifacts map[string]Artifact
}

// NewStore creates or reopens a store directory. Stale files from earlier
// sessions are removed because the index is intentionally session-scoped.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create artifact directory: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("scan artifact directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return nil, fmt.Errorf("clean stale artifact: %w", err)
			}
		}
	}
	return &Store{dir: dir, artifacts: make(map[string]Artifact)}, nil
}

// Dir reports the backing directory.
func (store *Store) Dir() string { return store.dir }

// ExpireOlderThan removes artifacts created before the given age, deleting
// their backing files, and returns how many were removed. A non-positive TTL
// disables expiry and never removes anything. Unknown-file removal errors are
// surfaced so an operator can notice a broken store, but the sweep continues
// reporting the count of artifacts removed so far this pass.
func (store *Store) ExpireOlderThan(ttl time.Duration) (int, error) {
	if ttl <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-ttl)
	store.mu.Lock()
	defer store.mu.Unlock()
	removed := 0
	for id, artifact := range store.artifacts {
		if artifact.CreatedAt.After(cutoff) {
			continue
		}
		if err := os.Remove(store.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("remove expired artifact: %w", err)
		}
		delete(store.artifacts, id)
		removed++
	}
	return removed, nil
}

// Put writes one immutable artifact and returns its descriptor.
func (store *Store) Put(contextID, kind, mimeType string, data []byte) (Artifact, error) {
	id, err := newID()
	if err != nil {
		return Artifact{}, err
	}
	sum := sha256.Sum256(data)
	artifact := Artifact{
		ID:        id,
		Kind:      kind,
		MimeType:  mimeType,
		SizeBytes: int64(len(data)),
		SHA256:    hex.EncodeToString(sum[:]),
		ContextID: contextID,
		CreatedAt: time.Now().UTC(),
	}
	if err := os.WriteFile(store.path(id), data, 0o600); err != nil {
		return Artifact{}, fmt.Errorf("write artifact bytes: %w", err)
	}
	store.mu.Lock()
	store.artifacts[id] = artifact
	store.mu.Unlock()
	return artifact, nil
}

// Metadata resolves one artifact scoped to an analysis context.
func (store *Store) Metadata(id, contextID string) (Artifact, error) {
	artifact, err := store.lookup(id, contextID)
	if err != nil {
		return Artifact{}, err
	}
	info, err := os.Stat(store.path(id))
	if err != nil {
		return Artifact{}, fmt.Errorf("stat artifact bytes: %w", err)
	}
	artifact.SizeBytes = info.Size()
	return artifact, nil
}

// Bytes returns the immutable content of one context-scoped artifact.
func (store *Store) Bytes(id, contextID string) ([]byte, Artifact, error) {
	artifact, err := store.lookup(id, contextID)
	if err != nil {
		return nil, Artifact{}, err
	}
	data, err := os.ReadFile(store.path(id))
	if err != nil {
		return nil, Artifact{}, fmt.Errorf("read artifact bytes: %w", err)
	}
	return data, artifact, nil
}

// Preview renders a bounded textual view of one artifact.
func (store *Store) Preview(id, contextID string, offset, length int64, mode string) (map[string]any, error) {
	if length <= 0 {
		length = 512
	}
	if length > maxPreviewBytes {
		return nil, fmt.Errorf("preview length is capped at %d bytes", maxPreviewBytes)
	}
	data, artifact, err := store.Bytes(id, contextID)
	if err != nil {
		return nil, err
	}
	if offset < 0 || offset > int64(len(data)) {
		return nil, errors.New("preview offset outside the artifact")
	}
	end := offset + length
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	slice := data[offset:end]
	preview := map[string]any{
		"artifact_id": artifact.ID,
		"mime_type":   artifact.MimeType,
		"size_bytes":  artifact.SizeBytes,
		"offset":      offset,
		"length":      len(slice),
		"mode":        mode,
		"truncated":   end < int64(len(data)),
	}
	switch mode {
	case "text":
		preview["text"] = sanitizeText(slice)
	case "base64":
		preview["data_base64"] = base64Encode(slice)
	default:
		preview["hex"] = HexDump(slice, offset)
	}
	return preview, nil
}

var idPattern = regexp.MustCompile(`^art_[0-9A-Za-z_-]{8,32}$`)

func (store *Store) lookup(id, contextID string) (Artifact, error) {
	if !idPattern.MatchString(id) {
		return Artifact{}, errUnknownArtifact
	}
	store.mu.RLock()
	artifact, present := store.artifacts[id]
	store.mu.RUnlock()
	if !present || artifact.ContextID != contextID {
		return Artifact{}, errUnknownArtifact
	}
	return artifact, nil
}

func (store *Store) path(id string) string { return filepath.Join(store.dir, id) }

// Handler serves GET /artifacts/{id} with ETag and single byte-range support,
// using the same loopback authentication posture as the MCP endpoint.
func (store *Store) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		prefix := "/artifacts/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, prefix)
		data, artifact, err := store.Bytes(id, artifactContextFromRequest(r))
		if err != nil {
			http.Error(w, "unknown artifact", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", artifact.MimeType)
		w.Header().Set("ETag", `"sha256-`+artifact.SHA256+`"`)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Cache-Control", "private, max-age=3600")
		if match := r.Header.Get("If-None-Match"); match != "" && match == `"sha256-`+artifact.SHA256+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		start, end, status := resolveRange(r.Header.Get("Range"), int64(len(data)))
		if status == http.StatusRequestedRangeNotSatisfiable {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(data)))
			http.Error(w, "requested range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.WriteHeader(status)
		if status == http.StatusPartialContent {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
			w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
			if r.Method != http.MethodHead {
				_, _ = w.Write(data[start : end+1])
			}
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(int64(len(data)), 10))
		if r.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
	})
}

func artifactContextFromRequest(r *http.Request) string {
	contextID := r.URL.Query().Get("context")
	if contextID == "" {
		contextID = r.Header.Get("X-Exodus-Context")
	}
	return contextID
}

func resolveRange(header string, size int64) (int64, int64, int) {
	if header == "" {
		return 0, size - 1, http.StatusOK
	}
	spec, ok := strings.CutPrefix(header, "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return 0, 0, http.StatusRequestedRangeNotSatisfiable
	}
	dash := strings.Index(spec, "-")
	if dash < 0 {
		return 0, 0, http.StatusRequestedRangeNotSatisfiable
	}
	startText, endText := spec[:dash], spec[dash+1:]
	if startText == "" {
		suffix, err := strconv.ParseInt(endText, 10, 64)
		if err != nil || suffix <= 0 {
			return 0, 0, http.StatusRequestedRangeNotSatisfiable
		}
		if suffix > size {
			suffix = size
		}
		start := size - suffix
		if size == 0 {
			return 0, -1, http.StatusRequestedRangeNotSatisfiable
		}
		return start, size - 1, http.StatusPartialContent
	}
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, http.StatusRequestedRangeNotSatisfiable
	}
	end := size - 1
	if endText != "" {
		if end, err = strconv.ParseInt(endText, 10, 64); err != nil || end < start {
			return 0, 0, http.StatusRequestedRangeNotSatisfiable
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end, http.StatusPartialContent
}

func newID() (string, error) {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate artifact id: %w", err)
	}
	return "art_" + base64URLEncode(buffer), nil
}
