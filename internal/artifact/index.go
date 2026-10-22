package artifact

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Artifact discovery (roadmap issue #10): one per-context index over the
// artifacts a store already persists, so an agent can enumerate what exists in
// a context instead of copying ids out of earlier responses.
//
// The index is kept in memory and mirrored to a single JSON document inside the
// store directory. It is rewritten atomically on every mutation, so a restarted
// server reopens the artifacts it wrote instead of discarding them; the store
// still removes files no index entry claims, so a partially written or
// hand-placed file never becomes an artifact.

const (
	// indexFileName is the persisted metadata document. It never matches the
	// artifact id pattern, and the startup sweep skips it explicitly.
	indexFileName = "artifact-index.json"
	// indexSchema is the versioned index document. A future revision is a
	// separate version, never a silent shape change.
	indexSchema = "artifact-index/1"

	// DefaultListLimit and MaxListLimit bound one artifact_list page.
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// ErrInvalidCursor is returned when a list cursor is malformed or points past
// the filtered listing.
var ErrInvalidCursor = errors.New("invalid artifact cursor")

// ListQuery filters one artifact_list page. Empty fields do not filter; Limit
// defaults to DefaultListLimit and is capped at MaxListLimit.
type ListQuery struct {
	ContextID string
	Kind      string
	CaptureID string
	Cursor    string
	Limit     int
}

// ListPage is one page of the filtered, creation-ordered artifact listing.
type ListPage struct {
	Artifacts  []Artifact
	Total      int
	HasMore    bool
	NextCursor string
}

// List returns one page of the artifacts of a context, ordered by creation time
// and then by id so repeated pages are stable. CaptureID matches the capture id
// the artifact's provenance carries.
func (store *Store) List(query ListQuery) (ListPage, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = DefaultListLimit
	}
	if limit > MaxListLimit {
		limit = MaxListLimit
	}
	offset, err := decodeListCursor(query.Cursor)
	if err != nil {
		return ListPage{}, err
	}
	store.mu.RLock()
	matches := make([]Artifact, 0, len(store.artifacts))
	for _, stored := range store.artifacts {
		if stored.ContextID != query.ContextID {
			continue
		}
		if query.Kind != "" && stored.Kind != query.Kind {
			continue
		}
		if query.CaptureID != "" && captureIDOf(stored) != query.CaptureID {
			continue
		}
		matches = append(matches, stored)
	}
	store.mu.RUnlock()
	sort.Slice(matches, func(left, right int) bool {
		if matches[left].CreatedAt.Equal(matches[right].CreatedAt) {
			return matches[left].ID < matches[right].ID
		}
		return matches[left].CreatedAt.Before(matches[right].CreatedAt)
	})
	total := len(matches)
	if offset > total {
		return ListPage{}, fmt.Errorf("%w: offset %d is past the %d matching artifacts", ErrInvalidCursor, offset, total)
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := ListPage{
		Artifacts: append([]Artifact{}, matches[offset:end]...),
		Total:     total,
		HasMore:   end < total,
	}
	if page.HasMore {
		page.NextCursor = encodeListCursor(end)
	}
	return page, nil
}

// Retention reports the TTL the store currently enforces (0 means unlimited).
func (store *Store) Retention() time.Duration {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.retention
}

// SetRetention records the TTL the store enforces, so listing can report the
// expiry of each artifact before a download fails. A non-positive TTL means
// unlimited retention. The value is persisted with the index.
func (store *Store) SetRetention(ttl time.Duration) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if ttl < 0 {
		ttl = 0
	}
	if ttl == store.retention {
		return nil
	}
	store.retention = ttl
	return store.persistIndexLocked()
}

// ExpiresAt returns the expiry instant of an artifact created at the given
// time, or nil when retention is unlimited.
func (store *Store) ExpiresAt(createdAt time.Time) *time.Time {
	ttl := store.Retention()
	if ttl <= 0 {
		return nil
	}
	expiry := createdAt.Add(ttl).UTC()
	return &expiry
}

// captureIDOf returns the capture id an artifact's provenance carries, if any.
func captureIDOf(stored Artifact) string {
	if stored.Provenance == nil {
		return ""
	}
	return stored.Provenance.CaptureID
}

// listCursorPrefix versions the cursor encoding so a future revision can reject
// old cursors instead of misreading them.
const listCursorPrefix = "o1."

func encodeListCursor(offset int) string {
	return listCursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

func decodeListCursor(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	encoded, ok := strings.CutPrefix(cursor, listCursorPrefix)
	if !ok {
		return 0, fmt.Errorf("%w: %q is not a cursor this server issued", ErrInvalidCursor, cursor)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not a cursor this server issued", ErrInvalidCursor, cursor)
	}
	offset, err := strconv.Atoi(string(decoded))
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("%w: %q is not a cursor this server issued", ErrInvalidCursor, cursor)
	}
	return offset, nil
}

// indexDocument is the persisted form of both indexes.
type indexDocument struct {
	SchemaVersion    string     `json:"schema_version"`
	RetentionSeconds int64      `json:"retention_seconds,omitempty"`
	Artifacts        []Artifact `json:"artifacts"`
	Captures         []Capture  `json:"captures,omitempty"`
}

// indexFilePath is the persisted index location.
func (store *Store) indexFilePath() string { return filepath.Join(store.dir, indexFileName) }

// loadIndexLocked rebuilds the in-memory indexes from disk. Artifacts whose
// backing file disappeared are dropped instead of being advertised as readable.
func (store *Store) loadIndex() error {
	data, err := os.ReadFile(store.indexFilePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read artifact index: %w", err)
	}
	var document indexDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse artifact index %s: %w", store.indexFilePath(), err)
	}
	if document.SchemaVersion != indexSchema {
		return fmt.Errorf("artifact index %s has unsupported schema %q (want %q)", store.indexFilePath(), document.SchemaVersion, indexSchema)
	}
	store.retention = time.Duration(document.RetentionSeconds) * time.Second
	for _, stored := range document.Artifacts {
		if !idPattern.MatchString(stored.ID) || stored.ContextID == "" {
			continue
		}
		if _, err := os.Stat(store.path(stored.ID)); err != nil {
			continue
		}
		store.artifacts[stored.ID] = stored
	}
	for _, capture := range document.Captures {
		if !captureIDPattern.MatchString(capture.CaptureID) || capture.ContextID == "" {
			continue
		}
		store.captures[capture.CaptureID] = capture
	}
	return nil
}

// persistIndexLocked rewrites the index document atomically. The caller must
// hold the write lock.
func (store *Store) persistIndexLocked() error {
	document := indexDocument{
		SchemaVersion:    indexSchema,
		RetentionSeconds: int64(store.retention / time.Second),
		Artifacts:        make([]Artifact, 0, len(store.artifacts)),
		Captures:         make([]Capture, 0, len(store.captures)),
	}
	for _, stored := range store.artifacts {
		document.Artifacts = append(document.Artifacts, stored)
	}
	for _, capture := range store.captures {
		document.Captures = append(document.Captures, capture)
	}
	sort.Slice(document.Artifacts, func(left, right int) bool {
		return document.Artifacts[left].ID < document.Artifacts[right].ID
	})
	sort.Slice(document.Captures, func(left, right int) bool {
		return document.Captures[left].CaptureID < document.Captures[right].CaptureID
	})
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode artifact index: %w", err)
	}
	temp, err := os.CreateTemp(store.dir, ".artifact-index-*.tmp")
	if err != nil {
		return fmt.Errorf("create artifact index: %w", err)
	}
	tempName := temp.Name()
	if _, err = temp.Write(encoded); err != nil {
		_ = temp.Close()
		_ = os.Remove(tempName)
		return fmt.Errorf("write artifact index: %w", err)
	}
	if err = temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("close artifact index: %w", err)
	}
	if err = os.Rename(tempName, store.indexFilePath()); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("replace artifact index: %w", err)
	}
	return nil
}
