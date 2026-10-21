package tracing

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ManifestSchema is the versioned schema of a durable trace-session manifest.
const ManifestSchema = "trace-session-manifest/1"

// Manifest is the durable, restart-surviving description of one session: its
// configuration, the limits that were actually in force, the ROM identity it
// was bound to, its explicit loss accounting, the counters it reached, and the
// artifacts that hold its raw records.
//
// A manifest never claims more than survived. Raw access and execution events
// live in the event store and in exported artifacts; the manifest records the
// counters, the loss, and the artifact ids so a restarted server can tell what
// existed and can reload whatever artifact still exists.
type Manifest struct {
	Schema       string    `json:"schema"`
	SessionID    string    `json:"session_id"`
	ContextID    string    `json:"context_id"`
	CPU          string    `json:"cpu"`
	AddressSpace string    `json:"address_space"`
	ByteOrder    string    `json:"byte_order"`
	StartedAt    time.Time `json:"started_at"`
	StoppedAt    time.Time `json:"stopped_at,omitempty"`
	Stopped      bool      `json:"stopped"`
	UpdatedAt    time.Time `json:"updated_at"`

	Config Config `json:"config"`
	Limits Limits `json:"limits"`

	ROMPath                 string `json:"rom_path,omitempty"`
	ROMSHA256               string `json:"rom_sha256,omitempty"`
	TargetGenerationAtStart uint64 `json:"target_generation_at_start,omitempty"`

	Totals     map[string]uint64 `json:"totals,omitempty"`
	Parse      ParseStats        `json:"parse"`
	Access     ParseStats        `json:"access_parse"`
	Loss       Loss              `json:"loss"`
	Retained   int               `json:"retained_events"`
	AccessSeq  uint64            `json:"last_access_sequence,omitempty"`
	Artifacts  []string          `json:"artifacts,omitempty"`
	EventsFile string            `json:"events_file,omitempty"`
	Native     map[string]any    `json:"native,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
}

// Limits states the capacity values a session ran with, so a recovered view
// cannot be mistaken for an unbounded one.
type Limits struct {
	MaxEvents       int `json:"max_events"`
	MaxAddresses    int `json:"max_addresses"`
	MaxWatchSamples int `json:"max_watch_samples"`
}

// NewManifest snapshots one live session into a manifest.
func NewManifest(session *Session, romPath, romSHA256 string, native map[string]any) *Manifest {
	session.mu.Lock()
	defer session.mu.Unlock()
	manifest := &Manifest{
		Schema:                  ManifestSchema,
		SessionID:               session.ID,
		ContextID:               session.ContextID,
		CPU:                     session.CPU,
		AddressSpace:            session.AddressSpace,
		ByteOrder:               byteOrderForCPU(session.CPU),
		StartedAt:               session.StartedAt,
		StoppedAt:               session.StoppedAt,
		Stopped:                 session.Stopped,
		UpdatedAt:               time.Now().UTC(),
		Config:                  session.Config,
		Limits:                  Limits{MaxEvents: session.capMax, MaxAddresses: session.addrCap, MaxWatchSamples: session.sampleCap},
		ROMPath:                 romPath,
		ROMSHA256:               romSHA256,
		TargetGenerationAtStart: session.generationAtStart,
		Parse:                   session.stats,
		Access:                  session.accessStats,
		Loss:                    session.loss,
		Retained:                session.count,
		AccessSeq:               session.lastAccessSequence,
		Artifacts:               append([]string{}, session.artifacts...),
		Native:                  native,
	}
	manifest.Totals = make(map[string]uint64, len(session.totals))
	for key, value := range session.totals {
		manifest.Totals[key] = value
	}
	if session.roAtStart != "" && manifest.ROMPath == "" {
		manifest.ROMPath = session.roAtStart
	}
	return manifest
}

// ManifestPath returns the manifest path for one session inside a root
// directory.
func ManifestPath(root, sessionID string) string {
	return filepath.Join(root, sessionID, "manifest.json")
}

// Save writes the manifest atomically: a crash mid-write leaves the previous
// manifest intact instead of a truncated one.
func (manifest *Manifest) Save(root string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("manifest root is empty")
	}
	directory := filepath.Join(root, manifest.SessionID)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", err
	}
	manifest.UpdatedAt = time.Now().UTC()
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, "manifest.json")
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		return "", err
	}
	return path, nil
}

// LoadManifest reads one manifest file.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	if manifest.Schema != ManifestSchema {
		return nil, fmt.Errorf("unsupported manifest schema %q", manifest.Schema)
	}
	if manifest.SessionID == "" {
		return nil, fmt.Errorf("manifest has no session id")
	}
	return &manifest, nil
}

// ManifestEntry is one recoverable session discovered in a manifest root.
type ManifestEntry struct {
	Path        string    `json:"path"`
	SessionID   string    `json:"session_id"`
	ContextID   string    `json:"context_id"`
	CPU         string    `json:"cpu"`
	Stopped     bool      `json:"stopped"`
	UpdatedAt   time.Time `json:"updated_at"`
	StartedAt   time.Time `json:"started_at"`
	Retained    int       `json:"retained_events"`
	Artifacts   int       `json:"artifacts"`
	ROMSHA256   string    `json:"rom_sha256,omitempty"`
	Recoverable bool      `json:"recoverable"`
	Note        string    `json:"note,omitempty"`
}

// ListManifests discovers every readable manifest under a root, newest first.
func ListManifests(root string) ([]ManifestEntry, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	manifests := make([]ManifestEntry, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name(), "manifest.json")
		manifest, err := LoadManifest(path)
		if err != nil {
			continue
		}
		item := ManifestEntry{
			Path:      path,
			SessionID: manifest.SessionID,
			ContextID: manifest.ContextID,
			CPU:       manifest.CPU,
			Stopped:   manifest.Stopped,
			UpdatedAt: manifest.UpdatedAt,
			StartedAt: manifest.StartedAt,
			Retained:  manifest.Retained,
			Artifacts: len(manifest.Artifacts),
			ROMSHA256: manifest.ROMSHA256,
		}
		item.Recoverable = manifest.EventsFile != ""
		if !item.Recoverable {
			item.Note = "no raw event file was recorded (access_mode off or nothing was exported); the manifest recovers counters and loss only"
		}
		manifests = append(manifests, item)
	}
	sort.Slice(manifests, func(i, j int) bool { return manifests[i].UpdatedAt.After(manifests[j].UpdatedAt) })
	return manifests, nil
}

// RestoreSession rebuilds a read-only Session view from a manifest and the raw
// events that still exist on disk. The restored session is marked stopped and
// reports the manifest's loss verbatim, so a caller can never mistake recovered
// counters for a complete capture.
func RestoreSession(manifest *Manifest, events []Event) *Session {
	session := NewSession(manifest.SessionID, manifest.ContextID, manifest.CPU, manifest.AddressSpace, manifest.Config)
	session.StartedAt = manifest.StartedAt
	session.MarkStarted(manifest.TargetGenerationAtStart, manifest.ROMPath)
	session.MarkROMIdentity(manifest.ROMSHA256)
	session.AddParseStats(manifest.Parse)
	session.AddAccessParseStats(manifest.Access)
	if len(events) > 0 {
		session.AddEvents(events)
	}
	session.mu.Lock()
	session.loss.DroppedEvents += manifest.Loss.DroppedEvents
	session.loss.DroppedAddressCounts += manifest.Loss.DroppedAddressCounts
	session.loss.DroppedWatchSamples += manifest.Loss.DroppedWatchSamples
	session.loss.MalformedLines += manifest.Loss.MalformedLines
	session.loss.TruncatedLines += manifest.Loss.TruncatedLines
	session.loss.EvictedSegments += manifest.Loss.EvictedSegments
	session.loss.EvictedBytes += manifest.Loss.EvictedBytes
	session.loss.EvictedUnreadSegments += manifest.Loss.EvictedUnreadSegments
	session.loss.AccessMalformedLines += manifest.Loss.AccessMalformedLines
	session.loss.AccessTruncatedLines += manifest.Loss.AccessTruncatedLines
	session.loss.EvictedAccessSegments += manifest.Loss.EvictedAccessSegments
	session.loss.EvictedAccessBytes += manifest.Loss.EvictedAccessBytes
	session.loss.EvictedUnreadAccessSegments += manifest.Loss.EvictedUnreadAccessSegments
	session.loss.AccessSequenceGaps += manifest.Loss.AccessSequenceGaps
	session.loss.AccessSequenceGapSamples = append([]string{}, manifest.Loss.AccessSequenceGapSamples...)
	session.loss.Notes = append([]string{}, manifest.Loss.Notes...)
	session.artifacts = append([]string{}, manifest.Artifacts...)
	session.mu.Unlock()
	session.MarkStopped()
	return session
}

// ReadEventsFile loads a JSONL event artifact, up to limit events.
func ReadEventsFile(path string, limit int) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	events := make([]Event, 0, 256)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return events, fmt.Errorf("line %d: %w", len(events)+1, err)
		}
		events = append(events, event)
		if limit > 0 && len(events) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return events, err
	}
	return events, nil
}
