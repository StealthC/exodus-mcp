package artifact

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Capture resolution (roadmap issues #2 and #10): one index from a capture id to
// the manifest artifact that describes it and the component artifacts that hold
// its bytes. Producers register a capture when they publish its manifest, so a
// later call can resolve the id without the original response, and readers can
// consume the stored components instead of performing a fresh device read.

// ErrUnknownCapture is returned when a capture id does not resolve in the
// caller's context, or is structurally invalid.
var ErrUnknownCapture = errors.New("unknown capture")

// captureIDPattern is the stable shape of a capture id issued by newCaptureID in
// the MCP layer (cap_ plus base64url bytes).
var captureIDPattern = regexp.MustCompile(`^cap_[0-9A-Za-z_-]{4,64}$`)

// ValidCaptureID reports whether an id is structurally a capture id.
func ValidCaptureID(id string) bool { return captureIDPattern.MatchString(id) }

// CaptureComponent is one artifact of a capture, with the address facts a
// consumer needs to decide whether it covers the range it wants to read. The
// address fields mirror the artifact-provenance/2 envelope; they are recorded at
// registration time so resolution never has to read the bytes first.
type CaptureComponent struct {
	Name         string  `json:"name"`
	ArtifactID   string  `json:"artifact_id"`
	Kind         string  `json:"kind"`
	MimeType     string  `json:"mime_type"`
	SizeBytes    int64   `json:"size_bytes"`
	SHA256       string  `json:"sha256,omitempty"`
	AddressSpace string  `json:"address_space,omitempty"`
	StartAddress *uint64 `json:"start_address,omitempty"`
	ByteLength   *uint64 `json:"byte_length,omitempty"`
	// Omitted marks a component the producer deliberately skipped (a selection
	// argument); Unavailable marks one the producer could not capture at all.
	// Both carry Reason, and neither carries an artifact id.
	Omitted     bool   `json:"omitted,omitempty"`
	Unavailable bool   `json:"unavailable,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// Capture is one indexed capture: which tool produced it, the manifest artifact
// that describes it, its components, and the target facts observed at capture
// time.
type Capture struct {
	CaptureID        string             `json:"capture_id"`
	ContextID        string             `json:"context_id"`
	ProducerTool     string             `json:"producer_tool"`
	ManifestArtifact string             `json:"manifest_artifact_id"`
	SchemaVersion    string             `json:"schema_version,omitempty"`
	Components       []CaptureComponent `json:"components,omitempty"`
	FrameToken       *uint64            `json:"frame_token,omitempty"`
	TargetGeneration *uint64            `json:"target_generation,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
}

// PutCapture records one capture in the index. Registration is idempotent for
// the same id; a later producer re-registering an id replaces its record.
func (store *Store) PutCapture(capture Capture) error {
	if !captureIDPattern.MatchString(capture.CaptureID) {
		return fmt.Errorf("invalid capture id %q", capture.CaptureID)
	}
	if capture.ContextID == "" {
		return errors.New("capture registration requires a context id")
	}
	if capture.ManifestArtifact != "" && !idPattern.MatchString(capture.ManifestArtifact) {
		return fmt.Errorf("invalid capture manifest artifact id %q", capture.ManifestArtifact)
	}
	if capture.CreatedAt.IsZero() {
		capture.CreatedAt = time.Now().UTC()
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.captures[capture.CaptureID] = capture
	return store.persistIndexLocked()
}

// Capture resolves one capture id inside an analysis context.
func (store *Store) Capture(captureID, contextID string) (Capture, error) {
	if !captureIDPattern.MatchString(captureID) {
		return Capture{}, ErrUnknownCapture
	}
	store.mu.RLock()
	capture, present := store.captures[captureID]
	store.mu.RUnlock()
	if !present || capture.ContextID != contextID {
		return Capture{}, ErrUnknownCapture
	}
	return capture, nil
}

// Component resolves one named component of a capture.
func (capture Capture) Component(name string) (CaptureComponent, bool) {
	for _, component := range capture.Components {
		if component.Name == name {
			return component, true
		}
	}
	return CaptureComponent{}, false
}
