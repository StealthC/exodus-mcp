package experiment

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"regexp"
	"strings"
)

// Wire message types exchanged with a Python script over its stdin/stdout
// JSON-lines duplex.
const (
	messageInit     = "init"     // Go -> script, once, before anything else
	messageResult   = "result"   // Go -> script, one reply per call/artifact
	messageError    = "error"    // Go -> script, fatal; the run ends after it
	messageCall     = "call"     // script -> Go, one allowlisted tool call
	messageArtifact = "artifact" // script -> Go, publish bounded derived bytes
	messageComplete = "complete" // script -> Go, successful conclusion
)

// initMessage is the first message a Python script receives on stdin. It
// carries the call arguments and the limits the runner enforces.
type initMessage struct {
	Type         string         `json:"type"`
	ExperimentID string         `json:"experiment_id"`
	Script       string         `json:"script"`
	Arguments    map[string]any `json:"arguments,omitempty"`
	Limits       limitsView     `json:"limits"`
}

type limitsView struct {
	MaxSteps       int   `json:"max_steps"`
	MaxOutputBytes int64 `json:"max_output_bytes"`
}

// protocolError is the machine-readable error shape used in result replies,
// fatal error messages, and the manifest.
type protocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// resultMessage replies to one call or artifact message.
type resultMessage struct {
	Type  string         `json:"type"`
	ID    string         `json:"id"`
	OK    bool           `json:"ok"`
	Value map[string]any `json:"value,omitempty"`
	Error *protocolError `json:"error,omitempty"`
}

// runnerErrorMessage is the fatal message sent just before the runner kills
// a misbehaving script.
type runnerErrorMessage struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// callMessage requests one allowlisted tool execution.
type callMessage struct {
	Type      string         `json:"type"`
	ID        string         `json:"id"`
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// artifactMessage publishes bounded derived bytes into the context's
// artifact store; the runner replies with the artifact descriptor.
type artifactMessage struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	MimeType   string `json:"mime_type"`
	DataBase64 string `json:"data_base64"`
}

// completeMessage concludes a run successfully; the runner stops executing
// steps after it.
type completeMessage struct {
	Type    string         `json:"type"`
	Summary map[string]any `json:"summary,omitempty"`
}

// messageType reports the type field of one script line. Anything that does
// not parse as a JSON object with a known "type" is a protocol violation.
func messageType(line []byte) (string, error) {
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &envelope); err != nil {
		return "", err
	}
	switch envelope.Type {
	case messageCall, messageArtifact, messageComplete:
		return envelope.Type, nil
	default:
		return "", fmt.Errorf("unsupported message type %q", envelope.Type)
	}
}

// validateMessageID enforces the bounded identifier contract shared by call
// and artifact messages.
func validateMessageID(id string) error {
	if id == "" {
		return errors.New("message id must not be empty")
	}
	if len(id) > maxMessageIDBytes {
		return fmt.Errorf("message id exceeds %d bytes", maxMessageIDBytes)
	}
	return nil
}

var kindPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// validateArtifactMeta rejects unsafe or oversized artifact announcements:
// the kind names the artifact index, and the MIME type must be parseable and
// short.
func validateArtifactMeta(kind, mimeType string) error {
	if !kindPattern.MatchString(kind) {
		return fmt.Errorf("invalid artifact kind %q", kind)
	}
	if len(mimeType) > 128 {
		return errors.New("mime_type exceeds 128 bytes")
	}
	if _, _, err := mime.ParseMediaType(mimeType); err != nil {
		return fmt.Errorf("invalid mime_type %q: %v", mimeType, err)
	}
	return nil
}

// excerpt renders a bounded, printable excerpt of an offending line for
// diagnostic messages without echoing attacker-controlled control bytes.
func excerpt(line []byte) string {
	text := string(line)
	if len(text) > 200 {
		text = text[:200]
	}
	text = strings.ToValidUTF8(text, "\uFFFD")
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return '\uFFFD'
		}
		return r
	}, text)
}

// sanitizeDiagnosticText makes captured script stderr safe to store as a
// text artifact: valid UTF-8 and no NUL bytes.
func sanitizeDiagnosticText(text string) string {
	text = strings.ToValidUTF8(text, "\uFFFD")
	return strings.ReplaceAll(text, "\x00", "")
}
