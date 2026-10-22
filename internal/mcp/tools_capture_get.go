package mcp

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// Capture resolution (roadmap issues #2 and #10): a capture id resolves to the
// manifest artifact that describes the capture and to every component artifact
// that holds its bytes, so a consumer never needs the original response to reach
// the data. Producers register their capture when they publish the manifest.

const captureManifestDocumentMaxBytes = 1 << 20

// captureGetToolSpecs declares capture resolution.
func captureGetToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "capture_get",
			description: "Resolve one capture id to its manifest and every component artifact. Returns which tool produced the capture, when, its frame token and target generation, the manifest artifact descriptor plus its parsed document when it is bounded JSON, and one descriptor per component (artifact_id, kind, mime_type, size_bytes, sha256, address domain and captured range, download URL) including components the producer omitted or could not capture and why. Artifacts that retention already removed are reported as unavailable instead of being advertised as downloadable.",
			schema: objectSchema(map[string]any{
				"capture_id": stringProperty("Capture id returned by memory_snapshot_capture, system_snapshot_capture, or vdp_capture (cap_...)."),
				"context":    contextProperty(),
			}, []string{"capture_id"}),
			run: runCaptureGet,
		},
	}
}

type captureGetArgs struct {
	CaptureID string `json:"capture_id"`
	Context   string `json:"context"`
}

func runCaptureGet(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[captureGetArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	capture, err := tc.server.store.Capture(parsed.CaptureID, context.ID)
	if err != nil {
		return failureResult(captureNotFoundFailure(parsed.CaptureID, context.ID), tc.modern)
	}
	result := map[string]any{
		"capture_id":        capture.CaptureID,
		"context_id":        capture.ContextID,
		"producer_tool":     capture.ProducerTool,
		"created_at":        capture.CreatedAt,
		"frame_token":       nil,
		"target_generation": nil,
		"component_count":   len(capture.Components),
		"components":        captureComponentViews(tc, capture, context.ID),
	}
	if capture.FrameToken != nil {
		result["frame_token"] = *capture.FrameToken
	}
	if capture.TargetGeneration != nil {
		result["target_generation"] = *capture.TargetGeneration
	}
	if capture.SchemaVersion != "" {
		result["schema_version"] = capture.SchemaVersion
	}
	if capture.ManifestArtifact != "" {
		manifestView, document, documentNote := captureManifestView(tc, capture.ManifestArtifact, context.ID)
		result["manifest"] = manifestView
		if document != nil {
			result["manifest_document"] = document
		}
		result["manifest_document_note"] = documentNote
	}
	return okResult(result, tc.modern)
}

// captureNotFoundFailure is the stable failure for an unknown, expired, or
// foreign capture id. It never falls back to a live read.
func captureNotFoundFailure(captureID, contextID string) *toolFailure {
	return &toolFailure{
		Code:    "capture_not_found",
		Message: fmt.Sprintf("capture %q does not resolve in the active analysis context; check the id, the context, and whether retention already removed it", captureID),
		Data:    map[string]any{"capture_id": captureID, "context_id": contextID},
	}
}

// captureManifestView resolves the manifest artifact and, when it is bounded
// JSON, its parsed document.
func captureManifestView(tc toolContext, artifactID, contextID string) (map[string]any, any, string) {
	stored, err := tc.server.store.Metadata(artifactID, contextID)
	if err != nil {
		view := map[string]any{
			"artifact_id": artifactID,
			"available":   false,
			"reason":      "the manifest artifact no longer resolves in this context (retention or context change)",
		}
		return view, nil, "the manifest artifact is unavailable, so its document cannot be read"
	}
	view := artifactSummaryView(tc.server, stored, contextID)
	view["available"] = true
	data, _, err := tc.server.store.Bytes(artifactID, contextID)
	if err != nil {
		return view, nil, "reading the manifest bytes failed: " + err.Error()
	}
	if len(data) > captureManifestDocumentMaxBytes {
		return view, nil, fmt.Sprintf("the manifest is larger than the %d byte inline cap; fetch its URL instead", captureManifestDocumentMaxBytes)
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return view, nil, "the manifest is not JSON; fetch its URL instead"
	}
	return view, document, ""
}

// captureComponentViews renders every component of one capture, including the
// ones the producer omitted or could not capture.
func captureComponentViews(tc toolContext, capture artifact.Capture, contextID string) []map[string]any {
	views := make([]map[string]any, 0, len(capture.Components))
	for _, component := range capture.Components {
		view := map[string]any{
			"name":        component.Name,
			"artifact_id": component.ArtifactID,
			"kind":        component.Kind,
			"mime_type":   component.MimeType,
			"size_bytes":  component.SizeBytes,
			"sha256":      component.SHA256,
			"created_at":  nil,
			"expires_at":  nil,
			"available":   false,
		}
		if component.ArtifactID == "" {
			view["available"] = false
			if component.Omitted {
				view["omitted"] = true
			}
			if component.Unavailable {
				view["unavailable"] = true
			}
			if component.Reason != "" {
				view["reason"] = component.Reason
			}
			if component.AddressSpace != "" {
				view["address_space"] = component.AddressSpace
			}
			views = append(views, view)
			continue
		}
		if stored, err := tc.server.store.Metadata(component.ArtifactID, contextID); err == nil {
			view["available"] = true
			view["created_at"] = stored.CreatedAt
			view["size_bytes"] = stored.SizeBytes
			if expiry := tc.server.store.ExpiresAt(stored.CreatedAt); expiry != nil {
				view["expires_at"] = *expiry
			}
			if stored.SchemaVersion != "" {
				view["schema_version"] = stored.SchemaVersion
			}
			view["url"] = fmt.Sprintf("%s/artifacts/%s?context=%s", tc.server.baseURL, stored.ID, contextID)
		} else {
			view["reason"] = "the component artifact no longer resolves in this context (retention or context change)"
		}
		if component.AddressSpace != "" {
			view["address_space"] = component.AddressSpace
		}
		if component.StartAddress != nil {
			view["start_address"] = *component.StartAddress
			view["start_address_hex"] = canonicalHex(*component.StartAddress)
		}
		if component.ByteLength != nil {
			view["byte_length"] = *component.ByteLength
		}
		views = append(views, view)
	}
	return views
}

// registerCapture records one capture in the durable capture index. A producer
// calls it after its manifest artifact and every component artifact are written,
// so resolution never points at an artifact that does not exist.
func registerCapture(store *artifact.Store, capture artifact.Capture) *toolFailure {
	if capture.CaptureID == "" {
		return nil
	}
	if err := store.PutCapture(capture); err != nil {
		code := "artifact_error"
		if errors.Is(err, artifact.ErrUnknownCapture) {
			code = "capture_not_found"
		}
		return &toolFailure{Code: code, Message: "register capture index: " + err.Error()}
	}
	return nil
}

// captureComponentFromProvenance indexes one stored component artifact, copying
// the address facts a reader needs to decide whether the component covers the
// range it wants.
func captureComponentFromProvenance(name string, stored artifact.Artifact) artifact.CaptureComponent {
	component := artifact.CaptureComponent{
		Name:       name,
		ArtifactID: stored.ID,
		Kind:       stored.Kind,
		MimeType:   stored.MimeType,
		SizeBytes:  stored.SizeBytes,
		SHA256:     stored.SHA256,
	}
	if provenance := stored.Provenance; provenance != nil {
		component.AddressSpace = provenance.AddressSpace
		component.StartAddress = provenance.StartAddress
		component.ByteLength = provenance.ByteLength
	}
	return component
}

// omittedCaptureComponent indexes a component the producer deliberately skipped
// or could not capture, so capture_get reports it instead of hiding it.
func omittedCaptureComponent(name string, omitted, unavailable bool, reason string) artifact.CaptureComponent {
	return artifact.CaptureComponent{Name: name, Omitted: omitted, Unavailable: unavailable, Reason: reason}
}
