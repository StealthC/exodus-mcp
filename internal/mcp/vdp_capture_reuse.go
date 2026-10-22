package mcp

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// VDP capture reuse (roadmap issue #2): vdp_capture stores the VDP buffers its
// readers need, and the four readers consume those stored components instead of
// reading the device again. When the data really comes from a capture the
// response says so (data_source "capture", vdp_capture_reused true, the manifest
// frame token, and the capture's own capture_consistency); when it cannot, the
// call fails with capture_component_omitted instead of silently reading live.

// vdpCaptureProducerTool is the only producer whose manifest holds the VDP
// buffers a reader can consume.
const vdpCaptureProducerTool = "vdp_capture"

// vdpCaptureData is one resolved vdp_capture: its manifest facts and the stored
// components, read lazily and cached for the duration of one tool call.
type vdpCaptureData struct {
	capture     artifact.Capture
	consistency *artifact.CaptureConsistency
	frameToken  *uint64

	status   map[string]any
	statusAt bool

	vram      []byte
	vramStart uint64
	vramRead  bool

	cached map[string][]byte
}

// resolveVDPCapture resolves a capture id for one of the VDP readers. An unknown
// or foreign id is capture_not_found; the caller turns a missing component into
// capture_component_omitted when it asks for one.
func resolveVDPCapture(tc toolContext, contextID, captureID string) (*vdpCaptureData, *toolFailure) {
	capture, err := tc.server.store.Capture(captureID, contextID)
	if err != nil {
		return nil, captureNotFoundFailure(captureID, contextID)
	}
	if capture.ProducerTool != vdpCaptureProducerTool {
		return nil, &toolFailure{
			Code:    "capture_not_found",
			Message: fmt.Sprintf("capture %s was produced by %s, not %s; it holds no VDP buffer components", captureID, capture.ProducerTool, vdpCaptureProducerTool),
			Data:    map[string]any{"capture_id": captureID, "producer_tool": capture.ProducerTool},
		}
	}
	data := &vdpCaptureData{capture: capture, frameToken: capture.FrameToken, cached: map[string][]byte{}}
	if capture.ManifestArtifact != "" {
		if manifest, err := tc.server.store.Metadata(capture.ManifestArtifact, contextID); err == nil && manifest.Provenance != nil {
			data.consistency = manifest.Provenance.CaptureConsistency
		}
	}
	return data, nil
}

// componentBytes returns the stored bytes of one component. A component the
// manifest omitted, could not capture, or no longer serves is reported as
// capture_component_omitted with the full component inventory, never as a live
// read.
func (data *vdpCaptureData) componentBytes(tc toolContext, contextID, name string) ([]byte, *toolFailure) {
	if cached, present := data.cached[name]; present {
		return cached, nil
	}
	component, present := data.capture.Component(name)
	if !present {
		return nil, data.omittedFailure(name, "the capture manifest has no such component")
	}
	switch {
	case component.Omitted:
		reason := component.Reason
		if reason == "" {
			reason = "the capture call did not request this component"
		}
		return nil, data.omittedFailure(name, reason)
	case component.Unavailable:
		reason := component.Reason
		if reason == "" {
			reason = "the producing build could not capture this component"
		}
		return nil, data.omittedFailure(name, reason)
	case component.ArtifactID == "":
		return nil, data.omittedFailure(name, "the component records no artifact")
	}
	raw, _, err := tc.server.store.Bytes(component.ArtifactID, contextID)
	if err != nil {
		return nil, data.omittedFailure(name, "the component artifact no longer resolves in this context (retention or context change)")
	}
	data.cached[name] = raw
	return raw, nil
}

// statusView returns the captured VDP status payload. The status is part of every
// VDP capture, so a missing one is reported like any other omitted component.
func (data *vdpCaptureData) statusView(tc toolContext, contextID string) (map[string]any, *toolFailure) {
	if data.statusAt {
		return data.status, nil
	}
	raw, failure := data.componentBytes(tc, contextID, "vdp_status")
	if failure != nil {
		return nil, failure
	}
	var status map[string]any
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, &toolFailure{
			Code:    "capture_component_omitted",
			Message: fmt.Sprintf("the stored vdp_status component of capture %s is not a decodable status payload: %v", data.capture.CaptureID, err),
			Data:    map[string]any{"capture_id": data.capture.CaptureID, "required_component": "vdp_status"},
		}
	}
	data.status = status
	data.statusAt = true
	return status, nil
}

// vramRange returns the bytes of one VRAM range from the stored component,
// rejecting a capture whose VRAM component does not cover the range.
func (data *vdpCaptureData) vramRange(tc toolContext, contextID string, start, length uint64) ([]byte, *toolFailure) {
	if !data.vramRead {
		raw, failure := data.componentBytes(tc, contextID, "vram")
		if failure != nil {
			return nil, failure
		}
		data.vram = raw
		if component, present := data.capture.Component("vram"); present && component.StartAddress != nil {
			data.vramStart = *component.StartAddress
		}
		data.vramRead = true
	}
	covered := uint64(len(data.vram))
	end := start + length
	if start < data.vramStart || end < start || end > data.vramStart+covered {
		return nil, data.omittedFailure("vram", fmt.Sprintf(
			"the capture's VRAM component covers 0x%X-0x%X, which does not include the requested 0x%X-0x%X (capture with include_vram and a covering vram_address/vram_length)",
			data.vramStart, data.vramStart+covered-1, start, end-1))
	}
	offset := start - data.vramStart
	return data.vram[offset : offset+length], nil
}

// omittedFailure reports a missing component together with the inventory of the
// capture, so a caller can see what it actually holds.
func (data *vdpCaptureData) omittedFailure(name, reason string) *toolFailure {
	captured := []string{}
	skipped := []string{}
	for _, component := range data.capture.Components {
		if component.ArtifactID != "" && !component.Omitted && !component.Unavailable {
			captured = append(captured, component.Name)
			continue
		}
		if component.Omitted || component.Unavailable {
			skipped = append(skipped, component.Name)
		}
	}
	sort.Strings(captured)
	sort.Strings(skipped)
	return &toolFailure{
		Code: "capture_component_omitted",
		Message: fmt.Sprintf("capture %s cannot serve the %q component: %s. Capture components: %v; omitted or unavailable: %v",
			data.capture.CaptureID, name, reason, captured, skipped),
		Data: map[string]any{
			"capture_id":          data.capture.CaptureID,
			"producer_tool":       data.capture.ProducerTool,
			"required_component":  name,
			"reason":              reason,
			"components_captured": captured,
			"components_skipped":  skipped,
		},
	}
}

// captureConsistencyView is the capture's own capture_consistency object, or nil
// when the manifest provenance carries none.
func (data *vdpCaptureData) captureConsistencyView() map[string]any {
	return captureConsistencyToMap(data.consistency)
}

// captureConsistencyState is the capture's consistency label, or "unknown".
func (data *vdpCaptureData) captureConsistencyState() string {
	if data.consistency == nil || data.consistency.State == "" {
		return "unknown"
	}
	return data.consistency.State
}

// coherentCapture reports whether the capture describes one coherent instant,
// so a composite derived from it may claim snapshot coherence.
func (data *vdpCaptureData) coherentCapture() bool {
	switch data.captureConsistencyState() {
	case consistencyPaused, consistencyAtomic:
		return true
	default:
		return false
	}
}

// captureReuseSource carries the response facts every reader reports when it
// consumed a stored capture instead of the device.
type captureReuseSource struct {
	unused bool
	id     string
	data   *vdpCaptureData
}

// captureReuseOf reports the reuse facts for a resolved capture, or an empty
// source for a live read.
func captureReuseOf(captureID string, data *vdpCaptureData) captureReuseSource {
	if captureID == "" || data == nil {
		return captureReuseSource{unused: true}
	}
	return captureReuseSource{id: captureID, data: data}
}

// annotate stamps the data_source, reuse flag, and capture facts on a reader
// response. A live read is labeled live and carries no reuse claim.
func (source captureReuseSource) annotate(tc toolContext, value map[string]any, note string) {
	if source.unused {
		value["data_source"] = "live"
		return
	}
	value["data_source"] = "capture"
	value["vdp_capture_reused"] = true
	value["vdp_capture_id"] = source.id
	value["vdp_capture_frame_token"] = nil
	if source.data.frameToken != nil {
		value["vdp_capture_frame_token"] = *source.data.frameToken
	}
	value["capture_consistency"] = source.data.captureConsistencyView()
	value["consistency"] = source.data.captureConsistencyState()
	if note != "" {
		value["note"] = note
	}
}

// captureReuseNote is the honest note of a reader that consumed stored bytes.
func captureReuseNote(tool, component, captureID string) string {
	return fmt.Sprintf("%s decoded the stored %s component of capture %s; no device read was performed for this response, and the capture's own capture_consistency describes how it was sampled.", tool, component, captureID)
}
