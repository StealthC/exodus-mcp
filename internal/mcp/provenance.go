package mcp

import (
	"encoding/json"
	"time"

	"github.com/StealthC/exodus-mcp/internal/artifact"
)

// Shared capture provenance (roadmap P0): one versioned envelope recorded at
// capture time for every artifact whose bytes have an address, time, target,
// or decoding interpretation. The envelope is immutable artifact metadata;
// memory_search and memory_diff derive their address domain from it instead of
// accepting caller restatement, and artifact_describe exposes the full typed
// view. Since envelope v2 the envelope also carries the standardized
// capture_consistency object and, for composite captures, a stable capture id.

// mdSpaceDevice names the owning device of each known space on the documented
// Mega Drive baseline, mirroring the bus mapping table in spacemap.go. Unknown
// spaces keep the space id as the device label instead of inventing a name.
var mdSpaceDevice = map[string]string{
	"m68k-bus":            "68000 CPU bus",
	"mem-ram":             "68000 work RAM",
	"mem-rom":             "cartridge ROM",
	"mem-boot-rom":        "boot ROM",
	"mem-z80-ram":         "Z80 RAM (68K window)",
	"z80-bus":             "Z80 CPU bus",
	"mem-vdp-vram":        "VDP VRAM",
	"mem-vdp-cram":        "VDP CRAM",
	"mem-vdp-vsram":       "VDP VSRAM",
	"mem-vdp-spritecache": "VDP sprite cache",
}

// provenanceEnvelopeView renders the typed provenance envelope as a plain map
// so structured responses and tests always see the same JSON shape.
func provenanceEnvelopeView(provenance artifact.Provenance) map[string]any {
	encoded, err := json.Marshal(provenance)
	if err != nil {
		return map[string]any{"artifact_schema": artifact.ProvenanceSchema, "state": artifact.ProvenanceStateUnknown}
	}
	var view map[string]any
	if err := json.Unmarshal(encoded, &view); err != nil {
		return map[string]any{"artifact_schema": artifact.ProvenanceSchema, "state": artifact.ProvenanceStateUnknown}
	}
	return view
}

// provenanceUnknownView is the honest envelope for artifacts whose producer
// attached no capture metadata: never invented addresses or targets.
func provenanceUnknownView() map[string]any {
	return map[string]any{
		"artifact_schema": artifact.ProvenanceSchema,
		"state":           artifact.ProvenanceStateUnknown,
		"note":            "The producing tool did not attach capture metadata; the artifact's address and target facts are unknown. Do not derive addresses from this artifact.",
	}
}

// genericProvenance builds a minimal envelope for producers without an address
// domain (frames, traces, coverage, exports): kind, target generation, ROM
// identity, capture time, and the standardized capture-consistency object.
// Byte order is recorded when the producer knows it; otherwise the field is
// omitted rather than guessed.
func genericProvenance(server *Server, kind string, capturedAt time.Time) *artifact.Provenance {
	generation := server.target.Generation()
	romFacts := server.romIdentity.romFileFacts(server.currentROMPath())
	provenance := &artifact.Provenance{
		State:              artifact.ProvenanceStateComplete,
		Kind:               kind,
		TargetGeneration:   &generation,
		ROMSHA256:          romFacts.SHA256,
		ROMPath:            server.currentROMPath(),
		CapturedAt:         capturedAt,
		RawByteOrdering:    "address-order",
		CPURunState:        server.runStateString(),
		CaptureConsistency: buildCaptureConsistency(server, map[string]any{}, false, true, nil, nil),
	}
	if provenance.CaptureConsistency.Note == "" {
		provenance.CaptureConsistency.Note = "Capture-time run state; the artifact may span an execution window (see the tool summary)."
	}
	return provenance
}

// captureProvenance builds the full envelope for a mem_read-style capture:
// address domain, byte order, space kind, device, target identity, run state,
// consistency, and capture time from one bridge payload. requestedAddress is
// the caller-supplied range start; payload mirrors the plugin mem_read shape.
// captureID links artifacts of one composite capture ("" for standalone
// reads); consistency overrides the derived object (nil derives it from the
// payload and the run-state tracker).
func captureProvenance(server *Server, kind, spaceID string, requestedAddress uint64, byteLength uint64, payload map[string]any, capturedAt time.Time, captureID string, consistency *artifact.CaptureConsistency) *artifact.Provenance {
	effective, _ := payload["effective_address"].(float64)
	byteOrder, _ := payload["byte_order"].(string)
	spaceKind, _ := payload["kind"].(string)
	consistencyLabel, _ := payload["consistency"].(string)
	pausedDuringRead, _ := payload["system_paused_during_read"].(bool)
	generation := server.target.Generation()
	romFacts := server.romIdentity.romFileFacts(server.currentROMPath())

	start := requestedAddress
	effectiveAddress := uint64(effective)
	if effectiveAddress == 0 && len(payload) > 0 {
		// Payload without an effective_address field (tests, older plugin
		// shapes): the requested address is the effective one.
		effectiveAddress = requestedAddress
	}
	provenance := &artifact.Provenance{
		State:               artifact.ProvenanceStateComplete,
		Kind:                kind,
		AddressSpace:        spaceID,
		StartAddress:        &start,
		EffectiveAddress:    &effectiveAddress,
		StartAddressHex:     canonicalHex(start),
		EffectiveAddressHex: canonicalHex(effectiveAddress),
		ByteLength:          &byteLength,
		RawByteOrdering:     "address-order",
		ByteOrder:           byteOrder,
		SpaceKind:           spaceKind,
		TargetGeneration:    &generation,
		ROMSHA256:           romFacts.SHA256,
		ROMPath:             server.currentROMPath(),
		Consistency:         consistencyLabel,
		CapturedAt:          capturedAt,
		CaptureID:           captureID,
	}
	if device, known := mdSpaceDevice[spaceID]; known {
		provenance.Device = device
	} else {
		provenance.Device = spaceID
	}
	if pausedDuringRead {
		// The handler had to stop a running system to sample; the capture is
		// paused-atomically from a running state.
		provenance.CPURunState = "running"
	} else if running, known := server.runState.currentState(); known {
		if running {
			provenance.CPURunState = "running"
		} else {
			provenance.CPURunState = "paused"
		}
	} else {
		provenance.CPURunState = "unknown"
	}
	if consistency == nil {
		consistency = buildCaptureConsistency(server, payload, false, true, nil, nil)
	}
	provenance.CaptureConsistency = consistency
	return provenance
}

// runStateString renders the last observed run state as a provenance label.
func (server *Server) runStateString() string {
	if running, known := server.runState.currentState(); known {
		if running {
			return "running"
		}
		return "paused"
	}
	return "unknown"
}
