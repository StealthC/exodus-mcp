package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// VDP buffer byte caps (roadmap P2 documented baseline): VRAM is 64 KiB
// standard (131072 with extended VRAM), CRAM is 128 bytes, VSRAM is 80 bytes.
const (
	vdpExportVRAMCap  = uint64(65536)
	vdpExportCRAMCap  = uint64(128)
	vdpExportVSRAMCap = uint64(80)
	vdpExportKind     = "vdp-memory-export"
	vdpExportMimeType = "application/octet-stream"
)

// vdpExportToolSpecs implements artifact-first binary export of arbitrary
// VRAM/CRAM/VSRAM ranges (roadmap Phase 9): large regions never travel as
// Base64 through tool responses; the raw bytes land in an immutable artifact
// with the versioned provenance envelope.
func vdpExportToolSpecs() []toolSpec {
	return []toolSpec{
		{
			name:        "vdp_memory_export",
			description: "Export raw bytes of one VDP buffer (vram, cram, or vsram) as a downloadable binary artifact instead of Base64 inline. The response returns the artifact descriptor (hash, size, URL), the address domain, byte order, target generation, and the standardized capture_consistency object. Timed-buffer reads pause a running system briefly and restore it (system_paused_during_read); optional capture_mode \"paused\" makes the sample temporally atomic (one explicit pause/resume cycle). Length defaults to the full buffer (vram 65536, cram 128, vsram 80 bytes) and is capped per buffer.",
			schema: objectSchema(map[string]any{
				"context":      contextProperty(),
				"target":       enumProperty("VDP memory buffer to export.", []string{"vram", "cram", "vsram"}),
				"address":      addressProperty(),
				"length":       integerProperty("Bytes to export (default: the full buffer; caps: vram 65536, cram 128, vsram 80).", 1),
				"capture_mode": enumProperty("Capture mode: \"live\" (default) never pauses; \"paused\" pauses once, reads, and restores the prior run state.", []string{"live", "paused"}),
			}, []string{"target", "address"}),
			run: runVDPMemoryExport,
		},
	}
}

type vdpMemoryExportArgs struct {
	Context      string `json:"context"`
	Target       string `json:"target"`
	Address      any    `json:"address"`
	AddressSpace string `json:"address_space"`
	Length       uint64 `json:"length"`
	CaptureMode  string `json:"capture_mode"`
}

// vdpExportCapForTarget returns the buffer byte cap for one VDP target.
func vdpExportCapForTarget(target string) (uint64, bool) {
	switch target {
	case "vram":
		return vdpExportVRAMCap, true
	case "cram":
		return vdpExportCRAMCap, true
	case "vsram":
		return vdpExportVSRAMCap, true
	default:
		return 0, false
	}
}

// vdpExportSpaceForTarget maps a VDP target to its provenance address space.
func vdpExportSpaceForTarget(target string) string {
	switch target {
	case "vram":
		return "mem-vdp-vram"
	case "cram":
		return "mem-vdp-cram"
	default:
		return "mem-vdp-vsram"
	}
}

// vdpExportDeviceForTarget names the owning device for provenance.
func vdpExportDeviceForTarget(target string) string {
	switch target {
	case "vram":
		return "VDP VRAM"
	case "cram":
		return "VDP CRAM"
	default:
		return "VDP VSRAM"
	}
}

func runVDPMemoryExport(tc toolContext, args json.RawMessage) map[string]any {
	parsed, failure := decodeArgs[vdpMemoryExportArgs](args)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	context, failure := resolveContext(tc.server, parsed.Context)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	capBytes, known := vdpExportCapForTarget(parsed.Target)
	if !known {
		return failureResult(&toolFailure{Code: "invalid_params", Message: "target must be vram, cram, or vsram"}, tc.modern)
	}
	address, failure := resolveAddress(parsed.Address, addressSpaceFromArgs(args), "mem-vdp-"+parsed.Target)
	if failure != nil {
		return failureResult(failure, tc.modern)
	}
	length := parsed.Length
	if length == 0 {
		length = capBytes - address
	}
	if address >= capBytes {
		return failureResult(&toolFailure{
			Code:    "out_of_range",
			Message: fmt.Sprintf("address must be within the %s buffer (0x%X..0x%X)", parsed.Target, 0, capBytes-1),
		}, tc.modern)
	}
	if length > capBytes-address {
		return failureResult(&toolFailure{
			Code:    "length_exceeds_buffer",
			Message: fmt.Sprintf("length %d extends past the %s buffer end (0x%X); the buffer holds %d bytes from address 0x%X", length, parsed.Target, capBytes, capBytes-address, address),
		}, tc.modern)
	}

	guard := captureGuard{Mode: parsed.CaptureMode}
	if failure = guard.resolve(); failure != nil {
		return failureResult(failure, tc.modern)
	}
	export := func() (map[string]any, *toolFailure) {
		payload, failure := tc.server.executeCommand(tc.ctx, "vdp_mem_read", map[string]string{
			"target":  parsed.Target,
			"address": fmt.Sprintf("%d", address),
			"length":  fmt.Sprintf("%d", length),
		})
		if failure != nil {
			return nil, failure
		}
		rawDataBase64, _ := payload["data"].(string)
		raw, err := base64.StdEncoding.DecodeString(rawDataBase64)
		if err != nil {
			return nil, &toolFailure{Code: "bridge_error", Message: "decode base64 vdp payload: " + err.Error()}
		}
		byteOrder, _ := payload["byte_order"].(string)
		pausedDuringRead, _ := payload["system_paused_during_read"].(bool)
		capturedAt := time.Now().UTC()

		provenance := genericProvenance(tc.server, vdpExportKind, capturedAt)
		start := address
		provenance.AddressSpace = vdpExportSpaceForTarget(parsed.Target)
		provenance.Device = vdpExportDeviceForTarget(parsed.Target)
		provenance.StartAddress = &start
		provenance.EffectiveAddress = &start
		provenance.StartAddressHex = canonicalHex(address)
		provenance.EffectiveAddressHex = canonicalHex(address)
		byteLength := uint64(len(raw))
		provenance.ByteLength = &byteLength
		provenance.SpaceKind = "timed-buffer"
		provenance.ByteOrder = byteOrder
		provenance.Consistency = "live"
		provenance.CaptureConsistency = buildCaptureConsistency(tc.server, payload, false, true, nil, nil)

		stored, err := tc.server.store.PutWithProvenance(context.ID, vdpExportKind, vdpExportMimeType, raw, provenance)
		if err != nil {
			return nil, &toolFailure{Code: "artifact_error", Message: err.Error()}
		}
		result := map[string]any{
			"target":                    parsed.Target,
			"address_space":             vdpExportSpaceForTarget(parsed.Target),
			"address":                   address,
			"address_hex":               canonicalHex(address),
			"length":                    len(raw),
			"byte_order":                byteOrder,
			"raw_byte_ordering":         "address-order",
			"system_paused_during_read": pausedDuringRead,
			"capture_consistency":       captureConsistencyToMap(provenance.CaptureConsistency),
			"artifact":                  artifactDescriptor(tc.server, stored, context.ID),
			"sha256":                    stored.SHA256,
		}
		annotateAddressPair(result, vdpExportSpaceForTarget(parsed.Target), address)
		return result, nil
	}
	return withCaptureGuard(tc, guard, export)
}
